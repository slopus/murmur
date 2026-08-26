import {
    RelayService,
    RelayWebSocketSession,
    SqliteRelayStore,
    createRelayFetchHandler,
    type RelayOptions,
    type RelaySessionClaims,
    type RelayWebSocketPeer,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    DeliveryCursorTrimmedError,
    DeliveryTransportError,
    HttpDeliveryTransport,
    InboxProcessor,
    WebSocketDeliveryTransport,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    type DeliveryFetch,
    type DeliveryPublishOutcome,
    type DeliveryTransport,
    type DeliveryWebSocket,
    type DeliveryWebSocketCloseEvent,
    type DeliveryWebSocketMessageEvent,
    type InboxPage,
    type RelaySessionProvider,
    type SignedDelivery,
    type SignedInboxAck,
    type SignedInboxRead,
} from "../../delivery/index.js";
import {
    MurmurClient,
    MurmurResetRequiredError,
    type MurmurResetEvent,
    type MurmurUpdate,
} from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { equalBytes, utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    ChaosInjectedError,
    FaultInjectingDeliveryTransport,
    ManualVirtualClock,
    SeededChaosSchedule,
    SeededRandom,
    type ChaosRule,
} from "../index.js";

const NOW = 1_700_000_000_000;
const DAY_MILLISECONDS = 24 * 60 * 60 * 1_000;
const TWENTY_NINE_DAYS = 29 * DAY_MILLISECONDS;
const SIX_MONTHS = 180 * DAY_MILLISECONDS;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "network-delivery-chaos",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

function cloneDelivery(delivery: SignedDelivery): SignedDelivery {
    return {
        version: 1,
        id: delivery.id,
        sender: delivery.sender.slice(),
        senderAccount: delivery.senderAccount.slice(),
        recipients: delivery.recipients.map((recipient) => recipient.slice()),
        targetAccounts: delivery.targetAccounts.map((target) => ({
            accountKey: target.accountKey.slice(),
            rosterRevision: target.rosterRevision,
        })),
        ownerAccount: delivery.ownerAccount?.slice() ?? null,
        sessionId: delivery.sessionId?.slice() ?? null,
        createdAt: delivery.createdAt,
        expiresAt: delivery.expiresAt,
        ciphertext: delivery.ciphertext.slice(),
        signature: delivery.signature.slice(),
    };
}

function cloneRead(request: SignedInboxRead): SignedInboxRead {
    return {
        version: 1,
        recipient: request.recipient.slice(),
        after: request.after,
        limit: request.limit,
        waitMilliseconds: request.waitMilliseconds,
        createdAt: request.createdAt,
        signature: request.signature.slice(),
    };
}

function cloneAck(request: SignedInboxAck): SignedInboxAck {
    return {
        version: 1,
        recipient: request.recipient.slice(),
        through: request.through,
        createdAt: request.createdAt,
        signature: request.signature.slice(),
    };
}

class RecordingDeliveryTransport implements DeliveryTransport {
    readonly published: SignedDelivery[] = [];
    readonly reads: SignedInboxRead[] = [];
    readonly acknowledgements: SignedInboxAck[] = [];
    readonly #delegate: DeliveryTransport;
    readonly stream?: NonNullable<DeliveryTransport["stream"]>;

    constructor(delegate: DeliveryTransport) {
        this.#delegate = delegate;
        if (delegate.stream !== undefined) {
            this.stream = (request, signal, hooks) => {
                this.reads.push(cloneRead(request));
                return delegate.stream!.call(delegate, request, signal, hooks);
            };
        }
    }

    async publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        this.published.push(cloneDelivery(delivery));
        return this.#delegate.publish(delivery, signal);
    }

    async read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        this.reads.push(cloneRead(request));
        return this.#delegate.read(request, signal);
    }

    async acknowledge(
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }> {
        this.acknowledgements.push(cloneAck(request));
        return this.#delegate.acknowledge(request, signal);
    }
}

interface NetworkFixture {
    readonly clock: ManualVirtualClock;
    readonly relay: RelayService;
    readonly http: HttpDeliveryTransport;
    readonly recording: RecordingDeliveryTransport;
}

function networkFixture(options: RelayOptions = {}, now: number = NOW): NetworkFixture {
    const clock = new ManualVirtualClock(now);
    const relay = new RelayService(new SqliteRelayStore(":memory:"), options, undefined, () =>
        clock.now(),
    );
    const http = new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) });
    return { clock, relay, http, recording: new RecordingDeliveryTransport(http) };
}

class RelayBackedWebSocket implements DeliveryWebSocket {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null = null;
    readonly #session: RelayWebSocketSession;

    constructor(relay: RelayService, claims: RelaySessionClaims) {
        const peer: RelayWebSocketPeer = {
            send: (message) => {
                queueMicrotask(() => this.onmessage?.({ data: message }));
            },
            close: (code = 1000, reason = "") => {
                if (this.readyState === 3) return;
                this.readyState = 3;
                queueMicrotask(() => this.onclose?.({ code, reason, wasClean: code === 1000 }));
            },
        };
        this.#session = new RelayWebSocketSession({ relay, claims, peer });
        queueMicrotask(() => {
            if (this.readyState !== 0) return;
            this.readyState = 1;
            this.onopen?.();
        });
    }

    send(data: string): void {
        void this.#session.receive(data).catch(() => this.onerror?.());
    }

    close(code: number = 1000, reason: string = ""): void {
        this.#session.close(code, reason);
    }
}

function negotiatedTransport(
    fixture: NetworkFixture,
    identity: IdentityKeyPair,
): WebSocketDeliveryTransport {
    const endpoint = "wss://relay.test/v2/connect";
    const provider: RelaySessionProvider = {
        issue: async () => ({
            version: 1,
            protocol: "murmur-websocket-v1",
            endpoint,
            token: "network.delivery.ticket",
            expiresAt: fixture.clock.now() + 60_000,
        }),
    };
    return new WebSocketDeliveryTransport(identity, provider, {
        now: fixture.clock.now,
        webSocketFactory: () =>
            new RelayBackedWebSocket(fixture.relay, {
                version: 1,
                protocol: "murmur-websocket-v1",
                device: identity.publicKey.slice(),
                endpoint,
                admissionPrincipal: "network-delivery-chaos",
                issuedAt: fixture.clock.now(),
                expiresAt: fixture.clock.now() + 60_000,
                nonce: new Uint8Array(24).fill(4),
            }),
    });
}

async function murmurClient(
    identity: IdentityKeyPair,
    transport: DeliveryTransport,
    store: MemoryMurmurStore,
    now: () => number,
): Promise<MurmurClient> {
    return MurmurClient.open({ identity, transport, store, now });
}

async function drainUpdates(client: MurmurClient, values: string[]): Promise<void> {
    await client.synchronize(
        { waitMilliseconds: 0 },
        {
            onUpdates: (updates: readonly MurmurUpdate[]) => {
                values.push(...updates.map((update) => utf8Decode(update.bytes)));
            },
        },
    );
}

function labeledDelivery(
    sender: IdentityKeyPair,
    recipients: readonly IdentityKeyPair[],
    label: string,
    createdAt: number = NOW,
    expiresAt: number = createdAt + 60_000,
): SignedDelivery {
    return createSignedDelivery(
        sender,
        recipients.map((recipient) => recipient.publicKey),
        utf8Encode(label),
        { createdAt, expiresAt },
    );
}

async function inbox(
    transport: DeliveryTransport,
    recipient: IdentityKeyPair,
    now: number,
    after: string | null = null,
): Promise<InboxPage> {
    try {
        return await transport.read(
            createSignedInboxRead(recipient, { after, limit: 256, createdAt: now }),
        );
    } catch (error: unknown) {
        if (!(error instanceof DeliveryCursorTrimmedError) || after !== null) throw error;
        return transport.read(
            createSignedInboxRead(recipient, {
                after: error.acknowledgedThrough,
                limit: 256,
                createdAt: now,
            }),
        );
    }
}

function expectExactDelivery(left: SignedDelivery, right: SignedDelivery): void {
    expect(left).toEqual(right);
    expect(left.id).toBe(right.id);
}

function processor(
    identity: IdentityKeyPair,
    transport: DeliveryTransport,
    store: MemoryMurmurStore,
    effects: string[],
    now: () => number,
): InboxProcessor {
    return new InboxProcessor(
        { identity, transport, store },
        async (transaction, queued) => {
            const label = utf8Decode(queued.delivery.ciphertext);
            await transaction.set(`application/${queued.delivery.id}`, queued.delivery.ciphertext);
            effects.push(label);
        },
        { now },
    );
}

describe("network and delivery contract chaos", () => {
    test("NET-01 rejects before acceptance and retries the exact delivery ID", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const delivery = labeledDelivery(alice, [bob], "NET-01");
        const schedule = new SeededChaosSchedule(0x4e455401, [
            {
                id: "publish-partition",
                selector: { operation: "publish", phase: "before" },
                effect: { type: "throw", message: "relay unreachable" },
                maximumApplications: 3,
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.recording,
            schedule,
        });
        try {
            for (let attempt = 0; attempt < 3; attempt += 1) {
                await expect(transport.publish(delivery)).rejects.toThrow("relay unreachable");
                expect(fixture.recording.published).toHaveLength(0);
                expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(0);
            }
            const accepted = await transport.publish(delivery);
            expect(accepted.duplicate).toBe(false);
            expect(fixture.recording.published).toHaveLength(1);
            expectExactDelivery(fixture.recording.published[0]!, delivery);
            expect(
                (await inbox(fixture.http, bob, NOW)).deliveries.map((item) => item.delivery.id),
            ).toEqual([delivery.id]);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-02 loses accepted responses and relay-deduplicates exact retries", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const delivery = labeledDelivery(alice, [bob], "NET-02");
        const schedule = new SeededChaosSchedule(0x4e455402, [
            {
                id: "lost-publish-response",
                selector: { operation: "publish", phase: "after" },
                effect: { type: "drop" },
                maximumApplications: 3,
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.recording,
            schedule,
        });
        try {
            for (let attempt = 0; attempt < 3; attempt += 1) {
                await expect(transport.publish(delivery)).rejects.toBeInstanceOf(
                    ChaosInjectedError,
                );
            }
            await expect(transport.publish(delivery)).resolves.toMatchObject({ duplicate: true });
            expect(fixture.recording.published).toHaveLength(4);
            for (const attempted of fixture.recording.published) {
                expectExactDelivery(attempted, delivery);
            }
            const page = await inbox(fixture.http, bob, NOW);
            expect(page.deliveries).toHaveLength(1);
            expect(page.deliveries[0]!.delivery.id).toBe(delivery.id);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-03 real relay multicast is all-or-nothing for the exact recipient set", async () => {
        const acceptedFixture = networkFixture();
        const rejectedFixture = networkFixture({
            maximumGlobalReferences: 2,
            maximumAdmissionReferences: 2,
            maximumSenderReferences: 2,
        });
        const alice = generateIdentityKeyPair();
        const recipients = [
            generateIdentityKeyPair(),
            generateIdentityKeyPair(),
            generateIdentityKeyPair(),
        ];
        const accepted = labeledDelivery(alice, recipients, "NET-03 accepted");
        const rejected = labeledDelivery(alice, recipients, "NET-03 rejected");
        try {
            await acceptedFixture.http.publish(accepted);
            for (const recipient of recipients) {
                const page = await inbox(acceptedFixture.http, recipient, NOW);
                expect(page.deliveries.map((item) => item.delivery.id)).toEqual([accepted.id]);
            }

            await expect(rejectedFixture.http.publish(rejected)).rejects.toBeInstanceOf(
                DeliveryTransportError,
            );
            for (const recipient of recipients) {
                expect((await inbox(rejectedFixture.http, recipient, NOW)).deliveries).toHaveLength(
                    0,
                );
            }
        } finally {
            await acceptedFixture.relay.close();
            await rejectedFixture.relay.close();
        }
    });

    test("NET-04 response order cannot replace per-inbox UUIDv7 acceptance order", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const earlyCreated = labeledDelivery(alice, [bob], "created early", NOW - 1_000);
        const lateCreated = labeledDelivery(alice, [bob], "created late", NOW + 1_000);
        let releaseDelay: (() => void) | undefined;
        let delayStarted: (() => void) | undefined;
        const entered = new Promise<void>((resolve) => {
            delayStarted = resolve;
        });
        const gate = new Promise<void>((resolve) => {
            releaseDelay = resolve;
        });
        const schedule = new SeededChaosSchedule(0x4e455404, [
            {
                id: "delay-first-response",
                selector: { operation: "publish", phase: "after", ordinal: 1 },
                effect: { type: "delay", milliseconds: 1 },
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.recording,
            schedule,
            delay: async () => {
                delayStarted?.();
                await gate;
            },
        });
        try {
            const responses: string[] = [];
            const first = transport.publish(earlyCreated).then((outcome) => {
                responses.push("early-created");
                return outcome;
            });
            await entered;
            const second = await transport.publish(lateCreated);
            responses.push("late-created");
            releaseDelay?.();
            const firstOutcome = await first;

            expect(responses).toEqual(["late-created", "early-created"]);
            expect(firstOutcome.eventId < second.eventId).toBe(true);
            const page = await inbox(fixture.http, bob, NOW);
            expect(page.deliveries.map((item) => item.eventId)).toEqual([
                firstOutcome.eventId,
                second.eventId,
            ]);
            expect(page.deliveries.map((item) => utf8Decode(item.delivery.ciphertext))).toEqual([
                "created early",
                "created late",
            ]);
            schedule.assertConsumed();
        } finally {
            releaseDelay?.();
            await fixture.relay.close();
        }
    });

    test("NET-05 aborts cleanly before delegate reach and after ambiguous acceptance", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const before = labeledDelivery(alice, [bob], "abort-before");
        const during = labeledDelivery(alice, [bob], "abort-during");
        const after = labeledDelivery(alice, [bob], "abort-after");
        try {
            const immediate = new FaultInjectingDeliveryTransport({
                actor: "alice",
                delegate: fixture.recording,
                schedule: new SeededChaosSchedule(0x4e455405),
            });
            const preAborted = new AbortController();
            preAborted.abort(new Error("abort before publish"));
            await expect(immediate.publish(before, preAborted.signal)).rejects.toThrow(
                "abort before publish",
            );

            const duringController = new AbortController();
            const duringSchedule = new SeededChaosSchedule(0x4e455406, [
                {
                    id: "blocked-before-publish",
                    selector: { operation: "publish", phase: "before" },
                    effect: { type: "delay", milliseconds: 1 },
                },
            ]);
            const blocked = new FaultInjectingDeliveryTransport({
                actor: "alice",
                delegate: fixture.recording,
                schedule: duringSchedule,
                delay: () => duringController.abort(new Error("abort blocked publish")),
            });
            await expect(blocked.publish(during, duringController.signal)).rejects.toThrow(
                "abort blocked publish",
            );

            const afterController = new AbortController();
            const afterSchedule = new SeededChaosSchedule(0x4e455407, [
                {
                    id: "abort-after-acceptance",
                    selector: { operation: "publish", phase: "after" },
                    effect: { type: "delay", milliseconds: 1 },
                },
            ]);
            const ambiguous = new FaultInjectingDeliveryTransport({
                actor: "alice",
                delegate: fixture.recording,
                schedule: afterSchedule,
                delay: () => afterController.abort(new Error("abort accepted publish")),
            });
            await expect(ambiguous.publish(after, afterController.signal)).rejects.toThrow(
                "abort accepted publish",
            );
            await expect(immediate.publish(after)).resolves.toMatchObject({ duplicate: true });

            expect(fixture.recording.published.map((item) => item.id)).toEqual([
                after.id,
                after.id,
            ]);
            expect(
                (await inbox(fixture.http, bob, NOW)).deliveries.map((item) => item.delivery.id),
            ).toEqual([after.id]);
            duringSchedule.assertConsumed();
            afterSchedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-06 enforces the configured 29-day remaining-TTL boundary at one millisecond", async () => {
        const fixture = networkFixture({
            maximumDeliveryTtlMilliseconds: TWENTY_NINE_DAYS,
            maximumAuthenticationSkewMilliseconds: 1_000,
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        try {
            const lagged = labeledDelivery(
                alice,
                [bob],
                "lagged",
                NOW - 1_000,
                NOW + TWENTY_NINE_DAYS,
            );
            const leading = labeledDelivery(
                alice,
                [bob],
                "leading",
                NOW + 1_000,
                NOW + TWENTY_NINE_DAYS,
            );
            await expect(fixture.http.publish(lagged)).resolves.toMatchObject({ duplicate: false });
            await expect(fixture.http.publish(leading)).resolves.toMatchObject({
                duplicate: false,
            });
            await expect(
                fixture.http.publish(
                    labeledDelivery(
                        alice,
                        [bob],
                        "one millisecond too long",
                        NOW,
                        NOW + TWENTY_NINE_DAYS + 1,
                    ),
                ),
            ).rejects.toMatchObject({ status: 401, code: "unauthorized" });
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(2);
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-07 duplicate and stale replay pages never apply an event twice", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e455407, [
            {
                id: "duplicate-first-page-entry",
                selector: { operation: "read", phase: "after", ordinal: 1 },
                effect: { type: "duplicate", copies: 1, index: 0 },
            },
            {
                id: "replay-stale-page",
                selector: { operation: "read", phase: "after", ordinal: 3 },
                effect: { type: "replay" },
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const store = new MemoryMurmurStore();
        const effects: string[] = [];
        const inboxProcessor = processor(bob, fault, store, effects, () => NOW);
        try {
            for (let index = 0; index < 3; index += 1) {
                await fixture.http.publish(labeledDelivery(alice, [bob], `event-${index}`));
            }
            await expect(inboxProcessor.synchronize()).rejects.toThrow(
                "Inbox continuity was irrecoverably lost",
            );
            expect(effects).toEqual([]);
            expect(await inboxProcessor.cursor()).toBeNull();

            const applied = await inboxProcessor.synchronize();
            expect(applied).toMatchObject({ processed: 3, rejected: 0, exhausted: true });
            const cursor = await inboxProcessor.cursor();
            await expect(inboxProcessor.synchronize()).rejects.toThrow(
                "Inbox continuity was irrecoverably lost",
            );
            expect(effects).toEqual(["event-0", "event-1", "event-2"]);
            expect(await inboxProcessor.cursor()).toBe(cursor);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-08 a reversed page fails closed without cursor or acknowledgement progress", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e455408, [
            {
                id: "reverse-first-page",
                selector: { operation: "read", phase: "after", ordinal: 1 },
                effect: { type: "reorder", order: "reverse" },
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const effects: string[] = [];
        const inboxProcessor = processor(bob, fault, new MemoryMurmurStore(), effects, () => NOW);
        try {
            for (let index = 0; index < 3; index += 1) {
                await fixture.http.publish(labeledDelivery(alice, [bob], `ordered-${index}`));
            }
            await expect(inboxProcessor.synchronize()).rejects.toThrow(
                "Inbox continuity was irrecoverably lost",
            );
            expect(await inboxProcessor.cursor()).toBeNull();
            expect(fixture.recording.acknowledgements).toHaveLength(0);
            await expect(inboxProcessor.synchronize()).resolves.toMatchObject({ processed: 3 });
            expect(effects).toEqual(["ordered-0", "ordered-1", "ordered-2"]);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-09 truncated pages recover every hidden tail with a monotonic cursor", async () => {
        for (const requestedLimit of [2, 3]) {
            const fixture = networkFixture();
            const alice = generateIdentityKeyPair();
            const bob = generateIdentityKeyPair();
            const schedule = new SeededChaosSchedule(0x4e455409 + requestedLimit, [
                {
                    id: "truncate-first-page",
                    selector: { operation: "read", phase: "after", ordinal: 1 },
                    effect: { type: "truncate", limit: 1 },
                },
            ]);
            const fault = new FaultInjectingDeliveryTransport({
                actor: "bob",
                delegate: fixture.recording,
                schedule,
            });
            const effects: string[] = [];
            const inboxProcessor = processor(
                bob,
                fault,
                new MemoryMurmurStore(),
                effects,
                () => NOW,
            );
            try {
                for (let index = 0; index < 3; index += 1) {
                    await fixture.http.publish(labeledDelivery(alice, [bob], `tail-${index}`));
                }
                const first = await inboxProcessor.synchronize({ limit: requestedLimit });
                expect(first).toMatchObject({ processed: 1, exhausted: false });
                const cursors = [first.cursor!];
                while (effects.length < 3) {
                    const next = await inboxProcessor.synchronize({ limit: requestedLimit });
                    cursors.push(next.cursor!);
                }
                expect(effects).toEqual(["tail-0", "tail-1", "tail-2"]);
                expect([...cursors].sort()).toEqual(cursors);
                expect(new Set(cursors).size).toBe(cursors.length);
                schedule.assertConsumed();
            } finally {
                await fixture.relay.close();
            }
        }
    });

    test("NET-10 five hidden reads cannot acknowledge past a dropped visibility gap", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e45540a, [
            {
                id: "hide-page",
                selector: { operation: "read", phase: "after" },
                effect: { type: "drop" },
                maximumApplications: 5,
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const effects: string[] = [];
        const inboxProcessor = processor(bob, fault, new MemoryMurmurStore(), effects, () => NOW);
        try {
            await fixture.http.publish(labeledDelivery(alice, [bob], "hidden-gap"));
            for (let read = 0; read < 5; read += 1) {
                await expect(inboxProcessor.synchronize()).resolves.toMatchObject({
                    processed: 0,
                    exhausted: false,
                    cursor: null,
                });
            }
            expect(fixture.recording.acknowledgements).toHaveLength(0);
            await expect(inboxProcessor.synchronize()).resolves.toMatchObject({ processed: 1 });
            expect(effects).toEqual(["hidden-gap"]);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-11 stream disconnect ladder reconnects from the durable cursor and closes", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e45540b, [
            {
                id: "disconnect-before-open",
                selector: { operation: "stream.open", phase: "before", ordinal: 1 },
                effect: { type: "throw", message: "stream unavailable" },
            },
            {
                id: "disconnect-after-open",
                selector: { operation: "stream.open", phase: "after", ordinal: 2 },
                effect: { type: "drop" },
            },
            {
                id: "duplicate-first-hook",
                selector: { operation: "stream.delivery", phase: "before", ordinal: 1 },
                effect: { type: "duplicate", copies: 1 },
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const store = new MemoryMurmurStore();
        const effects: string[] = [];
        const faultProcessor = processor(bob, fault, store, effects, () => NOW);
        try {
            for (let index = 0; index < 3; index += 1) {
                await fixture.http.publish(labeledDelivery(alice, [bob], `stream-${index}`));
            }
            for (const message of ["stream unavailable", "lost transport response"]) {
                const controller = new AbortController();
                const iterator = faultProcessor.stream({ signal: controller.signal });
                await expect(iterator.next()).rejects.toThrow(message);
                controller.abort();
            }

            const duplicateController = new AbortController();
            const duplicateStream = faultProcessor.stream({ signal: duplicateController.signal });
            await expect(duplicateStream.next()).resolves.toMatchObject({
                done: false,
                value: { processed: 1 },
            });
            await expect(duplicateStream.next()).rejects.toThrow("out-of-order inbox stream");
            duplicateController.abort();
            expect(effects).toEqual(["stream-0"]);

            const clean = processor(bob, fixture.http, store, effects, () => NOW);
            const reconnectController = new AbortController();
            let connected = 0;
            const reconnect = clean.stream({
                signal: reconnectController.signal,
                onConnected: () => {
                    connected += 1;
                },
            });
            await expect(reconnect.next()).resolves.toMatchObject({ value: { processed: 1 } });
            await expect(reconnect.next()).resolves.toMatchObject({ value: { processed: 1 } });
            reconnectController.abort(new Error("test stream closed"));
            await expect(reconnect.next()).resolves.toMatchObject({ done: true });
            expect(connected).toBe(1);
            expect(effects).toEqual(["stream-0", "stream-1", "stream-2"]);
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(0);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-12 malformed and oversized stream frames never poison clean polling", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const delivery = labeledDelivery(alice, [bob], "poll-after-invalid-stream");
        try {
            await fixture.http.publish(delivery);
            const request = createSignedInboxRead(bob, {
                createdAt: NOW,
                waitMilliseconds: 0,
            });
            const invalidFrames = [
                "",
                "event: delivery\nid: invalid\ndata: {\n\n",
                "event: wake\nid: 00000000-0000-7000-8000-000000000001\ndata: {}\n\n",
                `event: delivery\nid: 00000000-0000-7000-8000-000000000001\ndata: ${"x".repeat(257)}\n\n`,
            ];
            let callbacks = 0;
            for (const frame of invalidFrames) {
                const malformed = new HttpDeliveryTransport("https://relay.test", {
                    maximumResponseBytes: 256,
                    fetch: async () =>
                        new Response(frame, {
                            headers: { "content-type": "text/event-stream" },
                        }),
                });
                const wrapped = new FaultInjectingDeliveryTransport({
                    actor: "bob",
                    delegate: malformed,
                    schedule: new SeededChaosSchedule(0x4e45540c),
                });
                const stream = wrapped.stream!(request, undefined, {
                    onConnected: () => {
                        callbacks += 1;
                    },
                });
                const result = await stream[Symbol.asyncIterator]()
                    .next()
                    .catch((error: unknown) => error);
                if (frame.length === 0) {
                    expect(result).toMatchObject({ done: true });
                } else {
                    expect(result).toBeInstanceOf(DeliveryTransportError);
                }
            }
            expect(callbacks).toBe(invalidFrames.length);

            const effects: string[] = [];
            const clean = processor(bob, fixture.http, new MemoryMurmurStore(), effects, () => NOW);
            await expect(clean.synchronize()).resolves.toMatchObject({ processed: 1 });
            expect(effects).toEqual(["poll-after-invalid-stream"]);
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-12B negotiated WebSocket acknowledgement preserves continuity generation", async () => {
        const fixture = networkFixture();
        const identity = generateIdentityKeyPair();
        const transport = negotiatedTransport(fixture, identity);
        try {
            const delivery = labeledDelivery(identity, [identity], "WebSocket continuity ack");
            const published = await transport.publish(delivery);
            const page = await transport.read(
                createSignedInboxRead(identity, {
                    createdAt: fixture.clock.now(),
                    waitMilliseconds: 0,
                }),
            );
            expect(page.deliveries).toHaveLength(1);
            expect(page.generation).toBeInstanceOf(Uint8Array);
            await expect(
                transport.acknowledge(
                    createSignedInboxAck(identity, published.eventId, fixture.clock.now()),
                ),
            ).resolves.toMatchObject({
                removed: 1,
                sequence: 1,
                generation: page.generation,
            });
        } finally {
            destroyIdentity(identity);
            await fixture.relay.close();
        }
    });

    test("NET-13 rejected acknowledgements retry the exact durable cursor", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e45540d, [
            {
                id: "ack-partition",
                selector: { operation: "acknowledge", phase: "before" },
                effect: { type: "throw", message: "ack relay unreachable" },
                maximumApplications: 3,
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const effects: string[] = [];
        const inboxProcessor = processor(bob, fault, new MemoryMurmurStore(), effects, () => NOW);
        try {
            await fixture.http.publish(labeledDelivery(alice, [bob], "ack-once"));
            await expect(inboxProcessor.synchronize()).rejects.toThrow("ack relay unreachable");
            expect(effects).toEqual(["ack-once"]);
            const cursor = await inboxProcessor.cursor();
            expect(cursor).not.toBeNull();
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(1);

            for (let retry = 0; retry < 2; retry += 1) {
                await expect(inboxProcessor.synchronize()).rejects.toThrow("ack relay unreachable");
            }
            await expect(inboxProcessor.synchronize()).resolves.toMatchObject({ processed: 0 });
            expect(effects).toEqual(["ack-once"]);
            expect(fixture.recording.acknowledgements).toHaveLength(1);
            expect(fixture.recording.acknowledgements[0]!.through).toBe(cursor);
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(0);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-14 accepted acknowledgement response loss is idempotent and non-regressing", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e45540e, [
            {
                id: "lost-ack-response",
                selector: { operation: "acknowledge", phase: "after" },
                effect: { type: "drop" },
                maximumApplications: 2,
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const effects: string[] = [];
        const inboxProcessor = processor(bob, fault, new MemoryMurmurStore(), effects, () => NOW);
        try {
            for (let index = 0; index < 2; index += 1) {
                await fixture.http.publish(labeledDelivery(alice, [bob], `ack-loss-${index}`));
            }
            await expect(inboxProcessor.synchronize()).rejects.toBeInstanceOf(ChaosInjectedError);
            const cursor = await inboxProcessor.cursor();
            await expect(inboxProcessor.synchronize()).rejects.toBeInstanceOf(ChaosInjectedError);
            await expect(inboxProcessor.synchronize()).resolves.toMatchObject({ processed: 0 });
            expect(effects).toEqual(["ack-loss-0", "ack-loss-1"]);
            expect(fixture.recording.acknowledgements.map((ack) => ack.through)).toEqual([
                cursor,
                cursor,
                cursor,
            ]);
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(0);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-15 forged, wrong-recipient, stale, and future acknowledgements are rejected", async () => {
        const fixture = networkFixture({ maximumAuthenticationSkewMilliseconds: 1_000 });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        try {
            const outcome = await fixture.http.publish(labeledDelivery(alice, [bob], "retain-me"));
            const valid = createSignedInboxAck(bob, outcome.eventId, NOW);
            const forgedThrough = {
                ...cloneAck(valid),
                through: `${outcome.eventId.slice(0, -1)}${outcome.eventId.endsWith("0") ? "1" : "0"}`,
            };
            const wrongRecipient = { ...cloneAck(valid), recipient: carol.publicKey.slice() };
            const forgedSignature = cloneAck(valid);
            forgedSignature.signature[0] = forgedSignature.signature[0]! ^ 1;
            const stale = createSignedInboxAck(bob, outcome.eventId, NOW - 1_001);
            const future = createSignedInboxAck(bob, outcome.eventId, NOW + 1_001);
            for (const invalid of [forgedThrough, wrongRecipient, forgedSignature, stale, future]) {
                await expect(fixture.http.acknowledge(invalid)).rejects.toMatchObject({
                    status: 401,
                    code: "unauthorized",
                });
                expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(1);
            }
            await expect(fixture.http.acknowledge(valid)).resolves.toMatchObject({
                removed: 1,
                sequence: 1,
            });
            expect((await inbox(fixture.http, bob, NOW)).deliveries).toHaveLength(0);
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-16 asymmetric actor partitions do not block unrelated exact inboxes", async () => {
        const fixture = networkFixture({ maximumDeliveryTtlMilliseconds: TWENTY_NINE_DAYS });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        const aliceSchedule = new SeededChaosSchedule(0x4e455410, [
            {
                id: "alice-cannot-read",
                selector: { operation: "read", phase: "before", ordinal: 1 },
                effect: { type: "throw", message: "alice read partition" },
            },
        ]);
        const bobSchedule = new SeededChaosSchedule(0x4e455411, [
            {
                id: "bob-cannot-publish",
                selector: { operation: "publish", phase: "before", ordinal: 1 },
                effect: { type: "throw", message: "bob publish partition" },
            },
        ]);
        const aliceTransport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.http,
            schedule: aliceSchedule,
        });
        const bobTransport = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.http,
            schedule: bobSchedule,
        });
        try {
            await aliceTransport.publish(
                labeledDelivery(alice, [bob, carol], "alice fanout", NOW, NOW + TWENTY_NINE_DAYS),
            );
            await expect(
                bobTransport.publish(
                    labeledDelivery(bob, [alice], "blocked bob", NOW, NOW + TWENTY_NINE_DAYS),
                ),
            ).rejects.toThrow("bob publish partition");
            await fixture.http.publish(
                labeledDelivery(carol, [alice], "carol to alice", NOW, NOW + TWENTY_NINE_DAYS),
            );

            expect((await inbox(bobTransport, bob, NOW)).deliveries).toHaveLength(1);
            await expect(inbox(aliceTransport, alice, NOW)).rejects.toThrow("alice read partition");
            expect((await inbox(fixture.http, carol, NOW)).deliveries).toHaveLength(1);

            fixture.clock.advance(12 * 60 * 60 * 1_000);
            await bobTransport.publish(
                labeledDelivery(
                    bob,
                    [alice],
                    "healed bob",
                    fixture.clock.now(),
                    NOW + TWENTY_NINE_DAYS,
                ),
            );
            const alicePage = await inbox(aliceTransport, alice, fixture.clock.now());
            expect(
                alicePage.deliveries.map((item) => utf8Decode(item.delivery.ciphertext)),
            ).toEqual(["carol to alice", "healed bob"]);
            aliceSchedule.assertConsumed();
            bobSchedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-16A reconnect adopts an accepted Commit before publishing Welcome", async () => {
        const fixture = networkFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const schedule = new SeededChaosSchedule(0x4e455416, [
            {
                id: "disconnect-after-commit-acceptance",
                selector: {
                    operation: "publish",
                    phase: "after",
                    deliveryKind: 3,
                },
                effect: { type: "drop" },
            },
            {
                id: "disconnect-before-commit-echo",
                selector: { operation: "read", phase: "before", ordinal: 1 },
                effect: { type: "throw", message: "negotiated reconnect" },
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.recording,
            schedule,
            classifyDelivery: (delivery) => delivery.ciphertext[0],
        });
        const alice = await murmurClient(aliceIdentity, fault, aliceStore, fixture.clock.now);
        const bob = await murmurClient(
            bobIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("negotiated commit reconnect"),
                members: [await bob.createKeyPackage()],
            });
            await expect(alice.synchronize({ waitMilliseconds: 0 })).rejects.toThrow(
                "negotiated reconnect",
            );
            expect(await alice.session(session.id)).toMatchObject({ status: "creating" });
            expect(
                (await inbox(fixture.http, bobIdentity, fixture.clock.now())).deliveries,
            ).toEqual([]);
            const acceptedCommit = await inbox(fixture.http, aliceIdentity, fixture.clock.now());
            expect(acceptedCommit.deliveries.map(({ delivery }) => delivery.ciphertext[0])).toEqual(
                [3],
            );

            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                transientPublicationFailures: 0,
                pendingOutboxes: 1,
            });
            expect(await alice.session(session.id)).toMatchObject({
                status: "active",
                members: [alice.identity, bob.identity],
            });
            expect(fixture.recording.published.map(({ ciphertext }) => ciphertext[0])).toEqual([
                3, 3, 1, 2,
            ]);
            expect(fixture.recording.published[1]?.id).toBe(fixture.recording.published[0]?.id);
            const bobPage = await inbox(fixture.http, bobIdentity, fixture.clock.now());
            expect(bobPage.deliveries.map(({ delivery }) => delivery.ciphertext[0])).toEqual([
                1, 2,
            ]);
            await bob.synchronize({ waitMilliseconds: 0 });
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
            await alice.synchronize({ waitMilliseconds: 0 });
            expect(fault.operationCounts.get("publish")).toBe(5);
            expect(fixture.recording.published[4]?.id).toBe(fixture.recording.published[3]?.id);
            schedule.assertConsumed();
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    }, 30_000);

    test("NET-16B Welcome reconnect preserves post-Commit application ordering", async () => {
        const fixture = networkFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e455417, [
            {
                id: "disconnect-before-welcome",
                selector: {
                    operation: "publish",
                    phase: "before",
                    deliveryKind: 1,
                },
                effect: { type: "throw", message: "Welcome connection lost" },
            },
        ]);
        const fault = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate: fixture.recording,
            schedule,
            classifyDelivery: (delivery) => delivery.ciphertext[0],
        });
        const alice = await murmurClient(
            aliceIdentity,
            fault,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        const bob = await murmurClient(
            bobIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("Welcome reconnect"),
                members: [await bob.createKeyPackage()],
            });
            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 1,
                transientPublicationFailures: 1,
                pendingOutboxes: 2,
            });
            expect(await alice.session(session.id)).toMatchObject({ status: "active" });
            expect(fixture.recording.published.map(({ ciphertext }) => ciphertext[0])).toEqual([3]);
            expect(
                (await inbox(fixture.http, bobIdentity, fixture.clock.now())).deliveries,
            ).toEqual([]);

            const queued = await alice.send(session.id, utf8Encode("after Welcome"));
            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                transientPublicationFailures: 0,
                pendingOutboxes: 1,
            });
            expect(fixture.recording.published.map(({ ciphertext }) => ciphertext[0])).toEqual([
                3, 1, 2, 2,
            ]);
            expect(fixture.recording.published.at(-1)?.id).toBe(queued);

            await bob.synchronize({ waitMilliseconds: 0 });
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
            await bob.activateSession(session.id);
            const updates: string[] = [];
            await drainUpdates(bob, updates);
            expect(updates).toEqual(["after Welcome"]);
            schedule.assertConsumed();
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    }, 30_000);

    test("NET-16C admission completion reconnect gates another member's Commit", async () => {
        const fixture = networkFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const carolIdentity = generateIdentityKeyPair();
        const daveIdentity = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        let alice = await murmurClient(aliceIdentity, fixture.http, aliceStore, fixture.clock.now);
        const bob = await murmurClient(
            bobIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        const carol = await murmurClient(
            carolIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        const dave = await murmurClient(
            daveIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("admission completion reconnect"),
                members: [await bob.createKeyPackage()],
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(session.id);
            await alice.synchronize({ waitMilliseconds: 0 });

            alice.close();
            const recording = new RecordingDeliveryTransport(fixture.http);
            const schedule = new SeededChaosSchedule(0x4e455418, [
                {
                    id: "disconnect-before-admission-completion",
                    selector: {
                        operation: "publish",
                        phase: "before",
                        deliveryKind: 2,
                    },
                    effect: { type: "throw", message: "admission completion disconnected" },
                },
            ]);
            const fault = new FaultInjectingDeliveryTransport({
                actor: "alice",
                delegate: recording,
                schedule,
                classifyDelivery: (delivery) => delivery.ciphertext[0],
            });
            alice = await murmurClient(aliceIdentity, fault, aliceStore, fixture.clock.now);
            await alice.addMember(session.id, await carol.createKeyPackage());
            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 1,
                transientPublicationFailures: 0,
                pendingOutboxes: 3,
            });
            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 2,
                transientPublicationFailures: 1,
                pendingOutboxes: 1,
            });
            expect(recording.published.map(({ ciphertext }) => ciphertext[0])).toEqual([3, 3, 1]);
            await carol.synchronize({ waitMilliseconds: 0 });
            await carol.activateSession(session.id);
            await bob.synchronize({ waitMilliseconds: 0 });
            expect((await bob.session(session.id))?.members).toHaveLength(3);

            await bob.addMember(session.id, await dave.createKeyPackage());
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 0,
                pendingOutboxes: 3,
            });
            expect(await dave.session(session.id)).toBeUndefined();

            alice.close();
            alice = await murmurClient(aliceIdentity, recording, aliceStore, fixture.clock.now);
            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 1,
                pendingOutboxes: 0,
            });
            expect(recording.published.map(({ ciphertext }) => ciphertext[0])).toEqual([
                3, 3, 1, 2,
            ]);
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 1,
                pendingOutboxes: 3,
            });
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                pendingOutboxes: 1,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await dave.synchronize({ waitMilliseconds: 0 });
            await dave.activateSession(session.id);
            await bob.synchronize({ waitMilliseconds: 0 });
            expect((await alice.session(session.id))?.members).toHaveLength(4);
            expect((await bob.session(session.id))?.members).toHaveLength(4);
            expect((await carol.session(session.id))?.members).toHaveLength(4);
            expect((await dave.session(session.id))?.members).toHaveLength(4);
            schedule.assertConsumed();
        } finally {
            alice.close();
            bob.close();
            carol.close();
            dave.close();
            await fixture.relay.close();
        }
    }, 60_000);

    test("NET-17 a Bob-only publish black hole cannot suppress Alice traffic", async () => {
        const fixture = networkFixture();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const schedule = new SeededChaosSchedule(0x4e455411, [
            {
                id: "bob-black-hole",
                selector: { operation: "publish", phase: "before" },
                effect: { type: "drop" },
                maximumApplications: 3,
            },
        ]);
        const bobTransport = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate: fixture.recording,
            schedule,
        });
        const bobDelivery = labeledDelivery(bob, [alice], "bob commit");
        try {
            for (let attempt = 0; attempt < 3; attempt += 1) {
                await expect(bobTransport.publish(bobDelivery)).rejects.toBeInstanceOf(
                    ChaosInjectedError,
                );
            }
            const aliceDelivery = labeledDelivery(alice, [bob], "alice competing commit");
            await fixture.http.publish(aliceDelivery);
            expect((await inbox(fixture.http, bob, NOW)).deliveries[0]!.delivery.id).toBe(
                aliceDelivery.id,
            );
            await expect(bobTransport.publish(bobDelivery)).resolves.toMatchObject({
                duplicate: false,
            });
            expect(
                (await inbox(fixture.http, alice, NOW)).deliveries.map((item) => item.delivery.id),
            ).toEqual([bobDelivery.id]);
            expect(fixture.recording.published.map((item) => item.id)).toEqual([bobDelivery.id]);
            schedule.assertConsumed();
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-18 recipient offline expiry uses exact 29-day relay comparisons", async () => {
        const fixture = networkFixture({ maximumDeliveryTtlMilliseconds: TWENTY_NINE_DAYS });
        const alice = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        const expiresAt = NOW + TWENTY_NINE_DAYS;
        try {
            await fixture.http.publish(
                labeledDelivery(alice, [carol], "offline-carol", NOW, expiresAt),
            );
            fixture.clock.set(expiresAt - 1);
            expect((await inbox(fixture.http, carol, fixture.clock.now())).deliveries).toHaveLength(
                1,
            );

            fixture.clock.set(expiresAt);
            await fixture.relay.pruneExpired();
            expect((await inbox(fixture.http, carol, fixture.clock.now())).deliveries).toHaveLength(
                0,
            );
            fixture.clock.advance(1);
            expect(await fixture.relay.pruneExpired()).toBe(0);

            await fixture.http.publish(
                labeledDelivery(
                    alice,
                    [carol],
                    "post-reconnect",
                    fixture.clock.now(),
                    fixture.clock.now() + 60_000,
                ),
            );
            expect(
                (await inbox(fixture.http, carol, fixture.clock.now())).deliveries.map((item) =>
                    utf8Decode(item.delivery.ciphertext),
                ),
            ).toEqual(["post-reconnect"]);
        } finally {
            await fixture.relay.close();
        }
    });

    test("NET-18A exact six-month expiry advances continuity and resets real MLS state", async () => {
        const fixture = networkFixture({ maximumDeliveryTtlMilliseconds: SIX_MONTHS });
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const expiringSender = generateIdentityKeyPair();
        const alice = await murmurClient(
            aliceIdentity,
            fixture.http,
            new MemoryMurmurStore(),
            fixture.clock.now,
        );
        const bobStore = new MemoryMurmurStore();
        const bob = await murmurClient(bobIdentity, fixture.http, bobStore, fixture.clock.now);
        const resets: MurmurResetEvent[] = [];
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("six-month continuity"),
                members: [await bob.createKeyPackage()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(session.id);
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });

            const baseline = await inbox(fixture.http, bobIdentity, fixture.clock.now());
            expect(baseline.generation).toBeDefined();
            expect(baseline.headSequence).toBe(baseline.acknowledgedSequence);
            const expiresAt = NOW + SIX_MONTHS;
            await fixture.http.publish(
                labeledDelivery(
                    expiringSender,
                    [bobIdentity],
                    "expires at six months",
                    NOW,
                    expiresAt,
                ),
            );
            fixture.clock.set(expiresAt - 1);
            const retained = await inbox(fixture.http, bobIdentity, fixture.clock.now());
            expect(retained.deliveries).toHaveLength(1);
            expect(retained.deliveries[0]?.sequence).toBe((baseline.headSequence ?? 0) + 1);
            expect(equalBytes(retained.generation!, baseline.generation!)).toBe(true);

            fixture.clock.set(expiresAt);
            await expect(fixture.relay.pruneExpired()).resolves.toBe(1);
            const lost = await inbox(fixture.http, bobIdentity, fixture.clock.now());
            expect(lost.deliveries).toHaveLength(0);
            expect(equalBytes(lost.generation!, baseline.generation!)).toBe(false);

            await expect(
                bob.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onReset: (reset) => {
                            resets.push(reset);
                        },
                    },
                ),
            ).rejects.toMatchObject({
                name: "MurmurResetRequiredError",
                committed: true,
            } satisfies Partial<MurmurResetRequiredError>);
            expect(resets).toHaveLength(1);
            expect(resets[0]?.sessions).toHaveLength(1);
            expect(equalBytes(resets[0]!.sessions[0]!.id, session.id)).toBe(true);
            expect(await bob.session(session.id)).toBeUndefined();
            expect(await bobStore.get("murmur/reset/v1/pending")).toBeUndefined();
            await expect(bob.synchronize({ waitMilliseconds: 0 })).resolves.toMatchObject({
                inbox: { processed: 0 },
            });

            for (let round = 0; round < 8; round += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                if ((await bob.session(session.id))?.reAdmission === true) break;
            }
            expect(await bob.session(session.id)).toMatchObject({
                status: "pending",
                descriptor: session.descriptor,
                reAdmission: true,
            });
        } finally {
            alice.close();
            bob.close();
            destroyIdentity(expiringSender);
            await fixture.relay.close();
        }
    }, 60_000);

    test("NET-19 the 180-day hard delivery bound is exact", async () => {
        const hardFixture = networkFixture({ maximumDeliveryTtlMilliseconds: SIX_MONTHS });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        try {
            await expect(
                hardFixture.http.publish(
                    labeledDelivery(alice, [bob], "hard edge", NOW, NOW + SIX_MONTHS),
                ),
            ).resolves.toMatchObject({ duplicate: false });
            await expect(
                hardFixture.http.publish(
                    labeledDelivery(alice, [bob], "over hard edge", NOW, NOW + SIX_MONTHS + 1),
                ),
            ).rejects.toMatchObject({ status: 401, code: "unauthorized" });
            expect(() =>
                networkFixture({ maximumDeliveryTtlMilliseconds: SIX_MONTHS + 1 }),
            ).toThrow("cannot exceed 180 days");
        } finally {
            await hardFixture.relay.close();
        }
    });

    test("NET-20 64 fixed mixed seeds replay 30-operation normalized traces", async () => {
        interface MixedResult {
            readonly script: readonly number[];
            readonly labels: readonly string[];
            readonly cursorRank: number;
            readonly trace: readonly string[];
        }

        const run = async (seed: number): Promise<MixedResult> => {
            const fixture = networkFixture({
                maximumAuthenticationSkewMilliseconds: 5 * 60 * 1_000,
            });
            const random = new SeededRandom(seed);
            const alice = generateIdentityKeyPair();
            const bob = generateIdentityKeyPair();
            const publishFailures = random.integer(1, 4);
            const loseAfterAcceptance = random.oneIn(2);
            const rules: ChaosRule[] = [
                {
                    id: "seeded-publish-loss",
                    selector: {
                        operation: "publish",
                        phase: loseAfterAcceptance ? "after" : "before",
                    },
                    effect: loseAfterAcceptance
                        ? { type: "drop" }
                        : { type: "throw", message: "seeded partition" },
                    maximumApplications: publishFailures,
                },
                {
                    id: "seeded-duplicate-page",
                    selector: { operation: "read", phase: "after", ordinal: 1 },
                    effect: { type: "duplicate", copies: 1, index: 0 },
                },
                {
                    id: "seeded-ack-loss",
                    selector: { operation: "acknowledge", phase: "after", ordinal: 1 },
                    effect: { type: "drop" },
                },
            ];
            const schedule = new SeededChaosSchedule(seed, rules);
            const fault = new FaultInjectingDeliveryTransport({
                actor: "mixed",
                delegate: fixture.recording,
                schedule,
            });
            const deliveries = Array.from({ length: 12 }, (_, index) =>
                labeledDelivery(alice, [bob], `label-${index}`),
            );
            try {
                for (;;) {
                    try {
                        await fault.publish(deliveries[0]!);
                        break;
                    } catch (error: unknown) {
                        expect(error).toBeInstanceOf(ChaosInjectedError);
                    }
                }
                for (const delivery of deliveries.slice(1)) await fault.publish(delivery);

                const page = await inbox(fault, bob, fixture.clock.now());
                const labels: string[] = [];
                const seen = new Set<string>();
                for (const queued of page.deliveries) {
                    if (seen.has(queued.delivery.id)) continue;
                    seen.add(queued.delivery.id);
                    labels.push(utf8Decode(queued.delivery.ciphertext));
                }
                expect(page.head).not.toBeNull();
                const ack = createSignedInboxAck(bob, page.head!, fixture.clock.now());
                await expect(fault.acknowledge(ack)).rejects.toBeInstanceOf(ChaosInjectedError);
                await fault.acknowledge(ack);

                const script = Array.from({ length: 30 }, () => random.integer(0, 6));
                for (const operation of script) {
                    if (operation === 0 || operation === 3) {
                        const controller = new AbortController();
                        controller.abort(new Error("seeded partition"));
                        await expect(
                            fault.publish(deliveries[0]!, controller.signal),
                        ).rejects.toThrow("seeded partition");
                    } else if (operation === 1) {
                        await inbox(fault, bob, fixture.clock.now());
                    } else if (operation === 2) {
                        await inbox(fault, bob, fixture.clock.now(), page.head);
                    } else if (operation === 4) {
                        fixture.clock.advance(1);
                    } else {
                        await fault.acknowledge(
                            createSignedInboxAck(bob, page.head!, fixture.clock.now()),
                        );
                    }
                }
                expect(
                    (await inbox(fixture.http, bob, fixture.clock.now())).deliveries,
                ).toHaveLength(0);
                schedule.assertConsumed();
                return {
                    script,
                    labels,
                    cursorRank: seen.size,
                    trace: schedule.trace.map(
                        (entry) =>
                            `${entry.operation}:${entry.phase}:${entry.ordinal}:${entry.effect}:${entry.ruleId ?? "-"}`,
                    ),
                };
            } finally {
                await fixture.relay.close();
            }
        };

        for (let seed = 0x4e455400; seed <= 0x4e45543f; seed += 1) {
            try {
                const first = await run(seed);
                const replay = await run(seed);
                expect(first).toEqual(replay);
                expect(first.labels).toEqual(
                    Array.from({ length: 12 }, (_, index) => `label-${index}`),
                );
                expect(first.cursorRank).toBe(12);
            } catch (error: unknown) {
                const rendered = seed.toString(16).padStart(8, "0");
                throw new Error(`NET-20 seed=0x${rendered}`, { cause: error });
            }
        }
    }, 120_000);
});
