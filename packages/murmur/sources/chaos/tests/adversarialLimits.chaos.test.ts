import { createRootContext } from "@steve.kite/stdlib";
import {
    DELIVERY_RETENTION_MILLISECONDS,
    RelayService,
    SqliteRelayStore,
    createRelayFetchHandler,
    type RelayOptions,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { decodeDeviceRosterMutation, encodeDeviceRosterMutation } from "../../accounts/index.js";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    hashBytes,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    HttpDeliveryTransport,
    InboxContinuityLossError,
    InboxProcessor,
    TerminalInboxDeliveryError,
    WebSocketDeliveryTransport,
    containsRecipient,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    parseSignedDelivery,
    signedDeliveryToJson,
    type DeliveryFetch,
    type DeliveryWebSocket,
    type DeliveryWebSocketCloseEvent,
    type DeliveryWebSocketMessageEvent,
    type RelaySessionProvider,
    type SignedDelivery,
} from "../../delivery/index.js";
import { type MlsGroupContext } from "../../mls/groupContext/index.js";
import {
    decodeMlsPrivateMessage,
    encodeMlsPrivateMessage,
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
} from "../../mls/privateMessage/index.js";
import { MlsSecretTree, destroyMlsGenerationKey } from "../../mls/secretTree/index.js";
import { MurmurClient, type MurmurUpdate } from "../../sessions/index.js";
import {
    decodeSessionRoles,
    encodeSessionRoles,
    openCommitCiphertext,
    parseSessionCiphertext,
    sealCommitCiphertext,
    type SessionRoles,
} from "../../sessions/impl/sessionFrames.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import { SeededRandom } from "../index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;
const MINUTE_MILLISECONDS = 60_000;
const SIX_MONTHS_MILLISECONDS = 180 * 24 * 60 * MINUTE_MILLISECONDS;
const STREAM_EVENT_ID = "018bcfe5-6800-7000-8000-000000000001";
const STREAM_GENERATION = encodeBase64Url(new Uint8Array(32));

interface WebSocketRequestFrame {
    readonly version: 1;
    readonly id: string;
    readonly operation: "publish" | "read" | "acknowledge" | "stream";
    readonly body: unknown;
}

class ScriptedWebSocket implements DeliveryWebSocket {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null = null;
    readonly #handle: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void;

    constructor(handle: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void) {
        this.#handle = handle;
        queueMicrotask(() => {
            this.readyState = 1;
            this.onopen?.();
        });
    }

    send(data: string): void {
        this.#handle(JSON.parse(data) as WebSocketRequestFrame, this);
    }

    close(): void {
        this.readyState = 3;
    }

    receive(data: unknown): void {
        this.onmessage?.({ data });
    }
}

function relaySessionProvider(): RelaySessionProvider {
    return {
        issue: async (_ctx) => ({
            version: 1,
            protocol: "murmur-websocket-v1",
            endpoint: "wss://relay.test/v2/connect",
            token: "adversarial.ticket",
            expiresAt: NOW + MINUTE_MILLISECONDS,
        }),
    };
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "adversarial-limits-chaos",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

interface RelayFixture {
    readonly relay: RelayService;
    readonly transport: HttpDeliveryTransport;
}

function relayFixture(options: RelayOptions = {}, now: () => number = () => NOW): RelayFixture {
    const relay = new RelayService(new SqliteRelayStore(":memory:"), options, undefined, now);
    return {
        relay,
        transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) }),
    };
}

function delivery(
    sender: IdentityKeyPair,
    recipients: readonly Uint8Array[],
    bytes: Uint8Array,
    createdAt: number = NOW,
    expiresAt: number = NOW + MINUTE_MILLISECONDS,
): SignedDelivery {
    return createSignedDelivery(sender, recipients, bytes, { createdAt, expiresAt });
}

function flip(bytes: Uint8Array, index: number = bytes.length - 1): Uint8Array {
    const result = bytes.slice();
    if (result.length > 0) {
        const offset = Math.max(0, Math.min(index, result.length - 1));
        result[offset] = (result[offset] ?? 0) ^ 1;
    }
    return result;
}

function context(epoch: bigint = 7n): MlsGroupContext {
    return {
        groupId: utf8Encode("adversarial-group"),
        epoch,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("transcript")),
    };
}

function objectJson(bytes: Uint8Array): Record<string, unknown> {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Expected JSON object");
    }
    return parsed as Record<string, unknown>;
}

async function closeFixture(
    fixture: RelayFixture,
    identities: readonly IdentityKeyPair[],
): Promise<void> {
    await fixture.relay.close();
    for (const identity of identities) destroyIdentity(identity);
}

describe("adversarial inputs and resource limits", () => {
    test("ADV-01/15 poison classes cannot starve later valid work and diagnostics stay bounded", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const effects: string[] = [];
        const poisonClasses = [
            "application",
            "commit",
            "welcome",
            "directory-prekey",
            "roster-mutation",
            "role-control",
            "account-roster",
            "roster-notification",
        ] as const;
        const processor = new InboxProcessor(
            { identity: recipient, transport: fixture.transport, store },
            async (transaction, staged, queued) => {
                const label = utf8Decode(queued.delivery.ciphertext);
                if (label.startsWith("poison/")) {
                    throw new TerminalInboxDeliveryError(
                        `invalid_${label.slice("poison/".length).replaceAll("-", "_")}`,
                    );
                }
                await staged.set(
                    transaction,
                    `application/${queued.delivery.id}`,
                    utf8Encode(label),
                );
                effects.push(label);
            },
            { now: () => NOW, maximumRejections: 8 },
        );
        try {
            for (let index = 0; index < 100; index += 1) {
                const label = poisonClasses[index % poisonClasses.length]!;
                await fixture.transport.publish(
                    ctx,
                    delivery(sender, [recipient.publicKey], utf8Encode(`poison/${label}`)),
                );
            }
            await fixture.transport.publish(
                ctx,
                delivery(sender, [recipient.publicKey], utf8Encode("valid-after-poison")),
            );

            await expect(processor.synchronize(ctx, { limit: 50 })).resolves.toMatchObject({
                processed: 0,
                rejected: 50,
                exhausted: false,
            });
            await expect(processor.synchronize(ctx, { limit: 50 })).resolves.toMatchObject({
                processed: 0,
                rejected: 50,
                exhausted: false,
            });
            await expect(processor.synchronize(ctx, { limit: 50 })).resolves.toMatchObject({
                processed: 1,
                rejected: 0,
                exhausted: true,
            });

            expect(effects).toEqual(["valid-after-poison"]);
            expect(await store.list(ctx, "application/")).toHaveLength(1);
            expect(await processor.rejections(ctx)).toHaveLength(8);
            expect(await processor.continuity(ctx)).toMatchObject({ sequence: 101 });
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-02/05 tampered MLS messages and 64-bit jumps do not burn current traffic", () => {
        const signer = generateIdentityKeyPair();
        const encryptionSecret = hashBytes(utf8Encode("encryption"));
        const senderDataSecret = hashBytes(utf8Encode("sender-data"));
        const senderTree = new MlsSecretTree(encryptionSecret, 1);
        const receiverTree = new MlsSecretTree(encryptionSecret, 1);
        try {
            const valid = sealMlsApplicationMessage({
                context: context(),
                sender: 0,
                signingSecretKey: signer.secretKey,
                senderDataSecret,
                secretTree: senderTree,
                applicationData: utf8Encode("valid-current"),
            });
            const parsed = decodeMlsPrivateMessage(valid);
            const tampered = encodeMlsPrivateMessage({
                ...parsed,
                ciphertext: flip(parsed.ciphertext),
            });
            expect(() =>
                openMlsApplicationMessage({
                    context: context(),
                    senderDataSecret,
                    secretTree: receiverTree,
                    message: tampered,
                    signatureKeyFor: () => signer.publicKey,
                }),
            ).toThrow();
            expect(
                utf8Decode(
                    openMlsApplicationMessage({
                        context: context(),
                        senderDataSecret,
                        secretTree: receiverTree,
                        message: valid,
                        signatureKeyFor: () => signer.publicKey,
                    }).applicationData,
                ),
            ).toBe("valid-current");

            for (const epoch of [0n, 6n, 8n, 9n, 7n + 2n ** 16n, 7n + 2n ** 32n, 2n ** 64n - 1n]) {
                const tree = new MlsSecretTree(encryptionSecret, 1);
                try {
                    expect(() =>
                        openMlsApplicationMessage({
                            context: context(),
                            senderDataSecret,
                            secretTree: tree,
                            message: encodeMlsPrivateMessage({ ...parsed, epoch }),
                            signatureKeyFor: () => signer.publicKey,
                        }),
                    ).toThrow();
                } finally {
                    tree.destroy();
                }
            }

            const bounded = new MlsSecretTree(encryptionSecret, 1, 2, 4);
            const generationTwo = bounded.take(0, "application", 2);
            destroyMlsGenerationKey(generationTwo);
            const skippedZero = bounded.take(0, "application", 0);
            destroyMlsGenerationKey(skippedZero);
            expect(() => bounded.take(0, "application", 2 ** 16)).toThrow("too far");
            expect(() => bounded.take(0, "application", 2 ** 32 - 1)).toThrow("too far");
            expect(() => bounded.take(0, "application", 2 ** 32)).toThrow("Invalid");
            bounded.destroy();
        } finally {
            senderTree.destroy();
            receiverTree.destroy();
            zeroBytes(encryptionSecret);
            zeroBytes(senderDataSecret);
            destroyIdentity(signer);
        }
    });

    test("ADV-03/04 an earlier malformed Commit cannot block the first valid role Commit", async () => {
        const fixture = relayFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const attacker = generateIdentityKeyPair();
        const alice = await MurmurClient.open(ctx, {
            identity: aliceIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open(ctx, {
            identity: bobIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("adversarial-commit-order"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.activateSession(ctx, session.id);

            const poison = delivery(attacker, [bob.deviceKey], new Uint8Array([3, 0xff, 0x00]));
            await fixture.transport.publish(ctx, poison);
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const synchronized = await bob.synchronize(ctx, { waitMilliseconds: 0 });

            expect(synchronized.inbox).toMatchObject({ rejected: 1, processed: 1 });
            expect(await bob.session(ctx, session.id)).toMatchObject({
                policies: { adminsAssignAdmins: true, anyoneCanAddMembers: true },
            });

            await alice.send(ctx, session.id, utf8Encode("live-after-invalid-commit"));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const updates: MurmurUpdate[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, batch) => {
                        updates.push(...batch);
                    },
                },
            );
            expect(updates.map((update) => utf8Decode(update.bytes))).toContain(
                "live-after-invalid-commit",
            );
        } finally {
            alice.close();
            bob.close();
            await closeFixture(fixture, [aliceIdentity, bobIdentity, attacker]);
        }
    }, 120_000);

    test("ADV-04 role and Commit framing rejects swaps and malformed controls", () => {
        const owner = new Uint8Array(32).fill(1);
        const admin = new Uint8Array(32).fill(2);
        const roles: SessionRoles = {
            owner,
            admins: [admin],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
            sendPolicy: "everyone",
        };
        const key = hashBytes(utf8Encode("commit-key"));
        const groupId = utf8Encode("group-a");
        try {
            const wire = parseSessionCiphertext(
                sealCommitCiphertext(key, {
                    version: 1,
                    groupId,
                    epoch: 7n,
                    commit: utf8Encode("valid-commit"),
                    roles,
                }),
            );
            expect(wire.kind).toBe("commit");
            if (wire.kind !== "commit") throw new Error("Expected Commit ciphertext");
            expect(openCommitCiphertext(key, wire)).toMatchObject({ epoch: 7n, roles });
            expect(() =>
                openCommitCiphertext(key, { ...wire, groupId: utf8Encode("group-b") }),
            ).toThrow();
            expect(() => openCommitCiphertext(key, { ...wire, epoch: 8n })).toThrow();
            expect(() => openCommitCiphertext(flip(key), wire)).toThrow();

            const canonical = objectJson(encodeSessionRoles(roles));
            const malformed = [
                { ...canonical, owner: encodeBase64Url(new Uint8Array(31)) },
                { ...canonical, admins: [encodeBase64Url(admin), encodeBase64Url(admin)] },
                { ...canonical, admins: [encodeBase64Url(owner)] },
                { ...canonical, adminsAssignAdmins: 1 },
                { ...canonical, unknownPolicy: true },
            ];
            for (const value of malformed) {
                expect(() => decodeSessionRoles(utf8Encode(JSON.stringify(value)))).toThrow();
            }
        } finally {
            zeroBytes(key);
            zeroBytes(owner);
            zeroBytes(admin);
        }
    });

    test("ADV-05 Commit framing enforces the uint64 epoch ceiling", () => {
        const frame = (epoch: bigint): Uint8Array =>
            new Uint8Array([
                3,
                ...canonicalJsonBytes({
                    version: 1,
                    groupId: encodeBase64Url(utf8Encode("overflow-group")),
                    epoch: epoch.toString(),
                    nonce: encodeBase64Url(new Uint8Array(12)),
                    ciphertext: encodeBase64Url(new Uint8Array(16)),
                }),
            ]);
        expect(parseSessionCiphertext(frame(2n ** 64n - 1n))).toMatchObject({
            kind: "commit",
            epoch: 2n ** 64n - 1n,
        });
        for (const overflow of [2n ** 64n, 2n ** 64n + 1n, 2n ** 128n]) {
            expect(() => parseSessionCiphertext(frame(overflow))).toThrow(
                "Invalid Commit ciphertext",
            );
        }
    });

    test("ADV-07/08 signed delivery, authentication, fanout, quota, and retention boundaries", async () => {
        expect(DELIVERY_RETENTION_MILLISECONDS).toBe(SIX_MONTHS_MILLISECONDS);
        const fixture = relayFixture({
            maximumCiphertextBytes: 4,
            maximumRecipients: 2,
            maximumDeliveryTtlMilliseconds: SIX_MONTHS_MILLISECONDS,
            maximumAuthenticationSkewMilliseconds: 1,
            maximumSenderReferences: 2,
            maximumAdmissionReferences: 2,
            maximumGlobalReferences: 2,
        });
        const sender = generateIdentityKeyPair();
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        const third = generateIdentityKeyPair();
        try {
            const exact = delivery(
                sender,
                [first.publicKey, second.publicKey],
                new Uint8Array(4),
                NOW,
                NOW + SIX_MONTHS_MILLISECONDS,
            );
            await expect(fixture.transport.publish(ctx, exact)).resolves.toMatchObject({
                duplicate: false,
            });
            await expect(fixture.transport.publish(ctx, exact)).resolves.toMatchObject({
                duplicate: true,
            });
            await expect(
                fixture.transport.publish(
                    ctx,
                    delivery(sender, [first.publicKey], new Uint8Array(5)),
                ),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                fixture.transport.publish(
                    ctx,
                    delivery(
                        sender,
                        [first.publicKey, second.publicKey, third.publicKey],
                        new Uint8Array(1),
                    ),
                ),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                fixture.transport.publish(
                    ctx,
                    delivery(
                        sender,
                        [first.publicKey],
                        new Uint8Array(1),
                        NOW,
                        NOW + SIX_MONTHS_MILLISECONDS + 1,
                    ),
                ),
            ).rejects.toMatchObject({ status: 401 });

            const forged = { ...exact, signature: flip(exact.signature) };
            await expect(fixture.relay.publish(forged, "forged")).rejects.toMatchObject({
                status: 401,
            });
            expect(containsRecipient(exact, third.publicKey)).toBe(false);
            const empty = createSignedDelivery(sender, [], new Uint8Array(1), {
                createdAt: NOW,
                expiresAt: NOW + 1,
            });
            await expect(fixture.relay.publish(empty, "empty")).rejects.toMatchObject({
                status: 400,
            });
            expect(() =>
                createSignedDelivery(
                    sender,
                    [first.publicKey, first.publicKey],
                    new Uint8Array(1),
                    {
                        createdAt: NOW,
                        expiresAt: NOW + 1,
                    },
                ),
            ).toThrow();

            const wrongRead = {
                ...createSignedInboxRead(first, { createdAt: NOW }),
                recipient: second.publicKey,
            };
            await expect(fixture.relay.readQueue(wrongRead)).rejects.toMatchObject({ status: 401 });
            const firstPage = await fixture.transport.read(
                ctx,
                createSignedInboxRead(first, { createdAt: NOW }),
            );
            const eventId = firstPage.deliveries[0]!.eventId;
            const wrongAck = {
                ...createSignedInboxAck(first, eventId, NOW),
                recipient: second.publicKey,
            };
            await expect(fixture.relay.acknowledge(wrongAck)).rejects.toMatchObject({
                status: 401,
            });
            await expect(
                fixture.relay.readQueue(createSignedInboxRead(first, { createdAt: NOW + 2 })),
            ).rejects.toMatchObject({ status: 401 });

            await expect(
                fixture.transport.publish(
                    ctx,
                    delivery(sender, [third.publicKey], new Uint8Array(1), NOW, NOW + 2),
                ),
            ).rejects.toMatchObject({ status: 503 });
        } finally {
            await closeFixture(fixture, [sender, first, second, third]);
        }
    });

    test("ADV-07 forged continuity metadata is rejected before durable continuity accounting", async () => {
        const recipient = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const validRead = createSignedInboxRead(recipient, { createdAt: NOW });
        const malformedPages: readonly Record<string, unknown>[] = [
            {
                deliveries: [],
                head: null,
                headSequence: 0,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(31)),
                exhausted: true,
            },
            {
                deliveries: [],
                head: null,
                headSequence: -1,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(32)),
                exhausted: true,
            },
            {
                deliveries: [],
                head: null,
                headSequence: 0,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(32)),
                exhausted: true,
                forged: true,
            },
        ];
        try {
            for (const page of malformedPages) {
                const transport = new HttpDeliveryTransport("https://relay.test", {
                    fetch: async (_ctx): Promise<Response> =>
                        new Response(JSON.stringify(page), {
                            status: 200,
                            headers: { "content-type": "application/json" },
                        }),
                });
                const processor = new InboxProcessor(
                    { identity: recipient, transport, store },
                    async (_ctx) => undefined,
                    { now: () => NOW },
                );
                await expect(processor.synchronize(ctx)).rejects.toThrow();
                expect(await processor.continuity(ctx)).toBeUndefined();
            }
            expect(validRead.recipient).toEqual(recipient.publicKey);
        } finally {
            destroyIdentity(recipient);
        }
    });

    test("ADV-07 late replay advances sequence once and a restored generation stops processing", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const effects: string[] = [];
        const processor = new InboxProcessor(
            {
                identity: recipient,
                transport: fixture.transport,
                store: new MemoryMurmurStore(),
            },
            async (_ctx, _transaction, queued) => {
                effects.push(queued.delivery.id);
            },
            { now: () => NOW },
        );
        try {
            const replayed = delivery(sender, [recipient.publicKey], utf8Encode("late replay"));
            const firstPublication = await fixture.transport.publish(ctx, replayed);
            await expect(processor.synchronize(ctx)).resolves.toMatchObject({
                processed: 1,
                rejected: 0,
            });
            const firstContinuity = await processor.continuity(ctx);
            expect(firstContinuity).toMatchObject({ sequence: 1 });

            const latePublication = await fixture.transport.publish(ctx, replayed);
            expect(latePublication).toMatchObject({ duplicate: false });
            expect(latePublication.eventId).not.toBe(firstPublication.eventId);
            await expect(processor.synchronize(ctx)).resolves.toMatchObject({
                processed: 0,
                rejected: 1,
            });
            expect(effects).toEqual([replayed.id]);
            const replayContinuity = await processor.continuity(ctx);
            expect(replayContinuity).toMatchObject({ sequence: 2 });
            expect(replayContinuity?.generation).toEqual(firstContinuity?.generation);

            await expect(fixture.relay.declareRestored()).resolves.toBe(1);
            const afterRestore = delivery(
                sender,
                [recipient.publicKey],
                utf8Encode("must wait for reset"),
            );
            await fixture.transport.publish(ctx, afterRestore);
            const loss = await processor.synchronize(ctx).catch((error: unknown) => error);
            expect(loss).toBeInstanceOf(InboxContinuityLossError);
            expect(loss).toMatchObject({
                reason: "generation_changed",
                expectedSequence: 3,
                observedSequence: 3,
            });
            expect(await processor.continuity(ctx)).toEqual(replayContinuity);
            expect(effects).toEqual([replayed.id]);

            const pending = await fixture.transport.read(
                ctx,
                createSignedInboxRead(recipient, {
                    after: latePublication.eventId,
                    createdAt: NOW,
                }),
            );
            expect(pending.deliveries).toMatchObject([
                { sequence: 3, delivery: { id: afterRestore.id } },
            ]);
            expect(pending.generation).not.toEqual(replayContinuity?.generation);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-09 concurrent and sequential KeyPackage claims admit exactly once", async () => {
        const fixture = relayFixture();
        const alice = await MurmurClient.open(ctx, {
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open(ctx, {
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const replayed = await bob.createKeyPackage(ctx);
            const concurrent = await Promise.allSettled([
                alice.createSession(ctx, {
                    descriptor: utf8Encode("concurrent KeyPackage claim A"),
                    members: [replayed],
                }),
                alice.createSession(ctx, {
                    descriptor: utf8Encode("concurrent KeyPackage claim B"),
                    members: [replayed],
                }),
            ]);
            expect(concurrent.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
            expect(concurrent.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
            expect(concurrent.find((outcome) => outcome.status === "rejected")).toMatchObject({
                reason: expect.objectContaining({
                    message: expect.stringContaining("already used"),
                }),
            });
            expect((await alice.sessions(ctx)).sessions).toHaveLength(1);
            await expect(
                alice.createSession(ctx, {
                    descriptor: utf8Encode("replayed KeyPackage claim"),
                    members: [replayed],
                }),
            ).rejects.toThrow("already used");
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    });

    test("ADV-10 prior-epoch traffic is capped at 64 messages and five minutes", async () => {
        let now = NOW;
        const fixture = relayFixture({}, () => now);
        const alice = await MurmurClient.open(ctx, {
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        const bob = await MurmurClient.open(ctx, {
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("prior-epoch-adversarial"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.activateSession(ctx, session.id);

            for (let index = 0; index < 65; index += 1) {
                await bob.send(ctx, session.id, utf8Encode(`prior-${index}`));
            }
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            const boundedUpdates: MurmurUpdate[] = [];
            const bounded = await alice.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, batch) => {
                        boundedUpdates.push(...batch);
                    },
                },
            );
            expect(bounded.inbox.rejected).toBe(1);
            expect(
                boundedUpdates.filter((update) => utf8Decode(update.bytes).startsWith("prior-")),
            ).toHaveLength(64);

            await bob.send(ctx, session.id, utf8Encode("expired-prior"));
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            now += 5 * MINUTE_MILLISECONDS + 1;
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            const expiredUpdates: MurmurUpdate[] = [];
            const expired = await alice.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, batch) => {
                        expiredUpdates.push(...batch);
                    },
                },
            );
            expect(expired.inbox.rejected).toBe(1);
            expect(expiredUpdates.map((update) => utf8Decode(update.bytes))).not.toContain(
                "expired-prior",
            );

            await bob.send(ctx, session.id, utf8Encode("current-after-prior-abuse"));
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            const current: MurmurUpdate[] = [];
            await alice.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, batch) => {
                        current.push(...batch);
                    },
                },
            );
            expect(current.map((update) => utf8Decode(update.bytes))).toContain(
                "current-after-prior-abuse",
            );
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    }, 120_000);

    test("ADV-13 strict HTTP and response framing recovers after malformed inputs", async () => {
        const maximumJsonBodyBytes = 4_200;
        const fixture = relayFixture({
            maximumCiphertextBytes: 1,
            maximumRecipients: 1,
            maximumJsonBodyBytes,
        });
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const handler = createRelayFetchHandler(fixture.relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "http-adversarial",
        });
        try {
            const valid = delivery(sender, [recipient.publicKey], new Uint8Array([1]));
            const validJson = signedDeliveryToJson(valid);
            const malformedBodies = [
                "{",
                JSON.stringify({ ...validJson, unknown: true }),
                JSON.stringify({ ...validJson, sender: "not-base64url" }),
                JSON.stringify({ ...validJson, recipients: [] }),
                JSON.stringify({ ...validJson, ciphertext: "A===" }),
            ];
            for (const body of malformedBodies) {
                const response = await handler(
                    new Request("https://relay.test/v1/deliveries", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body,
                    }),
                );
                expect(response.status).toBeGreaterThanOrEqual(400);
            }
            const binary = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: { "content-type": "application/octet-stream" },
                    body: new Uint8Array([0, 1, 2]),
                }),
            );
            expect(binary.status).toBeGreaterThanOrEqual(400);
            const declaredOversized = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        "content-length": String(maximumJsonBodyBytes + 1),
                    },
                    body: "{}",
                }),
            );
            expect(declaredOversized.status).toBe(413);

            const accepted = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify(validJson),
                }),
            );
            expect(accepted.status).toBe(200);
            expect(
                (
                    await fixture.transport.read(
                        ctx,
                        createSignedInboxRead(recipient, { createdAt: NOW }),
                    )
                ).deliveries.map((queued) => queued.delivery.id),
            ).toEqual([valid.id]);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-13 WebSocket responses and streams reject oversize, truncation, binary, and pre-connect data", async () => {
        const identity = generateIdentityKeyPair();
        const page = {
            deliveries: [],
            head: STREAM_EVENT_ID,
            headSequence: 1,
            acknowledgedThrough: null,
            acknowledgedSequence: 0,
            generation: STREAM_GENERATION,
            exhausted: true,
        };
        const responseText = (id: string): string =>
            JSON.stringify({ version: 1, id, type: "response", status: 200, body: page });
        const exactBytes = utf8Encode(responseText("A".repeat(24))).length;
        const transport = (
            maximumMessageBytes: number,
            response: (valid: string) => unknown,
        ): WebSocketDeliveryTransport =>
            new WebSocketDeliveryTransport(identity, relaySessionProvider(), {
                now: () => NOW,
                maximumMessageBytes,
                webSocketFactory: (_ctx) =>
                    new ScriptedWebSocket((frame, socket) => {
                        socket.receive(response(responseText(frame.id)));
                    }),
            });
        const read = createSignedInboxRead(identity, { createdAt: NOW, limit: 1 });
        try {
            await expect(
                transport(exactBytes, (valid) => valid).read(ctx, read),
            ).resolves.toMatchObject({
                head: STREAM_EVENT_ID,
                headSequence: 1,
            });
            await expect(
                transport(exactBytes - 1, (valid) => valid).read(ctx, read),
            ).rejects.toMatchObject({ code: "invalid_response" });
            await expect(
                transport(exactBytes, (valid) => valid.slice(0, -1)).read(ctx, read),
            ).rejects.toMatchObject({ code: "invalid_response" });
            await expect(
                transport(exactBytes, (valid) => utf8Encode(valid)).read(ctx, read),
            ).rejects.toMatchObject({ code: "invalid_response" });

            await expect(
                transport(exactBytes, (valid) => valid).read(ctx, read),
            ).resolves.toMatchObject({
                deliveries: [],
                exhausted: true,
            });

            const streamTransport = (
                script: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void,
            ): WebSocketDeliveryTransport =>
                new WebSocketDeliveryTransport(identity, relaySessionProvider(), {
                    now: () => NOW,
                    maximumMessageBytes: exactBytes,
                    webSocketFactory: (_ctx) => new ScriptedWebSocket(script),
                });
            const streamRead = createSignedInboxRead(identity, {
                createdAt: NOW,
                limit: 1,
                waitMilliseconds: 0,
            });
            await expect(
                streamTransport((_frame, socket) => socket.receive("{"))
                    .stream(ctx, streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((_frame, socket) => socket.receive(new Uint8Array([1, 2, 3])))
                    .stream(ctx, streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((frame, socket) =>
                    socket.receive(
                        JSON.stringify({
                            version: 1,
                            id: frame.id,
                            type: "continuity",
                            body: page,
                        }),
                    ),
                )
                    .stream(ctx, streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((_frame, socket) => socket.receive("x".repeat(exactBytes + 1)))
                    .stream(ctx, streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });

            const live = streamTransport((frame, socket) => {
                socket.receive(
                    JSON.stringify({
                        version: 1,
                        id: frame.id,
                        type: "response",
                        status: 200,
                        body: { connected: true },
                    }),
                );
                queueMicrotask(() =>
                    socket.receive(
                        JSON.stringify({
                            version: 1,
                            id: frame.id,
                            type: "continuity",
                            body: {
                                generation: STREAM_GENERATION,
                                head: STREAM_EVENT_ID,
                                headSequence: 1,
                                acknowledgedThrough: null,
                                acknowledgedSequence: 0,
                            },
                        }),
                    ),
                );
            }).stream(ctx, streamRead);
            await expect(live.next()).resolves.toMatchObject({
                value: { type: "continuity", head: STREAM_EVENT_ID },
            });
            await live.return(undefined);
        } finally {
            destroyIdentity(identity);
        }
    });

    test("ADV-13 SSE frames enforce exact event bounds and reject truncation or invalid UTF-8", async () => {
        const identity = generateIdentityKeyPair();
        const event = utf8Encode(
            `event: continuity\ndata: ${JSON.stringify({
                generation: STREAM_GENERATION,
                head: STREAM_EVENT_ID,
                headSequence: 1,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
            })}\n\n`,
        );
        const request = createSignedInboxRead(identity, {
            createdAt: NOW,
            limit: 1,
            waitMilliseconds: 0,
        });
        const transport = (body: Uint8Array, maximumResponseBytes: number): HttpDeliveryTransport =>
            new HttpDeliveryTransport("https://relay.test", {
                maximumResponseBytes,
                fetch: async (_ctx) =>
                    new Response(body.slice(), {
                        headers: { "content-type": "text/event-stream" },
                    }),
            });
        try {
            const exact = transport(event, event.length).stream(ctx, request);
            await expect(exact.next()).resolves.toMatchObject({
                done: false,
                value: { type: "continuity", headSequence: 1 },
            });
            await exact.return(undefined);

            await expect(
                transport(event, event.length - 1)
                    .stream(ctx, request)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                transport(event.slice(0, -1), event.length).stream(ctx, request).next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                transport(new Uint8Array([0xc3]), event.length)
                    .stream(ctx, request)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });

            const live = transport(event, event.length).stream(ctx, request);
            await expect(live.next()).resolves.toMatchObject({
                value: { type: "continuity", head: STREAM_EVENT_ID },
            });
            await live.return(undefined);
        } finally {
            destroyIdentity(identity);
        }
    });

    test("ADV-13 HTTP rejects duplicate security fields atomically", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const handler = createRelayFetchHandler(fixture.relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "duplicate-field-adversarial",
        });
        try {
            const valid = delivery(sender, [recipient.publicKey], new Uint8Array([1]));
            const canonical = JSON.stringify(signedDeliveryToJson(valid));
            const duplicateBodies = [
                canonical.replace("{", '{"version":2,'),
                canonical.replace('"recipients":', '"recipients":[],"recipients":'),
                canonical.replace('"ciphertext":', '"ciphertext":"","ciphertext":'),
                canonical.replace('"signature":', '"signature":"AA","signature":'),
            ];
            const statuses: number[] = [];
            for (const body of duplicateBodies) {
                const response = await handler(
                    new Request("https://relay.test/v1/deliveries", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body,
                    }),
                );
                statuses.push(response.status);
            }
            const page = await fixture.transport.read(
                ctx,
                createSignedInboxRead(recipient, { createdAt: NOW }),
            );
            expect(statuses).toEqual([400, 400, 400, 400]);
            expect(page.deliveries).toHaveLength(0);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-14 1,000-way delivery and acknowledgement replay storms remain exact-once", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const replayed = delivery(sender, [recipient.publicKey], utf8Encode("replayed"));
        const effects: string[] = [];
        const processor = new InboxProcessor(
            {
                identity: recipient,
                transport: fixture.transport,
                store: new MemoryMurmurStore(),
            },
            async (_ctx, _transaction, queued) => {
                effects.push(queued.delivery.id);
            },
            { now: () => NOW },
        );
        try {
            let duplicates = 0;
            for (let replay = 0; replay < 1_000; replay += 1) {
                if ((await fixture.relay.publish(replayed, "replay-storm")).duplicate) {
                    duplicates += 1;
                }
            }
            expect(duplicates).toBe(999);
            await expect(processor.synchronize(ctx)).resolves.toMatchObject({ processed: 1 });
            expect(effects).toEqual([replayed.id]);
            const cursor = await processor.cursor(ctx);
            if (cursor === null) throw new Error("Missing replay-storm cursor");
            const ack = createSignedInboxAck(recipient, cursor, NOW);
            for (let replay = 0; replay < 1_000; replay += 1) {
                await expect(fixture.relay.acknowledge(ack)).resolves.toMatchObject({ removed: 0 });
            }
            await expect(processor.synchronize(ctx)).resolves.toMatchObject({ processed: 0 });
            expect(effects).toHaveLength(1);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    }, 120_000);

    test("ADV-16 256 seeded structural mutations are deterministic and controls stay live", () => {
        const identity = generateIdentityKeyPair();
        const peer = generateIdentityKeyPair();
        const signed = delivery(identity, [peer.publicKey], utf8Encode("mutation-control"));
        const signedBytes = utf8Encode(JSON.stringify(signedDeliveryToJson(signed)));
        const rosterMutation = encodeDeviceRosterMutation({
            version: 1,
            type: "register",
            deviceKey: peer.publicKey,
            resetGeneration: 0,
            keyPackage: utf8Encode("mutation-key-package"),
            encryptedMetadata: new Uint8Array(),
        });
        const roles = encodeSessionRoles({
            owner: identity.publicKey,
            admins: [peer.publicKey],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
            sendPolicy: "everyone",
        });
        const corpus = [
            {
                name: "delivery",
                bytes: signedBytes,
                parse: (value: Uint8Array): void => {
                    parseSignedDelivery(JSON.parse(utf8Decode(value)) as unknown);
                },
            },
            {
                name: "roster-mutation",
                bytes: rosterMutation,
                parse: (value: Uint8Array): void => {
                    decodeDeviceRosterMutation(value);
                },
            },
            {
                name: "role-control",
                bytes: roles,
                parse: (value: Uint8Array): void => {
                    decodeSessionRoles(value);
                },
            },
        ] as const;

        const campaign = (): readonly string[] => {
            const random = new SeededRandom(0x41445616);
            const trace: string[] = [];
            for (let seed = 0; seed < 256; seed += 1) {
                const artifact = corpus[random.integer(0, corpus.length)]!;
                const operator = random.integer(0, 4);
                let mutated: Uint8Array;
                if (operator === 0) {
                    mutated = artifact.bytes.slice(0, Math.max(0, artifact.bytes.length - 1));
                } else if (operator === 1) {
                    mutated = flip(artifact.bytes, random.integer(0, artifact.bytes.length));
                } else if (operator === 2) {
                    mutated = new Uint8Array([...artifact.bytes, random.integer(0, 256)]);
                } else {
                    mutated = new Uint8Array();
                }
                let outcome = "accepted";
                try {
                    artifact.parse(mutated);
                } catch {
                    outcome = "rejected";
                }
                trace.push(`${seed}:${artifact.name}:${operator}:${outcome}`);
            }
            return trace;
        };

        try {
            const first = campaign();
            const second = campaign();
            expect(second).toEqual(first);
            expect(first).toHaveLength(256);
            expect(first.join("\n").length).toBeLessThan(16 * 1_024);
            expect(first.filter((entry) => entry.endsWith(":rejected")).length).toBeGreaterThan(
                180,
            );
            for (let operation = 0; operation < 20; operation += 1) {
                const artifact = corpus[operation % corpus.length]!;
                expect(() => artifact.parse(artifact.bytes)).not.toThrow();
            }
        } finally {
            destroyIdentity(identity);
            destroyIdentity(peer);
        }
    });
});
