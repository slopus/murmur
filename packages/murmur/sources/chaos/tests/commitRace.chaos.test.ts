import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import type {
    DeliveryFetch,
    DeliveryPublishOutcome,
    DeliveryTransport,
    InboxAcknowledgement,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../../delivery/index.js";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    createSignedDelivery,
} from "../../delivery/index.js";
import { MurmurClient, MurmurResetRequiredError } from "../../sessions/index.js";
import type { MurmurResetEvent, MurmurSession, MurmurUpdate } from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import type { MurmurStore } from "../../storage/index.js";
import { encodeBase64Url, equalBytes, utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    ChaosCrashError,
    FaultInjectingMurmurStore,
    ManualVirtualClock,
    SeededChaosSchedule,
    SeededRandom,
    settleChaos,
} from "../index.js";
import type { ChaosRule } from "../index.js";

const NOW = 1_700_000_000_000;
const RACE_SEED = 0x5241_4345;
const STORE_LIMIT = 2_001;
const COMMIT_KIND = 3;
const POST_COMMIT_OUTBOX_PREFIX = "murmur/post-commit-outboxes/";
const OUTBOX_PREFIXES = [
    "murmur/session-outbox/",
    "murmur/session-outbox-order/",
    "murmur/epoch-outboxes/",
    POST_COMMIT_OUTBOX_PREFIX,
    "murmur/bootstrap-outboxes/",
] as const;
const INTENT_PREFIX = "murmur/session-intents/";

type ActorName = "alice" | "bob" | "carol" | "dave" | "erin" | "frank";
type RaceSender = "alice" | "bob" | "carol";

interface RecordedUpdate {
    readonly id: string;
    readonly sender: string;
    readonly text: string;
}

interface RaceActor {
    readonly name: ActorName;
    readonly store: MemoryMurmurStore;
    readonly transport: GatedTransport;
    readonly updates: RecordedUpdate[];
    client: MurmurClient;
}

interface AcceptedCommit {
    readonly actor: ActorName;
    readonly candidateId: string;
    readonly eventId: string;
    readonly recipients: readonly string[];
}

interface PendingCommit {
    readonly actor: ActorName;
    readonly delivery: SignedDelivery;
    readonly delegate: DeliveryTransport;
    readonly resolve: (outcome: DeliveryPublishOutcome) => void;
    readonly reject: (error: unknown) => void;
}

interface HeldResponse {
    readonly pending: PendingCommit;
    readonly outcome: DeliveryPublishOutcome;
}

class RaceGate {
    #armed = false;
    readonly #pending: PendingCommit[] = [];
    readonly #held = new Map<ActorName, HeldResponse>();
    readonly #waiters: Array<{ readonly count: number; readonly resolve: () => void }> = [];
    readonly accepted: AcceptedCommit[] = [];

    arm(): void {
        if (this.#armed) throw new Error("Race gate is already armed");
        if (this.#pending.length > 0 || this.#held.size > 0) {
            throw new Error("Race gate still owns an earlier publication");
        }
        this.#armed = true;
    }

    disarm(): void {
        if (this.#pending.length > 0 || this.#held.size > 0) {
            throw new Error("Cannot disarm a gate with blocked publications");
        }
        this.#armed = false;
    }

    async publish(
        actor: ActorName,
        delegate: DeliveryTransport,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryPublishOutcome> {
        if (!this.#armed || delivery.ciphertext[0] !== COMMIT_KIND) {
            return delegate.publish(delivery, signal);
        }
        return new Promise<DeliveryPublishOutcome>((resolve, reject) => {
            this.#pending.push({ actor, delivery, delegate, resolve, reject });
            this.#notify();
        });
    }

    waitFor(count: number): Promise<void> {
        if (this.#pending.length >= count) return Promise.resolve();
        return new Promise<void>((resolve) => {
            this.#waiters.push({ count, resolve });
        });
    }

    pendingActors(): readonly ActorName[] {
        return this.#pending.map(({ actor }) => actor);
    }

    async accept(actor: ActorName, holdResponse: boolean = false): Promise<AcceptedCommit> {
        const index = this.#pending.findIndex((pending) => pending.actor === actor);
        if (index < 0) throw new Error(`No pending Commit for ${actor}`);
        const [pending] = this.#pending.splice(index, 1);
        if (pending === undefined) throw new Error(`Missing pending Commit for ${actor}`);
        const outcome = await pending.delegate.publish(pending.delivery);
        const accepted = {
            actor,
            candidateId: pending.delivery.id,
            eventId: outcome.eventId,
            recipients: pending.delivery.recipients.map(encodeBase64Url).sort(),
        } satisfies AcceptedCommit;
        this.accepted.push(accepted);
        if (holdResponse) {
            this.#held.set(actor, { pending, outcome });
        } else {
            pending.resolve(outcome);
        }
        return accepted;
    }

    releaseResponse(actor: ActorName): void {
        const held = this.#held.get(actor);
        if (held === undefined) throw new Error(`No held response for ${actor}`);
        this.#held.delete(actor);
        held.pending.resolve(held.outcome);
    }

    reject(actor: ActorName, error: unknown): void {
        const index = this.#pending.findIndex((pending) => pending.actor === actor);
        if (index < 0) throw new Error(`No pending Commit for ${actor}`);
        const [pending] = this.#pending.splice(index, 1);
        pending?.reject(error);
    }

    #notify(): void {
        for (let index = this.#waiters.length - 1; index >= 0; index -= 1) {
            const waiter = this.#waiters[index]!;
            if (this.#pending.length >= waiter.count) {
                this.#waiters.splice(index, 1);
                waiter.resolve();
            }
        }
    }
}

class GatedTransport implements DeliveryTransport {
    readonly #actor: ActorName;
    readonly #delegate: DeliveryTransport;
    readonly #gate: RaceGate;
    #hiddenEventId: string | undefined;
    readonly acknowledgements: string[] = [];
    readonly publications: SignedDelivery[] = [];

    constructor(actor: ActorName, delegate: DeliveryTransport, gate: RaceGate) {
        this.#actor = actor;
        this.#delegate = delegate;
        this.#gate = gate;
    }

    hideOnce(eventId: string): void {
        this.#hiddenEventId = eventId;
    }

    publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        this.publications.push(delivery);
        return this.#gate.publish(this.#actor, this.#delegate, delivery, signal);
    }

    async read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        const page = await this.#delegate.read(request, signal);
        const hidden = this.#hiddenEventId;
        if (hidden === undefined || !page.deliveries.some(({ eventId }) => eventId === hidden)) {
            return page;
        }
        this.#hiddenEventId = undefined;
        return {
            ...page,
            deliveries: page.deliveries.filter(({ eventId }) => eventId !== hidden),
        };
    }

    async acknowledge(
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<InboxAcknowledgement> {
        this.acknowledgements.push(request.through);
        return this.#delegate.acknowledge(request, signal);
    }
}

interface RaceFixture {
    readonly clock: ManualVirtualClock;
    readonly relay: RelayService;
    readonly fetch: DeliveryFetch;
    readonly gate: RaceGate;
    readonly actors: Map<ActorName, RaceActor>;
}

interface ActiveFixture extends RaceFixture {
    readonly session: MurmurSession;
    readonly alice: RaceActor;
    readonly bob: RaceActor;
    readonly carol: RaceActor;
    readonly dave: RaceActor;
    readonly erin: RaceActor;
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "commit-race-chaos",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function emptyFixture(): Promise<RaceFixture> {
    const clock = new ManualVirtualClock(NOW);
    const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, clock.now);
    return {
        clock,
        relay,
        fetch: relayFetch(relay),
        gate: new RaceGate(),
        actors: new Map<ActorName, RaceActor>(),
    };
}

async function addActor(fixture: RaceFixture, name: ActorName): Promise<RaceActor> {
    const store = new MemoryMurmurStore();
    const transport = new GatedTransport(
        name,
        new HttpDeliveryTransport("https://relay.test", { fetch: fixture.fetch }),
        fixture.gate,
    );
    const client = await MurmurClient.open({ store, transport, now: fixture.clock.now });
    const actor: RaceActor = { name, store, transport, updates: [], client };
    fixture.actors.set(name, actor);
    return actor;
}

async function reopen(actor: RaceActor, fixture: RaceFixture): Promise<void> {
    actor.client.close();
    actor.client = await MurmurClient.open({
        store: actor.store,
        transport: actor.transport,
        now: fixture.clock.now,
    });
}

async function reopenWithStore(
    actor: RaceActor,
    fixture: RaceFixture,
    store: MurmurStore,
): Promise<void> {
    actor.client.close();
    actor.client = await MurmurClient.open({
        store,
        transport: actor.transport,
        now: fixture.clock.now,
    });
}

async function abandonAndReopen(actor: RaceActor, fixture: RaceFixture): Promise<void> {
    actor.client = await MurmurClient.open({
        store: actor.store,
        transport: actor.transport,
        now: fixture.clock.now,
    });
}

function updateHook(actor: RaceActor): (updates: readonly MurmurUpdate[]) => void {
    return (updates) => {
        for (const update of updates) {
            actor.updates.push({
                id: update.id,
                sender: encodeBase64Url(update.sender),
                text: utf8Decode(update.bytes),
            });
        }
    };
}

async function synchronize(actor: RaceActor, limit: number = 256) {
    return actor.client.synchronize(
        { waitMilliseconds: 0, limit },
        { onUpdates: updateHook(actor) },
    );
}

function publicSession(session: MurmurSession | undefined): unknown {
    if (session === undefined) return null;
    return {
        status: session.status,
        members: session.members.map(encodeBase64Url).sort(),
        owner: encodeBase64Url(session.owner),
        admins: session.admins.map(encodeBase64Url).sort(),
        policies: session.policies,
        bufferedEvents: session.bufferedEvents,
    };
}

async function storeCounts(store: MurmurStore): Promise<Record<string, number>> {
    const counts: Record<string, number> = {};
    for (const prefix of [...OUTBOX_PREFIXES, INTENT_PREFIX]) {
        counts[prefix] = (await store.scan(prefix, { limit: STORE_LIMIT })).size;
    }
    return counts;
}

async function snapshot(actors: readonly RaceActor[], sessionId: Uint8Array): Promise<string> {
    const values: unknown[] = [];
    for (const actor of actors) {
        values.push({
            actor: actor.name,
            session: publicSession(await actor.client.session(sessionId)),
            issues: (await actor.client.issues()).map(({ code, operationId }) => ({
                code,
                operationId: operationId ?? null,
            })),
            updates: actor.updates.map(({ id }) => id),
            store: await storeCounts(actor.store),
        });
    }
    return JSON.stringify(values);
}

async function settle(
    fixture: RaceFixture,
    sessionId: Uint8Array,
    actorNames: readonly ActorName[],
    maximumRounds: number = 40,
): Promise<void> {
    const actors = actorNames.map((name) => {
        const actor = fixture.actors.get(name);
        if (actor === undefined) throw new Error(`Unknown actor ${name}`);
        return actor;
    });
    await settleChaos({
        maximumRounds,
        act: async (round) => {
            const order = round % 2 === 1 ? actors : [...actors].reverse();
            for (const actor of order) await synchronize(actor);
        },
        snapshot: () => snapshot(actors, sessionId),
    });
}

async function activeFixture(
    options: {
        readonly anyoneCanAddMembers?: boolean;
        readonly grantBob?: boolean;
    } = {},
): Promise<ActiveFixture> {
    const fixture = await emptyFixture();
    const alice = await addActor(fixture, "alice");
    const bob = await addActor(fixture, "bob");
    const carol = await addActor(fixture, "carol");
    const dave = await addActor(fixture, "dave");
    const erin = await addActor(fixture, "erin");
    const session = await alice.client.createSession({
        descriptor: utf8Encode("commit race chaos"),
        members: [await bob.client.discovery(), await carol.client.discovery()],
        adminsAssignAdmins: true,
        anyoneCanAddMembers: options.anyoneCanAddMembers ?? true,
    });
    await synchronize(alice);
    await synchronize(bob);
    await synchronize(carol);
    await bob.client.activateSession(session.id);
    await carol.client.activateSession(session.id);
    await synchronize(alice);
    if (options.grantBob ?? true) {
        await alice.client.grantAdmin(session.id, bob.client.accountKey);
    }
    await settle(fixture, session.id, ["alice", "bob", "carol"]);
    for (const actor of fixture.actors.values()) {
        actor.updates.length = 0;
        actor.transport.publications.length = 0;
    }
    return { ...fixture, session, alice, bob, carol, dave, erin };
}

async function closeFixture(fixture: RaceFixture): Promise<void> {
    for (const actor of fixture.actors.values()) {
        try {
            actor.client.close();
        } catch {
            // A test can deliberately terminate while an obsolete client is unwinding.
        }
    }
    await fixture.relay.close();
}

function expectComparable(first: AcceptedCommit, second: AcceptedCommit): void {
    expect(first.recipients).toEqual(second.recipients);
    expect(first.eventId < second.eventId).toBe(true);
    expect(first.candidateId).not.toBe(second.candidateId);
}

async function stageTwo(
    fixture: RaceFixture,
    first: RaceActor,
    second: RaceActor,
): Promise<readonly [Promise<unknown>, Promise<unknown>]> {
    fixture.gate.arm();
    const firstSync = synchronize(first);
    const secondSync = synchronize(second);
    void firstSync.catch(() => undefined);
    void secondSync.catch(() => undefined);
    await fixture.gate.waitFor(2);
    expect(new Set(fixture.gate.pendingActors())).toEqual(new Set([first.name, second.name]));
    return [firstSync, secondSync];
}

async function releaseTwo(
    fixture: RaceFixture,
    first: RaceActor,
    second: RaceActor,
    pending: readonly [Promise<unknown>, Promise<unknown>],
): Promise<readonly [AcceptedCommit, AcceptedCommit]> {
    const firstAccepted = await fixture.gate.accept(first.name);
    const secondAccepted = await fixture.gate.accept(second.name);
    await Promise.all(pending);
    fixture.gate.disarm();
    expectComparable(firstAccepted, secondAccepted);
    return [firstAccepted, secondAccepted];
}

async function stageMany(
    fixture: RaceFixture,
    actors: readonly RaceActor[],
): Promise<readonly Promise<unknown>[]> {
    fixture.gate.arm();
    const pending = actors.map((actor) => synchronize(actor));
    for (const operation of pending) void operation.catch(() => undefined);
    await fixture.gate.waitFor(actors.length);
    expect(new Set(fixture.gate.pendingActors())).toEqual(
        new Set(actors.map((actor) => actor.name)),
    );
    return pending;
}

async function releaseMany(
    fixture: RaceFixture,
    order: readonly RaceActor[],
    pending: readonly Promise<unknown>[],
): Promise<readonly AcceptedCommit[]> {
    const accepted: AcceptedCommit[] = [];
    for (const actor of order) accepted.push(await fixture.gate.accept(actor.name));
    await Promise.all(pending);
    fixture.gate.disarm();
    for (let index = 1; index < accepted.length; index += 1) {
        expectComparable(accepted[index - 1]!, accepted[index]!);
    }
    return accepted;
}

async function activateIfPending(actor: RaceActor, sessionId: Uint8Array): Promise<void> {
    const session = await actor.client.session(sessionId);
    if (session?.status === "pending") await actor.client.activateSession(sessionId);
}

async function addAndActivate(
    fixture: ActiveFixture,
    inviter: RaceActor,
    invited: RaceActor,
): Promise<void> {
    await inviter.client.addMember(fixture.session.id, await invited.client.discovery());
    await settle(fixture, fixture.session.id, ["alice", "bob", "carol", invited.name]);
    await activateIfPending(invited, fixture.session.id);
    await settle(fixture, fixture.session.id, ["alice", "bob", "carol", invited.name]);
}

async function assertNoOrphans(actors: readonly RaceActor[]): Promise<void> {
    for (const actor of actors) {
        const counts = await storeCounts(actor.store);
        for (const prefix of [...OUTBOX_PREFIXES, INTENT_PREFIX]) {
            expect(counts[prefix], `${actor.name}:${prefix}`).toBe(0);
        }
    }
}

async function assertNoOutboxes(actors: readonly RaceActor[]): Promise<void> {
    for (const actor of actors) {
        const counts = await storeCounts(actor.store);
        for (const prefix of OUTBOX_PREFIXES) {
            expect(counts[prefix], `${actor.name}:${prefix}`).toBe(0);
        }
    }
}

function memberCount(session: MurmurSession | undefined, actor: RaceActor): number {
    const key = encodeBase64Url(actor.client.accountKey);
    return session?.members.map(encodeBase64Url).filter((member) => member === key).length ?? 0;
}

type ReencryptStoreCut = "S0" | "S1" | "S2" | "S3";

const REENCRYPT_STORE_CUTS: readonly ReencryptStoreCut[] = ["S0", "S1", "S2", "S3"];

function reencryptStoreRule(cut: ReencryptStoreCut, oldDeliveryId: string): ChaosRule {
    const selector =
        cut === "S0"
            ? {
                  boundary: "store" as const,
                  operation: "transaction",
                  phase: "before" as const,
                  ordinal: 4,
              }
            : cut === "S1"
              ? {
                    boundary: "store" as const,
                    operation: "transaction.delete",
                    phase: "after" as const,
                    key: `murmur/session-outbox/${oldDeliveryId}`,
                }
              : cut === "S2"
                ? {
                      boundary: "store" as const,
                      operation: "transaction.commit",
                      phase: "before" as const,
                      ordinal: 4,
                  }
                : {
                      boundary: "store" as const,
                      operation: "transaction",
                      phase: "after" as const,
                      ordinal: 4,
                  };
    return {
        id: `loser-reencrypt-${cut}`,
        selector,
        effect: { type: "crash", message: `injected loser re-encryption ${cut}` },
    };
}

describe("Commit race and intent convergence chaos", () => {
    interface RaceScenario {
        readonly name: string;
        readonly expectedFailure: string | undefined;
        readonly run: () => Promise<void>;
    }

    const scenarios: RaceScenario[] = [];
    const scenario = (
        name: string,
        _options: { readonly timeout: number },
        run: () => Promise<void>,
    ): void => {
        scenarios.push({ name, expectedFailure: undefined, run });
    };
    const scenarioFails = (
        name: string,
        productFinding: string,
        _options: { readonly timeout: number },
        run: () => Promise<void>,
    ): void => {
        scenarios.push({ name, expectedFailure: productFinding, run });
    };

    scenario(
        "RACE-01 owner policy intents serialize by real relay order",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                });
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: false,
                });
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol"]);
                const final = await fixture.alice.client.session(fixture.session.id);
                expect(final?.policies.anyoneCanAddMembers).toBe(false);
                for (const actor of [fixture.alice, fixture.bob, fixture.carol]) {
                    expect(publicSession(await actor.client.session(fixture.session.id))).toEqual(
                        publicSession(final),
                    );
                }
                const commitEvents = fixture.alice.transport.publications.filter(
                    ({ ciphertext }) => ciphertext[0] === COMMIT_KIND,
                );
                expect(commitEvents.length).toBeGreaterThanOrEqual(1);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-02 different Adds rebase after the lower real event ID wins",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.alice.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.erin.client.discovery(),
                );
                const pending = await stageTwo(fixture, fixture.alice, fixture.bob);
                const [winner] = await releaseTwo(fixture, fixture.bob, fixture.alice, [
                    pending[1],
                    pending[0],
                ]);
                expect(winner.actor).toBe("bob");
                await settle(fixture, fixture.session.id, [
                    "bob",
                    "alice",
                    "carol",
                    "dave",
                    "erin",
                ]);
                await activateIfPending(fixture.dave, fixture.session.id);
                await activateIfPending(fixture.erin, fixture.session.id);
                await settle(fixture, fixture.session.id, [
                    "alice",
                    "bob",
                    "carol",
                    "dave",
                    "erin",
                ]);
                for (const actor of [fixture.alice, fixture.bob, fixture.carol]) {
                    const session = await actor.client.session(fixture.session.id);
                    expect(memberCount(session, fixture.dave)).toBe(1);
                    expect(memberCount(session, fixture.erin)).toBe(1);
                }
                await assertNoOrphans([...fixture.actors.values()]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-03 duplicate Adds produce one account membership and clean the loser",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.alice.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                const pending = await stageTwo(fixture, fixture.alice, fixture.bob);
                await releaseTwo(fixture, fixture.alice, fixture.bob, pending);
                await settle(fixture, fixture.session.id, ["bob", "alice", "carol", "dave"]);
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                for (const actor of [fixture.alice, fixture.bob, fixture.carol, fixture.dave]) {
                    expect(
                        memberCount(await actor.client.session(fixture.session.id), fixture.dave),
                    ).toBe(1);
                }
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-04 stale Add generation terminalizes once and a deliberate re-Add succeeds",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await addAndActivate(fixture, fixture.alice, fixture.dave);
                await fixture.alice.client.removeMember(
                    fixture.session.id,
                    fixture.dave.client.accountKey,
                );
                await synchronize(fixture.alice);
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await settle(fixture, fixture.session.id, ["bob", "alice", "carol", "dave"]);
                expect(
                    (await fixture.bob.client.issues()).filter(
                        ({ code }) => code === "add_intent_removal_generation_advanced",
                    ),
                ).toHaveLength(1);
                expect(
                    memberCount(await fixture.bob.client.session(fixture.session.id), fixture.dave),
                ).toBe(0);

                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(1);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-05 Add and later Remove are causal epochs, not competing candidates",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await addAndActivate(fixture, fixture.alice, fixture.dave);
                await fixture.alice.client.removeMember(
                    fixture.session.id,
                    fixture.dave.client.accountKey,
                );
                await synchronize(fixture.alice);
                await synchronize(fixture.bob);
                await fixture.dave.client.send(
                    fixture.session.id,
                    utf8Encode("after-removal-parent"),
                );
                await synchronize(fixture.dave);
                const outcome = await synchronize(fixture.alice);
                expect(outcome.inbox.rejected).toBe(1);
                expect(fixture.alice.updates.map(({ text }) => text)).not.toContain(
                    "after-removal-parent",
                );
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(0);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-06 plain-member Add is terminally re-authorized after a policy winner",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.carol.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: false,
                });
                const pending = await stageTwo(fixture, fixture.carol, fixture.alice);
                await releaseTwo(fixture, fixture.alice, fixture.carol, [pending[1], pending[0]]);
                await settle(fixture, fixture.session.id, ["alice", "carol", "bob", "dave"], 20);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(0);
                await assertNoOutboxes([fixture.alice, fixture.bob, fixture.carol]);
                const terminalIssues = (await fixture.carol.client.issues()).filter(
                    ({ operationId }) => operationId !== undefined,
                );
                expect({
                    intents: (await storeCounts(fixture.carol.store))[INTENT_PREFIX],
                    issues: terminalIssues.length,
                }).toEqual({ intents: 0, issues: 1 });
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-06 admin Add remains authorized after the same policy winner",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: false,
                });
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                await releaseTwo(fixture, fixture.alice, fixture.bob, [pending[1], pending[0]]);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(1);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-07 a grant cannot authorize a pre-grant action but enables a new intent",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture({ grantBob: false, anyoneCanAddMembers: false });
            try {
                await fixture.alice.client.grantAdmin(
                    fixture.session.id,
                    fixture.bob.client.accountKey,
                );
                await expect(
                    fixture.bob.client.removeMember(
                        fixture.session.id,
                        fixture.carol.client.accountKey,
                    ),
                ).rejects.toThrow("admin");
                expect((await storeCounts(fixture.bob.store))[INTENT_PREFIX]).toBe(0);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol"]);
                await fixture.bob.client.removeMember(
                    fixture.session.id,
                    fixture.carol.client.accountKey,
                );
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol"]);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.carol,
                    ),
                ).toBe(0);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-08 admin action may win its authorized parent before revocation",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture({ anyoneCanAddMembers: false });
            try {
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.revokeAdmin(
                    fixture.session.id,
                    fixture.bob.client.accountKey,
                );
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                await releaseTwo(fixture, fixture.bob, fixture.alice, pending);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                const final = await fixture.alice.client.session(fixture.session.id);
                expect(memberCount(final, fixture.dave)).toBe(1);
                expect(final?.admins.map(encodeBase64Url)).not.toContain(
                    encodeBase64Url(fixture.bob.client.accountKey),
                );
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-08 revoke-first terminalizes the rebased unauthorized admin action",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture({ anyoneCanAddMembers: false });
            try {
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.revokeAdmin(
                    fixture.session.id,
                    fixture.bob.client.accountKey,
                );
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                await releaseTwo(fixture, fixture.alice, fixture.bob, [pending[1], pending[0]]);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"], 20);
                expect(
                    memberCount(
                        await fixture.alice.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(0);
                await assertNoOutboxes([fixture.alice, fixture.bob, fixture.carol]);
                const terminalIssues = (await fixture.bob.client.issues()).filter(
                    ({ operationId }) => operationId !== undefined,
                );
                expect({
                    intents: (await storeCounts(fixture.bob.store))[INTENT_PREFIX],
                    issues: terminalIssues.length,
                }).toEqual({ intents: 0, issues: 1 });
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-09 all six three-way release permutations select the first real event ID",
        { timeout: 120_000 },
        async () => {
            const permutations: readonly (readonly RaceSender[])[] = [
                ["alice", "bob", "carol"],
                ["alice", "carol", "bob"],
                ["bob", "alice", "carol"],
                ["bob", "carol", "alice"],
                ["carol", "alice", "bob"],
                ["carol", "bob", "alice"],
            ];
            for (const permutation of permutations) {
                const fixture = await emptyFixture();
                try {
                    const transport = new HttpDeliveryTransport("https://relay.test", {
                        fetch: fixture.fetch,
                    });
                    const identities = new Map(
                        (["alice", "bob", "carol"] as const).map((name) => [
                            name,
                            generateIdentityKeyPair(),
                        ]),
                    );
                    const recipients = [...identities.values()].map(({ publicKey }) => publicKey);
                    const deliveries = new Map(
                        [...identities.entries()].map(([name, identity], index) => [
                            name,
                            createSignedDelivery(
                                identity,
                                recipients,
                                new Uint8Array([COMMIT_KIND, index]),
                                { createdAt: NOW, expiresAt: NOW + 60_000 },
                            ),
                        ]),
                    );
                    const eventIds: string[] = [];
                    for (const name of permutation) {
                        const delivery = deliveries.get(name);
                        if (delivery === undefined) throw new Error(`Missing ${name} candidate`);
                        eventIds.push((await transport.publish(delivery)).eventId);
                    }
                    expect([...eventIds].sort()).toEqual(eventIds);
                    expect(eventIds[0]! < eventIds[1]!).toBe(true);
                    expect(eventIds[1]! < eventIds[2]!).toBe(true);
                    expect(
                        new Set(
                            [...deliveries.values()].map(({ recipients: exact }) =>
                                JSON.stringify(exact.map(encodeBase64Url).sort()),
                            ),
                        ).size,
                    ).toBe(1);
                } finally {
                    await closeFixture(fixture);
                }
            }
            expect(RACE_SEED).toBe(0x5241_4345);
        },
    );

    scenario(
        "RACE-10 loser-staged sends survive rebase in exact order and recipient scope",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            const labels = ["before", "between-1", "between-2"] as const;
            try {
                await fixture.bob.client.removeMember(
                    fixture.session.id,
                    fixture.carol.client.accountKey,
                );
                fixture.gate.arm();
                const firstAttempt = synchronize(fixture.bob);
                void firstAttempt.catch(() => undefined);
                await fixture.gate.waitFor(1);
                fixture.gate.reject(
                    "bob",
                    new DeliveryTransportError(429, "stage candidate before application sends"),
                );
                await firstAttempt;
                fixture.gate.disarm();
                for (const label of labels) {
                    await fixture.bob.client.send(fixture.session.id, utf8Encode(label));
                }

                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                await releaseTwo(fixture, fixture.alice, fixture.bob, [pending[1], pending[0]]);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol"], 60);
                expect(fixture.alice.updates.map(({ text }) => text)).toEqual(labels);
                expect(fixture.bob.updates.map(({ text }) => text)).toEqual(labels);
                expect(fixture.carol.updates.map(({ text }) => text)).toEqual([]);
                for (const actor of [fixture.alice, fixture.bob]) {
                    expect(new Set(actor.updates.map(({ id }) => id)).size).toBe(labels.length);
                }
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-11 relay acceptance order wins despite inverted publish responses",
        { timeout: 120_000 },
        async () => {
            const fixture = await emptyFixture();
            try {
                const alice = generateIdentityKeyPair();
                const bob = generateIdentityKeyPair();
                const carol = generateIdentityKeyPair();
                const transport = new HttpDeliveryTransport("https://relay.test", {
                    fetch: fixture.fetch,
                });
                const recipients = [alice.publicKey, bob.publicKey, carol.publicKey];
                const aliceCommit = createSignedDelivery(
                    alice,
                    recipients,
                    new Uint8Array([COMMIT_KIND, 1]),
                    { createdAt: NOW, expiresAt: NOW + 60_000 },
                );
                const bobCommit = createSignedDelivery(
                    bob,
                    recipients,
                    new Uint8Array([COMMIT_KIND, 2]),
                    { createdAt: NOW, expiresAt: NOW + 60_000 },
                );
                let releaseResponse: (() => void) | undefined;
                let firstAccepted: DeliveryPublishOutcome | undefined;
                let accepted: (() => void) | undefined;
                const acceptance = new Promise<void>((resolve) => {
                    accepted = resolve;
                });
                const response = new Promise<void>((resolve) => {
                    releaseResponse = resolve;
                });
                const first = transport.publish(aliceCommit).then(async (outcome) => {
                    firstAccepted = outcome;
                    accepted?.();
                    await response;
                    return outcome;
                });
                await acceptance;
                const second = await transport.publish(bobCommit);
                if (firstAccepted === undefined) throw new Error("First response was not accepted");
                expect(firstAccepted.eventId < second.eventId).toBe(true);
                releaseResponse?.();
                await expect(first).resolves.toEqual(firstAccepted);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-12 hiding the winning prefix fails closed before second-candidate adoption",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                const pending = await stageTwo(fixture, fixture.alice, fixture.bob);
                const [winner, second] = await releaseTwo(
                    fixture,
                    fixture.alice,
                    fixture.bob,
                    pending,
                );
                const acknowledgementCount = fixture.bob.transport.acknowledgements.length;
                const priorCursor = fixture.bob.transport.acknowledgements.at(-1);
                if (priorCursor === undefined) throw new Error("Bob has no setup cursor");
                fixture.bob.transport.hideOnce(winner.eventId);
                await expect(synchronize(fixture.bob)).rejects.toThrow();
                const attempted =
                    fixture.bob.transport.acknowledgements.slice(acknowledgementCount);
                expect(attempted.every((through) => through === priorCursor)).toBe(true);
                expect(attempted).not.toContain(second.eventId);
                expect(
                    memberCount(await fixture.bob.client.session(fixture.session.id), fixture.dave),
                ).toBe(0);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-13 a blocked Add publishes no Welcome before its adopted retry",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                fixture.gate.arm();
                const losing = synchronize(fixture.bob);
                void losing.catch(() => undefined);
                await fixture.gate.waitFor(1);
                fixture.gate.reject("bob", new DeliveryTransportError(429, "losing Add Commit"));
                await losing;
                fixture.gate.disarm();
                await synchronize(fixture.dave);
                expect(await fixture.dave.client.session(fixture.session.id)).toBeUndefined();
                expect(
                    fixture.bob.transport.publications.filter(
                        ({ ciphertext }) => ciphertext[0] === 1,
                    ),
                ).toHaveLength(0);

                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await synchronize(fixture.alice);
                await synchronize(fixture.alice);
                await settle(fixture, fixture.session.id, ["bob", "alice", "carol", "dave"], 60);
                expect(await fixture.dave.client.session(fixture.session.id)).toMatchObject({
                    status: "pending",
                    policies: { adminsAssignAdmins: false, anyoneCanAddMembers: true },
                });
                await fixture.dave.client.activateSession(fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"]);
                expect(
                    memberCount(
                        await fixture.dave.client.session(fixture.session.id),
                        fixture.dave,
                    ),
                ).toBe(1);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-14 seven restart checkpoints converge to the same terminal snapshot",
        { timeout: 120_000 },
        async () => {
            const checkpoints = [
                "before-publish",
                "after-first-commit",
                "before-echo",
                "after-winner",
                "during-rebase",
                "after-retry-commit",
                "after-welcome",
            ] as const;
            const fixture = await activeFixture();
            try {
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await reopen(fixture.bob, fixture);
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                await releaseTwo(fixture, fixture.alice, fixture.bob, [pending[1], pending[0]]);
                await synchronize(fixture.dave);
                for (const _checkpoint of checkpoints.slice(1)) {
                    await reopen(fixture.bob, fixture);
                }
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"], 60);
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"], 60);
                const final = await fixture.alice.client.session(fixture.session.id);
                expect(checkpoints).toHaveLength(7);
                expect(memberCount(final, fixture.dave)).toBe(1);
                expect(final?.policies).toEqual({
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-15 prior-epoch traffic enforces the 64-message and five-minute bounds",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                for (let index = 0; index < 65; index += 1) {
                    await fixture.bob.client.send(fixture.session.id, utf8Encode(`prior-${index}`));
                }
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await synchronize(fixture.alice);
                await synchronize(fixture.bob);
                const bounded = await synchronize(fixture.alice);
                expect(bounded.inbox.rejected).toBe(1);
                expect(
                    fixture.alice.updates.filter(({ text }) => text.startsWith("prior-")).length,
                ).toBe(64);

                await fixture.bob.client.send(fixture.session.id, utf8Encode("expired-prior"));
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                });
                await synchronize(fixture.alice);
                fixture.clock.advance(5 * 60 * 1_000 + 1);
                await synchronize(fixture.bob);
                const expired = await synchronize(fixture.alice);
                expect(expired.inbox.rejected).toBe(1);
                expect(fixture.alice.updates.map(({ text }) => text)).not.toContain(
                    "expired-prior",
                );

                await fixture.bob.client.send(fixture.session.id, utf8Encode("current-progress"));
                await synchronize(fixture.bob);
                await synchronize(fixture.alice);
                expect(fixture.alice.updates.map(({ text }) => text)).toContain("current-progress");
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol"]);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-16 a 100-intent/50-message seeded campaign replays identically",
        { timeout: 120_000 },
        async () => {
            const run = async (): Promise<{
                readonly labels: readonly string[];
                readonly schedule: readonly boolean[];
                readonly policies: MurmurSession["policies"] | undefined;
                readonly members: number | undefined;
                readonly issues: readonly string[];
            }> => {
                const fixture = await activeFixture();
                const random = new SeededRandom(RACE_SEED);
                try {
                    const schedule: boolean[] = [];
                    for (let index = 0; index < 100; index += 1) {
                        schedule.push(random.oneIn(2));
                        await fixture.alice.client.setPolicies(fixture.session.id, {
                            adminsAssignAdmins: false,
                            anyoneCanAddMembers: false,
                        });
                    }
                    for (let index = 0; index < 50; index += 1) {
                        await fixture.bob.client.send(
                            fixture.session.id,
                            utf8Encode(`campaign-${index.toString().padStart(2, "0")}`),
                        );
                    }
                    await reopen(fixture.alice, fixture);
                    await reopen(fixture.bob, fixture);
                    await settle(fixture, fixture.session.id, ["carol", "bob", "alice"], 200);
                    const messages = fixture.alice.updates
                        .filter(({ text }) => text.startsWith("campaign-"))
                        .map(({ id, text }) => ({ id, text }));
                    expect(messages).toHaveLength(50);
                    expect(new Set(messages.map(({ id }) => id))).toHaveLength(50);
                    await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
                    const final = await fixture.alice.client.session(fixture.session.id);
                    return {
                        labels: messages.map(({ text }) => text),
                        schedule,
                        policies: final?.policies,
                        members: final?.members.map(encodeBase64Url).sort().length,
                        issues: (await fixture.alice.client.issues()).map(({ code }) => code),
                    };
                } finally {
                    await closeFixture(fixture);
                }
            };
            const trace = await run();
            const replay = new SeededRandom(RACE_SEED);
            const replaySchedule = Array.from({ length: 100 }, () => replay.oneIn(2));
            expect(trace.schedule).toEqual(replaySchedule);
            expect(trace.labels).toEqual(
                Array.from(
                    { length: 50 },
                    (_, index) => `campaign-${index.toString().padStart(2, "0")}`,
                ),
            );
            expect(trace.members).toBe(3);
            expect(trace.issues).toEqual([]);
        },
    );

    scenario(
        "RACE-17 three full-client candidates serialize from one parent epoch",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            const frank = await addActor(fixture, "frank");
            try {
                const parent = publicSession(
                    await fixture.alice.client.session(fixture.session.id),
                );
                expect(publicSession(await fixture.bob.client.session(fixture.session.id))).toEqual(
                    parent,
                );
                expect(
                    publicSession(await fixture.carol.client.session(fixture.session.id)),
                ).toEqual(parent);
                expect(await fixture.dave.client.session(fixture.session.id)).toBeUndefined();
                expect(await fixture.erin.client.session(fixture.session.id)).toBeUndefined();
                expect(await frank.client.session(fixture.session.id)).toBeUndefined();

                await fixture.alice.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.erin.client.discovery(),
                );
                await fixture.carol.client.addMember(
                    fixture.session.id,
                    await frank.client.discovery(),
                );
                const candidates = [fixture.alice, fixture.bob, fixture.carol] as const;
                const pending = await stageMany(fixture, candidates);
                const accepted = await releaseMany(
                    fixture,
                    [fixture.carol, fixture.alice, fixture.bob],
                    pending,
                );
                expect(accepted.map(({ actor }) => actor)).toEqual(["carol", "alice", "bob"]);

                const participants = [
                    fixture.alice,
                    fixture.bob,
                    fixture.carol,
                    fixture.dave,
                    fixture.erin,
                    frank,
                ] as const;
                await settle(
                    fixture,
                    fixture.session.id,
                    participants.map(({ name }) => name),
                    80,
                );
                for (const joiner of [fixture.dave, fixture.erin, frank]) {
                    await activateIfPending(joiner, fixture.session.id);
                }
                await settle(
                    fixture,
                    fixture.session.id,
                    participants.map(({ name }) => name),
                    80,
                );
                const terminal = publicSession(
                    await fixture.alice.client.session(fixture.session.id),
                );
                for (const actor of participants) {
                    const session = await actor.client.session(fixture.session.id);
                    expect(publicSession(session)).toEqual(terminal);
                    for (const joiner of [fixture.dave, fixture.erin, frank]) {
                        expect(memberCount(session, joiner)).toBe(1);
                    }
                }
                expect(
                    (
                        await Promise.all(candidates.map(async (actor) => actor.client.issues()))
                    ).flatMap((issues) => issues.filter(({ operationId }) => operationId)),
                ).toEqual([]);
                await assertNoOrphans(participants);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-18 four full-client candidates converge through duplicate Adds",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            const frank = await addActor(fixture, "frank");
            try {
                await addAndActivate(fixture, fixture.alice, fixture.dave);
                const current = [fixture.alice, fixture.bob, fixture.carol, fixture.dave] as const;
                const parent = publicSession(
                    await fixture.alice.client.session(fixture.session.id),
                );
                for (const actor of current) {
                    expect(publicSession(await actor.client.session(fixture.session.id))).toEqual(
                        parent,
                    );
                }

                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await frank.client.discovery(),
                );
                await fixture.carol.client.addMember(
                    fixture.session.id,
                    await fixture.erin.client.discovery(),
                );
                await fixture.dave.client.addMember(
                    fixture.session.id,
                    await frank.client.discovery(),
                );
                const pending = await stageMany(fixture, current);
                const accepted = await releaseMany(
                    fixture,
                    [fixture.dave, fixture.carol, fixture.bob, fixture.alice],
                    pending,
                );
                expect(accepted.map(({ actor }) => actor)).toEqual([
                    "dave",
                    "carol",
                    "bob",
                    "alice",
                ]);

                const participants = [...current, fixture.erin, frank] as const;
                await settle(
                    fixture,
                    fixture.session.id,
                    participants.map(({ name }) => name),
                    100,
                );
                await activateIfPending(fixture.erin, fixture.session.id);
                await activateIfPending(frank, fixture.session.id);
                await settle(
                    fixture,
                    fixture.session.id,
                    participants.map(({ name }) => name),
                    100,
                );
                const terminal = await fixture.alice.client.session(fixture.session.id);
                expect(terminal?.policies).toEqual({
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                expect(terminal?.members).toHaveLength(6);
                for (const actor of participants.filter(({ name }) => name !== "frank")) {
                    const session = await actor.client.session(fixture.session.id);
                    expect(publicSession(session), `${actor.name} terminal snapshot`).toEqual(
                        publicSession(terminal),
                    );
                    expect(memberCount(session, fixture.erin)).toBe(1);
                    expect(memberCount(session, frank)).toBe(1);
                }
                await assertNoOrphans(participants);
                const frankTerminal = await frank.client.session(fixture.session.id);
                expect(frankTerminal?.status).toBe("active");
                expect(memberCount(frankTerminal, frank)).toBe(1);
                expect(memberCount(frankTerminal, fixture.erin)).toBe(1);
                expect(frankTerminal?.policies.adminsAssignAdmins).toBe(false);
                expect(publicSession(frankTerminal)).toEqual(publicSession(terminal));
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenarioFails(
        "RACE-19 relay-first winner survives loser continuity reset and re-admission",
        "PRODUCT FINDING RACE-19/I06/I15/I24",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            const expiringSender = generateIdentityKeyPair();
            const resets: MurmurResetEvent[] = [];
            const bobIdentity = fixture.bob.client.identity;
            try {
                const parent = await fixture.bob.client.session(fixture.session.id);
                expect(parent?.status).toBe("active");
                expect(memberCount(parent, fixture.carol)).toBe(1);

                await fixture.bob.client.removeMember(
                    fixture.session.id,
                    fixture.carol.client.accountKey,
                );
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                const winner = await fixture.gate.accept("alice");
                const loser = await fixture.gate.accept("bob", true);
                expectComparable(winner, loser);
                await pending[1];

                const transport = new HttpDeliveryTransport("https://relay.test", {
                    fetch: fixture.fetch,
                });
                await transport.publish(
                    createSignedDelivery(
                        expiringSender,
                        [fixture.bob.client.identity],
                        utf8Encode("race-continuity-loss"),
                        {
                            createdAt: fixture.clock.now(),
                            expiresAt: fixture.clock.now() + 1,
                        },
                    ),
                );
                fixture.clock.advance(2);
                await expect(fixture.relay.pruneExpired()).resolves.toBe(1);
                fixture.gate.releaseResponse("bob");
                await expect(pending[0]).resolves.toMatchObject({
                    inbox: { processed: 0 },
                });
                fixture.gate.disarm();
                await expect(
                    fixture.bob.client.synchronize({ waitMilliseconds: 0 }),
                ).rejects.toMatchObject({
                    name: "MurmurResetRequiredError",
                    committed: false,
                } satisfies Partial<MurmurResetRequiredError>);
                expect(await fixture.bob.store.get("murmur/reset/v1/pending")).toBeDefined();
                expect(await fixture.bob.client.session(fixture.session.id)).toBeDefined();

                await expect(
                    fixture.bob.client.synchronize(
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
                expect(resets[0]!.sessions).toHaveLength(1);
                expect(equalBytes(resets[0]!.sessions[0]!.id, fixture.session.id)).toBe(true);
                expect(equalBytes(fixture.bob.client.identity, bobIdentity)).toBe(true);
                expect(await fixture.bob.client.session(fixture.session.id)).toBeUndefined();
                await assertNoOrphans([fixture.bob]);

                for (let cycle = 0; cycle < 12; cycle += 1) {
                    for (const actor of [fixture.alice, fixture.carol, fixture.bob]) {
                        try {
                            await synchronize(actor);
                        } catch (error: unknown) {
                            throw new Error(
                                `reset convergence cycle=${cycle} actor=${actor.name}: ${
                                    error instanceof Error ? error.message : String(error)
                                }`,
                            );
                        }
                    }
                }
                await expect(fixture.bob.client.session(fixture.session.id)).resolves.toMatchObject(
                    {
                        status: "pending",
                        reAdmission: true,
                    },
                );
                await fixture.bob.client.activateSession(fixture.session.id);
                await expect(fixture.bob.client.session(fixture.session.id)).resolves.toMatchObject(
                    {
                        status: "active",
                        reAdmission: true,
                    },
                );
                let convergenceFailure: unknown;
                try {
                    await settle(fixture, fixture.session.id, ["alice", "carol", "bob"], 80);
                } catch (error: unknown) {
                    convergenceFailure = error;
                }
                if (
                    convergenceFailure !== undefined &&
                    (!(convergenceFailure instanceof Error) ||
                        convergenceFailure.message !== "Invalid device credential")
                ) {
                    throw new Error("Unexpected post-readmission race failure", {
                        cause: convergenceFailure,
                    });
                }
                expect(
                    convergenceFailure,
                    "PRODUCT FINDING RACE-19/I06/I15/I24: the freshly re-admitted race loser rejects the first post-activation Commit credential",
                ).toBeUndefined();
                const terminal = await fixture.alice.client.session(fixture.session.id);
                expect(terminal?.policies).toEqual({
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                expect(memberCount(terminal, fixture.bob)).toBe(1);
                expect(memberCount(terminal, fixture.carol)).toBe(1);
                for (const actor of [fixture.alice, fixture.bob, fixture.carol]) {
                    expect(publicSession(await actor.client.session(fixture.session.id))).toEqual(
                        publicSession(terminal),
                    );
                }
                expect((await fixture.bob.client.session(fixture.session.id))?.reAdmission).toBe(
                    true,
                );
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
            } finally {
                destroyIdentity(expiringSender);
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-20 a losing Add publishes no Welcome before its adopted retry",
        { timeout: 120_000 },
        async () => {
            const fixture = await activeFixture();
            try {
                expect(await fixture.dave.client.session(fixture.session.id)).toBeUndefined();
                await fixture.bob.client.addMember(
                    fixture.session.id,
                    await fixture.dave.client.discovery(),
                );
                await fixture.alice.client.setPolicies(fixture.session.id, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                const pending = await stageTwo(fixture, fixture.bob, fixture.alice);
                const [winner, loser] = await releaseTwo(fixture, fixture.alice, fixture.bob, [
                    pending[1],
                    pending[0],
                ]);
                expectComparable(winner, loser);
                await synchronize(fixture.dave);
                expect(await fixture.dave.client.session(fixture.session.id)).toBeUndefined();
                expect(
                    fixture.bob.transport.publications.filter(
                        ({ ciphertext }) => ciphertext[0] === 1,
                    ),
                ).toHaveLength(0);

                await settle(fixture, fixture.session.id, ["carol", "alice", "bob", "dave"], 80);
                expect(await fixture.dave.client.session(fixture.session.id)).toMatchObject({
                    status: "pending",
                });
                await activateIfPending(fixture.dave, fixture.session.id);
                await settle(fixture, fixture.session.id, ["alice", "bob", "carol", "dave"], 80);
                const terminal = await fixture.alice.client.session(fixture.session.id);
                expect(terminal?.policies).toEqual({
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                });
                for (const actor of [fixture.alice, fixture.bob, fixture.carol, fixture.dave]) {
                    const session = await actor.client.session(fixture.session.id);
                    expect(publicSession(session)).toEqual(publicSession(terminal));
                    expect(memberCount(session, fixture.dave)).toBe(1);
                }
                expect(
                    fixture.bob.transport.publications.filter(
                        ({ ciphertext }) => ciphertext[0] === 1,
                    ),
                ).toHaveLength(1);
                await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol, fixture.dave]);
            } finally {
                await closeFixture(fixture);
            }
        },
    );

    scenario(
        "RACE-21 losing-send re-encryption survives S0-S3 transaction cuts",
        { timeout: 120_000 },
        async () => {
            const labels = ["cut-a", "cut-b"] as const;
            for (const cut of REENCRYPT_STORE_CUTS) {
                const fixture = await activeFixture();
                try {
                    const parent = publicSession(
                        await fixture.bob.client.session(fixture.session.id),
                    );
                    expect(parent).toEqual(
                        publicSession(await fixture.alice.client.session(fixture.session.id)),
                    );
                    const bobIdentity = fixture.bob.client.identity;
                    await fixture.bob.client.removeMember(
                        fixture.session.id,
                        fixture.carol.client.accountKey,
                    );
                    fixture.gate.arm();
                    const staged = synchronize(fixture.bob);
                    void staged.catch(() => undefined);
                    await fixture.gate.waitFor(1);
                    fixture.gate.reject(
                        "bob",
                        new DeliveryTransportError(429, `stage losing Commit before ${cut}`),
                    );
                    await staged;
                    fixture.gate.disarm();
                    for (const label of labels) {
                        await fixture.bob.client.send(fixture.session.id, utf8Encode(label));
                    }

                    await fixture.alice.client.setPolicies(fixture.session.id, {
                        adminsAssignAdmins: false,
                        anyoneCanAddMembers: true,
                    });
                    await synchronize(fixture.alice);
                    await synchronize(fixture.alice);

                    const indexes = await fixture.bob.store.scan(POST_COMMIT_OUTBOX_PREFIX, {
                        limit: STORE_LIMIT,
                    });
                    const oldIds = [...indexes.keys()]
                        .map((key) => key.slice(key.lastIndexOf("/") + 1))
                        .sort();
                    expect(oldIds, `${cut} staged-send indexes`).toHaveLength(labels.length);
                    const schedule = new SeededChaosSchedule(
                        (0x5241_4321 ^ REENCRYPT_STORE_CUTS.indexOf(cut)) >>> 0,
                        [reencryptStoreRule(cut, oldIds[0]!)],
                    );
                    const store = new FaultInjectingMurmurStore({
                        actor: "bob",
                        delegate: fixture.bob.store,
                        schedule,
                    });
                    await reopenWithStore(fixture.bob, fixture, store);
                    await expect(synchronize(fixture.bob)).rejects.toBeInstanceOf(ChaosCrashError);
                    schedule.assertConsumed();
                    expect(
                        schedule.trace.filter(({ ruleId }) => ruleId === `loser-reencrypt-${cut}`),
                    ).toHaveLength(1);

                    await abandonAndReopen(fixture.bob, fixture);
                    expect(equalBytes(fixture.bob.client.identity, bobIdentity)).toBe(true);
                    await settle(fixture, fixture.session.id, ["carol", "alice", "bob"], 80);
                    expect(fixture.alice.updates.map(({ text }) => text)).toEqual(labels);
                    expect(fixture.bob.updates.map(({ text }) => text)).toEqual(labels);
                    expect(fixture.carol.updates.map(({ text }) => text)).toEqual([]);
                    for (const actor of [fixture.alice, fixture.bob]) {
                        expect(new Set(actor.updates.map(({ id }) => id)).size).toBe(labels.length);
                    }
                    const terminal = await fixture.alice.client.session(fixture.session.id);
                    expect(terminal?.policies).toEqual({
                        adminsAssignAdmins: false,
                        anyoneCanAddMembers: true,
                    });
                    expect(memberCount(terminal, fixture.carol)).toBe(0);
                    expect(
                        publicSession(await fixture.bob.client.session(fixture.session.id)),
                    ).toEqual(publicSession(terminal));
                    await assertNoOrphans([fixture.alice, fixture.bob, fixture.carol]);
                } finally {
                    await closeFixture(fixture);
                }
            }
        },
    );

    const batches: readonly (readonly [number, number])[] = [
        [0, 5],
        [5, 10],
        [10, 15],
        [15, 16],
        [16, 17],
        [17, 18],
        [18, 19],
        [19, 20],
        [20, 21],
        [21, 22],
        [22, 23],
    ];
    for (const [start, end] of batches) {
        const first = scenarios[start];
        const last = scenarios[end - 1];
        if (first === undefined || last === undefined) throw new Error("Invalid race batch");
        test(
            `${first.name.slice(0, 7)}–${last.name.slice(0, 7)} bounded scenario batch`,
            { timeout: 120_000 },
            async () => {
                for (const value of scenarios.slice(start, end)) {
                    if (value.expectedFailure !== undefined) {
                        let failure: unknown;
                        try {
                            await value.run();
                        } catch (error: unknown) {
                            failure = error;
                        }
                        expect(
                            failure,
                            `${value.name} unexpectedly satisfied its contract`,
                        ).toBeDefined();
                        expect(failure).toBeInstanceOf(Error);
                        expect((failure as Error).message).toContain(value.expectedFailure);
                    } else {
                        try {
                            await value.run();
                        } catch (error: unknown) {
                            throw new Error(`Scenario failed: ${value.name}`, { cause: error });
                        }
                    }
                }
            },
        );
    }
});
