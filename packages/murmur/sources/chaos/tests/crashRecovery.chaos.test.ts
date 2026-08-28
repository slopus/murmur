import { createRootContext, type Context } from "@steve.kite/stdlib";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type {
    DeliveryFetch,
    DeliveryPublishOutcome,
    DeliveryTransport,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../../delivery/index.js";
import { HttpDeliveryTransport } from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import type { MurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurSession, MurmurUpdate } from "../../sessions/index.js";
import {
    ChaosCrashError,
    FaultInjectingDeliveryTransport,
    FaultInjectingMurmurStore,
    ManualVirtualClock,
    SeededChaosSchedule,
    settleChaos,
} from "../index.js";
import type {
    ChaosEffect,
    ChaosPoint,
    ChaosRule,
    ChaosSchedule,
    ChaosTraceEntry,
} from "../index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;
const CRASH_LADDER_SEED = 0x4352_4153;
const STORE_LIMIT = 1_001;
const SESSION_STATE_PREFIX = "murmur/session-states/";
const SESSION_INTENT_PREFIX = "murmur/session-intents/";
const OUTBOX_PREFIX = "murmur/session-outbox/";
const OUTBOX_ORDER_PREFIX = "murmur/session-outbox-order/";
const EPOCH_OUTBOX_PREFIX = "murmur/epoch-outboxes/";
const POST_COMMIT_OUTBOX_PREFIX = "murmur/post-commit-outboxes/";
const BOOTSTRAP_OUTBOX_PREFIX = "murmur/bootstrap-outboxes/";
const APPLICATION_UPDATE_PREFIX = "murmur/application-updates/";
const QUARANTINE_PREFIX = "murmur/session-quarantine/";
const PENDING_SESSION_PREFIX = "murmur/pending-sessions/";
const PENDING_MEMBERSHIP_CONTROL_PREFIX = "murmur/pending-membership-controls/";
const CURSOR_KEY = "murmur/delivery/cursor";
const IDENTITY_KEY = "murmur/identity/root";

type StoreCut = "S0" | "S1" | "S2" | "S3";
type SyncOrder = readonly ["alice", "bob"] | readonly ["bob", "alice"];

const STORE_CUTS: readonly StoreCut[] = ["S0", "S1", "S2", "S3"];
const SYNC_ORDERS: readonly SyncOrder[] = [
    ["alice", "bob"],
    ["bob", "alice"],
];
const CONTINUE: ChaosEffect = Object.freeze({ type: "continue" });

function seedLabel(seed: number): string {
    return `${seed >>> 0} (0x${(seed >>> 0).toString(16).padStart(8, "0")})`;
}

async function withSeed<Result>(seed: number, operation: () => Promise<Result>): Promise<Result> {
    try {
        return await operation();
    } catch (error: unknown) {
        throw new Error(`Chaos failure seed=${seedLabel(seed)}`, { cause: error });
    }
}

class ArmableSchedule implements ChaosSchedule {
    readonly #seed: number;
    #active: SeededChaosSchedule | undefined;
    readonly #faultTrace: ChaosTraceEntry[] = [];

    constructor(seed: number) {
        this.#seed = seed >>> 0;
    }

    get trace(): readonly ChaosTraceEntry[] {
        return [
            ...this.#faultTrace,
            ...(this.#active?.trace.filter((entry) => entry.ruleId !== undefined) ?? []),
        ];
    }

    arm(rules: readonly ChaosRule[]): void {
        if (this.#active !== undefined) throw new Error("Chaos schedule is already armed");
        this.#active = new SeededChaosSchedule(this.#seed, rules);
    }

    decide(point: ChaosPoint): ChaosEffect {
        return this.#active?.decide(point) ?? CONTINUE;
    }

    assertConsumed(): void {
        this.#active?.assertConsumed();
    }

    consume(): void {
        if (this.#active === undefined) throw new Error("Chaos schedule is not armed");
        this.#active.assertConsumed();
        this.#faultTrace.push(...this.#active.trace.filter((entry) => entry.ruleId !== undefined));
        this.#active = undefined;
    }
}

class DelayTrap {
    #entered: (() => void) | undefined;
    #wait: Promise<void> | undefined;

    block(): Promise<void> {
        if (this.#wait !== undefined) throw new Error("Chaos delay trap is already armed");
        let entered: (() => void) | undefined;
        const reached = new Promise<void>((resolve) => {
            entered = resolve;
        });
        this.#entered = entered;
        this.#wait = new Promise<void>(() => undefined);
        return reached;
    }

    async handle(): Promise<void> {
        const wait = this.#wait;
        if (wait === undefined) return;
        this.#wait = undefined;
        this.#entered?.();
        this.#entered = undefined;
        await wait;
    }
}

class ObservingTransport implements DeliveryTransport {
    readonly #delegate: DeliveryTransport;
    readonly publishAttempts: SignedDelivery[] = [];
    readonly accepted = new Map<string, string>();
    readonly reads: InboxPage[] = [];
    readonly acknowledgements: string[] = [];
    readonly deleteAccount?: NonNullable<DeliveryTransport["deleteAccount"]>;
    readonly deleteSession?: NonNullable<DeliveryTransport["deleteSession"]>;
    readonly mutateDeviceRoster?: NonNullable<DeliveryTransport["mutateDeviceRoster"]>;
    readonly readDeviceRoster?: NonNullable<DeliveryTransport["readDeviceRoster"]>;
    readonly stream?: NonNullable<DeliveryTransport["stream"]>;

    constructor(delegate: DeliveryTransport) {
        this.#delegate = delegate;
        if (delegate.deleteAccount !== undefined) {
            this.deleteAccount = (_ctx, delivery, signal) =>
                delegate.deleteAccount!(ctx, delivery, signal);
        }
        if (delegate.deleteSession !== undefined) {
            this.deleteSession = (_ctx, delivery, signal) =>
                delegate.deleteSession!(ctx, delivery, signal);
        }
        if (delegate.mutateDeviceRoster !== undefined) {
            this.mutateDeviceRoster = (_ctx, delivery, signal) =>
                delegate.mutateDeviceRoster!(ctx, delivery, signal);
        }
        if (delegate.readDeviceRoster !== undefined) {
            this.readDeviceRoster = (_ctx, accountKey, signal) =>
                delegate.readDeviceRoster!(ctx, accountKey, signal);
        }
        if (delegate.stream !== undefined) {
            this.stream = (_ctx, request, signal, hooks) =>
                delegate.stream!(ctx, request, signal, hooks);
        }
    }

    async publish(
        _ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryPublishOutcome> {
        this.publishAttempts.push({
            ...delivery,
            sender: delivery.sender.slice(),
            recipients: delivery.recipients.map((recipient) => recipient.slice()),
            ciphertext: delivery.ciphertext.slice(),
            signature: delivery.signature.slice(),
        });
        const outcome = await this.#delegate.publish(ctx, delivery, signal);
        this.accepted.set(delivery.id, outcome.eventId);
        return outcome;
    }

    async read(_ctx: Context, request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        const page = await this.#delegate.read(ctx, request, signal);
        this.reads.push(page);
        return page;
    }

    async acknowledge(
        _ctx: Context,
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }> {
        this.acknowledgements.push(request.through);
        return this.#delegate.acknowledge(ctx, request, signal);
    }
}

interface RecordedUpdate {
    readonly id: string;
    readonly text: string;
}

interface ChaosActor {
    readonly name: "alice" | "bob" | "carol";
    readonly delegate: MemoryMurmurStore;
    readonly storeSchedule: ArmableSchedule;
    readonly transportSchedule: ArmableSchedule;
    readonly delay: DelayTrap;
    readonly store: FaultInjectingMurmurStore;
    readonly observer: ObservingTransport;
    readonly transport: FaultInjectingDeliveryTransport;
    readonly updates: RecordedUpdate[];
    client: MurmurClient;
}

interface ChaosFixture {
    readonly seed: number;
    readonly clock: ManualVirtualClock;
    readonly relay: RelayService;
    readonly fetch: DeliveryFetch;
    readonly actors: ChaosActor[];
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "crash-recovery-chaos",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

async function createFixture(seed: number): Promise<ChaosFixture> {
    const clock = new ManualVirtualClock(NOW);
    const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, clock.now);
    return {
        seed,
        clock,
        relay,
        fetch: relayFetch(relay),
        actors: [],
    };
}

async function createActor(fixture: ChaosFixture, name: ChaosActor["name"]): Promise<ChaosActor> {
    const actorSeed =
        (fixture.seed ^ (name === "alice" ? 0xa11ce : name === "bob" ? 0xb0b : 0xca701)) >>> 0;
    const delegate = new MemoryMurmurStore();
    const storeSchedule = new ArmableSchedule(actorSeed);
    const transportSchedule = new ArmableSchedule(actorSeed ^ 0x7472_616e);
    const delay = new DelayTrap();
    const store = new FaultInjectingMurmurStore({
        actor: name,
        delegate,
        schedule: storeSchedule,
        delay: () => delay.handle(),
    });
    const observer = new ObservingTransport(
        new HttpDeliveryTransport("https://relay.test", { fetch: fixture.fetch }),
    );
    const transport = new FaultInjectingDeliveryTransport({
        actor: name,
        delegate: observer,
        schedule: transportSchedule,
        delay: () => delay.handle(),
        classifyDelivery: (delivery) => delivery.ciphertext[0],
    });
    const client = await MurmurClient.open(ctx, {
        store,
        transport,
        now: fixture.clock.now,
    });
    const actor: ChaosActor = {
        name,
        delegate,
        storeSchedule,
        transportSchedule,
        delay,
        store,
        observer,
        transport,
        updates: [],
        client,
    };
    fixture.actors.push(actor);
    return actor;
}

async function reopen(actor: ChaosActor, clock: ManualVirtualClock): Promise<void> {
    actor.client = await MurmurClient.open(ctx, {
        store: actor.store,
        transport: actor.transport,
        now: clock.now,
    });
}

async function closeFixture(fixture: ChaosFixture): Promise<void> {
    for (const actor of fixture.actors) {
        try {
            actor.client.close(ctx);
        } catch {
            // A deliberately abandoned operation can retain only the dead client instance.
        }
    }
    await fixture.relay.close();
}

function updateHook(actor: ChaosActor): (_ctx: Context, updates: readonly MurmurUpdate[]) => void {
    return (_ctx, updates) => {
        for (const update of updates) {
            actor.updates.push({ id: update.id, text: utf8Decode(update.bytes) });
        }
    };
}

async function synchronize(actor: ChaosActor): Promise<void> {
    await actor.client.synchronize(ctx, { waitMilliseconds: 0 }, { onUpdates: updateHook(actor) });
}

function normalizeSession(session: MurmurSession | undefined): unknown {
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

async function prefixSize(store: MurmurStore, prefix: string): Promise<number> {
    return (await store.scan(ctx, prefix, { limit: STORE_LIMIT })).size;
}

async function stableSnapshot(
    actors: readonly ChaosActor[],
    sessionId: Uint8Array,
): Promise<string> {
    const snapshots: unknown[] = [];
    for (const actor of actors) {
        snapshots.push({
            actor: actor.name,
            session: normalizeSession(await actor.client.session(ctx, sessionId)),
            issues: (await actor.client.issues(ctx)).map((issue) => ({
                id: issue.id,
                code: issue.code,
                operationId: issue.operationId ?? null,
            })),
            updates: actor.updates.map((update) => update.id),
            outboxes: await prefixSize(actor.delegate, OUTBOX_PREFIX),
            intents: await prefixSize(actor.delegate, SESSION_INTENT_PREFIX),
            applicationUpdates: await prefixSize(actor.delegate, APPLICATION_UPDATE_PREFIX),
        });
    }
    return JSON.stringify(snapshots);
}

async function settleSession(
    actorsByName: ReadonlyMap<ChaosActor["name"], ChaosActor>,
    sessionId: Uint8Array,
    order: readonly ChaosActor["name"][],
    maximumRounds: number = 20,
): Promise<void> {
    const actors = [...actorsByName.values()];
    await settleChaos({
        maximumRounds,
        act: async (round) => {
            const roundOrder = round % 2 === 1 ? order : [...order].reverse();
            for (const name of roundOrder) {
                const actor = actorsByName.get(name);
                if (actor !== undefined) await synchronize(actor);
            }
        },
        snapshot: () => stableSnapshot(actors, sessionId),
    });
}

async function createActivePair(fixture: ChaosFixture): Promise<{
    readonly alice: ChaosActor;
    readonly bob: ChaosActor;
    readonly session: MurmurSession;
}> {
    const alice = await createActor(fixture, "alice");
    const bob = await createActor(fixture, "bob");
    const session = await alice.client.createSession(ctx, {
        descriptor: utf8Encode("crash recovery"),
        members: [await bob.client.createKeyPackage(ctx)],
    });
    await synchronize(alice);
    await synchronize(bob);
    await bob.client.activateSession(ctx, session.id);
    await synchronize(bob);
    await synchronize(alice);
    alice.updates.length = 0;
    bob.updates.length = 0;
    return { alice, bob, session };
}

async function createActiveTriple(fixture: ChaosFixture): Promise<{
    readonly alice: ChaosActor;
    readonly bob: ChaosActor;
    readonly carol: ChaosActor;
    readonly session: MurmurSession;
}> {
    const alice = await createActor(fixture, "alice");
    const bob = await createActor(fixture, "bob");
    const carol = await createActor(fixture, "carol");
    const session = await alice.client.createSession(ctx, {
        descriptor: utf8Encode("crash recovery triple"),
        members: [await bob.client.createKeyPackage(ctx), await carol.client.createKeyPackage(ctx)],
    });
    await synchronize(alice);
    await synchronize(bob);
    await synchronize(carol);
    await bob.client.activateSession(ctx, session.id);
    await carol.client.activateSession(ctx, session.id);
    await synchronize(alice);
    await synchronize(bob);
    await synchronize(carol);
    alice.updates.length = 0;
    bob.updates.length = 0;
    carol.updates.length = 0;
    return { alice, bob, carol, session };
}

function operationCount(store: FaultInjectingMurmurStore, operation: string): number {
    return store.operationCounts.get(operation) ?? 0;
}

interface StoreCutTarget {
    readonly transactionOrdinal: number;
    readonly commitOrdinal: number;
    readonly mutationOperation: "transaction.set" | "transaction.delete";
    readonly mutationKey?: string;
    readonly mutationKeyPrefix?: string;
}

function storeCutRule(cut: StoreCut, target: StoreCutTarget): ChaosRule {
    const selector =
        cut === "S0"
            ? {
                  boundary: "store" as const,
                  operation: "transaction",
                  phase: "before" as const,
                  ordinal: target.transactionOrdinal,
              }
            : cut === "S1"
              ? {
                    boundary: "store" as const,
                    operation: target.mutationOperation,
                    phase: "after" as const,
                    ...(target.mutationKey === undefined ? {} : { key: target.mutationKey }),
                    ...(target.mutationKeyPrefix === undefined
                        ? {}
                        : { keyPrefix: target.mutationKeyPrefix }),
                }
              : cut === "S2"
                ? {
                      boundary: "store" as const,
                      operation: "transaction.commit",
                      phase: "before" as const,
                      ordinal: target.commitOrdinal,
                  }
                : {
                      boundary: "store" as const,
                      operation: "transaction",
                      phase: "after" as const,
                      ordinal: target.transactionOrdinal,
                  };
    return {
        id: `store-${cut}`,
        selector,
        effect:
            cut === "S3"
                ? { type: "delay", milliseconds: 1 }
                : { type: "crash", message: `injected ${cut} process crash` },
    };
}

async function executeStoreCut(
    actor: ChaosActor,
    cut: StoreCut,
    target: StoreCutTarget,
    operation: () => Promise<unknown>,
    propagates: boolean = true,
): Promise<void> {
    const reached = cut === "S3" ? actor.delay.block() : undefined;
    actor.storeSchedule.arm([storeCutRule(cut, target)]);
    const pending = operation();
    if (cut === "S3") {
        void pending.catch(() => undefined);
        await reached;
    } else if (propagates) {
        await expect(pending).rejects.toBeInstanceOf(ChaosCrashError);
    } else {
        await pending;
    }
    actor.storeSchedule.consume();
}

function immediateStoreTarget(
    actor: ChaosActor,
    mutationOperation: StoreCutTarget["mutationOperation"],
    mutationKey?: string,
    mutationKeyPrefix?: string,
): StoreCutTarget {
    return {
        transactionOrdinal: operationCount(actor.store, "transaction") + 1,
        commitOrdinal: operationCount(actor.store, "transaction.commit") + 1,
        mutationOperation,
        ...(mutationKey === undefined ? {} : { mutationKey }),
        ...(mutationKeyPrefix === undefined ? {} : { mutationKeyPrefix }),
    };
}

function offsetStoreTarget(
    actor: ChaosActor,
    offset: number,
    mutationOperation: StoreCutTarget["mutationOperation"],
    mutationKey?: string,
    mutationKeyPrefix?: string,
): StoreCutTarget {
    return {
        transactionOrdinal: operationCount(actor.store, "transaction") + offset,
        commitOrdinal: operationCount(actor.store, "transaction.commit") + offset,
        mutationOperation,
        ...(mutationKey === undefined ? {} : { mutationKey }),
        ...(mutationKeyPrefix === undefined ? {} : { mutationKeyPrefix }),
    };
}

async function assertStoreShape(store: MurmurStore): Promise<Record<string, number>> {
    const outboxes = await store.scan(ctx, OUTBOX_PREFIX, { limit: STORE_LIMIT });
    const outboxIds = new Set([...outboxes.keys()].map((key) => key.slice(OUTBOX_PREFIX.length)));
    const families = {
        order: await store.scan(ctx, OUTBOX_ORDER_PREFIX, { limit: STORE_LIMIT }),
        epoch: await store.scan(ctx, EPOCH_OUTBOX_PREFIX, { limit: STORE_LIMIT }),
        postCommit: await store.scan(ctx, POST_COMMIT_OUTBOX_PREFIX, { limit: STORE_LIMIT }),
        bootstrap: await store.scan(ctx, BOOTSTRAP_OUTBOX_PREFIX, { limit: STORE_LIMIT }),
        pending: await store.scan(ctx, PENDING_SESSION_PREFIX, { limit: STORE_LIMIT }),
        pendingControls: await store.scan(ctx, PENDING_MEMBERSHIP_CONTROL_PREFIX, {
            limit: STORE_LIMIT,
        }),
        states: await store.scan(ctx, SESSION_STATE_PREFIX, { limit: STORE_LIMIT }),
        intents: await store.scan(ctx, SESSION_INTENT_PREFIX, { limit: STORE_LIMIT }),
        issues: await store.scan(ctx, QUARANTINE_PREFIX, { limit: STORE_LIMIT }),
    };
    for (const key of families.order.keys()) {
        expect(outboxIds.has(key.slice(key.lastIndexOf("/") + 1))).toBe(true);
    }
    for (const key of families.epoch.keys()) {
        expect(outboxIds.has(key.slice(key.lastIndexOf("/") + 1))).toBe(true);
    }
    for (const key of families.postCommit.keys()) {
        const suffix = key.slice(POST_COMMIT_OUTBOX_PREFIX.length).split("/");
        expect(suffix).toHaveLength(2);
        expect(outboxIds.has(suffix[0]!)).toBe(true);
        expect(outboxIds.has(suffix[1]!)).toBe(true);
    }
    for (const key of families.bootstrap.keys()) {
        const suffix = key.slice(BOOTSTRAP_OUTBOX_PREFIX.length).split("/");
        expect(suffix).toHaveLength(2);
        expect(outboxIds.has(suffix[1]!)).toBe(true);
    }
    for (const key of families.pending.keys()) {
        expect(
            families.states.has(
                `${SESSION_STATE_PREFIX}${key.slice(PENDING_SESSION_PREFIX.length)}`,
            ),
        ).toBe(true);
    }
    for (const family of [outboxes, ...Object.values(families)]) {
        expect(family.size).toBeLessThan(STORE_LIMIT);
    }
    return {
        outboxes: outboxes.size,
        order: families.order.size,
        epoch: families.epoch.size,
        postCommit: families.postCommit.size,
        bootstrap: families.bootstrap.size,
        pending: families.pending.size,
        pendingControls: families.pendingControls.size,
        states: families.states.size,
        intents: families.intents.size,
        issues: families.issues.size,
    };
}

function assertMonotonic(values: readonly string[]): void {
    for (let index = 1; index < values.length; index += 1) {
        expect(values[index]! >= values[index - 1]!).toBe(true);
    }
}

function updatesWithText(actor: ChaosActor, text: string): readonly RecordedUpdate[] {
    return actor.updates.filter((update) => update.text === text);
}

describe("crash and transaction recovery chaos", () => {
    test("CR-01 identity bootstrap is atomic across S0-S3", { timeout: 120_000 }, async () => {
        await withSeed(0x4352_0100, async () => {
            for (const cut of STORE_CUTS) {
                const fixture = await createFixture(0x4352_0100 ^ STORE_CUTS.indexOf(cut));
                try {
                    const delegate = new MemoryMurmurStore();
                    const schedule = new ArmableSchedule(fixture.seed);
                    const delay = new DelayTrap();
                    const store = new FaultInjectingMurmurStore({
                        actor: "alice",
                        delegate,
                        schedule,
                        delay: () => delay.handle(),
                    });
                    const observer = new ObservingTransport(
                        new HttpDeliveryTransport("https://relay.test", { fetch: fixture.fetch }),
                    );
                    const transport = new FaultInjectingDeliveryTransport({
                        actor: "alice",
                        delegate: observer,
                        schedule: new ArmableSchedule(fixture.seed ^ 1),
                    });
                    const target: StoreCutTarget = {
                        transactionOrdinal: 1,
                        commitOrdinal: 1,
                        mutationOperation: "transaction.set",
                        mutationKey: IDENTITY_KEY,
                    };
                    const reached = cut === "S3" ? delay.block() : undefined;
                    schedule.arm([storeCutRule(cut, target)]);
                    const first = MurmurClient.open(ctx, {
                        store,
                        transport,
                        now: fixture.clock.now,
                    });
                    if (cut === "S3") {
                        void first.catch(() => undefined);
                        await reached;
                    } else {
                        await expect(first).rejects.toBeInstanceOf(ChaosCrashError);
                    }
                    schedule.consume();

                    const root = await delegate.get(ctx, IDENTITY_KEY);
                    expect(root !== undefined).toBe(cut === "S3");

                    let reopened = await MurmurClient.open(ctx, {
                        store,
                        transport,
                        now: fixture.clock.now,
                    });
                    const identity = reopened.identity;
                    reopened = await MurmurClient.open(ctx, {
                        store,
                        transport,
                        now: fixture.clock.now,
                    });
                    expect(reopened.identity).toEqual(identity);
                    expect((await delegate.scan(ctx, "murmur/identity/", { limit: 10 })).size).toBe(
                        1,
                    );
                    reopened.close(ctx);
                } finally {
                    await closeFixture(fixture);
                }
            }
        });
    });

    test(
        "CR-02 send epoch and outbox persistence recover atomically in both sync orders",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0200, async () => {
                for (const order of SYNC_ORDERS) {
                    for (const cut of STORE_CUTS) {
                        const seed =
                            0x4352_0200 ^
                            (SYNC_ORDERS.indexOf(order) << 8) ^
                            STORE_CUTS.indexOf(cut);
                        const fixture = await createFixture(seed);
                        try {
                            const { alice, bob, session } = await createActivePair(fixture);
                            const target = immediateStoreTarget(
                                alice,
                                "transaction.set",
                                `${SESSION_STATE_PREFIX}${encodeBase64Url(session.id)}`,
                            );
                            await executeStoreCut(alice, cut, target, () =>
                                alice.client.send(ctx, session.id, utf8Encode("m1")),
                            );
                            await reopen(alice, fixture.clock);
                            const actors = new Map<ChaosActor["name"], ChaosActor>([
                                ["alice", alice],
                                ["bob", bob],
                            ]);
                            await settleSession(actors, session.id, order);
                            expect(updatesWithText(bob, "m1")).toHaveLength(cut === "S3" ? 1 : 0);

                            await alice.client.send(ctx, session.id, utf8Encode("m2"));
                            await settleSession(actors, session.id, order);
                            expect(updatesWithText(bob, "m2")).toHaveLength(1);
                            expect(new Set(bob.updates.map((update) => update.id)).size).toBe(
                                bob.updates.length,
                            );
                            const shape = await assertStoreShape(alice.delegate);
                            expect(shape.outboxes).toBe(0);
                            expect(shape.order).toBe(0);
                            expect(shape.epoch).toBe(0);
                        } finally {
                            await closeFixture(fixture);
                        }
                    }
                }
            });
        },
    );

    test(
        "CR-03 accepted publish response loss retries one exact delivery",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0300, async () => {
                for (const order of SYNC_ORDERS) {
                    const fixture = await createFixture(0x4352_0300 ^ SYNC_ORDERS.indexOf(order));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        const deliveryId = await alice.client.send(
                            ctx,
                            session.id,
                            utf8Encode("m1"),
                        );
                        const reached = alice.delay.block();
                        alice.transportSchedule.arm([
                            {
                                id: "accepted-publish-response-gap",
                                selector: {
                                    actor: "alice",
                                    boundary: "transport",
                                    operation: "publish",
                                    phase: "after",
                                    deliveryId,
                                },
                                effect: { type: "delay", milliseconds: 1 },
                            },
                        ]);
                        const deadSync = alice.client.synchronize(ctx, { waitMilliseconds: 0 });
                        void deadSync.catch(() => undefined);
                        await reached;
                        alice.transportSchedule.consume();
                        expect(alice.observer.accepted.has(deliveryId)).toBe(true);
                        const acceptedEventId = alice.observer.accepted.get(deliveryId);

                        await reopen(alice, fixture.clock);
                        const actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                        ]);
                        await settleSession(actors, session.id, order);
                        expect(updatesWithText(bob, "m1")).toHaveLength(1);
                        expect(
                            alice.observer.publishAttempts.filter(
                                (delivery) => delivery.id === deliveryId,
                            ),
                        ).toHaveLength(2);
                        expect(alice.observer.accepted.get(deliveryId)).toBe(acceptedEventId);
                        expect((await assertStoreShape(alice.delegate)).outboxes).toBe(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-04 read visibility and durable-buffer gaps preserve one update and ack order",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0400, async () => {
                for (const variant of ["after-read", "after-buffer"] as const) {
                    for (const order of SYNC_ORDERS) {
                        const fixture = await createFixture(
                            0x4352_0400 ^
                                (variant === "after-read" ? 0 : 0x10) ^
                                SYNC_ORDERS.indexOf(order),
                        );
                        try {
                            const { alice, bob, session } = await createActivePair(fixture);
                            await alice.client.send(ctx, session.id, utf8Encode("read-gap"));
                            await synchronize(alice);
                            bob.updates.length = 0;
                            const cursorBefore = await bob.delegate.get(ctx, CURSOR_KEY);

                            if (variant === "after-read") {
                                const reached = bob.delay.block();
                                bob.transportSchedule.arm([
                                    {
                                        id: "read-response-visible",
                                        selector: {
                                            actor: "bob",
                                            boundary: "transport",
                                            operation: "read",
                                            phase: "after",
                                        },
                                        effect: { type: "delay", milliseconds: 1 },
                                    },
                                ]);
                                const deadSync = bob.client.synchronize(ctx, {
                                    waitMilliseconds: 0,
                                });
                                void deadSync.catch(() => undefined);
                                await reached;
                                bob.transportSchedule.consume();
                                expect(await bob.delegate.get(ctx, CURSOR_KEY)).toEqual(
                                    cursorBefore,
                                );
                            } else {
                                const target = offsetStoreTarget(
                                    bob,
                                    4,
                                    "transaction.set",
                                    undefined,
                                    APPLICATION_UPDATE_PREFIX,
                                );
                                await executeStoreCut(bob, "S3", target, () =>
                                    bob.client.synchronize(ctx, { waitMilliseconds: 0 }),
                                );
                                expect(
                                    await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX),
                                ).toBe(1);
                            }

                            await reopen(bob, fixture.clock);
                            const actors = new Map<ChaosActor["name"], ChaosActor>([
                                ["alice", alice],
                                ["bob", bob],
                            ]);
                            await settleSession(actors, session.id, order);
                            expect(updatesWithText(bob, "read-gap")).toHaveLength(1);
                            assertMonotonic(bob.observer.acknowledgements);
                            expect(await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX)).toBe(
                                0,
                            );
                        } finally {
                            await closeFixture(fixture);
                        }
                    }
                }
            });
        },
    );

    test(
        "CR-05 callback failure, process loss, drain cuts, and ack loss retain exact work",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0500, async () => {
                for (const cut of STORE_CUTS) {
                    const fixture = await createFixture(0x4352_0500 ^ STORE_CUTS.indexOf(cut));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        await alice.client.send(ctx, session.id, utf8Encode(`drain-${cut}`));
                        await synchronize(alice);
                        await bob.client.synchronize(ctx, { waitMilliseconds: 0 });
                        expect(await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX)).toBe(1);

                        let callbacks = 0;
                        const reached = cut === "S3" ? bob.delay.block() : undefined;
                        const draining = bob.client.synchronize(
                            ctx,
                            { waitMilliseconds: 0 },
                            {
                                onUpdates: (_ctx, updates) => {
                                    callbacks += 1;
                                    updateHook(bob)(_ctx, updates);
                                    const target = immediateStoreTarget(
                                        bob,
                                        "transaction.delete",
                                        undefined,
                                        APPLICATION_UPDATE_PREFIX,
                                    );
                                    bob.storeSchedule.arm([storeCutRule(cut, target)]);
                                },
                            },
                        );
                        if (cut === "S3") {
                            void draining.catch(() => undefined);
                            await reached;
                        } else {
                            await expect(draining).rejects.toBeInstanceOf(ChaosCrashError);
                        }
                        bob.storeSchedule.consume();
                        await reopen(bob, fixture.clock);
                        await synchronize(bob);
                        const delivered = updatesWithText(bob, `drain-${cut}`);
                        expect(new Set(delivered.map((item) => item.id)).size).toBe(1);
                        expect(delivered).toHaveLength(cut === "S3" ? 1 : 2);
                        expect(callbacks).toBe(1);
                        expect(await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX)).toBe(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }

                const fixture = await createFixture(0x4352_05f0);
                try {
                    const { alice, bob, session } = await createActivePair(fixture);
                    await alice.client.send(ctx, session.id, utf8Encode("callback-cases"));
                    await synchronize(alice);
                    await bob.client.synchronize(ctx, { waitMilliseconds: 0 });

                    await expect(
                        bob.client.synchronize(
                            ctx,
                            { waitMilliseconds: 0 },
                            {
                                onUpdates: (_ctx) => {
                                    throw new Error("callback rejected");
                                },
                            },
                        ),
                    ).rejects.toThrow("callback rejected");
                    expect(await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX)).toBe(1);

                    const ambiguousEffects: string[] = [];
                    await expect(
                        bob.client.synchronize(
                            ctx,
                            { waitMilliseconds: 0 },
                            {
                                onUpdates: (_ctx, updates) => {
                                    ambiguousEffects.push(updates[0]!.id);
                                    throw new Error("effect then throw");
                                },
                            },
                        ),
                    ).rejects.toThrow("effect then throw");
                    expect(await prefixSize(bob.delegate, APPLICATION_UPDATE_PREFIX)).toBe(1);

                    let entered: (() => void) | undefined;
                    const callbackEntered = new Promise<void>((resolve) => {
                        entered = resolve;
                    });
                    const deadSync = bob.client.synchronize(
                        ctx,
                        { waitMilliseconds: 0 },
                        {
                            onUpdates: async (_ctx) => {
                                entered?.();
                                await new Promise<void>(() => undefined);
                            },
                        },
                    );
                    void deadSync.catch(() => undefined);
                    await callbackEntered;
                    await reopen(bob, fixture.clock);
                    await synchronize(bob);
                    expect(updatesWithText(bob, "callback-cases")).toHaveLength(1);
                    expect(new Set(ambiguousEffects).size).toBe(1);

                    await alice.client.send(ctx, session.id, utf8Encode("ack-loss"));
                    await synchronize(alice);
                    const ackReached = bob.delay.block();
                    bob.transportSchedule.arm([
                        {
                            id: "accepted-ack-response-gap",
                            selector: {
                                actor: "bob",
                                boundary: "transport",
                                operation: "acknowledge",
                                phase: "after",
                            },
                            effect: { type: "delay", milliseconds: 1 },
                        },
                    ]);
                    const deadAck = bob.client.synchronize(ctx, { waitMilliseconds: 0 });
                    void deadAck.catch(() => undefined);
                    await ackReached;
                    bob.transportSchedule.consume();
                    await reopen(bob, fixture.clock);
                    await synchronize(bob);
                    expect(updatesWithText(bob, "ack-loss")).toHaveLength(1);
                    assertMonotonic(bob.observer.acknowledgements);
                } finally {
                    await closeFixture(fixture);
                }
            });
        },
    );

    test(
        "CR-06 returned Add intents survive restart and S0-S3 never tear intent state",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0600, async () => {
                for (const cut of STORE_CUTS) {
                    const fixture = await createFixture(0x4352_0600 ^ STORE_CUTS.indexOf(cut));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        const carol = await createActor(fixture, "carol");
                        const keyPackage = await carol.client.createKeyPackage(ctx);
                        const target = immediateStoreTarget(
                            alice,
                            "transaction.set",
                            undefined,
                            SESSION_INTENT_PREFIX,
                        );
                        await executeStoreCut(alice, cut, target, () =>
                            alice.client.addMember(ctx, session.id, keyPackage),
                        );
                        await reopen(alice, fixture.clock);
                        const actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                            ["carol", carol],
                        ]);
                        const order =
                            STORE_CUTS.indexOf(cut) % 2 === 0
                                ? (["bob", "alice", "carol"] as const)
                                : (["alice", "bob", "carol"] as const);
                        await settleSession(actors, session.id, order);
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            cut === "S3" ? 3 : 2,
                        );

                        if (cut !== "S3") {
                            await alice.client.addMember(
                                ctx,
                                session.id,
                                await carol.client.createKeyPackage(ctx),
                            );
                            await reopen(alice, fixture.clock);
                            await settleSession(actors, session.id, order);
                        }
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            3,
                        );
                        expect(await prefixSize(alice.delegate, SESSION_INTENT_PREFIX)).toBe(0);
                        expect(
                            (await alice.client.issues(ctx)).filter(
                                (issue) => issue.operationId !== undefined,
                            ),
                        ).toHaveLength(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-07 staged Commit transactions keep candidate and active state separated",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0700, async () => {
                for (const cut of STORE_CUTS) {
                    const fixture = await createFixture(0x4352_0700 ^ STORE_CUTS.indexOf(cut));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        const carol = await createActor(fixture, "carol");
                        await alice.client.addMember(
                            ctx,
                            session.id,
                            await carol.client.createKeyPackage(ctx),
                        );
                        const target = offsetStoreTarget(
                            alice,
                            4,
                            "transaction.set",
                            `${SESSION_STATE_PREFIX}${encodeBase64Url(session.id)}`,
                        );
                        await executeStoreCut(
                            alice,
                            cut,
                            target,
                            () => alice.client.synchronize(ctx, { waitMilliseconds: 0 }),
                            cut === "S3",
                        );
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            2,
                        );
                        await assertStoreShape(alice.delegate);
                        await reopen(alice, fixture.clock);
                        const actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                            ["carol", carol],
                        ]);
                        await settleSession(actors, session.id, ["bob", "alice", "carol"]);
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            3,
                        );
                        expect((await bob.client.session(ctx, session.id))?.members).toHaveLength(
                            3,
                        );
                        expect((await carol.client.session(ctx, session.id))?.status).toBe(
                            "pending",
                        );
                        const acceptedKinds = alice.observer.publishAttempts.map(
                            (delivery) => delivery.ciphertext[0],
                        );
                        expect(acceptedKinds.indexOf(3)).toBeLessThan(acceptedKinds.indexOf(1));
                        expect((await assertStoreShape(alice.delegate)).outboxes).toBe(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-08 Welcome remains unpublished across a crash before its parent Commit",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0800, async () => {
                for (const order of SYNC_ORDERS) {
                    const fixture = await createFixture(0x4352_0800 ^ SYNC_ORDERS.indexOf(order));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        const carol = await createActor(fixture, "carol");
                        const publicationOffset = alice.observer.publishAttempts.length;
                        await alice.client.addMember(
                            ctx,
                            session.id,
                            await carol.client.createKeyPackage(ctx),
                        );
                        const reached = alice.delay.block();
                        alice.transportSchedule.arm([
                            {
                                id: "before-parent-commit",
                                selector: {
                                    actor: "alice",
                                    boundary: "transport",
                                    operation: "publish",
                                    phase: "before",
                                    deliveryKind: 3,
                                },
                                effect: { type: "delay", milliseconds: 1 },
                            },
                        ]);
                        const deadSync = alice.client.synchronize(ctx, { waitMilliseconds: 0 });
                        void deadSync.catch(() => undefined);
                        await reached;
                        alice.transportSchedule.consume();
                        expect(
                            alice.observer.publishAttempts
                                .slice(publicationOffset)
                                .some((delivery) => delivery.ciphertext[0] === 1),
                        ).toBe(false);
                        await synchronize(carol);
                        expect(await carol.client.session(ctx, session.id)).toBeUndefined();
                        expect(carol.updates).toHaveLength(0);

                        await reopen(alice, fixture.clock);
                        const actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                            ["carol", carol],
                        ]);
                        await settleSession(actors, session.id, [...order, "carol"]);
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            3,
                        );
                        expect((await carol.client.session(ctx, session.id))?.status).toBe(
                            "pending",
                        );
                        await carol.client.activateSession(ctx, session.id);
                        await synchronize(carol);
                        expect(carol.updates).toHaveLength(0);
                        const attemptedKinds = alice.observer.publishAttempts
                            .slice(publicationOffset)
                            .map((delivery) => delivery.ciphertext[0]);
                        expect(attemptedKinds.indexOf(3)).toBeLessThan(attemptedKinds.indexOf(1));
                        expect((await assertStoreShape(alice.delegate)).bootstrap).toBe(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-09 accepted Commit is adopted only from the local relay echo after reopen",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0900, async () => {
                const fixture = await createFixture(0x4352_0900);
                try {
                    const { alice, bob, session } = await createActivePair(fixture);
                    const carol = await createActor(fixture, "carol");
                    await alice.client.addMember(
                        ctx,
                        session.id,
                        await carol.client.createKeyPackage(ctx),
                    );
                    const reached = alice.delay.block();
                    alice.transportSchedule.arm([
                        {
                            id: "accepted-commit-response-gap",
                            selector: {
                                actor: "alice",
                                boundary: "transport",
                                operation: "publish",
                                phase: "after",
                                deliveryKind: 3,
                            },
                            effect: { type: "delay", milliseconds: 1 },
                        },
                    ]);
                    const deadSync = alice.client.synchronize(ctx, { waitMilliseconds: 0 });
                    void deadSync.catch(() => undefined);
                    await reached;
                    alice.transportSchedule.consume();
                    expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(2);
                    expect(await prefixSize(alice.delegate, OUTBOX_PREFIX)).toBeGreaterThan(0);

                    await reopen(alice, fixture.clock);
                    expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(2);
                    const actors = new Map<ChaosActor["name"], ChaosActor>([
                        ["alice", alice],
                        ["bob", bob],
                        ["carol", carol],
                    ]);
                    await settleSession(actors, session.id, ["bob", "alice", "carol"]);
                    expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(3);
                    expect((await bob.client.session(ctx, session.id))?.members).toHaveLength(3);
                    expect((await carol.client.session(ctx, session.id))?.members).toHaveLength(3);
                    expect((await assertStoreShape(alice.delegate)).outboxes).toBe(0);
                } finally {
                    await closeFixture(fixture);
                }
            });
        },
    );

    test(
        "CR-10 removal adoption cuts exclude the removed member and reject post-remove traffic",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0a00, async () => {
                for (const cut of STORE_CUTS) {
                    const fixture = await createFixture(0x4352_0a00 ^ STORE_CUTS.indexOf(cut));
                    try {
                        const { alice, bob, session } = await createActivePair(fixture);
                        await alice.client.removeMember(ctx, session.id, bob.client.identity);
                        const publishReached = alice.delay.block();
                        alice.transportSchedule.arm([
                            {
                                id: "commit-accepted-before-adoption",
                                selector: {
                                    actor: "alice",
                                    boundary: "transport",
                                    operation: "publish",
                                    phase: "after",
                                    deliveryKind: 3,
                                },
                                effect: { type: "delay", milliseconds: 1 },
                            },
                        ]);
                        const deadPublish = alice.client.synchronize(ctx, { waitMilliseconds: 0 });
                        void deadPublish.catch(() => undefined);
                        await publishReached;
                        alice.transportSchedule.consume();
                        await reopen(alice, fixture.clock);

                        await bob.client.send(ctx, session.id, utf8Encode("removed-prior"));
                        await synchronize(bob);
                        const target = offsetStoreTarget(
                            alice,
                            3,
                            "transaction.set",
                            `${SESSION_STATE_PREFIX}${encodeBase64Url(session.id)}`,
                        );
                        await executeStoreCut(alice, cut, target, () =>
                            alice.client.synchronize(ctx, { waitMilliseconds: 0 }),
                        );
                        await reopen(alice, fixture.clock);
                        const actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                        ]);
                        await settleSession(actors, session.id, ["alice", "bob"]);
                        expect((await alice.client.session(ctx, session.id))?.members).toEqual([
                            alice.client.identity,
                        ]);
                        expect(await bob.client.session(ctx, session.id)).toBeUndefined();
                        expect(updatesWithText(alice, "removed-prior")).toHaveLength(0);

                        await alice.client.send(ctx, session.id, utf8Encode("new-epoch"));
                        await settleSession(actors, session.id, ["alice", "bob"]);
                        expect(updatesWithText(bob, "new-epoch")).toHaveLength(0);
                        await expect(
                            bob.client.removeMember(ctx, session.id, alice.client.identity),
                        ).rejects.toThrow("Unknown active session");
                        expect((await assertStoreShape(alice.delegate)).outboxes).toBe(0);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-11 issue terminalization survives S0-S3 and deliberate re-add succeeds",
        { timeout: 120_000 },
        async () => {
            await withSeed(0x4352_0b00, async () => {
                for (const cut of STORE_CUTS) {
                    const fixture = await createFixture(0x4352_0b00 ^ STORE_CUTS.indexOf(cut));
                    try {
                        const { alice, bob, carol, session } = await createActiveTriple(fixture);
                        let actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                            ["carol", carol],
                        ]);
                        await alice.client.grantAdmin(ctx, session.id, bob.client.identity);
                        await synchronize(alice);
                        await synchronize(alice);
                        await synchronize(bob);
                        await synchronize(carol);
                        expect((await bob.client.session(ctx, session.id))?.admins).toContainEqual(
                            bob.client.identity,
                        );

                        await bob.client.removeMember(ctx, session.id, carol.client.identity);
                        await synchronize(bob);
                        await alice.client.addMember(
                            ctx,
                            session.id,
                            await carol.client.createKeyPackage(ctx),
                        );
                        const target = offsetStoreTarget(
                            alice,
                            6,
                            "transaction.set",
                            undefined,
                            QUARANTINE_PREFIX,
                        );
                        await executeStoreCut(
                            alice,
                            cut,
                            target,
                            () => alice.client.synchronize(ctx, { waitMilliseconds: 0 }),
                            false,
                        );
                        await reopen(alice, fixture.clock);
                        actors = new Map<ChaosActor["name"], ChaosActor>([
                            ["alice", alice],
                            ["bob", bob],
                            ["carol", carol],
                        ]);
                        await settleSession(actors, session.id, ["bob", "alice", "carol"]);
                        const issues = (await alice.client.issues(ctx)).filter(
                            (issue) => issue.code === "add_intent_removal_generation_advanced",
                        );
                        expect(issues).toHaveLength(1);
                        expect(issues[0]!.operationId).toBeDefined();
                        expect(await prefixSize(alice.delegate, SESSION_INTENT_PREFIX)).toBe(0);
                        expect(await carol.client.session(ctx, session.id)).toBeUndefined();

                        await alice.client.addMember(
                            ctx,
                            session.id,
                            await carol.client.createKeyPackage(ctx),
                        );
                        await settleSession(actors, session.id, ["alice", "bob", "carol"]);
                        expect((await alice.client.session(ctx, session.id))?.members).toHaveLength(
                            3,
                        );
                        expect((await assertStoreShape(alice.delegate)).issues).toBe(1);
                    } finally {
                        await closeFixture(fixture);
                    }
                }
            });
        },
    );

    test(
        "CR-12 fixed 25-crash ladder replays and converges exactly once",
        { timeout: 120_000 },
        async () => {
            const run = async (): Promise<{
                readonly trace: readonly string[];
                readonly aliceUpdates: readonly string[];
                readonly bobUpdates: readonly string[];
                readonly policies: MurmurSession["policies"];
                readonly shape: Record<string, number>;
            }> => {
                const fixture = await createFixture(CRASH_LADDER_SEED);
                try {
                    const { alice, bob, session } = await createActivePair(fixture);
                    const labels = Array.from({ length: 10 }, (_, index) => `ladder-${index}`);
                    for (let crash = 0; crash < 25; crash += 1) {
                        if (crash < labels.length) {
                            await alice.client.send(ctx, session.id, utf8Encode(labels[crash]!));
                        }
                        if (crash === labels.length) {
                            await alice.client.setPolicies(ctx, session.id, {
                                adminsAssignAdmins: false,
                                anyoneCanAddMembers: true,
                            });
                        }
                        const actor = crash % 2 === 0 ? alice : bob;
                        const target = immediateStoreTarget(
                            actor,
                            "transaction.set",
                            undefined,
                            "murmur/",
                        );
                        await executeStoreCut(actor, "S0", target, () =>
                            actor.client.synchronize(ctx, { waitMilliseconds: 0 }),
                        );
                        await reopen(actor, fixture.clock);
                    }
                    const actors = new Map<ChaosActor["name"], ChaosActor>([
                        ["alice", alice],
                        ["bob", bob],
                    ]);
                    await settleSession(actors, session.id, ["bob", "alice"], 40);
                    expect(
                        bob.updates
                            .map((update) => update.text)
                            .filter((text) => text.startsWith("ladder-")),
                    ).toEqual(labels);
                    expect(
                        alice.updates
                            .map((update) => update.text)
                            .filter((text) => text.startsWith("ladder-")),
                    ).toEqual(labels);
                    const aliceSession = (await alice.client.session(ctx, session.id))!;
                    const bobSession = (await bob.client.session(ctx, session.id))!;
                    expect(normalizeSession(bobSession)).toEqual(normalizeSession(aliceSession));
                    expect(aliceSession.policies.anyoneCanAddMembers).toBe(true);
                    const shape = await assertStoreShape(alice.delegate);
                    const trace = [...alice.storeSchedule.trace, ...bob.storeSchedule.trace]
                        .sort(
                            (left, right) =>
                                left.index - right.index || left.actor.localeCompare(right.actor),
                        )
                        .map(
                            (entry) =>
                                `${entry.actor}:${entry.boundary}:${entry.operation}:${entry.phase}:${entry.ordinal}:${entry.ruleId}`,
                        );
                    expect(trace).toHaveLength(25);
                    return {
                        trace,
                        aliceUpdates: alice.updates.map((update) => update.id),
                        bobUpdates: bob.updates.map((update) => update.id),
                        policies: aliceSession.policies,
                        shape,
                    };
                } finally {
                    await closeFixture(fixture);
                }
            };

            await withSeed(CRASH_LADDER_SEED, async () => {
                const first = await run();
                const second = await run();
                expect(second.trace).toEqual(first.trace);
                expect(second.policies).toEqual(first.policies);
                expect(second.shape).toEqual(first.shape);
                expect(second.aliceUpdates).toHaveLength(first.aliceUpdates.length);
                expect(second.bobUpdates).toHaveLength(first.bobUpdates.length);
            });
        },
    );
});
