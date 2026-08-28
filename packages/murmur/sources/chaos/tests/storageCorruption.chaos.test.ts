import { createRootContext, type Context } from "@steve.kite/stdlib";
import { sha256 } from "@noble/hashes/sha2";
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
import {
    MAXIMUM_STORE_SCAN_ITEMS,
    MemoryMurmurStore,
    type MurmurStore,
    type StoreScanOptions,
} from "../../storage/index.js";
import { MurmurClient, type MurmurUpdate } from "../../sessions/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";
import {
    FaultInjectingMurmurStore,
    SeededChaosSchedule,
    SeededRandom,
    settleChaos,
} from "../index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;
const IDENTITY_KEY = "murmur/identity/root";
const SESSION_STATE_PREFIX = "murmur/session-states/";
const OUTBOX_PREFIX = "murmur/session-outbox/";
const OUTBOX_ORDER_PREFIX = "murmur/session-outbox-order/";
const APPLICATION_UPDATE_PREFIX = "murmur/application-updates/";
const DELIVERY_CURSOR_KEY = "murmur/delivery/cursor";
const DELIVERY_STATE_KEYS = ["murmur/delivery/cursor", "murmur/delivery/continuity"] as const;
const DRAIN_PREFIX = "murmur/chaos/drained/";
const ACK_KEY = "murmur/chaos/ack";
const NORMAL_SCAN_LIMIT = 256;
const CAMPAIGN_FIRST_SEED = 0x5354_4f52;
const CAMPAIGN_LAST_SEED = 0x5354_4f7a;

interface MutationTrace {
    readonly key: string;
    readonly digest: string;
    readonly length: number;
    readonly operator: "append" | "delete" | "flip" | "replace" | "truncate";
    readonly offset?: number;
}

interface RecordFixture {
    readonly family: string;
    readonly key: string;
    readonly bytes: Uint8Array;
}

interface CapacityPolicy {
    readonly maximumKeys?: number;
    readonly maximumBytes?: number;
    readonly failPrefix?: string;
    readonly failWriteOrdinals?: readonly number[];
}

const RECORD_FIXTURES: readonly RecordFixture[] = Object.freeze([
    record("identity", IDENTITY_KEY),
    record("active-epoch", `${SESSION_STATE_PREFIX}active`),
    record("staged-epoch", `${OUTBOX_PREFIX}staged-commit`),
    record("outbox-index", `${OUTBOX_ORDER_PREFIX}0001/delivery`),
    record("intent", "murmur/session-intents/add-member"),
    record("welcome", "murmur/pending-sessions/welcome"),
    record("inbox", `${APPLICATION_UPDATE_PREFIX}event`),
    record("issue", "murmur/session-quarantine/issue"),
    record("key-package", "murmur/key-packages/reference"),
    record("key-package-expiry", "murmur/key-package-expiries/expiry/reference"),
    record("account-roster", "murmur/accounts/v1/own-roster"),
    record("account-job", "murmur/accounts/v1/convergence/session/device"),
]);

const BOUNDED_PREFIXES = Object.freeze([
    SESSION_STATE_PREFIX,
    "murmur/session-intents/",
    OUTBOX_PREFIX,
    OUTBOX_ORDER_PREFIX,
    "murmur/pending-sessions/",
    "murmur/pending-membership-controls/",
    APPLICATION_UPDATE_PREFIX,
    "murmur/session-quarantine/",
    "murmur/key-packages/",
    "murmur/accounts/v1/convergence/",
]);

function record(family: string, key: string): RecordFixture {
    return {
        family,
        key,
        bytes: utf8Encode(JSON.stringify({ version: 1, family, generation: 1 })),
    };
}

function digest(bytes: Uint8Array): string {
    return encodeBase64Url(sha256(bytes));
}

function capacityError(message: string): Error {
    return new Error(`Injected storage capacity failure: ${message}`);
}

/** Exact-key mutation fixture used only between client process lifetimes. */
class InspectableStoreFixture implements MurmurStore {
    readonly #delegate: MemoryMurmurStore;
    readonly #preimages = new Map<string, Uint8Array>();
    readonly #trace: MutationTrace[] = [];
    #openClients = 0;

    constructor(delegate: MemoryMurmurStore = new MemoryMurmurStore()) {
        this.#delegate = delegate;
    }

    get trace(): readonly MutationTrace[] {
        return this.#trace.map((entry) => Object.freeze({ ...entry }));
    }

    clientOpened(): void {
        this.#openClients += 1;
    }

    clientClosed(): void {
        if (this.#openClients < 1) throw new Error("No inspectable-store client is open");
        this.#openClients -= 1;
    }

    async get(ctx: Context, key: string): Promise<Uint8Array | undefined> {
        return this.#delegate.get(ctx, key);
    }

    async set(ctx: Context, key: string, value: Uint8Array): Promise<void> {
        await this.#delegate.set(ctx, key, value);
    }

    async delete(ctx: Context, key: string): Promise<void> {
        await this.#delegate.delete(ctx, key);
    }

    async list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.list(ctx, prefix);
    }

    async scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.scan(ctx, prefix, options);
    }

    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        return this.#delegate.tx(ctx, operation);
    }

    async snapshotExact(
        key: string,
    ): Promise<{ readonly digest: string; readonly length: number }> {
        this.#assertMutationAllowed(key);
        const bytes = await this.#required(key);
        try {
            if (!this.#preimages.has(key)) this.#preimages.set(key, bytes.slice());
            return Object.freeze({ digest: digest(bytes), length: bytes.length });
        } finally {
            zeroBytes(bytes);
        }
    }

    async deleteExact(key: string): Promise<void> {
        const before = await this.#beforeMutation(key, "delete");
        await this.#delegate.delete(ctx, key);
        this.#trace.push(before);
    }

    async replaceExact(key: string, value: Uint8Array): Promise<void> {
        const before = await this.#beforeMutation(key, "replace");
        await this.#delegate.set(ctx, key, value);
        this.#trace.push(before);
    }

    async flipExact(key: string, offset: number, xor: number = 1): Promise<void> {
        const bytes = await this.#requiredForMutation(key);
        try {
            if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) {
                throw new Error("Exact corruption offset is outside the selected value");
            }
            if (!Number.isSafeInteger(xor) || xor < 1 || xor > 255) {
                throw new Error("Exact corruption xor must be between 1 and 255");
            }
            const before = this.#metadata(key, bytes, "flip", offset);
            bytes[offset] = bytes[offset]! ^ xor;
            await this.#delegate.set(ctx, key, bytes);
            this.#trace.push(before);
        } finally {
            zeroBytes(bytes);
        }
    }

    async truncateExact(key: string, length: number): Promise<void> {
        const bytes = await this.#requiredForMutation(key);
        try {
            if (!Number.isSafeInteger(length) || length < 0 || length >= bytes.length) {
                throw new Error("Exact truncation must shorten the selected value");
            }
            const before = this.#metadata(key, bytes, "truncate", length);
            await this.#delegate.set(ctx, key, bytes.slice(0, length));
            this.#trace.push(before);
        } finally {
            zeroBytes(bytes);
        }
    }

    async appendExact(key: string, byte: number = 0): Promise<void> {
        const bytes = await this.#requiredForMutation(key);
        try {
            if (!Number.isSafeInteger(byte) || byte < 0 || byte > 255) {
                throw new Error("Exact append byte must be between 0 and 255");
            }
            const before = this.#metadata(key, bytes, "append", bytes.length);
            const appended = new Uint8Array(bytes.length + 1);
            appended.set(bytes);
            appended[bytes.length] = byte;
            await this.#delegate.set(ctx, key, appended);
            zeroBytes(appended);
            this.#trace.push(before);
        } finally {
            zeroBytes(bytes);
        }
    }

    async restoreExact(key: string): Promise<void> {
        this.#assertMutationAllowed(key);
        const preimage = this.#preimages.get(key);
        if (preimage === undefined) throw new Error("No exact-key pre-corruption copy exists");
        await this.#delegate.set(ctx, key, preimage);
    }

    async #beforeMutation(
        key: string,
        operator: MutationTrace["operator"],
    ): Promise<MutationTrace> {
        const bytes = await this.#requiredForMutation(key);
        try {
            return this.#metadata(key, bytes, operator);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #requiredForMutation(key: string): Promise<Uint8Array> {
        this.#assertMutationAllowed(key);
        const bytes = await this.#required(key);
        if (!this.#preimages.has(key)) this.#preimages.set(key, bytes.slice());
        return bytes;
    }

    async #required(key: string): Promise<Uint8Array> {
        const bytes = await this.#delegate.get(ctx, key);
        if (bytes === undefined) throw new Error(`Exact corruption target does not exist: ${key}`);
        return bytes;
    }

    #metadata(
        key: string,
        bytes: Uint8Array,
        operator: MutationTrace["operator"],
        offset?: number,
    ): MutationTrace {
        return Object.freeze({
            key,
            digest: digest(bytes),
            length: bytes.length,
            operator,
            ...(offset === undefined ? {} : { offset }),
        });
    }

    #assertMutationAllowed(key: string): void {
        if (
            key.length < 1 ||
            key.endsWith("/") ||
            key.includes("*") ||
            key.includes("?") ||
            key.includes("[")
        ) {
            throw new Error("Inspectable corruption requires one exact store key");
        }
        if (this.#openClients !== 0) {
            throw new Error("Inspectable corruption requires every store client to be closed");
        }
    }
}

/** Capacity delegate that preserves transaction rollback and never evicts. */
class CapacityMurmurStore implements MurmurStore {
    readonly #delegate: MurmurStore;
    #policy: CapacityPolicy;
    #writeOrdinal = 0;
    #enabled = true;

    constructor(delegate: MurmurStore, policy: CapacityPolicy) {
        this.#delegate = delegate;
        this.#policy = policy;
    }

    get writeOrdinal(): number {
        return this.#writeOrdinal;
    }

    constrain(policy: CapacityPolicy): void {
        this.#policy = policy;
        this.#writeOrdinal = 0;
        this.#enabled = true;
    }

    restoreCapacity(): void {
        this.#enabled = false;
    }

    async get(ctx: Context, key: string): Promise<Uint8Array | undefined> {
        return this.#delegate.get(ctx, key);
    }

    async set(ctx: Context, key: string, value: Uint8Array): Promise<void> {
        await this.#delegate.tx(ctx, async (transaction) => {
            await this.#beforeSet(transaction, key, value);
            await this.#delegate.set(transaction, key, value);
        });
    }

    async delete(ctx: Context, key: string): Promise<void> {
        await this.#delegate.delete(ctx, key);
    }

    async list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.list(ctx, prefix);
    }

    async scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.scan(ctx, prefix, options);
    }

    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        return this.#delegate.tx(ctx, operation);
    }

    async #beforeSet(transaction: Context, key: string, value: Uint8Array): Promise<void> {
        this.#writeOrdinal += 1;
        if (!this.#enabled) return;
        if (this.#policy.failWriteOrdinals?.includes(this.#writeOrdinal) === true) {
            throw capacityError(`write ${this.#writeOrdinal}`);
        }
        if (this.#policy.failPrefix !== undefined && key.startsWith(this.#policy.failPrefix)) {
            throw capacityError(`prefix ${this.#policy.failPrefix}`);
        }
        if (this.#policy.maximumKeys === undefined && this.#policy.maximumBytes === undefined) {
            return;
        }

        const values = await this.#delegate.scan(transaction, "", {
            limit: MAXIMUM_STORE_SCAN_ITEMS,
        });
        try {
            const existing = values.get(key);
            const keys = values.size + (existing === undefined ? 1 : 0);
            let bytes = value.length;
            for (const [entryKey, entryValue] of values) {
                if (entryKey !== key) bytes += entryValue.length;
            }
            if (this.#policy.maximumKeys !== undefined && keys > this.#policy.maximumKeys) {
                throw capacityError(`maximum key count ${this.#policy.maximumKeys}`);
            }
            if (this.#policy.maximumBytes !== undefined && bytes > this.#policy.maximumBytes) {
                throw capacityError(`maximum aggregate bytes ${this.#policy.maximumBytes}`);
            }
        } finally {
            for (const bytes of values.values()) zeroBytes(bytes);
        }
    }
}

class OfflineTransport implements DeliveryTransport {
    async publish(_ctx: Context, _delivery: SignedDelivery): Promise<DeliveryPublishOutcome> {
        throw new Error("Offline test transport does not publish");
    }

    async read(_ctx: Context, _request: SignedInboxRead): Promise<InboxPage> {
        return {
            deliveries: [],
            head: null,
            acknowledgedThrough: null,
            exhausted: true,
        };
    }

    async acknowledge(
        _ctx: Context,
        _request: SignedInboxAck,
    ): Promise<{ readonly removed: number }> {
        return { removed: 0 };
    }
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "storage-corruption-chaos",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

async function relayClient(relay: RelayService, store: MurmurStore): Promise<MurmurClient> {
    return MurmurClient.open(ctx, {
        transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) }),
        store,
        now: () => NOW,
    });
}

async function activate(client: MurmurClient, sessionId: Uint8Array): Promise<void> {
    await client.activateSession(ctx, sessionId);
}

async function consume(client: MurmurClient, received: string[]): Promise<number> {
    let count = 0;
    await client.synchronize(
        ctx,
        { waitMilliseconds: 0 },
        {
            onUpdates: async (_ctx, updates: readonly MurmurUpdate[]) => {
                for (const update of updates) received.push(utf8Decode(update.bytes));
                count += updates.length;
            },
        },
    );
    return count;
}

async function setRecords(
    store: MurmurStore,
    records: readonly Pick<RecordFixture, "key" | "bytes">[],
): Promise<void> {
    await store.tx(ctx, async (transaction) => {
        for (const fixture of records) await store.set(transaction, fixture.key, fixture.bytes);
    });
}

async function scanKeys(
    store: MurmurStore,
    prefix: string,
    limit: number,
): Promise<readonly string[]> {
    const keys: string[] = [];
    let after: string | undefined;
    for (;;) {
        const page = await store.scan(ctx, prefix, {
            ...(after === undefined ? {} : { after }),
            limit,
        });
        for (const [key, value] of page) {
            keys.push(key);
            after = key;
            zeroBytes(value);
        }
        if (page.size < limit) return keys;
    }
}

async function cloneMemoryStore(source: MurmurStore): Promise<MemoryMurmurStore> {
    const target = new MemoryMurmurStore();
    let after: string | undefined;
    for (;;) {
        const page = await source.scan(ctx, "", {
            ...(after === undefined ? {} : { after }),
            limit: NORMAL_SCAN_LIMIT,
        });
        try {
            await target.tx(ctx, async (transaction) => {
                for (const [key, value] of page) {
                    after = key;
                    await target.set(transaction, key, value);
                }
            });
        } finally {
            for (const value of page.values()) zeroBytes(value);
        }
        if (page.size < NORMAL_SCAN_LIMIT) return target;
    }
}

async function copyDeliveryProgress(source: MurmurStore, target: MurmurStore): Promise<void> {
    for (const key of DELIVERY_STATE_KEYS) {
        const value = await source.get(ctx, key);
        try {
            if (value === undefined) await target.delete(ctx, key);
            else await target.set(ctx, key, value);
        } finally {
            if (value !== undefined) zeroBytes(value);
        }
    }
}

async function storeFingerprint(store: MurmurStore): Promise<string> {
    const values = await store.scan(ctx, "", { limit: MAXIMUM_STORE_SCAN_ITEMS });
    try {
        return JSON.stringify(
            [...values].map(([key, value]) => ({
                key,
                digest: digest(value),
                length: value.length,
            })),
        );
    } finally {
        for (const value of values.values()) zeroBytes(value);
    }
}

async function requiredText(store: MurmurStore, key: string): Promise<string> {
    const bytes = await store.get(ctx, key);
    if (bytes === undefined) throw new Error(`Required store key is missing: ${key}`);
    try {
        return utf8Decode(bytes);
    } finally {
        zeroBytes(bytes);
    }
}

async function prefixCount(store: MurmurStore, prefix: string): Promise<number> {
    const values = await store.scan(ctx, prefix, { limit: MAXIMUM_STORE_SCAN_ITEMS });
    try {
        return values.size;
    } finally {
        for (const value of values.values()) zeroBytes(value);
    }
}

interface LiveIntentCapacityResult {
    readonly seed: number;
    readonly failedWriteOrdinal: number;
    readonly observedWrites: number;
    readonly atomicRollback: boolean;
    readonly partialIntents: number;
    readonly partialOutboxes: number;
    readonly recoveredMembers: number;
}

async function runLiveIntentCapacity(
    seed: number,
    failedWriteOrdinal: number = 0,
): Promise<LiveIntentCapacityResult> {
    const label = seed.toString(16).padStart(8, "0");
    const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
    const aliceDelegate = new MemoryMurmurStore();
    const constrained = new CapacityMurmurStore(aliceDelegate, {});
    const bobStore = new MemoryMurmurStore();
    const carolStore = new MemoryMurmurStore();
    const alice = await relayClient(relay, constrained);
    const bob = await relayClient(relay, bobStore);
    const carol = await relayClient(relay, carolStore);
    try {
        const session = await alice.createSession(ctx, {
            descriptor: utf8Encode(`ST-02L ${label}`),
            members: [await bob.createKeyPackage(ctx)],
        });
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.activateSession(ctx, session.id);
        for (let round = 0; round < 4; round += 1) {
            if ((await prefixCount(aliceDelegate, OUTBOX_PREFIX)) === 0) break;
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
        }
        expect(await prefixCount(aliceDelegate, OUTBOX_PREFIX)).toBe(0);
        const carolKeyPackage = await carol.createKeyPackage(ctx);

        const before = await storeFingerprint(aliceDelegate);
        constrained.constrain(
            failedWriteOrdinal === 0 ? {} : { failWriteOrdinals: [failedWriteOrdinal] },
        );
        if (failedWriteOrdinal === 0) {
            await alice.addMember(ctx, session.id, carolKeyPackage);
            return Object.freeze({
                seed,
                failedWriteOrdinal,
                observedWrites: constrained.writeOrdinal,
                atomicRollback: true,
                partialIntents: 0,
                partialOutboxes: 0,
                recoveredMembers: 0,
            });
        }

        await expect(alice.addMember(ctx, session.id, carolKeyPackage)).rejects.toThrow(
            `write ${failedWriteOrdinal}`,
        );
        const observedWrites = constrained.writeOrdinal;
        const after = await storeFingerprint(aliceDelegate);
        const partialIntents = await prefixCount(aliceDelegate, "murmur/session-intents/");
        const partialOutboxes = await prefixCount(aliceDelegate, OUTBOX_PREFIX);
        expect(await alice.session(ctx, session.id)).toMatchObject({ status: "active" });

        constrained.restoreCapacity();
        await alice.addMember(ctx, session.id, carolKeyPackage);
        let recoveredMembers = 0;
        for (let round = 0; round < 6; round += 1) {
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            recoveredMembers = (await alice.session(ctx, session.id))?.members.length ?? 0;
            if (recoveredMembers === 3 && (await carol.session(ctx, session.id)) !== undefined)
                break;
        }
        expect(await carol.session(ctx, session.id)).toMatchObject({ status: "pending" });

        return Object.freeze({
            seed,
            failedWriteOrdinal,
            observedWrites,
            atomicRollback: before === after,
            partialIntents,
            partialOutboxes,
            recoveredMembers,
        });
    } finally {
        alice.close(ctx);
        bob.close(ctx);
        carol.close(ctx);
        await relay.close();
    }
}

interface LiveCapacityResult {
    readonly seed: number;
    readonly atomicRollback: boolean;
    readonly retainedEvent: boolean;
    readonly stableUpdateId: boolean;
    readonly recovered: readonly string[];
    readonly followUp: readonly string[];
}

async function runLiveInboundCapacity(seed: number): Promise<LiveCapacityResult> {
    const label = seed.toString(16).padStart(8, "0");
    const relayStore = new SqliteRelayStore(":memory:");
    const relay = new RelayService(relayStore, {}, undefined, () => NOW);
    const aliceStore = new MemoryMurmurStore();
    const bobDelegate = new MemoryMurmurStore();
    const constrained = new CapacityMurmurStore(bobDelegate, {});
    const alice = await relayClient(relay, aliceStore);
    const bob = await relayClient(relay, constrained);
    try {
        const session = await alice.createSession(ctx, {
            descriptor: utf8Encode(`ST-03L ${label}`),
            members: [await bob.createKeyPackage(ctx)],
        });
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.activateSession(ctx, session.id);

        const previousCursor = await requiredText(bobDelegate, DELIVERY_CURSOR_KEY);
        const message = `capacity-replay-${label}`;
        await alice.send(ctx, session.id, utf8Encode(message));
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        const beforePage = await relayStore.readQueue(bob.deviceKey, previousCursor, 2, NOW, {
            maximumEncodedBytes: Number.MAX_SAFE_INTEGER,
        });
        expect(beforePage.deliveries).toHaveLength(1);
        const queuedEventId = beforePage.deliveries[0]!.eventId;
        zeroBytes(beforePage.generation);

        const before = await storeFingerprint(bobDelegate);
        let callbacks = 0;
        constrained.constrain({ failPrefix: APPLICATION_UPDATE_PREFIX });
        await expect(
            bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: (_ctx) => {
                        callbacks += 1;
                    },
                },
            ),
        ).rejects.toThrow(`prefix ${APPLICATION_UPDATE_PREFIX}`);
        const after = await storeFingerprint(bobDelegate);
        const failedCursor = await requiredText(bobDelegate, DELIVERY_CURSOR_KEY);
        const retainedPage = await relayStore.readQueue(bob.deviceKey, previousCursor, 2, NOW, {
            maximumEncodedBytes: Number.MAX_SAFE_INTEGER,
        });
        expect(callbacks).toBe(0);
        expect(retainedPage.deliveries).toHaveLength(1);
        const retainedEventId = retainedPage.deliveries[0]!.eventId;
        zeroBytes(retainedPage.generation);

        constrained.restoreCapacity();
        const recovered: string[] = [];
        let recoveredId: string | undefined;
        await bob.synchronize(
            ctx,
            { waitMilliseconds: 0 },
            {
                onUpdates: (_ctx, updates) => {
                    callbacks += 1;
                    for (const update of updates) {
                        recoveredId = update.id;
                        recovered.push(utf8Decode(update.bytes));
                    }
                },
            },
        );
        expect(callbacks).toBe(1);
        const recoveredCursor = await requiredText(bobDelegate, DELIVERY_CURSOR_KEY);
        const acknowledgedPage = await relayStore.readQueue(
            bob.deviceKey,
            recoveredCursor,
            2,
            NOW,
            {
                maximumEncodedBytes: Number.MAX_SAFE_INTEGER,
            },
        );
        expect(acknowledgedPage.deliveries).toHaveLength(0);
        expect(acknowledgedPage.acknowledgedThrough).toBe(recoveredCursor);
        zeroBytes(acknowledgedPage.generation);

        const followUpMessage = `capacity-follow-up-${label}`;
        await alice.send(ctx, session.id, utf8Encode(followUpMessage));
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        const followUp: string[] = [];
        await consume(bob, followUp);

        return Object.freeze({
            seed,
            atomicRollback: before === after && failedCursor === previousCursor,
            retainedEvent: retainedEventId === queuedEventId,
            stableUpdateId: recoveredId === queuedEventId && recoveredCursor === queuedEventId,
            recovered: Object.freeze(recovered.slice()),
            followUp: Object.freeze(followUp.slice()),
        });
    } finally {
        alice.close(ctx);
        bob.close(ctx);
        await relay.close();
    }
}

interface LiveDrainResult {
    readonly seed: number;
    readonly callbackIdsStable: boolean;
    readonly durableEffectCount: number;
    readonly callbackCount: number;
    readonly bufferedAfterFailure: number | undefined;
    readonly bufferedAfterRecovery: number | undefined;
    readonly relayAcknowledgedBeforeDrain: boolean;
}

async function runLiveDrainCapacity(seed: number): Promise<LiveDrainResult> {
    const label = seed.toString(16).padStart(8, "0");
    const relayStore = new SqliteRelayStore(":memory:");
    const relay = new RelayService(relayStore, {}, undefined, () => NOW);
    const aliceStore = new MemoryMurmurStore();
    const bobDelegate = new MemoryMurmurStore();
    const constrained = new CapacityMurmurStore(bobDelegate, {});
    const alice = await relayClient(relay, aliceStore);
    let bob = await relayClient(relay, constrained);
    try {
        const session = await alice.createSession(ctx, {
            descriptor: utf8Encode(`ST-04L ${label}`),
            members: [await bob.createKeyPackage(ctx)],
        });
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.activateSession(ctx, session.id);
        const previousCursor = await requiredText(bobDelegate, DELIVERY_CURSOR_KEY);

        await alice.send(ctx, session.id, utf8Encode(`owned-effect-${label}`));
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        const queuedCursor = await requiredText(bobDelegate, DELIVERY_CURSOR_KEY);
        expect(queuedCursor).not.toBe(previousCursor);
        const staged = await bob.session(ctx, session.id);
        expect(staged).toMatchObject({ status: "active", bufferedEvents: 1 });

        const callbackIds: string[] = [];
        const commitApplicationEffect = async (id: string): Promise<void> => {
            const key = `application/ST-04L/${id}`;
            const existing = await bobDelegate.get(ctx, key);
            if (existing === undefined) {
                await bobDelegate.set(ctx, key, utf8Encode(`committed-${label}`));
            } else {
                zeroBytes(existing);
            }
        };
        await expect(
            bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        expect(updates).toHaveLength(1);
                        const id = updates[0]!.id;
                        callbackIds.push(id);
                        await commitApplicationEffect(id);
                        constrained.constrain({ failWriteOrdinals: [1] });
                    },
                },
            ),
        ).rejects.toThrow("write 1");
        const bufferedAfterFailure = (await bob.session(ctx, session.id))?.bufferedEvents;
        const acknowledgedPage = await relayStore.readQueue(bob.deviceKey, queuedCursor, 2, NOW, {
            maximumEncodedBytes: Number.MAX_SAFE_INTEGER,
        });
        const relayAcknowledgedBeforeDrain =
            acknowledgedPage.deliveries.length === 0 &&
            acknowledgedPage.acknowledgedThrough === queuedCursor;
        zeroBytes(acknowledgedPage.generation);

        bob.close(ctx);
        constrained.restoreCapacity();
        bob = await relayClient(relay, constrained);
        await bob.synchronize(
            ctx,
            { waitMilliseconds: 0 },
            {
                onUpdates: async (_ctx, updates) => {
                    expect(updates).toHaveLength(1);
                    const id = updates[0]!.id;
                    callbackIds.push(id);
                    await commitApplicationEffect(id);
                },
            },
        );
        const bufferedAfterRecovery = (await bob.session(ctx, session.id))?.bufferedEvents;
        const durableEffectCount = await prefixCount(bobDelegate, "application/ST-04L/");

        return Object.freeze({
            seed,
            callbackIdsStable: callbackIds.length === 2 && callbackIds[0] === callbackIds[1],
            durableEffectCount,
            callbackCount: callbackIds.length,
            bufferedAfterFailure,
            bufferedAfterRecovery,
            relayAcknowledgedBeforeDrain,
        });
    } finally {
        alice.close(ctx);
        bob.close(ctx);
        await relay.close();
    }
}

interface LiveOutboxCorruptionResult {
    readonly seed: number;
    readonly operator: "flip" | "truncate";
    readonly offset: number;
    readonly recordLength: number;
    readonly issueCode: string | undefined;
    readonly corruptedDeliveries: readonly string[];
    readonly recoveredDeliveries: readonly string[];
}

async function runLiveOutboxCorruption(seed: number): Promise<LiveOutboxCorruptionResult> {
    const random = new SeededRandom(seed);
    const label = seed.toString(16).padStart(8, "0");
    const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
    const aliceStore = new InspectableStoreFixture();
    const bobStore = new MemoryMurmurStore();
    let alice = await relayClient(relay, aliceStore);
    let aliceOpen = true;
    aliceStore.clientOpened();
    let bob = await relayClient(relay, bobStore);
    try {
        const session = await alice.createSession(ctx, {
            descriptor: utf8Encode(`ST-07L ${label}`),
            members: [await bob.createKeyPackage(ctx)],
        });
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.activateSession(ctx, session.id);

        const corruptedId = await alice.send(ctx, session.id, utf8Encode(`corrupt-${label}`));
        const outboxKey = `${OUTBOX_PREFIX}${corruptedId}`;
        alice.close(ctx);
        aliceStore.clientClosed();
        aliceOpen = false;
        bob.close(ctx);
        const original = await aliceStore.snapshotExact(outboxKey);
        const operator = random.oneIn(2) ? "flip" : "truncate";
        let offset: number;
        if (operator === "flip") {
            offset = 0;
            await aliceStore.flipExact(outboxKey, offset, random.integer(1, 256));
        } else {
            offset = random.integer(0, Math.min(4, original.length));
            await aliceStore.truncateExact(outboxKey, offset);
        }

        alice = await relayClient(relay, aliceStore);
        aliceStore.clientOpened();
        aliceOpen = true;
        bob = await relayClient(relay, bobStore);
        const corruptionOutcome = await alice.synchronize(ctx, { waitMilliseconds: 0 });
        expect(corruptionOutcome).toMatchObject({
            pendingOutboxes: 0,
            terminalPublicationFailures: 1,
        });
        expect(await alice.session(ctx, session.id)).toMatchObject({ status: "active" });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        const corruptedDeliveries: string[] = [];
        await consume(bob, corruptedDeliveries);

        await alice.send(ctx, session.id, utf8Encode(`recovered-${label}`));
        await alice.synchronize(ctx, { waitMilliseconds: 0 });
        await bob.synchronize(ctx, { waitMilliseconds: 0 });
        const recoveredDeliveries: string[] = [];
        await consume(bob, recoveredDeliveries);

        return Object.freeze({
            seed,
            operator,
            offset,
            recordLength: original.length,
            issueCode: corruptionOutcome.issues.find((issue) => issue.code === "corrupt_outbox")
                ?.code,
            corruptedDeliveries: Object.freeze(corruptedDeliveries.slice()),
            recoveredDeliveries: Object.freeze(recoveredDeliveries.slice()),
        });
    } finally {
        alice.close(ctx);
        if (aliceOpen) aliceStore.clientClosed();
        bob.close(ctx);
        await relay.close();
    }
}

async function runContention(): Promise<{
    readonly statuses: readonly string[];
    readonly keys: readonly [string, number][];
}> {
    const delegate = new MemoryMurmurStore();
    const store = new CapacityMurmurStore(delegate, {
        failWriteOrdinals: [4, 14, 18],
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
        release = resolve;
    });
    const operations = Array.from({ length: 20 }, (_, index) =>
        (async (): Promise<void> => {
            await gate;
            await store.tx(ctx, async (transaction) => {
                const key = index < 10 ? `contention/independent/${index}` : "contention/shared";
                const current = await store.get(transaction, key);
                const next = (current?.[0] ?? 0) + 1;
                if (current !== undefined) zeroBytes(current);
                await store.set(transaction, key, new Uint8Array([next]));
            });
        })(),
    );
    release();
    const outcomes = await Promise.allSettled(operations);
    const values = await delegate.scan(ctx, "contention/", { limit: 32 });
    try {
        return {
            statuses: outcomes.map((outcome) => outcome.status),
            keys: [...values].map(([key, value]) => [key, value[0]!] as const),
        };
    } finally {
        for (const value of values.values()) zeroBytes(value);
    }
}

async function campaignRun(seed: number): Promise<string> {
    try {
        const random = new SeededRandom(seed);
        const selected = RECORD_FIXTURES[random.integer(0, RECORD_FIXTURES.length)]!;
        const fixture = new InspectableStoreFixture();
        await setRecords(fixture, RECORD_FIXTURES);
        const precondition = await fixture.snapshotExact(selected.key);
        const operation = random.integer(0, 4);
        if (operation === 0) {
            await fixture.deleteExact(selected.key);
        } else if (operation === 1) {
            await fixture.truncateExact(selected.key, random.integer(0, selected.bytes.length));
        } else if (operation === 2) {
            await fixture.flipExact(
                selected.key,
                random.integer(0, selected.bytes.length),
                random.integer(1, 256),
            );
        } else {
            await fixture.appendExact(selected.key, random.integer(0, 256));
        }

        const recovery = await settleChaos({
            maximumRounds: 20,
            act: async (round) => {
                if (round === 1) await fixture.restoreExact(selected.key);
            },
            snapshot: async () => {
                const bytes = await fixture.get(ctx, selected.key);
                if (bytes === undefined) return "missing";
                try {
                    return digest(bytes);
                } finally {
                    zeroBytes(bytes);
                }
            },
        });
        expect(recovery.rounds).toBeLessThanOrEqual(20);
        expect(recovery.state).toBe(precondition.digest);
        const trace = fixture.trace[0]!;
        expect(trace).toMatchObject({
            key: selected.key,
            digest: precondition.digest,
            length: precondition.length,
        });
        return JSON.stringify({ selected: selected.family, trace, rounds: recovery.rounds });
    } catch (error: unknown) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`storage campaign seed ${seed} (0x${seed.toString(16)}): ${detail}`, {
            cause: error,
        });
    }
}

describe("storage corruption and capacity chaos", () => {
    test("ST-01 disk-full send ladder is atomic and recovers exact outbox work", async () => {
        const writes = [
            record("outbox", `${OUTBOX_PREFIX}delivery`),
            record("order", `${OUTBOX_ORDER_PREFIX}0001/delivery`),
            record("epoch-index", "murmur/epoch-outboxes/session/delivery"),
            record("ratchet", `${SESSION_STATE_PREFIX}session`),
        ];
        for (let nth = 1; nth <= writes.length; nth += 1) {
            const delegate = new MemoryMurmurStore();
            const store = new CapacityMurmurStore(delegate, { failWriteOrdinals: [nth] });
            await expect(setRecords(store, writes)).rejects.toThrow("storage capacity failure");
            expect(await delegate.scan(ctx, "murmur/", { limit: 16 })).toEqual(new Map());

            store.restoreCapacity();
            await setRecords(store, writes);
            expect(await scanKeys(delegate, OUTBOX_PREFIX, 1)).toEqual([
                `${OUTBOX_PREFIX}delivery`,
            ]);
            expect(await scanKeys(delegate, OUTBOX_ORDER_PREFIX, 1)).toEqual([
                `${OUTBOX_ORDER_PREFIX}0001/delivery`,
            ]);
        }

        const keyBoundDelegate = new MemoryMurmurStore();
        await keyBoundDelegate.set(ctx, "capacity/existing", new Uint8Array([1]));
        const keyBound = new CapacityMurmurStore(keyBoundDelegate, { maximumKeys: 2 });
        await expect(
            keyBound.tx(ctx, async (transaction) => {
                await keyBound.set(transaction, "capacity/a", new Uint8Array([1]));
                await keyBound.set(transaction, "capacity/b", new Uint8Array([1]));
            }),
        ).rejects.toThrow("maximum key count");
        expect(await keyBoundDelegate.get(ctx, "capacity/a")).toBeUndefined();
        expect(await keyBoundDelegate.get(ctx, "capacity/b")).toBeUndefined();

        const byteBoundDelegate = new MemoryMurmurStore();
        const byteBound = new CapacityMurmurStore(byteBoundDelegate, { maximumBytes: 3 });
        await expect(byteBound.set(ctx, "capacity/bytes", new Uint8Array(4))).rejects.toThrow(
            "maximum aggregate bytes",
        );
        expect(await byteBoundDelegate.get(ctx, "capacity/bytes")).toBeUndefined();

        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceBaseline = new MemoryMurmurStore();
        const bobBaseline = new MemoryMurmurStore();
        let alice = await relayClient(relay, aliceBaseline);
        let bob = await relayClient(relay, bobBaseline);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("capacity send ladder"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);
            for (let round = 0; round < 4; round += 1) {
                if ((await prefixCount(aliceBaseline, OUTBOX_PREFIX)) === 0) break;
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect(await prefixCount(aliceBaseline, OUTBOX_PREFIX)).toBe(0);
            alice.close(ctx);
            bob.close(ctx);

            const calibrationDelegate = await cloneMemoryStore(aliceBaseline);
            const calibrationStore = new CapacityMurmurStore(calibrationDelegate, {});
            const calibrationClient = await relayClient(relay, calibrationStore);
            await calibrationClient.send(ctx, session.id, utf8Encode("calibration"));
            const sendWrites = calibrationStore.writeOrdinal;
            calibrationClient.close(ctx);
            expect(sendWrites).toBeGreaterThan(0);
            expect(sendWrites).toBeLessThanOrEqual(20);

            for (let nth = 1; nth <= sendWrites; nth += 1) {
                const aliceDelegate = await cloneMemoryStore(aliceBaseline);
                const bobDelegate = await cloneMemoryStore(bobBaseline);
                const constrained = new CapacityMurmurStore(aliceDelegate, {
                    failWriteOrdinals: [nth],
                });
                alice = await relayClient(relay, constrained);
                bob = await relayClient(relay, bobDelegate);
                await expect(
                    alice.send(ctx, session.id, utf8Encode(`rejected-${nth}`)),
                ).rejects.toThrow("storage capacity failure");
                expect(await aliceDelegate.scan(ctx, OUTBOX_PREFIX, { limit: 20 })).toEqual(
                    new Map(),
                );

                constrained.restoreCapacity();
                await alice.send(ctx, session.id, utf8Encode(`recovered-${nth}`));
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
                const recovered: string[] = [];
                expect(await consume(bob, recovered)).toBe(1);
                expect(recovered).toEqual([`recovered-${nth}`]);

                await alice.send(ctx, session.id, utf8Encode(`follow-up-${nth}`));
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
                const followUp: string[] = [];
                expect(await consume(bob, followUp)).toBe(1);
                expect(followUp).toEqual([`follow-up-${nth}`]);
                await copyDeliveryProgress(aliceDelegate, aliceBaseline);
                await copyDeliveryProgress(bobDelegate, bobBaseline);
                alice.close(ctx);
                bob.close(ctx);
            }
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    }, 120_000);

    test("ST-02 membership-intent capacity ladders retain no partial candidate epochs", async () => {
        const operations = [
            "add",
            "remove",
            "grant-admin",
            "revoke-admin",
            "set-policies",
            "leave",
        ];
        for (const operation of operations) {
            const records = [
                record("intent", `murmur/session-intents/${operation}`),
                record("candidate", `${OUTBOX_PREFIX}${operation}`),
                record("candidate-index", `${OUTBOX_ORDER_PREFIX}${operation}`),
            ];
            for (let nth = 1; nth <= records.length; nth += 1) {
                const delegate = new MemoryMurmurStore();
                const store = new CapacityMurmurStore(delegate, { failWriteOrdinals: [nth] });
                await expect(setRecords(store, records)).rejects.toThrow(
                    "storage capacity failure",
                );
                expect(await delegate.scan(ctx, "murmur/", { limit: 16 })).toEqual(new Map());
                store.restoreCapacity();
                await setRecords(store, records);
                expect(await scanKeys(delegate, "murmur/session-intents/", 1)).toHaveLength(1);
                expect(await scanKeys(delegate, OUTBOX_PREFIX, 1)).toHaveLength(1);
            }
        }

        const prefixDelegate = new MemoryMurmurStore();
        const prefixStore = new CapacityMurmurStore(prefixDelegate, {
            failPrefix: OUTBOX_PREFIX,
        });
        await expect(
            prefixStore.tx(ctx, async (transaction) => {
                await prefixStore.set(
                    transaction,
                    "murmur/session-intents/add",
                    new Uint8Array([1]),
                );
                await prefixStore.set(transaction, `${OUTBOX_PREFIX}add`, new Uint8Array([2]));
            }),
        ).rejects.toThrow(`prefix ${OUTBOX_PREFIX}`);
        expect(await prefixDelegate.scan(ctx, "murmur/", { limit: 4 })).toEqual(new Map());
    });

    test("ST-02L real Add intent write ladder rolls back KeyPackage claims and intent state", async () => {
        const seed = 0x5354_3032;
        const calibration = await runLiveIntentCapacity(seed);
        expect(calibration.observedWrites).toBeGreaterThan(1);
        expect(calibration.observedWrites).toBeLessThanOrEqual(20);
        for (let nth = 1; nth <= calibration.observedWrites; nth += 1) {
            const first = await runLiveIntentCapacity(seed, nth);
            const replay = await runLiveIntentCapacity(seed, nth);
            expect(replay).toEqual(first);
            expect(first).toMatchObject({
                seed,
                failedWriteOrdinal: nth,
                observedWrites: nth,
                atomicRollback: true,
                partialIntents: 0,
                partialOutboxes: 0,
                recoveredMembers: 3,
            });
        }
    }, 120_000);

    test("ST-03/ST-04 buffer, callback drain, ack, and lost-response ordering stay durable", async () => {
        const delegate = new MemoryMurmurStore();
        const eventKey = `${APPLICATION_UPDATE_PREFIX}event-1`;
        const bufferKey = "murmur/session-data/session/buffer/event-1";
        const constrained = new CapacityMurmurStore(delegate, {
            failPrefix: APPLICATION_UPDATE_PREFIX,
        });
        await expect(
            constrained.tx(ctx, async (transaction) => {
                await constrained.set(
                    transaction,
                    bufferKey,
                    utf8Encode("sentinel application update"),
                );
                await constrained.set(transaction, eventKey, utf8Encode("session"));
            }),
        ).rejects.toThrow("storage capacity failure");
        expect(await delegate.get(ctx, bufferKey)).toBeUndefined();
        expect(await delegate.get(ctx, eventKey)).toBeUndefined();
        expect(await delegate.get(ctx, ACK_KEY)).toBeUndefined();

        constrained.restoreCapacity();
        await constrained.tx(ctx, async (transaction) => {
            await constrained.set(
                transaction,
                bufferKey,
                utf8Encode("sentinel application update"),
            );
            await constrained.set(transaction, eventKey, utf8Encode("session"));
        });

        let callbacks = 0;
        callbacks += 1;
        const preCommitFailure = new CapacityMurmurStore(delegate, {
            failWriteOrdinals: [1],
        });
        await expect(
            preCommitFailure.tx(ctx, async (transaction) => {
                await preCommitFailure.delete(transaction, bufferKey);
                await preCommitFailure.delete(transaction, eventKey);
                await preCommitFailure.set(transaction, `${DRAIN_PREFIX}event-1`, new Uint8Array());
                await preCommitFailure.set(transaction, ACK_KEY, utf8Encode("event-1"));
            }),
        ).rejects.toThrow("storage capacity failure");
        expect(await delegate.get(ctx, eventKey)).toBeDefined();
        expect(await delegate.get(ctx, ACK_KEY)).toBeUndefined();
        callbacks += 1;
        expect(callbacks).toBe(2);

        const schedule = new SeededChaosSchedule(0x5354_3034, [
            {
                id: "lose-drain-commit-response",
                selector: { boundary: "store", operation: "transaction", phase: "after" },
                effect: { type: "drop" },
            },
        ]);
        const lostResponse = new FaultInjectingMurmurStore({
            actor: "drain",
            delegate,
            schedule,
        });
        await expect(
            lostResponse.tx(ctx, async (transaction) => {
                await lostResponse.delete(transaction, bufferKey);
                await lostResponse.delete(transaction, eventKey);
                await lostResponse.set(transaction, `${DRAIN_PREFIX}event-1`, new Uint8Array());
                await lostResponse.set(transaction, ACK_KEY, utf8Encode("event-1"));
            }),
        ).rejects.toThrow("lost transaction response");
        expect(await delegate.get(ctx, eventKey)).toBeUndefined();
        expect(await delegate.get(ctx, `${DRAIN_PREFIX}event-1`)).toEqual(new Uint8Array());
        expect(utf8Decode((await delegate.get(ctx, ACK_KEY))!)).toBe("event-1");
        expect(callbacks).toBe(2);
        schedule.assertConsumed();
    });

    test("ST-03L real inbound disk-full rollback retains the exact relay event", async () => {
        const seed = 0x5354_3033;
        const first = await runLiveInboundCapacity(seed);
        const replay = await runLiveInboundCapacity(seed);
        expect(replay).toEqual(first);
        expect(first).toEqual({
            seed,
            atomicRollback: true,
            retainedEvent: true,
            stableUpdateId: true,
            recovered: [`capacity-replay-${seed.toString(16)}`],
            followUp: [`capacity-follow-up-${seed.toString(16)}`],
        });
    });

    test("ST-04L real post-callback disk-full drain replays one stable update ID", async () => {
        const seed = 0x5354_3034;
        const first = await runLiveDrainCapacity(seed);
        const replay = await runLiveDrainCapacity(seed);
        expect(replay).toEqual(first);
        expect(first).toEqual({
            seed,
            callbackIdsStable: true,
            durableEffectCount: 1,
            callbackCount: 2,
            bufferedAfterFailure: 1,
            bufferedAfterRecovery: 0,
            relayAcknowledgedBeforeDrain: true,
        });
    });

    test("ST-05 bounded scans cover zero, page edges, after cursors, and maximum limits", async () => {
        const sizes = [0, 1, NORMAL_SCAN_LIMIT - 1, NORMAL_SCAN_LIMIT, NORMAL_SCAN_LIMIT + 1];
        for (const prefix of BOUNDED_PREFIXES) {
            for (const size of sizes) {
                const store = new MemoryMurmurStore();
                await store.tx(ctx, async (transaction) => {
                    for (let index = 0; index < size; index += 1) {
                        await store.set(
                            transaction,
                            `${prefix}${index.toString().padStart(6, "0")}`,
                            new Uint8Array([index & 0xff]),
                        );
                    }
                });
                const expected = Array.from(
                    { length: size },
                    (_, index) => `${prefix}${index.toString().padStart(6, "0")}`,
                );
                expect(await scanKeys(store, prefix, 1)).toEqual(expected);
                expect(await scanKeys(store, prefix, NORMAL_SCAN_LIMIT)).toEqual(expected);
                expect(await scanKeys(store, prefix, MAXIMUM_STORE_SCAN_ITEMS)).toEqual(expected);

                const before = await store.scan(ctx, prefix, { after: `${prefix}!`, limit: 1 });
                expect([...before.keys()]).toEqual(expected.slice(0, 1));
                if (size > 0) {
                    const first = expected[0]!;
                    const afterExact = await store.scan(ctx, prefix, { after: first, limit: 1 });
                    expect([...afterExact.keys()]).toEqual(expected.slice(1, 2));
                    const last = expected.at(-1)!;
                    expect(await store.scan(ctx, prefix, { after: last, limit: 1 })).toEqual(
                        new Map(),
                    );
                    const absent = `${prefix}000000~`;
                    const afterAbsent = await store.scan(ctx, prefix, { after: absent, limit: 1 });
                    expect([...afterAbsent.keys()]).toEqual(
                        expected.filter((key) => key > absent).slice(0, 1),
                    );
                }
                await expect(
                    store.scan(ctx, prefix, { limit: MAXIMUM_STORE_SCAN_ITEMS + 1 }),
                ).rejects.toThrow("Invalid Murmur store scan");
            }
        }
    });

    test("ST-06 twenty gated transactions are serializable and replay exact failures", async () => {
        const first = await runContention();
        const replay = await runContention();
        expect(replay).toEqual(first);
        expect(first.statuses.filter((status) => status === "rejected")).toHaveLength(3);
        expect(first.keys).toContainEqual(["contention/shared", 8]);
        expect(first.keys).not.toContainEqual(["contention/independent/3", 1]);
        expect(first.keys).toHaveLength(10);
    });

    test("ST-07 a corrupt active epoch is quarantined while another MLS session remains live", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new InspectableStoreFixture();
        const bobStore = new MemoryMurmurStore();
        const carolStore = new MemoryMurmurStore();
        let alice = await relayClient(relay, aliceStore);
        aliceStore.clientOpened();
        let bob = await relayClient(relay, bobStore);
        let carol = await relayClient(relay, carolStore);
        try {
            const damaged = await alice.createSession(ctx, {
                descriptor: utf8Encode("damaged chaos session"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, damaged.id);

            const healthy = await alice.createSession(ctx, {
                descriptor: utf8Encode("healthy chaos session"),
                members: [await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await carol.synchronize(ctx);
            await activate(carol, healthy.id);

            alice.close(ctx);
            aliceStore.clientClosed();
            bob.close(ctx);
            carol.close(ctx);
            const damagedKey = `${SESSION_STATE_PREFIX}${encodeBase64Url(damaged.id)}`;
            const selected = await aliceStore.snapshotExact(damagedKey);
            await aliceStore.truncateExact(damagedKey, 3);
            expect(aliceStore.trace.at(-1)).toMatchObject({
                key: damagedKey,
                digest: selected.digest,
                length: selected.length,
                operator: "truncate",
            });

            alice = await relayClient(relay, aliceStore);
            aliceStore.clientOpened();
            bob = await relayClient(relay, bobStore);
            carol = await relayClient(relay, carolStore);
            await alice.send(ctx, healthy.id, utf8Encode("healthy after corruption"));
            const outcome = await alice.synchronize(ctx, { waitMilliseconds: 0 });
            expect(outcome.terminalPublicationFailures).toBe(1);
            expect(outcome.issues).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "corrupt_session_state",
                        sessionId: damaged.id,
                    }),
                ]),
            );
            expect(await alice.session(ctx, damaged.id)).toBeUndefined();
            expect(await alice.session(ctx, healthy.id)).toMatchObject({ status: "active" });

            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            const received: string[] = [];
            expect(await consume(carol, received)).toBe(1);
            expect(received).toEqual(["healthy after corruption"]);
            const damagedUpdates: string[] = [];
            expect(await consume(bob, damagedUpdates)).toBe(0);
            expect(damagedUpdates).toEqual([]);
            expect(
                (await aliceStore.scan(ctx, "murmur/session-quarantine/", { limit: 20 })).size,
            ).toBeLessThanOrEqual(1);
        } finally {
            alice.close(ctx);
            if (aliceStore.trace.length > 0) {
                try {
                    aliceStore.clientClosed();
                } catch {
                    // The mutation guard itself verifies balanced lifecycle transitions.
                }
            }
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    }, 120_000);

    test("ST-07L a real outbox corrupted between syncs is quarantined and replayable", async () => {
        const seed = 0x5354_3037;
        const first = await runLiveOutboxCorruption(seed);
        const replay = await runLiveOutboxCorruption(seed);
        expect(replay).toEqual(first);
        expect(first).toMatchObject({
            seed,
            issueCode: "corrupt_outbox",
            corruptedDeliveries: [],
            recoveredDeliveries: [`recovered-${seed.toString(16)}`],
        });
        expect(["flip", "truncate"]).toContain(first.operator);
        expect(first.offset).toBeGreaterThanOrEqual(0);
        expect(first.offset).toBeLessThan(first.recordLength);
    });

    test("ST-08 identity corruption fails closed and traces contain metadata only", async () => {
        const fixture = new InspectableStoreFixture();
        const transport = new OfflineTransport();
        let client = await MurmurClient.open(ctx, { store: fixture, transport, now: () => NOW });
        fixture.clientOpened();
        const publicIdentity = client.identity;
        client.close(ctx);
        fixture.clientClosed();
        const original = await fixture.snapshotExact(IDENTITY_KEY);
        const mutationCases: readonly ((store: InspectableStoreFixture) => Promise<void>)[] = [
            (store) => store.truncateExact(IDENTITY_KEY, 0),
            (store) => store.truncateExact(IDENTITY_KEY, 1),
            (store) => store.truncateExact(IDENTITY_KEY, original.length - 1),
            (store) => store.flipExact(IDENTITY_KEY, 0),
            (store) => store.flipExact(IDENTITY_KEY, 11),
            (store) => store.appendExact(IDENTITY_KEY, 0),
        ];
        for (const mutate of mutationCases) {
            await fixture.restoreExact(IDENTITY_KEY);
            await mutate(fixture);
            const corrupted = await fixture.get(ctx, IDENTITY_KEY);
            await expect(
                MurmurClient.open(ctx, { store: fixture, transport, now: () => NOW }),
            ).rejects.toThrow();
            expect(await fixture.get(ctx, IDENTITY_KEY)).toEqual(corrupted);
            if (corrupted !== undefined) zeroBytes(corrupted);
        }

        await fixture.restoreExact(IDENTITY_KEY);
        client = await MurmurClient.open(ctx, { store: fixture, transport, now: () => NOW });
        fixture.clientOpened();
        expect(client.identity).toEqual(publicIdentity);
        await expect(fixture.flipExact(IDENTITY_KEY, 0)).rejects.toThrow(
            "requires every store client to be closed",
        );
        client.close(ctx);
        fixture.clientClosed();

        const sentinel = utf8Encode("ST-08 sentinel secret plaintext");
        await fixture.set(ctx, "murmur/chaos/secret-bearing-record", sentinel);
        await fixture.snapshotExact("murmur/chaos/secret-bearing-record");
        await fixture.flipExact("murmur/chaos/secret-bearing-record", 1);
        const traceJson = JSON.stringify(fixture.trace);
        expect(traceJson).not.toContain(utf8Decode(sentinel));
        expect(traceJson).not.toContain(encodeBase64Url(sentinel));
        expect(traceJson).not.toContain(JSON.stringify([...sentinel]));
        expect(fixture.trace.every((entry) => entry.digest.length === 43)).toBe(true);
        zeroBytes(sentinel);
    });

    test("corruption matrix snapshots every target family and restores every operator", async () => {
        for (const [index, selected] of RECORD_FIXTURES.entries()) {
            const fixture = new InspectableStoreFixture();
            await setRecords(fixture, RECORD_FIXTURES);
            const original = await fixture.snapshotExact(selected.key);
            await fixture.flipExact(selected.key, 0);
            await fixture.restoreExact(selected.key);
            await fixture.truncateExact(selected.key, selected.bytes.length - 1);
            await fixture.restoreExact(selected.key);
            await fixture.appendExact(selected.key, 0);
            await fixture.restoreExact(selected.key);
            await fixture.deleteExact(selected.key);
            expect(await fixture.get(ctx, selected.key)).toBeUndefined();
            await fixture.restoreExact(selected.key);
            const swapped = RECORD_FIXTURES[(index + 1) % RECORD_FIXTURES.length]!;
            await fixture.replaceExact(selected.key, swapped.bytes);
            expect(await fixture.get(ctx, selected.key)).toEqual(swapped.bytes);
            await fixture.restoreExact(selected.key);
            const restored = await fixture.get(ctx, selected.key);
            expect(restored).toBeDefined();
            expect(digest(restored!)).toBe(original.digest);
            zeroBytes(restored!);
            expect(fixture.trace).toHaveLength(5);
            expect(fixture.trace.every((entry) => entry.key === selected.key)).toBe(true);
            expect(fixture.trace.every((entry) => entry.digest === original.digest)).toBe(true);
        }
    });

    test("seeded campaign replays 0x53544f52 through 0x53544f7a within 20 rounds", async () => {
        for (let seed = CAMPAIGN_FIRST_SEED; seed <= CAMPAIGN_LAST_SEED; seed += 1) {
            const first = await campaignRun(seed);
            const replay = await campaignRun(seed);
            expect(replay).toBe(first);
        }
    });
});
