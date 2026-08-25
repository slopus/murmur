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
    type StoreTransaction,
} from "../../storage/index.js";
import { MurmurClient, type MurmurUpdate } from "../../sessions/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";
import {
    FaultInjectingMurmurStore,
    SeededChaosSchedule,
    SeededRandom,
    settleChaos,
} from "../index.js";

const NOW = 1_700_000_000_000;
const IDENTITY_KEY = "murmur/identity/root";
const SESSION_STATE_PREFIX = "murmur/session-states/";
const OUTBOX_PREFIX = "murmur/session-outbox/";
const OUTBOX_ORDER_PREFIX = "murmur/session-outbox-order/";
const APPLICATION_UPDATE_PREFIX = "murmur/application-updates/";
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
    record("provisioning", "murmur/accounts/v1/pending-envelope"),
    record("private-canonical", "murmur/private-groups/canonical/group"),
]);

const BOUNDED_PREFIXES = Object.freeze([
    SESSION_STATE_PREFIX,
    "murmur/session-intents/",
    OUTBOX_PREFIX,
    OUTBOX_ORDER_PREFIX,
    "murmur/pending-sessions/",
    APPLICATION_UPDATE_PREFIX,
    "murmur/session-quarantine/",
    "murmur/key-packages/",
    "murmur/accounts/v1/convergence/",
    "murmur/private-groups/canonical/",
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

    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#delegate.get(key);
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#delegate.set(key, value);
    }

    async delete(key: string): Promise<void> {
        await this.#delegate.delete(key);
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.list(prefix);
    }

    async scan(
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.scan(prefix, options);
    }

    async transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#delegate.transaction(operation);
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
        await this.#delegate.delete(key);
        this.#trace.push(before);
    }

    async replaceExact(key: string, value: Uint8Array): Promise<void> {
        const before = await this.#beforeMutation(key, "replace");
        await this.#delegate.set(key, value);
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
            await this.#delegate.set(key, bytes);
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
            await this.#delegate.set(key, bytes.slice(0, length));
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
            await this.#delegate.set(key, appended);
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
        await this.#delegate.set(key, preimage);
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
        const bytes = await this.#delegate.get(key);
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

class CapacityStoreView implements StoreTransaction {
    readonly #delegate: StoreTransaction;
    readonly #beforeSet: (
        transaction: StoreTransaction,
        key: string,
        value: Uint8Array,
    ) => Promise<void>;

    constructor(
        delegate: StoreTransaction,
        beforeSet: (transaction: StoreTransaction, key: string, value: Uint8Array) => Promise<void>,
    ) {
        this.#delegate = delegate;
        this.#beforeSet = beforeSet;
    }

    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#delegate.get(key);
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#beforeSet(this.#delegate, key, value);
        await this.#delegate.set(key, value);
    }

    async delete(key: string): Promise<void> {
        await this.#delegate.delete(key);
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.list(prefix);
    }

    async scan(
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.scan(prefix, options);
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

    restoreCapacity(): void {
        this.#enabled = false;
    }

    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#delegate.get(key);
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#delegate.transaction(async (transaction) => {
            const view = this.#view(transaction);
            await view.set(key, value);
        });
    }

    async delete(key: string): Promise<void> {
        await this.#delegate.delete(key);
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.list(prefix);
    }

    async scan(
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#delegate.scan(prefix, options);
    }

    async transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#delegate.transaction((transaction) => operation(this.#view(transaction)));
    }

    #view(transaction: StoreTransaction): StoreTransaction {
        return new CapacityStoreView(transaction, (candidate, key, value) =>
            this.#beforeSet(candidate, key, value),
        );
    }

    async #beforeSet(transaction: StoreTransaction, key: string, value: Uint8Array): Promise<void> {
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

        const values = await transaction.scan("", { limit: MAXIMUM_STORE_SCAN_ITEMS });
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
    async publish(_delivery: SignedDelivery): Promise<DeliveryPublishOutcome> {
        throw new Error("Offline test transport does not publish");
    }

    async read(_request: SignedInboxRead): Promise<InboxPage> {
        return {
            deliveries: [],
            head: null,
            acknowledgedThrough: null,
            exhausted: true,
        };
    }

    async acknowledge(_request: SignedInboxAck): Promise<{ readonly removed: number }> {
        return { removed: 0 };
    }
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "storage-corruption-chaos",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function relayClient(relay: RelayService, store: MurmurStore): Promise<MurmurClient> {
    return MurmurClient.open({
        transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) }),
        store,
        now: () => NOW,
    });
}

async function activate(client: MurmurClient, sessionId: Uint8Array): Promise<void> {
    await client.activateSession(sessionId);
}

async function consume(client: MurmurClient, received: string[]): Promise<number> {
    let count = 0;
    await client.synchronize(
        { waitMilliseconds: 0 },
        {
            onUpdates: async (updates: readonly MurmurUpdate[]) => {
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
    await store.transaction(async (transaction) => {
        for (const fixture of records) await transaction.set(fixture.key, fixture.bytes);
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
        const page = await store.scan(prefix, {
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
        const page = await source.scan("", {
            ...(after === undefined ? {} : { after }),
            limit: NORMAL_SCAN_LIMIT,
        });
        try {
            await target.transaction(async (transaction) => {
                for (const [key, value] of page) {
                    after = key;
                    await transaction.set(key, value);
                }
            });
        } finally {
            for (const value of page.values()) zeroBytes(value);
        }
        if (page.size < NORMAL_SCAN_LIMIT) return target;
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
            await store.transaction(async (transaction) => {
                const key = index < 10 ? `contention/independent/${index}` : "contention/shared";
                const current = await transaction.get(key);
                const next = (current?.[0] ?? 0) + 1;
                if (current !== undefined) zeroBytes(current);
                await transaction.set(key, new Uint8Array([next]));
            });
        })(),
    );
    release();
    const outcomes = await Promise.allSettled(operations);
    const values = await delegate.scan("contention/", { limit: 32 });
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
                const bytes = await fixture.get(selected.key);
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
            expect(await delegate.scan("murmur/", { limit: 16 })).toEqual(new Map());

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
        await keyBoundDelegate.set("capacity/existing", new Uint8Array([1]));
        const keyBound = new CapacityMurmurStore(keyBoundDelegate, { maximumKeys: 2 });
        await expect(
            keyBound.transaction(async (transaction) => {
                await transaction.set("capacity/a", new Uint8Array([1]));
                await transaction.set("capacity/b", new Uint8Array([1]));
            }),
        ).rejects.toThrow("maximum key count");
        expect(await keyBoundDelegate.get("capacity/a")).toBeUndefined();
        expect(await keyBoundDelegate.get("capacity/b")).toBeUndefined();

        const byteBoundDelegate = new MemoryMurmurStore();
        const byteBound = new CapacityMurmurStore(byteBoundDelegate, { maximumBytes: 3 });
        await expect(byteBound.set("capacity/bytes", new Uint8Array(4))).rejects.toThrow(
            "maximum aggregate bytes",
        );
        expect(await byteBoundDelegate.get("capacity/bytes")).toBeUndefined();

        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceBaseline = new MemoryMurmurStore();
        const bobBaseline = new MemoryMurmurStore();
        let alice = await relayClient(relay, aliceBaseline);
        let bob = await relayClient(relay, bobBaseline);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("capacity send ladder"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);
            alice.close();
            bob.close();

            const calibrationDelegate = await cloneMemoryStore(aliceBaseline);
            const calibrationStore = new CapacityMurmurStore(calibrationDelegate, {});
            const calibrationClient = await relayClient(relay, calibrationStore);
            await calibrationClient.send(session.id, utf8Encode("calibration"));
            const sendWrites = calibrationStore.writeOrdinal;
            calibrationClient.close();
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
                await expect(alice.send(session.id, utf8Encode(`rejected-${nth}`))).rejects.toThrow(
                    "storage capacity failure",
                );
                expect(await aliceDelegate.scan(OUTBOX_PREFIX, { limit: 20 })).toEqual(new Map());

                constrained.restoreCapacity();
                await alice.send(session.id, utf8Encode(`recovered-${nth}`));
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                const recovered: string[] = [];
                expect(await consume(bob, recovered)).toBe(1);
                expect(recovered).toEqual([`recovered-${nth}`]);

                await alice.send(session.id, utf8Encode(`follow-up-${nth}`));
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                const followUp: string[] = [];
                expect(await consume(bob, followUp)).toBe(1);
                expect(followUp).toEqual([`follow-up-${nth}`]);
                alice.close();
                bob.close();
            }
        } finally {
            alice.close();
            bob.close();
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
                expect(await delegate.scan("murmur/", { limit: 16 })).toEqual(new Map());
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
            prefixStore.transaction(async (transaction) => {
                await transaction.set("murmur/session-intents/add", new Uint8Array([1]));
                await transaction.set(`${OUTBOX_PREFIX}add`, new Uint8Array([2]));
            }),
        ).rejects.toThrow(`prefix ${OUTBOX_PREFIX}`);
        expect(await prefixDelegate.scan("murmur/", { limit: 4 })).toEqual(new Map());
    });

    test("ST-03/ST-04 buffer, callback drain, ack, and lost-response ordering stay durable", async () => {
        const delegate = new MemoryMurmurStore();
        const eventKey = `${APPLICATION_UPDATE_PREFIX}event-1`;
        const bufferKey = "murmur/session-data/session/buffer/event-1";
        const constrained = new CapacityMurmurStore(delegate, {
            failPrefix: APPLICATION_UPDATE_PREFIX,
        });
        await expect(
            constrained.transaction(async (transaction) => {
                await transaction.set(bufferKey, utf8Encode("sentinel application update"));
                await transaction.set(eventKey, utf8Encode("session"));
            }),
        ).rejects.toThrow("storage capacity failure");
        expect(await delegate.get(bufferKey)).toBeUndefined();
        expect(await delegate.get(eventKey)).toBeUndefined();
        expect(await delegate.get(ACK_KEY)).toBeUndefined();

        constrained.restoreCapacity();
        await constrained.transaction(async (transaction) => {
            await transaction.set(bufferKey, utf8Encode("sentinel application update"));
            await transaction.set(eventKey, utf8Encode("session"));
        });

        let callbacks = 0;
        callbacks += 1;
        const preCommitFailure = new CapacityMurmurStore(delegate, {
            failWriteOrdinals: [1],
        });
        await expect(
            preCommitFailure.transaction(async (transaction) => {
                await transaction.delete(bufferKey);
                await transaction.delete(eventKey);
                await transaction.set(`${DRAIN_PREFIX}event-1`, new Uint8Array());
                await transaction.set(ACK_KEY, utf8Encode("event-1"));
            }),
        ).rejects.toThrow("storage capacity failure");
        expect(await delegate.get(eventKey)).toBeDefined();
        expect(await delegate.get(ACK_KEY)).toBeUndefined();
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
            lostResponse.transaction(async (transaction) => {
                await transaction.delete(bufferKey);
                await transaction.delete(eventKey);
                await transaction.set(`${DRAIN_PREFIX}event-1`, new Uint8Array());
                await transaction.set(ACK_KEY, utf8Encode("event-1"));
            }),
        ).rejects.toThrow("lost transaction response");
        expect(await delegate.get(eventKey)).toBeUndefined();
        expect(await delegate.get(`${DRAIN_PREFIX}event-1`)).toEqual(new Uint8Array());
        expect(utf8Decode((await delegate.get(ACK_KEY))!)).toBe("event-1");
        expect(callbacks).toBe(2);
        schedule.assertConsumed();
    });

    test("ST-05 bounded scans cover zero, page edges, after cursors, and maximum limits", async () => {
        const sizes = [0, 1, NORMAL_SCAN_LIMIT - 1, NORMAL_SCAN_LIMIT, NORMAL_SCAN_LIMIT + 1];
        for (const prefix of BOUNDED_PREFIXES) {
            for (const size of sizes) {
                const store = new MemoryMurmurStore();
                await store.transaction(async (transaction) => {
                    for (let index = 0; index < size; index += 1) {
                        await transaction.set(
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

                const before = await store.scan(prefix, { after: `${prefix}!`, limit: 1 });
                expect([...before.keys()]).toEqual(expected.slice(0, 1));
                if (size > 0) {
                    const first = expected[0]!;
                    const afterExact = await store.scan(prefix, { after: first, limit: 1 });
                    expect([...afterExact.keys()]).toEqual(expected.slice(1, 2));
                    const last = expected.at(-1)!;
                    expect(await store.scan(prefix, { after: last, limit: 1 })).toEqual(new Map());
                    const absent = `${prefix}000000~`;
                    const afterAbsent = await store.scan(prefix, { after: absent, limit: 1 });
                    expect([...afterAbsent.keys()]).toEqual(
                        expected.filter((key) => key > absent).slice(0, 1),
                    );
                }
                await expect(
                    store.scan(prefix, { limit: MAXIMUM_STORE_SCAN_ITEMS + 1 }),
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
            const damaged = await alice.createSession({
                descriptor: utf8Encode("damaged chaos session"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, damaged.id);

            const healthy = await alice.createSession({
                descriptor: utf8Encode("healthy chaos session"),
                members: [await carol.discovery()],
            });
            await alice.synchronize();
            await carol.synchronize();
            await activate(carol, healthy.id);

            alice.close();
            aliceStore.clientClosed();
            bob.close();
            carol.close();
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
            await alice.send(healthy.id, utf8Encode("healthy after corruption"));
            const outcome = await alice.synchronize({ waitMilliseconds: 0 });
            expect(outcome.terminalPublicationFailures).toBe(1);
            expect(outcome.issues).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "corrupt_session_state",
                        sessionId: damaged.id,
                    }),
                ]),
            );
            expect(await alice.session(damaged.id)).toBeUndefined();
            expect(await alice.session(healthy.id)).toMatchObject({ status: "active" });

            await carol.synchronize({ waitMilliseconds: 0 });
            const received: string[] = [];
            expect(await consume(carol, received)).toBe(1);
            expect(received).toEqual(["healthy after corruption"]);
            const damagedUpdates: string[] = [];
            expect(await consume(bob, damagedUpdates)).toBe(0);
            expect(damagedUpdates).toEqual([]);
            expect(
                (await aliceStore.scan("murmur/session-quarantine/", { limit: 20 })).size,
            ).toBeLessThanOrEqual(1);
        } finally {
            alice.close();
            if (aliceStore.trace.length > 0) {
                try {
                    aliceStore.clientClosed();
                } catch {
                    // The mutation guard itself verifies balanced lifecycle transitions.
                }
            }
            bob.close();
            carol.close();
            await relay.close();
        }
    }, 120_000);

    test("ST-08 identity corruption fails closed and traces contain metadata only", async () => {
        const fixture = new InspectableStoreFixture();
        const transport = new OfflineTransport();
        let client = await MurmurClient.open({ store: fixture, transport, now: () => NOW });
        fixture.clientOpened();
        const publicIdentity = client.identity;
        client.close();
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
            const corrupted = await fixture.get(IDENTITY_KEY);
            await expect(
                MurmurClient.open({ store: fixture, transport, now: () => NOW }),
            ).rejects.toThrow();
            expect(await fixture.get(IDENTITY_KEY)).toEqual(corrupted);
            if (corrupted !== undefined) zeroBytes(corrupted);
        }

        await fixture.restoreExact(IDENTITY_KEY);
        client = await MurmurClient.open({ store: fixture, transport, now: () => NOW });
        fixture.clientOpened();
        expect(client.identity).toEqual(publicIdentity);
        await expect(fixture.flipExact(IDENTITY_KEY, 0)).rejects.toThrow(
            "requires every store client to be closed",
        );
        client.close();
        fixture.clientClosed();

        const sentinel = utf8Encode("ST-08 sentinel secret plaintext");
        await fixture.set("murmur/chaos/secret-bearing-record", sentinel);
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
            expect(await fixture.get(selected.key)).toBeUndefined();
            await fixture.restoreExact(selected.key);
            const swapped = RECORD_FIXTURES[(index + 1) % RECORD_FIXTURES.length]!;
            await fixture.replaceExact(selected.key, swapped.bytes);
            expect(await fixture.get(selected.key)).toEqual(swapped.bytes);
            await fixture.restoreExact(selected.key);
            const restored = await fixture.get(selected.key);
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
