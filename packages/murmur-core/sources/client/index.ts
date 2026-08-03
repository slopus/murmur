import type { IdentityKeyPair } from "../crypto/index.js";
import { destroyIdentity, generateIdentityKeyPair } from "../crypto/index.js";
import { identityId } from "../identity/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    createRelayBlob,
    createRelayEvent,
    equalRelayEvents,
    verifyRelayBlob,
    verifyRelayEvent,
    type ListOperation,
    type RelayBlob,
    type RelayTransport,
    type SignedRelayEvent,
    type SnapshotMutation,
} from "../transport/index.js";
import { encodeBase64Url, equalBytes, utf8Decode, utf8Encode } from "../utils/index.js";
import { decodeOutboundRecord, encodeOutboundRecord } from "./impl/eventCodec.js";
import type {
    LoadedTopicState,
    PublishResult,
    ReceivedEvent,
    RetryOutboundReport,
    SyncResult,
    TopicResetRequired,
} from "./types.js";

export type {
    LoadedTopicState,
    PublishResult,
    ReceivedEvent,
    RelayPublishResult,
    RetryOutboundFailure,
    RetryOutboundReport,
    SyncResult,
    TopicResetRequired,
} from "./types.js";

const DEFAULT_OUTBOUND_HISTORY = 256;
const DEFAULT_EVENT_PAGE_LIMIT = 100;

function isAborted(signal: AbortSignal | undefined): boolean {
    return signal?.aborted === true;
}

function cursorBytes(cursor: bigint): Uint8Array {
    return utf8Encode(cursor.toString());
}

function parseCursor(value: Uint8Array | undefined): bigint {
    if (value === undefined) {
        return 0n;
    }
    const text = utf8Decode(value);
    if (!/^(0|[1-9]\d*)$/.test(text)) {
        throw new Error("Invalid persisted Murmur topic cursor");
    }
    return BigInt(text);
}

function equalOptionalBytes(left: Uint8Array | undefined, right: Uint8Array | undefined): boolean {
    return (
        (left === undefined && right === undefined) ||
        (left !== undefined && right !== undefined && equalBytes(left, right))
    );
}

function equalListOperation(left: ListOperation, right: ListOperation): boolean {
    if (left.op !== right.op || left.id !== right.id) {
        return false;
    }
    if (left.op === "append" && right.op === "append") {
        return equalBytes(left.bytes, right.bytes);
    }
    if (left.op === "replace" && right.op === "replace") {
        return (
            left.expectedVersion === right.expectedVersion && equalBytes(left.bytes, right.bytes)
        );
    }
    return (
        left.op === "delete" &&
        right.op === "delete" &&
        left.expectedVersion === right.expectedVersion
    );
}

function equalEventApplication(left: SignedRelayEvent, right: SignedRelayEvent): boolean {
    const leftList = left.list ?? [];
    const rightList = right.list ?? [];
    return (
        left.topic === right.topic &&
        equalBytes(left.author.signingKey, right.author.signingKey) &&
        equalBytes(left.payload, right.payload) &&
        left.snapshot?.expectedVersion === right.snapshot?.expectedVersion &&
        equalOptionalBytes(left.snapshot?.bytes, right.snapshot?.bytes) &&
        leftList.length === rightList.length &&
        leftList.every((operation, index) => {
            const candidate = rightList[index];
            return candidate !== undefined && equalListOperation(operation, candidate);
        })
    );
}

/** Durable topic client over one or more fixed-contract relays. */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #transports: readonly RelayTransport[];
    readonly #transportById: ReadonlyMap<string, RelayTransport>;
    readonly #topics = new Set<string>();
    readonly #outboundHistoryLimit: number;
    readonly #cursorPrefix: string;
    readonly #outboundPrefix: string;

    constructor(options: {
        identity: IdentityKeyPair;
        store: MurmurStore;
        transports: readonly RelayTransport[];
        outboundHistoryLimit?: number;
    }) {
        if (options.transports.length === 0) {
            throw new Error("At least one transport is required");
        }
        const transportIds = new Set(options.transports.map((transport) => transport.id));
        if (transportIds.size !== options.transports.length) {
            throw new Error("Transport identifiers must be unique");
        }
        const outboundHistoryLimit = options.outboundHistoryLimit ?? DEFAULT_OUTBOUND_HISTORY;
        if (!Number.isSafeInteger(outboundHistoryLimit) || outboundHistoryLimit < 1) {
            throw new Error("Outbound history limit must be a positive safe integer");
        }
        this.#identity = options.identity;
        this.#store = options.store;
        this.#transports = [...options.transports];
        this.#transportById = new Map(
            this.#transports.map((transport) => [transport.id, transport] as const),
        );
        this.#outboundHistoryLimit = outboundHistoryLimit;
        const owner = identityId(options.identity);
        this.#cursorPrefix = `client/${owner}/cursor/`;
        this.#outboundPrefix = `client/${owner}/outbound/`;
    }

    /**
     * Follow a topic locally.
     *
     * Relays have no subscription state. This only adds the topic to this
     * client's synchronization set; persisted cursors remain in `MurmurStore`.
     */
    async subscribe(topic: string): Promise<void> {
        if (!/^[A-Za-z0-9_.:-]{1,512}$/.test(topic)) {
            throw new Error("Invalid relay topic");
        }
        this.#topics.add(topic);
    }

    /** Publish opaque bytes with optional atomic snapshot/list mutations. */
    async publish(
        topic: string,
        payload: Uint8Array,
        mutations: {
            readonly snapshot?: SnapshotMutation;
            readonly list?: readonly ListOperation[];
        } = {},
    ): Promise<PublishResult> {
        return this.publishEvent(createRelayEvent(this.#identity, topic, payload, mutations));
    }

    /**
     * Publish with a one-use relay signing identity.
     *
     * The opaque payload must carry its own end-to-end authentication. This is
     * intended for public first-contact inboxes where the ordinary event author
     * would identify the requester.
     */
    async publishUnlinkable(
        topic: string,
        payload: Uint8Array,
        mutations: {
            readonly snapshot?: SnapshotMutation;
            readonly list?: readonly ListOperation[];
        } = {},
    ): Promise<PublishResult> {
        const ephemeralAuthor = generateIdentityKeyPair();
        try {
            return this.#publishPreparedEvent(
                createRelayEvent(ephemeralAuthor, topic, payload, mutations),
                false,
            );
        } finally {
            destroyIdentity(ephemeralAuthor);
        }
    }

    /**
     * Durably publish one pre-created event owned by this client identity.
     *
     * Reusing the same event resumes its existing relay-acceptance record.
     */
    async publishEvent(event: SignedRelayEvent): Promise<PublishResult> {
        return this.#publishPreparedEvent(event, true);
    }

    /**
     * Atomically supersede one retained event with freshly signed,
     * content-equivalent bytes, then publish the replacement.
     *
     * Stable application/list IDs must provide logical idempotency because a
     * relay which accepted the prior event may also accept the replacement.
     */
    async replaceOutboundEvent(
        previous: SignedRelayEvent,
        replacement: SignedRelayEvent,
    ): Promise<PublishResult> {
        if (
            !verifyRelayEvent(previous) ||
            !verifyRelayEvent(replacement) ||
            !equalBytes(previous.author.signingKey, this.#identity.signingKey) ||
            !equalBytes(replacement.author.signingKey, this.#identity.signingKey) ||
            previous.id === replacement.id ||
            replacement.createdAt < previous.createdAt ||
            !equalEventApplication(previous, replacement)
        ) {
            throw new Error("Replacement relay event does not match retained application state");
        }
        const previousKey = this.#outboundKey(previous);
        const replacementKey = this.#outboundKey(replacement);
        const publishedRelayIds = await this.#store.transaction(async (transaction) => {
            const previousBytes = await transaction.get(previousKey);
            let published = new Set<string>();
            if (previousBytes !== undefined) {
                const record = decodeOutboundRecord(previousBytes);
                if (!equalRelayEvents(record.event, previous)) {
                    throw new Error("Previous relay event collides with retained outbound state");
                }
                published = new Set(record.publishedRelayIds);
            }
            const replacementBytes = await transaction.get(replacementKey);
            if (replacementBytes === undefined) {
                await transaction.set(
                    replacementKey,
                    encodeOutboundRecord(replacement, [...published]),
                );
            } else {
                const record = decodeOutboundRecord(replacementBytes);
                if (!equalRelayEvents(record.event, replacement)) {
                    throw new Error(
                        "Replacement relay event collides with retained outbound state",
                    );
                }
                for (const relayId of record.publishedRelayIds) {
                    published.add(relayId);
                }
                await transaction.set(
                    replacementKey,
                    encodeOutboundRecord(replacement, [...published]),
                );
            }
            await transaction.delete(previousKey);
            return [...published];
        });
        const result = await this.#publishRecord(replacementKey, replacement, publishedRelayIds);
        await this.#pruneOutboundHistory();
        return result;
    }

    async #publishPreparedEvent(
        event: SignedRelayEvent,
        requireClientAuthor: boolean,
    ): Promise<PublishResult> {
        if (
            !verifyRelayEvent(event) ||
            (requireClientAuthor && !equalBytes(event.author.signingKey, this.#identity.signingKey))
        ) {
            throw new Error("Prepared relay event is not owned by this Murmur client");
        }
        const key = this.#outboundKey(event);
        const existing = await this.#store.get(key);
        let publishedRelayIds: readonly string[] = [];
        if (existing === undefined) {
            await this.#store.set(key, encodeOutboundRecord(event, []));
        } else {
            const record = decodeOutboundRecord(existing);
            if (!equalRelayEvents(record.event, event)) {
                throw new Error("Prepared relay event collides with retained outbound state");
            }
            publishedRelayIds = record.publishedRelayIds;
        }
        const result = await this.#publishRecord(key, event, publishedRelayIds);
        await this.#pruneOutboundHistory();
        return result;
    }

    /** Retry retained events on transports which have not accepted them. */
    async retryOutbound(): Promise<readonly PublishResult[]> {
        const report = await this.retryOutboundSettled();
        if (report.failures.length > 0) {
            throw new AggregateError(
                report.failures.map((failure) => failure.error),
                "Some retained Murmur events remain unpublished",
            );
        }
        return report.results;
    }

    /** Retry every retained event independently and report all failures. */
    async retryOutboundSettled(): Promise<RetryOutboundReport> {
        const records = await this.#store.list(this.#outboundPrefix);
        const results: PublishResult[] = [];
        const failures: RetryOutboundReport["failures"][number][] = [];
        for (const [key, value] of [...records].sort(([left], [right]) =>
            left.localeCompare(right),
        )) {
            const record = decodeOutboundRecord(value);
            try {
                results.push(
                    await this.#publishRecord(key, record.event, record.publishedRelayIds),
                );
            } catch (error: unknown) {
                failures.push({
                    event: record.event,
                    error: error instanceof Error ? error : new Error(String(error)),
                });
            }
        }
        await this.#pruneOutboundHistory();
        return { results, failures };
    }

    /**
     * Read retained events after durable per-relay topic cursors.
     *
     * If any relay reports `reset`, no events are returned. The caller must
     * explicitly reload each reported topic with `loadTopic` before retrying.
     */
    async sync(waitMilliseconds: number = 0, signal?: AbortSignal): Promise<SyncResult> {
        const topics = [...this.#topics].sort();
        const reads = await Promise.allSettled(
            this.#transports.flatMap((transport) =>
                topics.map(async (topic) => {
                    const cursor = await this.#readCursor(transport.id, topic);
                    return {
                        transport,
                        topic,
                        cursor,
                        page: await transport.readEvents(
                            topic,
                            cursor,
                            DEFAULT_EVENT_PAGE_LIMIT,
                            waitMilliseconds,
                            signal,
                        ),
                    };
                }),
            ),
        );
        if (reads.length > 0 && !reads.some((read) => read.status === "fulfilled")) {
            throw new Error("Every transport failed while reading events");
        }
        const resets: TopicResetRequired[] = [];
        for (const read of reads) {
            if (read.status === "fulfilled" && read.value.page?.reset === true) {
                resets.push({
                    kind: "reset",
                    relayId: read.value.transport.id,
                    topic: read.value.topic,
                    requestedSince: read.value.cursor,
                    head: read.value.page.seq,
                });
            }
        }
        if (resets.length > 0) {
            return { status: "reset", resets };
        }

        const events: ReceivedEvent[] = [];
        for (const read of reads) {
            if (read.status !== "fulfilled" || read.value.page === undefined) {
                continue;
            }
            let expectedSequence = read.value.cursor;
            for (const retained of read.value.page.events) {
                if (
                    retained.seq !== expectedSequence + 1n ||
                    retained.event.topic !== read.value.topic ||
                    !verifyRelayEvent(retained.event)
                ) {
                    throw new Error(
                        `Relay ${read.value.transport.id} returned an invalid event sequence`,
                    );
                }
                expectedSequence = retained.seq;
                const cursorKey = this.#cursorKey(read.value.transport.id, read.value.topic);
                events.push({
                    kind: "event",
                    relayId: read.value.transport.id,
                    seq: retained.seq,
                    event: retained.event,
                    advanceCursor: async (transaction): Promise<void> => {
                        await this.#advanceCursor(transaction, cursorKey, retained.seq);
                    },
                });
            }
        }
        return {
            status: "events",
            events: events.sort(
                (left, right) =>
                    left.relayId.localeCompare(right.relayId) ||
                    left.event.topic.localeCompare(right.event.topic) ||
                    (left.seq < right.seq ? -1 : left.seq > right.seq ? 1 : 0),
            ),
        };
    }

    /** Yield near-realtime events while making reset handling mandatory. */
    async *events(
        signal?: AbortSignal,
        waitMilliseconds: number = 25_000,
    ): AsyncIterable<ReceivedEvent> {
        for (;;) {
            if (isAborted(signal)) {
                return;
            }
            const result = await this.sync(waitMilliseconds, signal);
            if (result.status === "reset") {
                const reset = result.resets[0];
                throw new Error(
                    reset === undefined
                        ? "Relay topic reset required"
                        : `Relay topic reset required for ${reset.topic} on ${reset.relayId}`,
                );
            }
            for (const event of result.events) {
                if (isAborted(signal)) {
                    return;
                }
                yield event;
            }
        }
    }

    /**
     * Load permanent snapshot/list state and atomically install its cursor.
     *
     * The application callback runs in the same transaction as the new cursor.
     */
    async loadTopic<Result>(
        topic: string,
        operation: (transaction: StoreTransaction, state: LoadedTopicState) => Promise<Result>,
        relayId: string = this.#transports[0]?.id ?? "",
    ): Promise<Result> {
        const transport = this.#transportById.get(relayId);
        if (transport === undefined) {
            throw new Error(`Unknown relay transport ${relayId}`);
        }
        const state = await transport.readState(topic, DEFAULT_EVENT_PAGE_LIMIT);
        const elements = [...(state?.list.elements ?? [])];
        let nextCursor = state?.list.nextCursor ?? null;
        while (nextCursor !== null) {
            const page = await transport.readList(topic, nextCursor, DEFAULT_EVENT_PAGE_LIMIT);
            if (page === undefined) {
                throw new Error("Relay topic disappeared while loading its permanent list");
            }
            elements.push(...page.elements);
            nextCursor = page.nextCursor;
        }
        const loaded: LoadedTopicState = {
            relayId,
            topic,
            seq: state?.seq ?? 0n,
            snapshot: state?.snapshot ?? null,
            elements,
        };
        return this.#store.transaction(async (transaction) => {
            const result = await operation(transaction, loaded);
            await transaction.set(this.#cursorKey(relayId, topic), cursorBytes(loaded.seq));
            return result;
        });
    }

    /** Upload ciphertext to all reachable relays and return its content ID. */
    async putBlob(ciphertext: Uint8Array): Promise<RelayBlob> {
        const blob = createRelayBlob(ciphertext);
        const attempts = await Promise.allSettled(
            this.#transports.map(async (transport) => transport.putBlob(blob)),
        );
        if (!attempts.some((attempt) => attempt.status === "fulfilled")) {
            throw new Error("Every transport rejected the blob");
        }
        return blob;
    }

    /** Download a ciphertext blob from the first relay with a valid copy. */
    async getBlob(id: string): Promise<RelayBlob | undefined> {
        for (const transport of this.#transports) {
            try {
                const blob = await transport.getBlob(id);
                if (blob !== undefined) {
                    if (!verifyRelayBlob(blob)) {
                        throw new Error(`Relay ${transport.id} returned a corrupt blob`);
                    }
                    return blob;
                }
            } catch {
                // Try the next independently configured relay.
            }
        }
        return undefined;
    }

    async #publishRecord(
        key: string,
        event: SignedRelayEvent,
        previouslyPublishedRelayIds: readonly string[],
    ): Promise<PublishResult> {
        const published = new Set(previouslyPublishedRelayIds);
        const pending = this.#transports.filter((transport) => !published.has(transport.id));
        const attempts = await Promise.allSettled(
            pending.map(async (transport) => ({
                relayId: transport.id,
                outcome: await transport.publish(event),
            })),
        );
        const publications: PublishResult["publications"][number][] = [];
        const failedRelayIds: string[] = [];
        for (let index = 0; index < attempts.length; index += 1) {
            const attempt = attempts[index];
            const transport = pending[index];
            if (attempt?.status === "fulfilled") {
                published.add(attempt.value.relayId);
                publications.push(attempt.value);
            } else if (transport !== undefined) {
                failedRelayIds.push(transport.id);
            }
        }
        await this.#store.set(key, encodeOutboundRecord(event, [...published]));
        if (published.size === 0) {
            throw new Error("Every transport rejected the event");
        }
        return {
            event,
            publications,
            publishedRelayIds: [...published].sort(),
            failedRelayIds: failedRelayIds.sort(),
        };
    }

    #cursorKey(relayId: string, topic: string): string {
        return `${this.#cursorPrefix}${encodeBase64Url(utf8Encode(relayId))}/${topic}`;
    }

    #outboundKey(event: SignedRelayEvent): string {
        return `${this.#outboundPrefix}${event.createdAt.toString().padStart(16, "0")}/${event.id}`;
    }

    async #readCursor(relayId: string, topic: string): Promise<bigint> {
        return parseCursor(await this.#store.get(this.#cursorKey(relayId, topic)));
    }

    async #advanceCursor(
        transaction: StoreTransaction,
        key: string,
        sequence: bigint,
    ): Promise<void> {
        const current = parseCursor(await transaction.get(key));
        if (sequence <= current) {
            return;
        }
        if (sequence !== current + 1n) {
            throw new Error(
                `Cannot advance Murmur topic cursor from ${current.toString()} to ${sequence.toString()}`,
            );
        }
        await transaction.set(key, cursorBytes(sequence));
    }

    async #pruneOutboundHistory(): Promise<void> {
        const transportIds = new Set(this.#transports.map((transport) => transport.id));
        const records = [...(await this.#store.list(this.#outboundPrefix))]
            .filter(([, value]) => {
                const record = decodeOutboundRecord(value);
                return [...transportIds].every((id) => record.publishedRelayIds.includes(id));
            })
            .map(([key]) => key)
            .sort();
        const excess = records.length - this.#outboundHistoryLimit;
        if (excess <= 0) {
            return;
        }
        await this.#store.transaction(async (transaction) => {
            for (const key of records.slice(0, excess)) {
                await transaction.delete(key);
            }
        });
    }
}
