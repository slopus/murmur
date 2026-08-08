import { hashBytes } from "../../crypto/index.js";
import type { StoreTransaction } from "../../storage/index.js";
import {
    concatBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
} from "../../utils/index.js";
import type {
    InboxDelivery,
    InboxDeliveryHandler,
    InboxProcessorDependencies,
    InboxProcessorOptions,
    InboxRejection,
    InboxStreamOptions,
    InboxSyncOptions,
    InboxSyncResult,
} from "../types.js";
import {
    DeliveryCursorTrimmedError,
    OversizedInboxDeliveryError,
} from "./deliveryHttpTransport.js";
import {
    containsRecipient,
    createSignedInboxAck,
    createSignedInboxRead,
    verifySignedDelivery,
} from "./deliveryCodec.js";
import { StagedStoreTransaction } from "./storeTransactionStage.js";

const CURSOR_KEY = "murmur/delivery/cursor";
const REJECTION_PREFIX = "murmur/delivery/rejections/";
const REPLAY_ENTRY_PREFIX = "murmur/delivery/replay/entries/";
const REPLAY_EXPIRY_PREFIX = "murmur/delivery/replay/expiry/";
const REPLAY_OVERFLOW_PREFIX = "murmur/delivery/replay/overflow/";
const REPLAY_TERMINAL_PREFIX = "murmur/delivery/replay/terminal/";
const REPLAY_COUNT_KEY = "murmur/delivery/replay/count";
const DEFAULT_MAXIMUM_REJECTIONS = 256;
const DEFAULT_MAXIMUM_REPLAY_ENTRIES = 10_000;
const DEFAULT_MAXIMUM_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1_000;
const DEFAULT_MAXIMUM_RELAY_CLOCK_SKEW_MILLISECONDS = 5 * 60 * 1_000;
const HARD_MAXIMUM_REPLAY_ENTRIES = 100_000;
const REPLAY_PRUNE_BATCH_SIZE = 100;
const REPLAY_PRUNE_BUDGET_MILLISECONDS = 1_000;
const REPLAY_OVERFLOW_EPOCH_MILLISECONDS = 90 * 24 * 60 * 60 * 1_000;
const REPLAY_OVERFLOW_SHARD_BYTES = 4 * 1_024;
const REPLAY_OVERFLOW_HASHES = 4;
const REPLAY_TERMINAL_RETAINED_EPOCHS = 3;
const REPLAY_TERMINAL_SHARDS_PER_EPOCH = 256;
const MAXIMUM_DELIVERY_TTL_MILLISECONDS = 90 * 24 * 60 * 60 * 1_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

interface RejectionJson {
    readonly version: 1;
    readonly eventId: string;
    readonly code: string;
}

interface ReplayJson {
    readonly version: 1;
    readonly fingerprint: string;
    readonly expiresAt: number;
}

/** @internal Capability used only by Murmur's built-in session handler. */
export const MURMUR_INTERNAL_INBOX_HANDLER = Symbol("murmur-internal-inbox-handler");

/** Marks a delivery as permanently invalid or unsupported for this client. */
export class TerminalInboxDeliveryError extends Error {
    /** Stable, non-secret rejection reason persisted for diagnostics. */
    readonly code: string;

    constructor(code: string, message: string = code) {
        if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(code)) {
            throw new Error("Invalid terminal inbox rejection code");
        }
        super(message);
        this.name = "TerminalInboxDeliveryError";
        this.code = code;
    }
}

/** Local durable inbox state predates a prefix already destroyed by the relay. */
export class InboxStateRollbackError extends Error {
    readonly localCursor: string | null;
    readonly acknowledgedThrough: string;

    constructor(localCursor: string | null, acknowledgedThrough: string) {
        super("Local inbox state was rolled back behind the relay acknowledgement");
        this.name = "InboxStateRollbackError";
        this.localCursor = localCursor;
        this.acknowledgedThrough = acknowledgedThrough;
    }
}

function cursorBytes(cursor: string): Uint8Array {
    if (!UUID_V7.test(cursor)) throw new Error("Invalid inbox cursor");
    return utf8Encode(cursor);
}

function parseCursor(bytes: Uint8Array | undefined): string | null {
    if (bytes === undefined) return null;
    const value = utf8Decode(bytes);
    if (!UUID_V7.test(value)) throw new Error("Invalid stored inbox cursor");
    return value;
}

function relayEventTime(eventId: string): number {
    if (!UUID_V7.test(eventId)) throw new Error("Invalid relay event time");
    const value = Number.parseInt(`${eventId.slice(0, 8)}${eventId.slice(9, 13)}`, 16);
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("Invalid relay event time");
    }
    return value;
}

function rejectionBytes(eventId: string, code: string): Uint8Array {
    return utf8Encode(JSON.stringify({ version: 1, eventId, code } satisfies RejectionJson));
}

function parseRejection(bytes: Uint8Array): InboxRejection {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid stored inbox rejection");
    }
    if (
        parsed === null ||
        typeof parsed !== "object" ||
        Array.isArray(parsed) ||
        (parsed as Record<string, unknown>).version !== 1 ||
        typeof (parsed as Record<string, unknown>).eventId !== "string" ||
        typeof (parsed as Record<string, unknown>).code !== "string" ||
        Object.keys(parsed).some((field) => !["version", "eventId", "code"].includes(field))
    ) {
        throw new Error("Invalid stored inbox rejection");
    }
    const value = parsed as unknown as RejectionJson;
    if (!UUID_V7.test(value.eventId)) throw new Error("Invalid stored inbox rejection");
    return { eventId: value.eventId, code: value.code };
}

/** Stateful, crash-safe processor for one identity's relay inbox. */
export class InboxProcessor {
    readonly #dependencies: InboxProcessorDependencies;
    readonly #handler: InboxDeliveryHandler;
    readonly #maximumRejections: number;
    readonly #maximumReplayEntries: number;
    readonly #maximumFutureSkewMilliseconds: number;
    readonly #maximumRelayClockSkewMilliseconds: number;
    readonly #now: () => number;
    readonly #allowMurmurMutations: boolean;
    #tail: Promise<void> = Promise.resolve();
    #streamActive = false;

    constructor(
        dependencies: InboxProcessorDependencies,
        handler: InboxDeliveryHandler,
        options: InboxProcessorOptions = {},
        internalAccess?: typeof MURMUR_INTERNAL_INBOX_HANDLER,
    ) {
        this.#dependencies = dependencies;
        this.#handler = handler;
        this.#maximumRejections = options.maximumRejections ?? DEFAULT_MAXIMUM_REJECTIONS;
        this.#maximumReplayEntries = options.maximumReplayEntries ?? DEFAULT_MAXIMUM_REPLAY_ENTRIES;
        this.#maximumFutureSkewMilliseconds =
            options.maximumFutureSkewMilliseconds ?? DEFAULT_MAXIMUM_FUTURE_SKEW_MILLISECONDS;
        this.#maximumRelayClockSkewMilliseconds =
            options.maximumRelayClockSkewMilliseconds ??
            DEFAULT_MAXIMUM_RELAY_CLOCK_SKEW_MILLISECONDS;
        this.#now = options.now ?? Date.now;
        this.#allowMurmurMutations = internalAccess === MURMUR_INTERNAL_INBOX_HANDLER;
        if (
            !Number.isSafeInteger(this.#maximumRejections) ||
            this.#maximumRejections < 1 ||
            this.#maximumRejections >= 10_000
        ) {
            throw new Error("Maximum inbox rejections must be between 1 and 9999");
        }
        if (
            !Number.isSafeInteger(this.#maximumReplayEntries) ||
            this.#maximumReplayEntries < 1 ||
            this.#maximumReplayEntries > HARD_MAXIMUM_REPLAY_ENTRIES ||
            !Number.isSafeInteger(this.#maximumFutureSkewMilliseconds) ||
            this.#maximumFutureSkewMilliseconds < 0 ||
            this.#maximumFutureSkewMilliseconds > 60 * 60 * 1_000 ||
            !Number.isSafeInteger(this.#maximumRelayClockSkewMilliseconds) ||
            this.#maximumRelayClockSkewMilliseconds < 0 ||
            this.#maximumRelayClockSkewMilliseconds > 24 * 60 * 60 * 1_000
        ) {
            throw new Error("Invalid inbox replay policy");
        }
    }

    /** Return the durable local cursor, or `null` before any terminal delivery. */
    async cursor(): Promise<string | null> {
        return parseCursor(await this.#dependencies.store.get(CURSOR_KEY));
    }

    /** Return retained terminal rejections in relay order. */
    async rejections(): Promise<readonly InboxRejection[]> {
        const entries = await this.#dependencies.store.scan(REJECTION_PREFIX, {
            limit: this.#maximumRejections,
        });
        return [...entries.values()].map(parseRejection);
    }

    /**
     * Read, transactionally apply or reject, then acknowledge one inbox page.
     *
     * Concurrent calls on one processor instance are serialized.
     */
    async synchronize(options: InboxSyncOptions = {}): Promise<InboxSyncResult> {
        if (this.#streamActive) {
            throw new Error("Cannot page an inbox while its event stream is active");
        }
        return this.#exclusive(async () => this.#synchronize(options));
    }

    /** Process and acknowledge exact queued events from one authenticated SSE stream. */
    async *stream(options: InboxStreamOptions): AsyncGenerator<InboxSyncResult> {
        if (this.#streamActive) {
            throw new Error("Inbox event stream is already active");
        }
        const openStream = this.#dependencies.transport.stream;
        if (openStream === undefined) {
            throw new Error("Delivery transport does not support event streaming");
        }
        this.#streamActive = true;
        try {
            let cursor = await this.cursor();
            if (cursor !== null) {
                await this.#pruneReplay(relayEventTime(cursor));
                try {
                    await this.#acknowledge(cursor, options.signal);
                } catch (error: unknown) {
                    if (error instanceof DeliveryCursorTrimmedError) {
                        throw new InboxStateRollbackError(cursor, error.acknowledgedThrough);
                    }
                    throw error;
                }
            }
            const request = createSignedInboxRead(this.#dependencies.identity, {
                after: cursor,
                limit: 1,
                waitMilliseconds: 0,
                createdAt: this.#requestTime(),
            });
            for await (const queued of openStream.call(
                this.#dependencies.transport,
                request,
                options.signal,
            )) {
                const result = await this.#exclusive(async () => {
                    cursor = await this.cursor();
                    if (cursor !== null && queued.eventId <= cursor) {
                        throw new Error("Relay returned an out-of-order inbox stream");
                    }
                    const processingNow = relayEventTime(queued.eventId);
                    this.#validateRelayEventTime(queued.eventId, this.#requestTime());
                    const outcome = await this.#process(queued, cursor, processingNow);
                    cursor = queued.eventId;
                    await this.#pruneReplay(processingNow);
                    await this.#acknowledge(cursor, options.signal);
                    return {
                        processed: outcome === "processed" ? 1 : 0,
                        rejected: outcome === "rejected" ? 1 : 0,
                        cursor,
                        exhausted: false,
                    } satisfies InboxSyncResult;
                });
                yield result;
            }
        } finally {
            this.#streamActive = false;
        }
    }

    async #synchronize(options: InboxSyncOptions): Promise<InboxSyncResult> {
        let cursor = await this.cursor();
        if (cursor !== null) {
            await this.#pruneReplay(relayEventTime(cursor));
            try {
                await this.#acknowledge(cursor, options.signal);
            } catch (error: unknown) {
                if (error instanceof DeliveryCursorTrimmedError) {
                    throw new InboxStateRollbackError(cursor, error.acknowledgedThrough);
                }
                throw error;
            }
        }

        let page;
        try {
            const requestedLimit = options.limit ?? 256;
            const readOptions = {
                after: cursor,
                limit: requestedLimit,
                ...(options.waitMilliseconds === undefined
                    ? {}
                    : { waitMilliseconds: options.waitMilliseconds }),
                createdAt: this.#requestTime(),
            };
            page = await this.#dependencies.transport.read(
                createSignedInboxRead(this.#dependencies.identity, readOptions),
                options.signal,
            );
            if (page.deliveries.length > requestedLimit) {
                throw new Error("Relay response exceeds the requested inbox page limit");
            }
        } catch (error: unknown) {
            if (error instanceof DeliveryCursorTrimmedError) {
                throw new InboxStateRollbackError(cursor, error.acknowledgedThrough);
            }
            if (!(error instanceof OversizedInboxDeliveryError)) throw error;
            if (
                (cursor !== null && error.eventId <= cursor) ||
                error.eventId > error.head ||
                (error.acknowledgedThrough !== null &&
                    (cursor === null || error.acknowledgedThrough > cursor))
            ) {
                throw new Error("Relay returned a non-advancing oversized delivery");
            }
            this.#validateRelayEventTime(error.eventId, this.#requestTime());
            await this.#persistTerminal(error.eventId, "delivery_too_large");
            cursor = error.eventId;
            await this.#pruneReplay(relayEventTime(cursor));
            await this.#acknowledge(cursor, options.signal);
            return { processed: 0, rejected: 1, cursor, exhausted: cursor === error.head };
        }
        let processed = 0;
        let rejected = 0;
        let previous = cursor;
        if (
            (page.head !== null && cursor !== null && page.head < cursor) ||
            (page.acknowledgedThrough !== null &&
                (cursor === null || page.acknowledgedThrough > cursor))
        ) {
            throw new Error("Relay returned inconsistent inbox metadata");
        }
        const pageRequestTime = this.#requestTime();
        for (const delivery of page.deliveries) {
            if (
                (previous !== null && delivery.eventId <= previous) ||
                page.head === null ||
                delivery.eventId > page.head
            ) {
                throw new Error("Relay returned an out-of-order inbox page");
            }
            this.#validateRelayEventTime(delivery.eventId, pageRequestTime);
            previous = delivery.eventId;
        }

        previous = cursor;
        for (const delivery of page.deliveries) {
            const outcome = await this.#process(
                delivery,
                previous,
                relayEventTime(delivery.eventId),
            );
            processed += outcome === "processed" ? 1 : 0;
            rejected += outcome === "rejected" ? 1 : 0;
            previous = delivery.eventId;
        }
        cursor = previous;
        if (cursor !== null && (processed > 0 || rejected > 0)) {
            await this.#pruneReplay(relayEventTime(cursor));
            await this.#acknowledge(cursor, options.signal);
        }
        return { processed, rejected, cursor, exhausted: page.exhausted };
    }

    async #process(
        queued: InboxDelivery,
        expectedCursor: string | null,
        processingNow: number,
    ): Promise<"processed" | "rejected"> {
        return this.#dependencies.store.transaction(async (transaction) => {
            const actualCursor = parseCursor(await transaction.get(CURSOR_KEY));
            if (actualCursor !== expectedCursor) {
                throw new Error("Inbox cursor changed during synchronization");
            }
            let rejection: string | undefined;
            const digest = this.#replayDigest(queued);
            if (queued.delivery.expiresAt <= processingNow) {
                rejection = "expired_delivery";
            } else if (await this.#terminalContains(transaction, digest, processingNow)) {
                rejection = "probable_terminal_replay";
            } else if (!verifySignedDelivery(queued.delivery)) {
                rejection = "invalid_delivery";
                if (queued.delivery.expiresAt > processingNow) {
                    await this.#addTerminal(transaction, digest, processingNow);
                }
            } else if (!containsRecipient(queued.delivery, this.#dependencies.identity.publicKey)) {
                rejection = "invalid_recipient";
                if (queued.delivery.expiresAt > processingNow) {
                    await this.#addTerminal(transaction, digest, processingNow);
                }
            } else if (
                queued.delivery.expiresAt - processingNow >
                MAXIMUM_DELIVERY_TTL_MILLISECONDS
            ) {
                rejection = "delivery_ttl_too_long";
            } else if (
                queued.delivery.createdAt >
                processingNow + this.#maximumFutureSkewMilliseconds
            ) {
                rejection = "future_delivery";
            } else {
                const replay = await this.#registerReplay(transaction, queued, processingNow);
                if (replay !== "new") {
                    rejection = replay;
                } else {
                    const staged = new StagedStoreTransaction(
                        transaction,
                        this.#allowMurmurMutations,
                    );
                    try {
                        await this.#handler(staged, queued);
                        await staged.commit();
                    } catch (error: unknown) {
                        staged.discard();
                        if (!(error instanceof TerminalInboxDeliveryError)) throw error;
                        rejection = error.code;
                    }
                }
            }
            if (rejection !== undefined) {
                await this.#storeRejection(transaction, queued.eventId, rejection);
            }
            await transaction.set(CURSOR_KEY, cursorBytes(queued.eventId));
            return rejection === undefined ? "processed" : "rejected";
        });
    }

    async #persistTerminal(eventId: string, code: string): Promise<void> {
        await this.#dependencies.store.transaction(async (transaction) => {
            const cursor = parseCursor(await transaction.get(CURSOR_KEY));
            if (cursor !== null && eventId <= cursor) {
                throw new Error("Relay returned a non-advancing terminal delivery");
            }
            await this.#storeRejection(transaction, eventId, code);
            await transaction.set(CURSOR_KEY, cursorBytes(eventId));
        });
    }

    async #storeRejection(
        transaction: StoreTransaction,
        eventId: string,
        code: string,
    ): Promise<void> {
        const key = `${REJECTION_PREFIX}${eventId}`;
        await transaction.set(key, rejectionBytes(eventId, code));
        const entries = await transaction.scan(REJECTION_PREFIX, {
            limit: this.#maximumRejections + 1,
        });
        if (entries.size > this.#maximumRejections) {
            const oldest = entries.keys().next().value;
            if (typeof oldest === "string") await transaction.delete(oldest);
        }
    }

    async #registerReplay(
        transaction: StoreTransaction,
        queued: InboxDelivery,
        processingNow: number,
    ): Promise<
        | "new"
        | "duplicate_delivery"
        | "delivery_id_collision"
        | "probable_duplicate_delivery"
        | "replay_capacity"
    > {
        const key = this.#replayKey(queued);
        const existingBytes = await transaction.get(key);
        const fingerprint = this.#deliveryFingerprint(queued);
        if (existingBytes !== undefined) {
            const existing = this.#parseReplay(existingBytes);
            if (queued.delivery.expiresAt > existing.expiresAt) {
                await transaction.delete(this.#replayExpiryKey(existing.expiresAt, key));
                await transaction.set(
                    key,
                    this.#replayBytes(existing.fingerprint, queued.delivery.expiresAt),
                );
                await transaction.set(
                    this.#replayExpiryKey(queued.delivery.expiresAt, key),
                    new Uint8Array(),
                );
            }
            return equalBytes(existing.fingerprint, fingerprint)
                ? "duplicate_delivery"
                : "delivery_id_collision";
        }
        const digest = this.#replayDigest(queued);
        if (await this.#overflowContains(transaction, digest, processingNow)) {
            return "probable_duplicate_delivery";
        }
        const count = await this.#replayCount(transaction);
        if (count >= this.#maximumReplayEntries) {
            await this.#addOverflow(transaction, digest, processingNow);
            return "replay_capacity";
        }
        await transaction.set(key, this.#replayBytes(fingerprint, queued.delivery.expiresAt));
        await transaction.set(
            this.#replayExpiryKey(queued.delivery.expiresAt, key),
            new Uint8Array(),
        );
        await this.#setReplayCount(transaction, count + 1);
        return "new";
    }

    #replayKey(queued: InboxDelivery): string {
        return `${REPLAY_ENTRY_PREFIX}${encodeBase64Url(this.#replayDigest(queued))}`;
    }

    #replayDigest(queued: InboxDelivery): Uint8Array {
        return hashBytes(
            concatBytes(
                queued.delivery.sender,
                new Uint8Array([0]),
                utf8Encode(queued.delivery.id),
            ),
        );
    }

    #replayExpiryKey(expiresAt: number, entryKey: string): string {
        if (
            !Number.isSafeInteger(expiresAt) ||
            expiresAt < 0 ||
            !entryKey.startsWith(REPLAY_ENTRY_PREFIX)
        ) {
            throw new Error("Invalid delivery replay expiration");
        }
        return `${REPLAY_EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}/${entryKey.slice(
            REPLAY_ENTRY_PREFIX.length,
        )}`;
    }

    async #pruneReplay(processingNow: number): Promise<void> {
        const deadline = Date.now() + REPLAY_PRUNE_BUDGET_MILLISECONDS;
        for (;;) {
            const removed = await this.#dependencies.store.transaction(async (transaction) =>
                this.#pruneReplayBatch(transaction, processingNow),
            );
            if (removed < REPLAY_PRUNE_BATCH_SIZE || Date.now() >= deadline) return;
        }
    }

    async #pruneReplayBatch(transaction: StoreTransaction, now: number): Promise<number> {
        const indexes = await transaction.scan(REPLAY_EXPIRY_PREFIX, {
            limit: REPLAY_PRUNE_BATCH_SIZE,
        });
        let removed = 0;
        for (const key of indexes.keys()) {
            const suffix = key.slice(REPLAY_EXPIRY_PREFIX.length);
            const separator = suffix.indexOf("/");
            const expiryText = suffix.slice(0, separator);
            const digest = suffix.slice(separator + 1);
            if (
                separator !== 16 ||
                !/^\d{16}$/.test(expiryText) ||
                !/^[A-Za-z0-9_-]{43}$/.test(digest)
            ) {
                throw new Error("Invalid stored delivery replay expiration");
            }
            const expiresAt = Number(expiryText);
            if (!Number.isSafeInteger(expiresAt) || expiresAt > now) break;
            const entryKey = `${REPLAY_ENTRY_PREFIX}${digest}`;
            const bytes = await transaction.get(entryKey);
            if (bytes === undefined || this.#parseReplay(bytes).expiresAt !== expiresAt) {
                throw new Error("Inconsistent stored delivery replay index");
            }
            await transaction.delete(key);
            await transaction.delete(entryKey);
            removed += 1;
        }
        if (removed > 0) {
            const count = await this.#replayCount(transaction);
            if (count < removed) throw new Error("Invalid stored delivery replay count");
            await this.#setReplayCount(transaction, count - removed);
        }
        await this.#pruneOverflow(transaction, now);
        await this.#pruneTerminal(transaction, now);
        return removed;
    }

    async #overflowContains(
        transaction: StoreTransaction,
        digest: Uint8Array,
        now: number,
    ): Promise<boolean> {
        const epoch = Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS);
        for (const candidate of [epoch, epoch - 1]) {
            if (candidate < 0) continue;
            const bytes = await transaction.get(this.#overflowKey(candidate, digest[0] ?? 0));
            if (bytes === undefined) continue;
            this.#validateOverflowShard(bytes);
            if (this.#overflowPositions(digest).every((position) => this.#bit(bytes, position))) {
                return true;
            }
        }
        return false;
    }

    async #addOverflow(
        transaction: StoreTransaction,
        digest: Uint8Array,
        now: number,
    ): Promise<void> {
        const epoch = Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS);
        const key = this.#overflowKey(epoch, digest[0] ?? 0);
        const existing = await transaction.get(key);
        const shard = existing ?? new Uint8Array(REPLAY_OVERFLOW_SHARD_BYTES);
        this.#validateOverflowShard(shard);
        for (const position of this.#overflowPositions(digest)) {
            shard[Math.floor(position / 8)] =
                (shard[Math.floor(position / 8)] ?? 0) | (1 << (position % 8));
        }
        await transaction.set(key, shard);
    }

    async #pruneOverflow(transaction: StoreTransaction, now: number): Promise<void> {
        const oldestRetained = Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS) - 1;
        const entries = await transaction.scan(REPLAY_OVERFLOW_PREFIX, {
            limit: REPLAY_PRUNE_BATCH_SIZE,
        });
        for (const key of entries.keys()) {
            const suffix = key.slice(REPLAY_OVERFLOW_PREFIX.length);
            const separator = suffix.indexOf("/");
            const epochText = suffix.slice(0, separator);
            if (
                separator !== 12 ||
                !/^\d{12}$/.test(epochText) ||
                !/^[0-9a-f]{2}$/.test(suffix.slice(separator + 1))
            ) {
                throw new Error("Invalid stored delivery replay overflow key");
            }
            const epoch = Number(epochText);
            if (!Number.isSafeInteger(epoch)) {
                throw new Error("Invalid stored delivery replay overflow epoch");
            }
            if (epoch >= oldestRetained) break;
            await transaction.delete(key);
        }
    }

    #overflowKey(epoch: number, shard: number): string {
        if (
            !Number.isSafeInteger(epoch) ||
            epoch < 0 ||
            !Number.isSafeInteger(shard) ||
            shard < 0 ||
            shard > 255
        ) {
            throw new Error("Invalid delivery replay overflow key");
        }
        return `${REPLAY_OVERFLOW_PREFIX}${epoch.toString().padStart(12, "0")}/${shard
            .toString(16)
            .padStart(2, "0")}`;
    }

    #overflowPositions(digest: Uint8Array): readonly number[] {
        if (digest.length !== 32) throw new Error("Invalid delivery replay digest");
        const bits = REPLAY_OVERFLOW_SHARD_BYTES * 8;
        return Array.from({ length: REPLAY_OVERFLOW_HASHES }, (_, index) => {
            const offset = 1 + index * 4;
            return (
                ((((digest[offset] ?? 0) << 24) |
                    ((digest[offset + 1] ?? 0) << 16) |
                    ((digest[offset + 2] ?? 0) << 8) |
                    (digest[offset + 3] ?? 0)) >>>
                    0) %
                bits
            );
        });
    }

    #bit(bytes: Uint8Array, position: number): boolean {
        return ((bytes[Math.floor(position / 8)] ?? 0) & (1 << (position % 8))) !== 0;
    }

    #validateOverflowShard(bytes: Uint8Array): void {
        if (bytes.length !== REPLAY_OVERFLOW_SHARD_BYTES) {
            throw new Error("Invalid stored delivery replay overflow shard");
        }
    }

    async #terminalContains(
        transaction: StoreTransaction,
        digest: Uint8Array,
        now: number,
    ): Promise<boolean> {
        const epoch = Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS);
        for (let offset = 0; offset < REPLAY_TERMINAL_RETAINED_EPOCHS; offset += 1) {
            const candidate = epoch - offset;
            if (candidate < 0) continue;
            const bytes = await transaction.get(this.#terminalKey(candidate, digest[0] ?? 0));
            if (bytes === undefined) continue;
            this.#validateOverflowShard(bytes);
            if (this.#overflowPositions(digest).every((position) => this.#bit(bytes, position))) {
                return true;
            }
        }
        return false;
    }

    async #addTerminal(
        transaction: StoreTransaction,
        digest: Uint8Array,
        now: number,
    ): Promise<void> {
        const epoch = Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS);
        const key = this.#terminalKey(epoch, digest[0] ?? 0);
        const existing = await transaction.get(key);
        const shard = existing ?? new Uint8Array(REPLAY_OVERFLOW_SHARD_BYTES);
        this.#validateOverflowShard(shard);
        for (const position of this.#overflowPositions(digest)) {
            shard[Math.floor(position / 8)] =
                (shard[Math.floor(position / 8)] ?? 0) | (1 << (position % 8));
        }
        await transaction.set(key, shard);
    }

    async #pruneTerminal(transaction: StoreTransaction, now: number): Promise<void> {
        const oldestRetained =
            Math.floor(now / REPLAY_OVERFLOW_EPOCH_MILLISECONDS) -
            (REPLAY_TERMINAL_RETAINED_EPOCHS - 1);
        const entries = await transaction.scan(REPLAY_TERMINAL_PREFIX, {
            limit: REPLAY_TERMINAL_SHARDS_PER_EPOCH,
        });
        for (const key of entries.keys()) {
            const suffix = key.slice(REPLAY_TERMINAL_PREFIX.length);
            const separator = suffix.indexOf("/");
            const epochText = suffix.slice(0, separator);
            if (
                separator !== 12 ||
                !/^\d{12}$/.test(epochText) ||
                !/^[0-9a-f]{2}$/.test(suffix.slice(separator + 1))
            ) {
                throw new Error("Invalid stored delivery terminal replay key");
            }
            const epoch = Number(epochText);
            if (!Number.isSafeInteger(epoch)) {
                throw new Error("Invalid stored delivery terminal replay epoch");
            }
            if (epoch >= oldestRetained) break;
            await transaction.delete(key);
        }
    }

    #terminalKey(epoch: number, shard: number): string {
        if (
            !Number.isSafeInteger(epoch) ||
            epoch < 0 ||
            !Number.isSafeInteger(shard) ||
            shard < 0 ||
            shard > 255
        ) {
            throw new Error("Invalid delivery terminal replay shard");
        }
        return `${REPLAY_TERMINAL_PREFIX}${epoch.toString().padStart(12, "0")}/${shard
            .toString(16)
            .padStart(2, "0")}`;
    }

    async #replayCount(transaction: StoreTransaction): Promise<number> {
        const bytes = await transaction.get(REPLAY_COUNT_KEY);
        if (bytes === undefined) return 0;
        const value = utf8Decode(bytes);
        if (!/^(0|[1-9]\d*)$/.test(value)) {
            throw new Error("Invalid stored delivery replay count");
        }
        const count = Number(value);
        if (!Number.isSafeInteger(count) || count < 0 || count > HARD_MAXIMUM_REPLAY_ENTRIES) {
            throw new Error("Invalid stored delivery replay count");
        }
        return count;
    }

    async #setReplayCount(transaction: StoreTransaction, count: number): Promise<void> {
        if (!Number.isSafeInteger(count) || count < 0 || count > HARD_MAXIMUM_REPLAY_ENTRIES) {
            throw new Error("Invalid delivery replay count");
        }
        if (count === 0) {
            await transaction.delete(REPLAY_COUNT_KEY);
        } else {
            await transaction.set(REPLAY_COUNT_KEY, utf8Encode(count.toString()));
        }
    }

    #deliveryFingerprint(queued: InboxDelivery): Uint8Array {
        return hashBytes(
            concatBytes(
                queued.delivery.sender,
                queued.delivery.signature,
                utf8Encode(queued.delivery.id),
            ),
        );
    }

    #replayBytes(fingerprint: Uint8Array, expiresAt: number): Uint8Array {
        return utf8Encode(
            JSON.stringify({
                version: 1,
                fingerprint: encodeBase64Url(fingerprint),
                expiresAt,
            } satisfies ReplayJson),
        );
    }

    #parseReplay(bytes: Uint8Array): {
        readonly fingerprint: Uint8Array;
        readonly expiresAt: number;
    } {
        let parsed: unknown;
        try {
            parsed = JSON.parse(utf8Decode(bytes)) as unknown;
        } catch {
            throw new Error("Invalid stored delivery replay record");
        }
        if (
            parsed === null ||
            typeof parsed !== "object" ||
            Array.isArray(parsed) ||
            (parsed as Record<string, unknown>).version !== 1 ||
            typeof (parsed as Record<string, unknown>).fingerprint !== "string" ||
            typeof (parsed as Record<string, unknown>).expiresAt !== "number" ||
            Object.keys(parsed).some(
                (field) => !["version", "fingerprint", "expiresAt"].includes(field),
            )
        ) {
            throw new Error("Invalid stored delivery replay record");
        }
        const record = parsed as unknown as ReplayJson;
        const fingerprint = decodeBase64Url(record.fingerprint);
        if (
            fingerprint.length !== 32 ||
            encodeBase64Url(fingerprint) !== record.fingerprint ||
            !Number.isSafeInteger(record.expiresAt) ||
            record.expiresAt < 0
        ) {
            throw new Error("Invalid stored delivery replay record");
        }
        return { fingerprint, expiresAt: record.expiresAt };
    }

    async #acknowledge(cursor: string, signal?: AbortSignal): Promise<void> {
        await this.#dependencies.transport.acknowledge(
            createSignedInboxAck(this.#dependencies.identity, cursor, this.#requestTime()),
            signal,
        );
    }

    #requestTime(): number {
        const now = this.#now();
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Invalid inbox processor clock");
        }
        return now;
    }

    #validateRelayEventTime(eventId: string, localNow: number): void {
        const eventTime = relayEventTime(eventId);
        const earliest =
            localNow - MAXIMUM_DELIVERY_TTL_MILLISECONDS - this.#maximumRelayClockSkewMilliseconds;
        const latest = localNow + this.#maximumRelayClockSkewMilliseconds;
        if (eventTime < earliest || eventTime > latest) {
            throw new Error("Relay event time is outside the trusted clock window");
        }
    }

    async #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#tail;
        this.#tail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await prior;
        try {
            return await operation();
        } finally {
            release?.();
        }
    }
}
