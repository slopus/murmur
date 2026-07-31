import {
    RelayError,
    isElementId,
    isEventId,
    isTopicId,
    relayEventFingerprint,
    verifyRelayEventSignature,
    type RelayBlob,
    type SignedRelayEvent,
} from "../protocol/index.js";
import type {
    EventPage,
    ListPage,
    PageReadConstraints,
    PublishOutcome,
    RelayStore,
    TopicState,
} from "../storage/index.js";
import { isBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { InProcessWakeSource } from "./impl/wakeInProcess.js";
import type { RelayOptions, RelayPruneOutcome, ResolvedRelayOptions, WakeSource } from "./types.js";

export { InProcessWakeSource } from "./impl/wakeInProcess.js";
export { PostgresWakeSource } from "./impl/wakePostgres.js";
export type { RelayOptions, RelayPruneOutcome, ResolvedRelayOptions, WakeSource } from "./types.js";

const MEBIBYTE = 1024 * 1024;
const FIVE_MINUTES = 5 * 60 * 1_000;
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1_000;
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1_000;
const HARD_MAXIMUM_LONG_POLL_MILLISECONDS = 30_000;

interface Waiter {
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
}

function positiveSafeInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return value;
}

function resolveOptions(options: RelayOptions): ResolvedRelayOptions {
    const resolved: ResolvedRelayOptions = {
        maximumEventPayloadBytes: positiveSafeInteger(
            options.maximumEventPayloadBytes ?? MEBIBYTE,
            "Maximum event payload bytes",
        ),
        maximumSnapshotBytes: positiveSafeInteger(
            options.maximumSnapshotBytes ?? 4 * MEBIBYTE,
            "Maximum snapshot bytes",
        ),
        maximumListElementBytes: positiveSafeInteger(
            options.maximumListElementBytes ?? 256 * 1024,
            "Maximum list element bytes",
        ),
        maximumListOperationsPerEvent: positiveSafeInteger(
            options.maximumListOperationsPerEvent ?? 256,
            "Maximum list operations per event",
        ),
        maximumElementsPerTopic: positiveSafeInteger(
            options.maximumElementsPerTopic ?? 100_000,
            "Maximum elements per topic",
        ),
        maximumBlobBytes: positiveSafeInteger(
            options.maximumBlobBytes ?? 64 * MEBIBYTE,
            "Maximum blob bytes",
        ),
        maximumJsonBodyBytes: positiveSafeInteger(
            options.maximumJsonBodyBytes ?? 8 * MEBIBYTE,
            "Maximum JSON body bytes",
        ),
        maximumEventsPerRead: positiveSafeInteger(
            options.maximumEventsPerRead ?? 256,
            "Maximum events per read",
        ),
        maximumListElementsPerPage: positiveSafeInteger(
            options.maximumListElementsPerPage ?? 256,
            "Maximum list elements per page",
        ),
        maximumLongPollMilliseconds: positiveSafeInteger(
            options.maximumLongPollMilliseconds ?? HARD_MAXIMUM_LONG_POLL_MILLISECONDS,
            "Maximum long poll milliseconds",
        ),
        maximumConcurrentLongPolls: positiveSafeInteger(
            options.maximumConcurrentLongPolls ?? 10_000,
            "Maximum concurrent long polls",
        ),
        eventRetentionMilliseconds: positiveSafeInteger(
            options.eventRetentionMilliseconds ?? SEVEN_DAYS,
            "Event retention milliseconds",
        ),
        topicInactivityMilliseconds: positiveSafeInteger(
            options.topicInactivityMilliseconds ?? THIRTY_DAYS,
            "Topic inactivity milliseconds",
        ),
    };
    if (resolved.maximumLongPollMilliseconds > HARD_MAXIMUM_LONG_POLL_MILLISECONDS) {
        throw new Error("Maximum long poll cannot exceed 30 seconds");
    }
    return resolved;
}

function abortError(signal: AbortSignal): Error {
    return signal.reason instanceof Error ? signal.reason : new Error("Long poll aborted");
}

/** Policy and realtime orchestration over one opaque relay store. */
export class RelayService {
    readonly #store: RelayStore;
    readonly #wakeSource: WakeSource;
    readonly #now: () => number;
    readonly #options: ResolvedRelayOptions;
    readonly #waiters = new Map<string, Set<Waiter>>();
    #waiterCount = 0;
    #closed = false;

    constructor(
        store: RelayStore,
        options: RelayOptions = {},
        wakeSource: WakeSource = new InProcessWakeSource(),
        now: () => number = Date.now,
    ) {
        this.#store = store;
        this.#options = resolveOptions(options);
        this.#wakeSource = wakeSource;
        this.#now = now;
        void this.#wakeSource
            .subscribe((topic) => {
                this.#wake(topic);
            })
            .catch(() => {
                // The timeout/read backstop preserves correctness without realtime wakes.
            });
    }

    /** Resolved immutable limits used by transport adapters before buffering bodies. */
    get options(): ResolvedRelayOptions {
        return this.#options;
    }

    /** Validate and atomically publish one signed event. */
    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        this.#assertOpen();
        if (
            event.version !== 1 ||
            !isEventId(event.id) ||
            !isTopicId(event.topic) ||
            !Number.isSafeInteger(event.createdAt) ||
            event.createdAt < 0 ||
            !(event.payload instanceof Uint8Array) ||
            !(event.author.signingKey instanceof Uint8Array) ||
            event.author.signingKey.length !== 32 ||
            !(event.signature instanceof Uint8Array) ||
            event.signature.length !== 64 ||
            (event.snapshot !== undefined &&
                (!Number.isSafeInteger(event.snapshot.expectedVersion) ||
                    event.snapshot.expectedVersion < 0 ||
                    (event.snapshot.bytes !== undefined &&
                        !(event.snapshot.bytes instanceof Uint8Array)))) ||
            (event.list !== undefined && !Array.isArray(event.list))
        ) {
            throw new RelayError(400, "Invalid relay event", { error: "malformed" });
        }
        if (event.payload.length > this.#options.maximumEventPayloadBytes) {
            throw new RelayError(413, "Event payload exceeds relay limit", {
                error: "limit",
            });
        }
        if (
            event.snapshot?.bytes !== undefined &&
            event.snapshot.bytes.length > this.#options.maximumSnapshotBytes
        ) {
            throw new RelayError(413, "Snapshot exceeds relay limit", {
                error: "limit",
            });
        }
        const operations = event.list ?? [];
        if (operations.length > this.#options.maximumListOperationsPerEvent) {
            throw new RelayError(413, "List operation count exceeds relay limit", {
                error: "limit",
            });
        }
        for (const operation of operations) {
            if (
                !isElementId(operation.id) ||
                (operation.op !== "append" &&
                    operation.op !== "replace" &&
                    operation.op !== "delete") ||
                (operation.op !== "append" &&
                    operation.expectedVersion !== undefined &&
                    (!Number.isSafeInteger(operation.expectedVersion) ||
                        operation.expectedVersion < 0)) ||
                (operation.op !== "delete" && !(operation.bytes instanceof Uint8Array))
            ) {
                throw new RelayError(400, "Invalid list operation", {
                    error: "malformed",
                });
            }
            if (
                operation.op !== "delete" &&
                operation.bytes.length > this.#options.maximumListElementBytes
            ) {
                throw new RelayError(413, "List element exceeds relay limit", {
                    error: "limit",
                });
            }
        }
        if (!verifyRelayEventSignature(event)) {
            throw new RelayError(401, "Invalid relay event signature", {
                error: "unauthorized",
            });
        }
        const fingerprint = relayEventFingerprint(event);
        const receipt = await this.#store.readPublishReceipt(event.topic, event.id);
        if (receipt !== undefined) {
            if (!equalBytes(receipt.fingerprint, fingerprint)) {
                throw new RelayError(409, "Event identifier collision", {
                    error: "id_collision",
                });
            }
            if (receipt.snapshotVersion === undefined) {
                return { seq: receipt.seq, duplicate: true };
            }
            return {
                seq: receipt.seq,
                duplicate: true,
                snapshotVersion: receipt.snapshotVersion,
            };
        }
        const now = this.#now();
        if (event.createdAt < now - FIVE_MINUTES || event.createdAt > now + FIVE_MINUTES) {
            throw new RelayError(401, "Expired relay event", { error: "unauthorized" });
        }
        const outcome = await this.#store.publish(event, now, {
            maximumElementsPerTopic: this.#options.maximumElementsPerTopic,
        });
        if (!outcome.duplicate) {
            this.#wake(event.topic);
            await this.#wakeSource.notify(event.topic).catch(() => {
                // A committed write remains successful; timeout-backed readers will poll.
            });
        }
        return outcome;
    }

    /** Read a transactionally consistent snapshot and first list page. */
    async readState(
        topic: string,
        limit?: number,
        maximumEncodedBytes?: number,
    ): Promise<TopicState | undefined> {
        this.#assertOpen();
        this.#validateTopic(topic);
        return this.#store.readState(
            topic,
            this.#pageLimit(limit),
            this.#pageReadConstraints(maximumEncodedBytes),
        );
    }

    /** Read a bounded ordered list page. */
    async readList(
        topic: string,
        cursor?: string,
        limit?: number,
        maximumEncodedBytes?: number,
    ): Promise<ListPage | undefined> {
        this.#assertOpen();
        this.#validateTopic(topic);
        return this.#store.readList(
            topic,
            cursor,
            this.#pageLimit(limit),
            this.#pageReadConstraints(maximumEncodedBytes),
        );
    }

    /** Read retained events, optionally parking until a wake or timeout. */
    async readEvents(
        topic: string,
        since: bigint,
        limit?: number,
        waitMilliseconds: number = 0,
        signal?: AbortSignal,
        maximumEncodedBytes?: number,
    ): Promise<EventPage | undefined> {
        this.#assertOpen();
        this.#validateTopic(topic);
        if (since < 0n) {
            throw new RelayError(400, "Invalid event sequence", { error: "malformed" });
        }
        const boundedLimit = this.#eventLimit(limit);
        const constraints = this.#pageReadConstraints(maximumEncodedBytes);
        if (
            !Number.isSafeInteger(waitMilliseconds) ||
            waitMilliseconds < 0 ||
            waitMilliseconds > this.#options.maximumLongPollMilliseconds
        ) {
            throw new RelayError(400, "Invalid long-poll duration", {
                error: "malformed",
            });
        }
        const current = await this.#store.readEvents(topic, since, boundedLimit, constraints);
        if (
            current === undefined ||
            current.reset ||
            current.events.length > 0 ||
            waitMilliseconds === 0
        ) {
            return current;
        }
        await this.#park(topic, since, boundedLimit, constraints, waitMilliseconds, signal);
        return this.#store.readEvents(topic, since, boundedLimit, constraints);
    }

    /** Store one valid, size-bounded content-addressed ciphertext blob. */
    async putBlob(blob: RelayBlob): Promise<void> {
        this.#assertOpen();
        if (!(blob.bytes instanceof Uint8Array)) {
            throw new RelayError(400, "Invalid blob bytes", { error: "malformed" });
        }
        if (blob.bytes.length > this.#options.maximumBlobBytes) {
            throw new RelayError(413, "Blob exceeds relay limit", { error: "limit" });
        }
        if (!isBase64Url(blob.id, 32)) {
            throw new RelayError(400, "Invalid blob identifier", {
                error: "malformed",
            });
        }
        await this.#store.putBlob({ id: blob.id, bytes: blob.bytes.slice() });
    }

    /** Fetch one opaque ciphertext blob when present. */
    async getBlob(id: string): Promise<RelayBlob | undefined> {
        this.#assertOpen();
        if (!isBase64Url(id, 32)) {
            throw new RelayError(400, "Invalid blob identifier", {
                error: "malformed",
            });
        }
        return this.#store.getBlob(id);
    }

    /** Run both configured retention policies using relay-observed time. */
    async prune(): Promise<RelayPruneOutcome> {
        this.#assertOpen();
        const now = this.#now();
        const events = await this.#store.pruneEvents(
            now - this.#options.eventRetentionMilliseconds,
        );
        const inactive = await this.#store.pruneInactiveTopics(
            now - this.#options.topicInactivityMilliseconds,
        );
        return { events, topics: inactive.topics };
    }

    /** Confirm the backing store is reachable. */
    async health(): Promise<void> {
        this.#assertOpen();
        await this.#store.health();
    }

    /** Stop waiters and close the wake source and store in dependency order. */
    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        for (const waiters of this.#waiters.values()) {
            for (const waiter of waiters) {
                waiter.reject(new Error("Relay service closed"));
            }
        }
        try {
            await this.#wakeSource.close();
        } finally {
            await this.#store.close();
        }
    }

    async #park(
        topic: string,
        since: bigint,
        limit: number,
        constraints: PageReadConstraints,
        milliseconds: number,
        signal?: AbortSignal,
    ): Promise<void> {
        if (signal?.aborted === true) {
            throw abortError(signal);
        }
        if (this.#waiterCount >= this.#options.maximumConcurrentLongPolls) {
            throw new RelayError(503, "Relay has too many concurrent long polls", {
                error: "overloaded",
            });
        }
        await new Promise<void>((resolve, reject) => {
            const waiters = this.#waiters.get(topic) ?? new Set<Waiter>();
            let settled = false;
            let timer: ReturnType<typeof setTimeout> | undefined;
            const cleanup = (): void => {
                if (settled) {
                    return;
                }
                settled = true;
                if (timer !== undefined) {
                    clearTimeout(timer);
                }
                signal?.removeEventListener("abort", onAbort);
                waiters.delete(waiter);
                this.#waiterCount -= 1;
                if (waiters.size === 0) {
                    this.#waiters.delete(topic);
                }
            };
            const onAbort = (): void => {
                if (signal !== undefined) {
                    waiter.reject(abortError(signal));
                }
            };
            const waiter: Waiter = {
                resolve: (): void => {
                    cleanup();
                    resolve();
                },
                reject: (error): void => {
                    cleanup();
                    reject(error);
                },
            };
            waiters.add(waiter);
            this.#waiterCount += 1;
            this.#waiters.set(topic, waiters);
            signal?.addEventListener("abort", onAbort, { once: true });
            timer = setTimeout(() => waiter.resolve(), milliseconds);
            void this.#store.readEvents(topic, since, limit, constraints).then(
                (page) => {
                    if (page === undefined || page.reset || page.events.length > 0) {
                        waiter.resolve();
                    }
                },
                (error: unknown) => {
                    waiter.reject(
                        error instanceof Error ? error : new Error("Relay event recheck failed"),
                    );
                },
            );
        });
    }

    #wake(topic: string): void {
        for (const waiter of this.#waiters.get(topic) ?? []) {
            waiter.resolve();
        }
    }

    #pageLimit(limit: number | undefined): number {
        const resolved = limit ?? this.#options.maximumListElementsPerPage;
        if (
            !Number.isSafeInteger(resolved) ||
            resolved < 1 ||
            resolved > this.#options.maximumListElementsPerPage
        ) {
            throw new RelayError(400, "Invalid list page limit", {
                error: "malformed",
            });
        }
        return resolved;
    }

    #eventLimit(limit: number | undefined): number {
        const resolved = limit ?? this.#options.maximumEventsPerRead;
        if (
            !Number.isSafeInteger(resolved) ||
            resolved < 1 ||
            resolved > this.#options.maximumEventsPerRead
        ) {
            throw new RelayError(400, "Invalid event page limit", {
                error: "malformed",
            });
        }
        return resolved;
    }

    #pageReadConstraints(maximumEncodedBytes: number | undefined): PageReadConstraints {
        const resolved = maximumEncodedBytes ?? Number.MAX_SAFE_INTEGER;
        if (!Number.isSafeInteger(resolved) || resolved < 1) {
            throw new RelayError(400, "Invalid page byte limit", {
                error: "malformed",
            });
        }
        return { maximumEncodedBytes: resolved };
    }

    #validateTopic(topic: string): void {
        if (!isTopicId(topic)) {
            throw new RelayError(400, "Invalid topic identifier", {
                error: "malformed",
            });
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Relay service is closed");
        }
    }
}
