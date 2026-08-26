import { sha256 } from "@noble/hashes/sha2";
import {
    RelayError,
    parseDeviceRosterMutation,
    validateSignedDeliveryShape,
    verifyDeliverySignature,
    verifyQueueAckSignature,
    verifyQueueReadSignature,
    type SignedDelivery,
    type SignedQueueAck,
    type SignedQueueRead,
    type DeviceRoster,
} from "../protocol/index.js";
import type {
    AcknowledgeOutcome,
    PublishOutcome,
    QueuedDelivery,
    QueuePage,
    RelayStore,
} from "../storage/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { InProcessWakeSource } from "./impl/wakeInProcess.js";
import type {
    QueueEventSubscription,
    QueueContinuityEvent,
    RelayOptions,
    ResolvedRelayOptions,
    WakeSource,
} from "./types.js";

export { InProcessWakeSource } from "./impl/wakeInProcess.js";
export { PostgresWakeSource } from "./impl/wakePostgres.js";
export type {
    QueueEventSubscription,
    QueueContinuityEvent,
    RelayOptions,
    ResolvedRelayOptions,
    WakeSource,
} from "./types.js";

const MEBIBYTE = 1024 * 1024;
const HARD_MAXIMUM_LONG_POLL_MILLISECONDS = 30_000;
/** Six-month relay delivery continuity window, defined as exactly 180 days. */
export const DELIVERY_RETENTION_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;
const HARD_MAXIMUM_DELIVERY_TTL_MILLISECONDS = DELIVERY_RETENTION_MILLISECONDS;
const HARD_MAXIMUM_RECIPIENTS = 1_024;
const HARD_MAXIMUM_QUEUE_ITEMS = 25_000;
const QUEUE_STREAM_HEARTBEAT_MILLISECONDS = 15_000;

interface Waiter {
    readonly resolve: (reason: "wake" | "timeout") => void;
    readonly reject: (error: Error) => void;
    readonly counted: boolean;
}

function positiveInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return value;
}

function resolveOptions(options: RelayOptions): ResolvedRelayOptions {
    const resolved: ResolvedRelayOptions = {
        maximumCiphertextBytes: positiveInteger(
            options.maximumCiphertextBytes ?? MEBIBYTE,
            "Maximum ciphertext bytes",
        ),
        maximumRecipients: positiveInteger(options.maximumRecipients ?? 256, "Maximum recipients"),
        maximumJsonBodyBytes: positiveInteger(
            options.maximumJsonBodyBytes ?? 2 * MEBIBYTE,
            "Maximum JSON body bytes",
        ),
        maximumQueueItems: positiveInteger(
            options.maximumQueueItems ?? 10_000,
            "Maximum queue items",
        ),
        maximumQueueBytes: positiveInteger(
            options.maximumQueueBytes ?? 256 * MEBIBYTE,
            "Maximum queue bytes",
        ),
        maximumSenderItems: positiveInteger(
            options.maximumSenderItems ?? 1_000,
            "Maximum sender items",
        ),
        maximumSenderBytes: positiveInteger(
            options.maximumSenderBytes ?? 256 * MEBIBYTE,
            "Maximum sender bytes",
        ),
        maximumSenderReferences: positiveInteger(
            options.maximumSenderReferences ?? 4_096,
            "Maximum sender references",
        ),
        maximumAdmissionReferences: positiveInteger(
            options.maximumAdmissionReferences ?? 10_000,
            "Maximum admission-principal references",
        ),
        maximumGlobalItems: positiveInteger(
            options.maximumGlobalItems ?? 100_000,
            "Maximum global items",
        ),
        maximumGlobalBytes: positiveInteger(
            options.maximumGlobalBytes ?? 10 * 1_024 * MEBIBYTE,
            "Maximum global bytes",
        ),
        maximumGlobalReferences: positiveInteger(
            options.maximumGlobalReferences ?? 1_000_000,
            "Maximum global references",
        ),
        maximumDeliveryTtlMilliseconds: positiveInteger(
            options.maximumDeliveryTtlMilliseconds ?? DELIVERY_RETENTION_MILLISECONDS,
            "Maximum delivery TTL",
        ),
        maximumAuthenticationSkewMilliseconds: positiveInteger(
            options.maximumAuthenticationSkewMilliseconds ?? 5 * 60 * 1_000,
            "Maximum authentication skew",
        ),
        maximumDeliveriesPerRead: positiveInteger(
            options.maximumDeliveriesPerRead ?? 256,
            "Maximum deliveries per read",
        ),
        maximumLongPollMilliseconds: positiveInteger(
            options.maximumLongPollMilliseconds ?? 30_000,
            "Maximum long poll milliseconds",
        ),
        maximumConcurrentLongPolls: positiveInteger(
            options.maximumConcurrentLongPolls ?? 10_000,
            "Maximum concurrent long polls",
        ),
        maximumConcurrentLongPollsPerIdentity: positiveInteger(
            options.maximumConcurrentLongPollsPerIdentity ?? 1,
            "Maximum concurrent long polls per identity",
        ),
    };
    if (resolved.maximumLongPollMilliseconds > HARD_MAXIMUM_LONG_POLL_MILLISECONDS) {
        throw new Error("Maximum long poll cannot exceed 30 seconds");
    }
    if (resolved.maximumDeliveryTtlMilliseconds > HARD_MAXIMUM_DELIVERY_TTL_MILLISECONDS) {
        throw new Error("Maximum delivery TTL cannot exceed 180 days");
    }
    if (resolved.maximumRecipients > HARD_MAXIMUM_RECIPIENTS) {
        throw new Error("Maximum recipients cannot exceed 1,024");
    }
    if (resolved.maximumQueueItems > HARD_MAXIMUM_QUEUE_ITEMS) {
        throw new Error("Maximum queue items cannot exceed 25,000");
    }
    const minimumJsonBytes =
        Math.ceil(resolved.maximumCiphertextBytes / 3) * 4 +
        resolved.maximumRecipients * 48 +
        4_096;
    if (resolved.maximumJsonBodyBytes < minimumJsonBytes) {
        throw new Error("Maximum JSON body must fit one maximum-sized delivery");
    }
    if (resolved.maximumConcurrentLongPollsPerIdentity > resolved.maximumConcurrentLongPolls) {
        throw new Error("Per-identity long poll limit cannot exceed the global limit");
    }
    return Object.freeze(resolved);
}

/** Authorization, queue policy, and long-poll orchestration. */
export class RelayService {
    readonly #store: RelayStore;
    readonly #wakeSource: WakeSource;
    readonly #now: () => number;
    readonly #options: ResolvedRelayOptions;
    readonly #wakeSubscription: Promise<void>;
    readonly #waiters = new Map<string, Set<Waiter>>();
    readonly #streamCounts = new Map<string, number>();
    readonly #streamClosers = new Set<() => void>();
    #waiterCount = 0;
    #streamCount = 0;
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
        this.#wakeSubscription = wakeSource.subscribe((queueId) => this.#wake(queueId));
        void this.#wakeSubscription.catch(() => undefined);
    }

    /** Resolved immutable limits used by the HTTP boundary. */
    get options(): ResolvedRelayOptions {
        return this.#options;
    }

    /** Validate and atomically multicast one signed encrypted delivery. */
    async publish(delivery: SignedDelivery, admissionPrincipal: string): Promise<PublishOutcome> {
        this.#assertOpen();
        validateSignedDeliveryShape(delivery);
        if (
            typeof admissionPrincipal !== "string" ||
            admissionPrincipal.length < 1 ||
            admissionPrincipal.length > 255
        ) {
            throw new RelayError(400, "Invalid admission principal", {
                error: "malformed",
            });
        }
        if (delivery.recipients.length > this.#options.maximumRecipients) {
            throw new RelayError(413, "Delivery recipient set exceeds relay limit", {
                error: "limit",
            });
        }
        if (delivery.recipients.length < 1) {
            throw new RelayError(400, "Delivery has no recipients", { error: "malformed" });
        }
        if (delivery.ciphertext.length > this.#options.maximumCiphertextBytes) {
            throw new RelayError(413, "Delivery ciphertext exceeds relay limit", {
                error: "limit",
            });
        }
        if (!verifyDeliverySignature(delivery)) {
            throw new RelayError(401, "Invalid delivery signature", {
                error: "unauthorized",
            });
        }
        const now = this.#now();
        if (
            delivery.createdAt > now + this.#options.maximumAuthenticationSkewMilliseconds ||
            delivery.createdAt <
                now -
                    this.#options.maximumDeliveryTtlMilliseconds -
                    this.#options.maximumAuthenticationSkewMilliseconds ||
            delivery.createdAt >= delivery.expiresAt ||
            delivery.expiresAt <= now ||
            delivery.expiresAt - now > this.#options.maximumDeliveryTtlMilliseconds
        ) {
            throw new RelayError(401, "Delivery violates relay time policy", {
                error: "unauthorized",
            });
        }
        const outcome = await this.#store.publish(
            delivery,
            now,
            {
                maximumItems: this.#options.maximumQueueItems,
                maximumBytes: this.#options.maximumQueueBytes,
                maximumSenderItems: this.#options.maximumSenderItems,
                maximumSenderBytes: this.#options.maximumSenderBytes,
                maximumSenderReferences: this.#options.maximumSenderReferences,
                maximumAdmissionReferences: this.#options.maximumAdmissionReferences,
                maximumGlobalItems: this.#options.maximumGlobalItems,
                maximumGlobalBytes: this.#options.maximumGlobalBytes,
                maximumGlobalReferences: this.#options.maximumGlobalReferences,
            },
            this.#digestAdmissionPrincipal(admissionPrincipal),
        );
        for (const recipient of delivery.recipients) {
            const queueId = encodeBase64Url(recipient);
            this.#wake(queueId);
            await this.#wakeSource.notify(queueId).catch(() => undefined);
        }
        return outcome;
    }

    /** Read one current roster by exact public account identity key. */
    async readDeviceRoster(accountKey: Uint8Array): Promise<DeviceRoster | undefined> {
        this.#assertOpen();
        return this.#store.readDeviceRoster(accountKey);
    }

    /** Validate, apply, and enqueue one identity-signed roster mutation. */
    async mutateDeviceRoster(
        delivery: SignedDelivery,
        admissionPrincipal: string,
    ): Promise<DeviceRoster> {
        this.#assertOpen();
        validateSignedDeliveryShape(delivery);
        if (
            typeof admissionPrincipal !== "string" ||
            admissionPrincipal.length < 1 ||
            admissionPrincipal.length > 255
        ) {
            throw new RelayError(400, "Invalid admission principal", {
                error: "malformed",
            });
        }
        if (!verifyDeliverySignature(delivery)) {
            throw new RelayError(401, "Invalid device roster mutation signature", {
                error: "unauthorized",
            });
        }
        if (delivery.recipients.length > this.#options.maximumRecipients) {
            throw new RelayError(413, "Device roster exceeds relay limit", { error: "limit" });
        }
        if (delivery.ciphertext.length > this.#options.maximumCiphertextBytes) {
            throw new RelayError(413, "Device roster mutation exceeds relay limit", {
                error: "limit",
            });
        }
        const now = this.#now();
        if (
            delivery.createdAt > now + this.#options.maximumAuthenticationSkewMilliseconds ||
            delivery.createdAt < now - this.#options.maximumAuthenticationSkewMilliseconds ||
            delivery.createdAt >= delivery.expiresAt ||
            delivery.expiresAt <= now ||
            delivery.expiresAt - now > this.#options.maximumDeliveryTtlMilliseconds
        ) {
            throw new RelayError(401, "Device roster mutation violates relay time policy", {
                error: "unauthorized",
            });
        }
        const mutation = parseDeviceRosterMutation(delivery.ciphertext);
        const roster = await this.#store.mutateDeviceRoster(
            delivery,
            mutation,
            now,
            {
                maximumItems: this.#options.maximumQueueItems,
                maximumBytes: this.#options.maximumQueueBytes,
                maximumSenderItems: this.#options.maximumSenderItems,
                maximumSenderBytes: this.#options.maximumSenderBytes,
                maximumSenderReferences: this.#options.maximumSenderReferences,
                maximumAdmissionReferences: this.#options.maximumAdmissionReferences,
                maximumGlobalItems: this.#options.maximumGlobalItems,
                maximumGlobalBytes: this.#options.maximumGlobalBytes,
                maximumGlobalReferences: this.#options.maximumGlobalReferences,
            },
            this.#digestAdmissionPrincipal(admissionPrincipal),
        );
        for (const recipient of delivery.recipients) {
            const queueId = encodeBase64Url(recipient);
            this.#wake(queueId);
            await this.#wakeSource.notify(queueId).catch(() => undefined);
        }
        return roster;
    }

    /** Authenticate and read one identity's queue, optionally long-polling. */
    async readQueue(
        request: SignedQueueRead,
        signal?: AbortSignal,
        maximumEncodedBytes: number = Number.MAX_SAFE_INTEGER,
    ): Promise<QueuePage> {
        this.#assertOpen();
        this.#validateQueueRead(request, maximumEncodedBytes, false);
        const constraints = { maximumEncodedBytes };
        const now = this.#now();
        let page = await this.#store.readQueue(
            request.recipient,
            request.after,
            request.limit,
            now,
            constraints,
        );
        if (request.waitMilliseconds === 0 || page.deliveries.length > 0) {
            return page;
        }
        const queueId = encodeBase64Url(request.recipient);
        if (signal?.aborted === true) {
            throw new RelayError(400, "Queue read aborted", {
                error: "aborted",
            });
        }
        await this.#wakeSubscription.catch(() => {
            throw new RelayError(503, "Queue wake subscription is unavailable", {
                error: "overloaded",
            });
        });
        const wait = this.#registerWait(queueId, request.waitMilliseconds, signal);
        try {
            page = await this.#store.readQueue(
                request.recipient,
                request.after,
                request.limit,
                this.#now(),
                constraints,
            );
            if (page.deliveries.length > 0) {
                return page;
            }
            await wait.promise;
            return this.#store.readQueue(
                request.recipient,
                request.after,
                request.limit,
                this.#now(),
                constraints,
            );
        } finally {
            wait.cancel();
        }
    }

    /**
     * Authenticate and open one pull-driven SSE source for an identity queue.
     *
     * Each non-null item is an exact queued delivery in that inbox's UUIDv7
     * order. Null items are transport heartbeats and carry no queue progress.
     */
    async openQueueEventStream(
        request: SignedQueueRead,
        signal?: AbortSignal,
    ): Promise<QueueEventSubscription> {
        this.#assertOpen();
        this.#validateQueueRead(request, Number.MAX_SAFE_INTEGER, true);
        await this.#wakeSubscription.catch(() => {
            throw new RelayError(503, "Queue wake subscription is unavailable", {
                error: "overloaded",
            });
        });
        const queueId = encodeBase64Url(request.recipient);
        if (this.#waiterCount + this.#streamCount >= this.#options.maximumConcurrentLongPolls) {
            throw new RelayError(503, "Too many concurrent queue receivers", {
                error: "overloaded",
            });
        }
        if (
            (this.#waiters.get(queueId)?.size ?? 0) + (this.#streamCounts.get(queueId) ?? 0) >=
            this.#options.maximumConcurrentLongPollsPerIdentity
        ) {
            throw new RelayError(429, "Too many concurrent receivers for identity", {
                error: "rate_limited",
            });
        }
        const controller = new AbortController();
        const forwardAbort = (): void => controller.abort(signal?.reason);
        signal?.addEventListener("abort", forwardAbort, { once: true });
        if (signal?.aborted === true) {
            signal.removeEventListener("abort", forwardAbort);
            throw new RelayError(400, "Queue event stream aborted", {
                error: "aborted",
            });
        }
        this.#streamCount += 1;
        this.#streamCounts.set(queueId, (this.#streamCounts.get(queueId) ?? 0) + 1);
        let closed = false;
        const close = (): void => {
            if (closed) return;
            closed = true;
            signal?.removeEventListener("abort", forwardAbort);
            controller.abort(new Error("Queue event stream closed"));
            this.#streamCount -= 1;
            const remaining = (this.#streamCounts.get(queueId) ?? 1) - 1;
            if (remaining === 0) {
                this.#streamCounts.delete(queueId);
            } else {
                this.#streamCounts.set(queueId, remaining);
            }
            this.#streamClosers.delete(close);
        };
        this.#streamClosers.add(close);
        return {
            events: this.#queueEvents(request, queueId, controller.signal, close),
            close,
        };
    }

    /** Authenticate and trim one durably processed queue prefix. */
    async acknowledge(request: SignedQueueAck): Promise<AcknowledgeOutcome> {
        this.#assertOpen();
        this.#validateRequestTime(request.createdAt);
        if (!verifyQueueAckSignature(request)) {
            throw new RelayError(401, "Invalid queue-acknowledgement signature", {
                error: "unauthorized",
            });
        }
        return this.#store.acknowledge(request.recipient, request.through, this.#now());
    }

    /** Remove expired pending deliveries and all of their queue references. */
    async pruneExpired(): Promise<number> {
        this.#assertOpen();
        return this.#store.pruneExpired(this.#now());
    }

    /** Invalidate known inbox continuity after an operator declares a backup restore. */
    async declareRestored(): Promise<number> {
        this.#assertOpen();
        return this.#store.declareRestored();
    }

    /** Confirm the wake subscription and backing store are reachable. */
    async health(): Promise<void> {
        this.#assertOpen();
        await this.#wakeSubscription;
        await this.#store.health();
    }

    /** Stop waits, wake dispatch, and persistence. */
    async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        const error = new Error("Relay is closed");
        for (const waiters of this.#waiters.values()) {
            for (const waiter of waiters) waiter.reject(error);
        }
        this.#waiters.clear();
        this.#waiterCount = 0;
        for (const close of Array.from(this.#streamClosers)) close();
        await this.#wakeSource.close();
        await this.#store.close();
    }

    #validateRequestTime(createdAt: number): void {
        const now = this.#now();
        if (
            !Number.isSafeInteger(createdAt) ||
            createdAt < 0 ||
            Math.abs(createdAt - now) > this.#options.maximumAuthenticationSkewMilliseconds
        ) {
            throw new RelayError(401, "Signed request violates relay time policy", {
                error: "unauthorized",
            });
        }
    }

    #validateQueueRead(
        request: SignedQueueRead,
        maximumEncodedBytes: number,
        stream: boolean,
    ): void {
        this.#validateRequestTime(request.createdAt);
        if (!verifyQueueReadSignature(request)) {
            throw new RelayError(401, "Invalid queue-read signature", {
                error: "unauthorized",
            });
        }
        if (
            request.limit < 1 ||
            request.limit > this.#options.maximumDeliveriesPerRead ||
            request.waitMilliseconds > this.#options.maximumLongPollMilliseconds ||
            (stream && (request.waitMilliseconds !== 0 || request.limit !== 1)) ||
            !Number.isSafeInteger(maximumEncodedBytes) ||
            maximumEncodedBytes < 1
        ) {
            throw new RelayError(400, "Invalid queue read", { error: "malformed" });
        }
    }

    async *#queueEvents(
        request: SignedQueueRead,
        queueId: string,
        signal: AbortSignal,
        close: () => void,
    ): AsyncGenerator<QueuedDelivery | QueueContinuityEvent | null> {
        let after = request.after;
        let observedGeneration: Uint8Array | undefined;
        const constraints = { maximumEncodedBytes: Number.MAX_SAFE_INTEGER };
        try {
            while (!signal.aborted) {
                let page = await this.#store.readQueue(
                    request.recipient,
                    after,
                    request.limit,
                    this.#now(),
                    constraints,
                );
                if (
                    observedGeneration === undefined ||
                    !equalBytes(observedGeneration, page.generation)
                ) {
                    observedGeneration = page.generation.slice();
                    yield {
                        type: "continuity",
                        generation: page.generation.slice(),
                        head: page.head,
                        headSequence: page.headSequence,
                        acknowledgedThrough: page.acknowledgedThrough,
                        acknowledgedSequence: page.acknowledgedSequence,
                    };
                }
                if (page.deliveries.length > 0) {
                    for (const queued of page.deliveries) {
                        if (after !== null && queued.eventId <= after) {
                            throw new Error("Queue store returned an out-of-order stream event");
                        }
                        after = queued.eventId;
                        yield queued;
                    }
                    continue;
                }
                const wait = this.#registerWait(
                    queueId,
                    QUEUE_STREAM_HEARTBEAT_MILLISECONDS,
                    signal,
                    false,
                );
                try {
                    page = await this.#store.readQueue(
                        request.recipient,
                        after,
                        request.limit,
                        this.#now(),
                        constraints,
                    );
                    if (page.deliveries.length > 0) continue;
                    const reason = await wait.promise;
                    if (!signal.aborted && reason === "timeout") yield null;
                } finally {
                    wait.cancel();
                }
            }
        } catch (error: unknown) {
            if (!signal.aborted) throw error;
        } finally {
            close();
        }
    }

    #digestAdmissionPrincipal(admissionPrincipal: string): Uint8Array {
        if (
            typeof admissionPrincipal !== "string" ||
            admissionPrincipal.length < 1 ||
            admissionPrincipal.length > 255
        ) {
            throw new RelayError(400, "Invalid admission principal", {
                error: "malformed",
            });
        }
        return sha256(new TextEncoder().encode(admissionPrincipal));
    }

    #registerWait(
        queueId: string,
        milliseconds: number,
        signal?: AbortSignal,
        enforceLimits: boolean = true,
    ): {
        readonly promise: Promise<"wake" | "timeout">;
        readonly cancel: () => void;
    } {
        this.#assertOpen();
        if (
            enforceLimits &&
            this.#waiterCount + this.#streamCount >= this.#options.maximumConcurrentLongPolls
        ) {
            throw new RelayError(503, "Too many concurrent long polls", {
                error: "overloaded",
            });
        }
        if (
            enforceLimits &&
            Array.from(this.#waiters.get(queueId) ?? []).filter(({ counted }) => counted).length >=
                this.#options.maximumConcurrentLongPollsPerIdentity -
                    (this.#streamCounts.get(queueId) ?? 0)
        ) {
            throw new RelayError(429, "Too many concurrent long polls for identity", {
                error: "rate_limited",
            });
        }
        let settled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;
        let waiter: Waiter;
        let removeAbort: (() => void) | undefined;
        const finish = (): void => {
            if (settled) return;
            settled = true;
            if (timer !== undefined) clearTimeout(timer);
            removeAbort?.();
            const waiters = this.#waiters.get(queueId);
            waiters?.delete(waiter);
            if (waiters?.size === 0) this.#waiters.delete(queueId);
            if (waiter.counted) this.#waiterCount -= 1;
        };
        const promise = new Promise<"wake" | "timeout">((resolve, reject) => {
            waiter = {
                counted: enforceLimits,
                resolve: (reason) => {
                    finish();
                    resolve(reason);
                },
                reject: (error) => {
                    finish();
                    reject(error);
                },
            };
            let waiters = this.#waiters.get(queueId);
            if (waiters === undefined) {
                waiters = new Set();
                this.#waiters.set(queueId, waiters);
            }
            waiters.add(waiter);
            if (waiter.counted) this.#waiterCount += 1;
            timer = setTimeout(() => waiter.resolve("timeout"), milliseconds);
            const abort = (): void =>
                waiter.reject(
                    new RelayError(400, "Queue read aborted", {
                        error: "aborted",
                    }),
                );
            if (signal !== undefined) {
                if (signal.aborted) {
                    abort();
                } else {
                    signal.addEventListener("abort", abort, { once: true });
                    removeAbort = () => signal.removeEventListener("abort", abort);
                }
            }
        });
        void promise.catch(() => undefined);
        return { promise, cancel: () => waiter.resolve("wake") };
    }

    #wake(queueId: string): void {
        const waiters = this.#waiters.get(queueId);
        if (waiters === undefined) return;
        for (const waiter of Array.from(waiters)) waiter.resolve("wake");
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Relay is closed");
        }
    }
}
