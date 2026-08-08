import { sha256 } from "@noble/hashes/sha2";
import {
    RelayError,
    validateSignedDeliveryShape,
    verifyDeliverySignature,
    verifyQueueAckSignature,
    verifyQueueReadSignature,
    type SignedDelivery,
    type SignedQueueAck,
    type SignedQueueRead,
} from "../protocol/index.js";
import type {
    AcknowledgeOutcome,
    PublishOutcome,
    QueuePage,
    RelayStore,
} from "../storage/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { InProcessWakeSource } from "./impl/wakeInProcess.js";
import type { RelayOptions, ResolvedRelayOptions, WakeSource } from "./types.js";

export { InProcessWakeSource } from "./impl/wakeInProcess.js";
export { PostgresWakeSource } from "./impl/wakePostgres.js";
export type { RelayOptions, ResolvedRelayOptions, WakeSource } from "./types.js";

const MEBIBYTE = 1024 * 1024;
const HARD_MAXIMUM_LONG_POLL_MILLISECONDS = 30_000;
const HARD_MAXIMUM_DELIVERY_TTL_MILLISECONDS = 90 * 24 * 60 * 60 * 1_000;
const HARD_MAXIMUM_RECIPIENTS = 1_024;
const HARD_MAXIMUM_QUEUE_ITEMS = 25_000;

interface Waiter {
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
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
            options.maximumDeliveryTtlMilliseconds ?? 30 * 24 * 60 * 60 * 1_000,
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
        throw new Error("Maximum delivery TTL cannot exceed 90 days");
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
        const principal = sha256(new TextEncoder().encode(admissionPrincipal));
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
            principal,
        );
        for (const recipient of delivery.recipients) {
            const queueId = encodeBase64Url(recipient);
            this.#wake(queueId);
            await this.#wakeSource.notify(queueId).catch(() => undefined);
        }
        return outcome;
    }

    /** Authenticate and read one identity's queue, optionally long-polling. */
    async readQueue(
        request: SignedQueueRead,
        signal?: AbortSignal,
        maximumEncodedBytes: number = Number.MAX_SAFE_INTEGER,
    ): Promise<QueuePage> {
        this.#assertOpen();
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
            !Number.isSafeInteger(maximumEncodedBytes) ||
            maximumEncodedBytes < 1
        ) {
            throw new RelayError(400, "Invalid queue read", { error: "malformed" });
        }
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

    /** Confirm the backing store is reachable. */
    async health(): Promise<void> {
        this.#assertOpen();
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

    #registerWait(
        queueId: string,
        milliseconds: number,
        signal?: AbortSignal,
    ): { readonly promise: Promise<void>; readonly cancel: () => void } {
        this.#assertOpen();
        if (this.#waiterCount >= this.#options.maximumConcurrentLongPolls) {
            throw new RelayError(503, "Too many concurrent long polls", {
                error: "overloaded",
            });
        }
        if (
            (this.#waiters.get(queueId)?.size ?? 0) >=
            this.#options.maximumConcurrentLongPollsPerIdentity
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
            this.#waiterCount -= 1;
        };
        const promise = new Promise<void>((resolve, reject) => {
            waiter = {
                resolve: () => {
                    finish();
                    resolve();
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
            this.#waiterCount += 1;
            timer = setTimeout(waiter.resolve, milliseconds);
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
        return { promise, cancel: () => waiter.resolve() };
    }

    #wake(queueId: string): void {
        const waiters = this.#waiters.get(queueId);
        if (waiters === undefined) return;
        for (const waiter of Array.from(waiters)) waiter.resolve();
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Relay is closed");
        }
    }
}
