import {
    MAX_RELAY_RECIPIENTS,
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    identityId,
    verifyRelayBlob,
    verifyRelayEvent,
    verifyQueueRequest,
    verifyTopicSubscription,
    type QueueAcknowledgeRequest,
    type QueueReadRequest,
    type RelayBlob,
    type RelayDelivery,
    type RelayEvent,
    type TopicSubscription,
} from "@murmur/core";
import type { RelayStore } from "../storage/index.js";
import type { PruneResult, RelayOptions } from "./types.js";

export type { PruneResult, RelayOptions } from "./types.js";

const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1_000;
const DEFAULT_MAXIMUM_EVENT_BYTES = MAX_RELAY_EVENT_PAYLOAD_BYTES;
const DEFAULT_MAXIMUM_BLOB_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_ENVELOPE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAXIMUM_WAITERS = 10_000;
const MAXIMUM_DELIVERY_BATCH = 16;
const DEFAULT_MAXIMUM_DELIVERY_BATCH = MAXIMUM_DELIVERY_BATCH;
const MAXIMUM_LONG_POLL_MILLISECONDS = 30_000;
const QUEUE_REQUEST_VALIDITY_MILLISECONDS = 5 * 60 * 1_000;

interface Waiter {
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
}

function sanitizeEvent(event: RelayEvent): RelayEvent {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        sender: {
            signingKey: event.sender.signingKey.slice(),
            encryptionKey: event.sender.encryptionKey.slice(),
        },
        recipients: [...event.recipients],
        createdAt: event.createdAt,
        payload: event.payload.slice(),
        signature: event.signature.slice(),
    };
}

function sanitizeSubscription(subscription: TopicSubscription): TopicSubscription {
    return {
        version: 1,
        topic: subscription.topic,
        subscriber: {
            signingKey: subscription.subscriber.signingKey.slice(),
            encryptionKey: subscription.subscriber.encryptionKey.slice(),
        },
        createdAt: subscription.createdAt,
        signature: subscription.signature.slice(),
    };
}

function abortError(signal: AbortSignal): Error {
    return signal.reason instanceof Error ? signal.reason : new Error("Long poll aborted");
}

/** Expected client-visible relay failure with an HTTP-compatible status. */
export class RelayProtocolError extends Error {
    constructor(
        readonly status: 400 | 401 | 409 | 413 | 429 | 503,
        message: string,
    ) {
        super(message);
    }
}

/** Validation and routing logic for a dumb relay. */
export class RelayService {
    readonly #store: RelayStore;
    readonly #now: () => number;
    readonly #topicInactivityMilliseconds: number;
    readonly #maximumEventBytes: number;
    readonly #maximumBlobBytes: number;
    readonly #maximumEnvelopeBytes: number;
    readonly #maximumRecipients: number;
    readonly #maximumWaiters: number;
    readonly #maximumDeliveryBatch: number;
    readonly #waiters = new Map<string, Set<Waiter>>();
    #waiterCount = 0;

    constructor(store: RelayStore, options: RelayOptions = {}, now: () => number = Date.now) {
        this.#store = store;
        this.#now = now;
        this.#topicInactivityMilliseconds = options.topicInactivityMilliseconds ?? THIRTY_DAYS;
        this.#maximumEventBytes = options.maximumEventBytes ?? DEFAULT_MAXIMUM_EVENT_BYTES;
        this.#maximumBlobBytes = options.maximumBlobBytes ?? DEFAULT_MAXIMUM_BLOB_BYTES;
        this.#maximumEnvelopeBytes = options.maximumEnvelopeBytes ?? DEFAULT_MAXIMUM_ENVELOPE_BYTES;
        this.#maximumRecipients = options.maximumRecipients ?? MAX_RELAY_RECIPIENTS;
        this.#maximumWaiters = options.maximumWaiters ?? DEFAULT_MAXIMUM_WAITERS;
        this.#maximumDeliveryBatch = options.maximumDeliveryBatch ?? DEFAULT_MAXIMUM_DELIVERY_BATCH;

        for (const [name, value] of [
            ["topic inactivity", this.#topicInactivityMilliseconds],
            ["event size", this.#maximumEventBytes],
            ["blob size", this.#maximumBlobBytes],
            ["envelope size", this.#maximumEnvelopeBytes],
            ["recipient count", this.#maximumRecipients],
            ["waiter count", this.#maximumWaiters],
            ["delivery batch", this.#maximumDeliveryBatch],
        ] as const) {
            if (!Number.isSafeInteger(value) || value < 1) {
                throw new Error(`Maximum ${name} must be a positive safe integer`);
            }
        }
        if (this.#maximumRecipients > MAX_RELAY_RECIPIENTS) {
            throw new Error(`Maximum recipient count cannot exceed ${MAX_RELAY_RECIPIENTS}`);
        }
        if (this.#maximumDeliveryBatch > MAXIMUM_DELIVERY_BATCH) {
            throw new Error(`Maximum delivery batch cannot exceed ${MAXIMUM_DELIVERY_BATCH}`);
        }
    }

    /** Add an authenticated public-key subscription. */
    async subscribe(subscription: TopicSubscription): Promise<void> {
        if (!verifyTopicSubscription(subscription)) {
            throw new RelayProtocolError(401, "Invalid topic subscription");
        }
        const now = this.#now();
        if (
            subscription.createdAt < now - QUEUE_REQUEST_VALIDITY_MILLISECONDS ||
            subscription.createdAt > now + QUEUE_REQUEST_VALIDITY_MILLISECONDS
        ) {
            throw new RelayProtocolError(401, "Expired topic subscription");
        }
        const sanitized = sanitizeSubscription(subscription);
        const replayed = await this.#store.addSubscription(sanitized, now);
        if (replayed > 0) {
            this.#wake(identityId(sanitized.subscriber));
        }
    }

    /** Validate and atomically fan out an opaque event. */
    async publish(event: RelayEvent): Promise<void> {
        if (
            typeof event.topic !== "string" ||
            !(event.payload instanceof Uint8Array) ||
            event.payload.length > this.#maximumEventBytes
        ) {
            throw new RelayProtocolError(413, `Event exceeds ${this.#maximumEventBytes} bytes`);
        }
        if (!Array.isArray(event.recipients) || event.recipients.length > this.#maximumRecipients) {
            throw new RelayProtocolError(
                413,
                `Event exceeds ${this.#maximumRecipients} recipients`,
            );
        }
        const approximateEnvelopeBytes =
            event.payload.length +
            event.topic.length * 4 +
            event.recipients.reduce(
                (total, recipient) =>
                    total + (typeof recipient === "string" ? recipient.length : 0),
                0,
            ) +
            (event.signature instanceof Uint8Array ? event.signature.length : 0) +
            (event.sender?.signingKey instanceof Uint8Array ? event.sender.signingKey.length : 0) +
            (event.sender?.encryptionKey instanceof Uint8Array
                ? event.sender.encryptionKey.length
                : 0) +
            512;
        if (approximateEnvelopeBytes > this.#maximumEnvelopeBytes) {
            throw new RelayProtocolError(
                413,
                `Event envelope exceeds ${this.#maximumEnvelopeBytes} bytes`,
            );
        }
        if (!verifyRelayEvent(event)) {
            throw new RelayProtocolError(401, "Invalid relay event");
        }

        const result = await this.#store.publish(sanitizeEvent(event), this.#now());
        if (result.disposition === "inserted") {
            for (const recipient of result.recipients) {
                this.#wake(recipient);
            }
        }
    }

    /** Pull a recipient queue, optionally waiting for a realtime wakeup. */
    async pull(
        request: QueueReadRequest,
        waitMilliseconds: number = 0,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]> {
        const recipientId = await this.#authenticateQueueRequest(request);
        if (
            !Number.isSafeInteger(waitMilliseconds) ||
            waitMilliseconds < 0 ||
            waitMilliseconds > MAXIMUM_LONG_POLL_MILLISECONDS
        ) {
            throw new RelayProtocolError(
                400,
                `Long poll must be between 0 and ${MAXIMUM_LONG_POLL_MILLISECONDS} milliseconds`,
            );
        }

        const current = await this.#store.pull(recipientId, this.#maximumDeliveryBatch);
        if (current.length > 0 || waitMilliseconds === 0) {
            return current;
        }

        await this.#wait(recipientId, waitMilliseconds, signal);
        return this.#store.pull(recipientId, this.#maximumDeliveryBatch);
    }

    /** Remove one queued copy. Acknowledgement is idempotent. */
    async acknowledge(request: QueueAcknowledgeRequest): Promise<void> {
        const recipientId = await this.#authenticateQueueRequest(request);
        await this.#store.acknowledge(recipientId, request.deliveryId);
    }

    /** Store only a valid content-addressed ciphertext blob. */
    async putBlob(blob: RelayBlob): Promise<void> {
        if (blob.bytes.length > this.#maximumBlobBytes) {
            throw new RelayProtocolError(413, `Blob exceeds ${this.#maximumBlobBytes} bytes`);
        }
        if (!verifyRelayBlob(blob)) {
            throw new RelayProtocolError(400, "Blob content identifier does not match its bytes");
        }
        await this.#store.putBlob(blob);
    }

    /** Fetch an opaque blob without interpreting its contents. */
    async getBlob(id: string): Promise<RelayBlob | undefined> {
        return this.#store.getBlob(id);
    }

    /** Drop topics which have seen no relay-observed activity for thirty days. */
    async pruneInactiveTopics(): Promise<PruneResult> {
        return this.#store.pruneInactiveTopics(this.#now() - this.#topicInactivityMilliseconds);
    }

    async #authenticateQueueRequest(
        request: QueueReadRequest | QueueAcknowledgeRequest,
    ): Promise<string> {
        if (!verifyQueueRequest(request)) {
            throw new RelayProtocolError(401, "Invalid queue request");
        }
        const now = this.#now();
        if (
            request.createdAt < now - QUEUE_REQUEST_VALIDITY_MILLISECONDS ||
            request.createdAt > now + QUEUE_REQUEST_VALIDITY_MILLISECONDS
        ) {
            throw new RelayProtocolError(401, "Expired queue request");
        }
        const recipientId = identityId(request.recipient);
        const consumed = await this.#store.consumeQueueRequest(
            recipientId,
            request.requestId,
            request.createdAt + QUEUE_REQUEST_VALIDITY_MILLISECONDS + 1,
            now,
        );
        if (!consumed) {
            throw new RelayProtocolError(409, "Replayed queue request");
        }
        return recipientId;
    }

    async #wait(recipientId: string, milliseconds: number, signal?: AbortSignal): Promise<void> {
        if (signal?.aborted === true) {
            throw abortError(signal);
        }
        if (this.#waiterCount >= this.#maximumWaiters) {
            throw new RelayProtocolError(503, "Relay has too many concurrent long polls");
        }

        await new Promise<void>((resolve, reject) => {
            const waiters = this.#waiters.get(recipientId) ?? new Set<Waiter>();
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
                    this.#waiters.delete(recipientId);
                }
            };
            const onAbort = (): void => waiter.reject(abortError(signal!));
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
            timer = setTimeout(() => waiter.resolve(), milliseconds);
            waiters.add(waiter);
            this.#waiterCount += 1;
            this.#waiters.set(recipientId, waiters);
            signal?.addEventListener("abort", onAbort, { once: true });

            void this.#store.pull(recipientId, this.#maximumDeliveryBatch).then(
                (deliveries) => {
                    if (deliveries.length > 0) {
                        waiter.resolve();
                    }
                },
                (error: unknown) =>
                    waiter.reject(
                        error instanceof Error ? error : new Error("Relay store pull failed"),
                    ),
            );
        });
    }

    #wake(recipientId: string): void {
        for (const waiter of this.#waiters.get(recipientId) ?? []) {
            waiter.resolve();
        }
    }
}
