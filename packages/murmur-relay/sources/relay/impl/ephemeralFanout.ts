import type { EphemeralFanout, EphemeralStreamMessage, EphemeralSubscription } from "../types.js";

/** Construction bounds for a bounded in-process ephemeral fan-out. */
export interface InProcessEphemeralFanoutOptions {
    /** Maximum simultaneous subscribers across all topics. */
    readonly maximumConcurrentStreams: number;
    /** Maximum simultaneous subscribers on one topic. */
    readonly maximumStreamsPerTopic: number;
    /** Maximum queued frames per subscriber before dropping the oldest. */
    readonly maximumStreamQueueFrames: number;
    /** Maximum queued frame bytes per subscriber before dropping the oldest. */
    readonly maximumStreamQueueBytes: number;
}

function positiveSafeInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return value;
}

/**
 * One subscriber's bounded queue plus a single-slot reader signal.
 *
 * The enqueue methods are synchronous and never touch the reader beyond
 * resolving one waiting promise, so producers cannot be slowed by a stalled
 * consumer. When the frame count or byte bound is exceeded the oldest frames
 * are discarded and a single coalesced `drop` count is retained; a `wake` is a
 * single coalesced flag. This keeps the buffer strictly bounded.
 */
class InProcessEphemeralSubscriber implements EphemeralSubscription {
    readonly #maximumFrames: number;
    readonly #maximumBytes: number;
    readonly #onClose: () => void;
    #frames: Uint8Array[] = [];
    #queuedBytes = 0;
    #droppedFrames = 0;
    #wakePending = false;
    #closed = false;
    #signal: (() => void) | undefined;

    constructor(maximumFrames: number, maximumBytes: number, onClose: () => void) {
        this.#maximumFrames = maximumFrames;
        this.#maximumBytes = maximumBytes;
        this.#onClose = onClose;
    }

    get closed(): boolean {
        return this.#closed;
    }

    /** Append one frame, dropping the oldest queued frames if a bound is exceeded. */
    enqueueFrame(frame: Uint8Array): void {
        if (this.#closed) {
            return;
        }
        this.#frames.push(frame);
        this.#queuedBytes += frame.length;
        while (
            this.#frames.length > this.#maximumFrames ||
            this.#queuedBytes > this.#maximumBytes
        ) {
            const dropped = this.#frames.shift();
            if (dropped === undefined) {
                break;
            }
            this.#queuedBytes -= dropped.length;
            this.#droppedFrames += 1;
        }
        this.#notify();
    }

    /** Record one coalesced wake for delivery to the reader. */
    enqueueWake(): void {
        if (this.#closed) {
            return;
        }
        this.#wakePending = true;
        this.#notify();
    }

    take(): readonly EphemeralStreamMessage[] {
        if (this.#frames.length === 0 && !this.#wakePending && this.#droppedFrames === 0) {
            return [];
        }
        const messages: EphemeralStreamMessage[] = [];
        for (const bytes of this.#frames) {
            messages.push({ kind: "frame", bytes });
        }
        this.#frames = [];
        this.#queuedBytes = 0;
        if (this.#wakePending) {
            messages.push({ kind: "wake" });
            this.#wakePending = false;
        }
        if (this.#droppedFrames > 0) {
            messages.push({ kind: "drop", frames: this.#droppedFrames });
            this.#droppedFrames = 0;
        }
        return messages;
    }

    async waitForActivity(keepAliveMilliseconds: number): Promise<void> {
        if (this.#closed || this.#hasQueued()) {
            return;
        }
        await new Promise<void>((resolve) => {
            const timer = setTimeout(() => {
                this.#signal = undefined;
                resolve();
            }, keepAliveMilliseconds);
            this.#signal = (): void => {
                clearTimeout(timer);
                this.#signal = undefined;
                resolve();
            };
        });
    }

    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        this.#frames = [];
        this.#queuedBytes = 0;
        this.#onClose();
        this.#notify();
    }

    #hasQueued(): boolean {
        return this.#frames.length > 0 || this.#wakePending || this.#droppedFrames > 0;
    }

    #notify(): void {
        this.#signal?.();
    }
}

/**
 * Bounded in-process default {@link EphemeralFanout}.
 *
 * ```text
 * publishFrame(topic) ─┬─> subscriber A queue ─drain─> SSE stream A
 *                      ├─> subscriber B queue ─drain─> SSE stream B
 *                      └─> ...                          (oldest dropped on overflow)
 * wake(topic) ────────── coalesced flag per subscriber
 * ```
 *
 * Every subscriber queue is bounded by frame count and byte size, so a stalled
 * reader can only cause bounded drops. Subscribers are bounded twice, per
 * process and per topic, because the stream route is unauthenticated and one
 * client would otherwise hold every process-wide slot on a single topic. A
 * shared implementation could replace this to fan frames across instances; the
 * wake path already works across instances through the relay's
 * {@link WakeSource}.
 */
export class InProcessEphemeralFanout implements EphemeralFanout {
    readonly #maximumConcurrentStreams: number;
    readonly #maximumStreamsPerTopic: number;
    readonly #maximumStreamQueueFrames: number;
    readonly #maximumStreamQueueBytes: number;
    readonly #topics = new Map<string, Set<InProcessEphemeralSubscriber>>();
    #subscriberCount = 0;
    #closed = false;

    constructor(options: InProcessEphemeralFanoutOptions) {
        this.#maximumConcurrentStreams = positiveSafeInteger(
            options.maximumConcurrentStreams,
            "Maximum concurrent streams",
        );
        this.#maximumStreamsPerTopic = positiveSafeInteger(
            options.maximumStreamsPerTopic,
            "Maximum streams per topic",
        );
        this.#maximumStreamQueueFrames = positiveSafeInteger(
            options.maximumStreamQueueFrames,
            "Maximum stream queue frames",
        );
        this.#maximumStreamQueueBytes = positiveSafeInteger(
            options.maximumStreamQueueBytes,
            "Maximum stream queue bytes",
        );
    }

    get subscriberCount(): number {
        return this.#subscriberCount;
    }

    subscriberCountForTopic(topic: string): number {
        return this.#topics.get(topic)?.size ?? 0;
    }

    subscribe(topic: string): EphemeralSubscription | undefined {
        if (this.#closed || this.#subscriberCount >= this.#maximumConcurrentStreams) {
            return undefined;
        }
        const existing = this.#topics.get(topic);
        if (existing !== undefined && existing.size >= this.#maximumStreamsPerTopic) {
            return undefined;
        }
        // Only reached when the subscriber will be admitted, so a rejected
        // subscribe never leaves an empty topic entry behind.
        const subscribers = existing ?? new Set<InProcessEphemeralSubscriber>();
        this.#topics.set(topic, subscribers);
        const subscriber = new InProcessEphemeralSubscriber(
            this.#maximumStreamQueueFrames,
            this.#maximumStreamQueueBytes,
            () => {
                if (subscribers.delete(subscriber)) {
                    this.#subscriberCount -= 1;
                    if (subscribers.size === 0) {
                        this.#topics.delete(topic);
                    }
                }
            },
        );
        subscribers.add(subscriber);
        this.#subscriberCount += 1;
        return subscriber;
    }

    publishFrame(topic: string, frame: Uint8Array): number {
        const subscribers = this.#topics.get(topic);
        if (subscribers === undefined) {
            return 0;
        }
        let delivered = 0;
        for (const subscriber of subscribers) {
            subscriber.enqueueFrame(frame);
            delivered += 1;
        }
        return delivered;
    }

    wake(topic: string): void {
        const subscribers = this.#topics.get(topic);
        if (subscribers === undefined) {
            return;
        }
        for (const subscriber of subscribers) {
            subscriber.enqueueWake();
        }
    }

    close(): void {
        this.#closed = true;
        // Snapshot the subscribers first: each close() detaches itself from these
        // collections, so iterating them live while they mutate would be fragile.
        const subscribers: InProcessEphemeralSubscriber[] = [];
        for (const topicSubscribers of this.#topics.values()) {
            for (const subscriber of topicSubscribers) {
                subscribers.push(subscriber);
            }
        }
        for (const subscriber of subscribers) {
            subscriber.close();
        }
        this.#topics.clear();
    }
}
