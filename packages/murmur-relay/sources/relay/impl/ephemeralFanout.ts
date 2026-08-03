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
    /** Maximum frame bytes retained across every subscriber before dropping the oldest. */
    readonly maximumTotalStreamQueueBytes: number;
}

/** Process-wide byte accounting one subscriber reports every retention change to. */
interface SubscriberLedger {
    /** Frame bytes the subscriber has started holding. */
    readonly retain: (bytes: number) => void;
    /** Frame bytes the subscriber no longer holds. */
    readonly release: (bytes: number) => void;
    /** Detach the subscriber from its fan-out. */
    readonly onClose: () => void;
}

interface InProcessEphemeralSubscriberOptions {
    readonly maximumFrames: number;
    readonly maximumBytes: number;
    readonly ledger: SubscriberLedger;
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
 *
 * Every byte held is reported to the fan-out's ledger, including the batch a
 * reader has already been handed but not yet come back from: {@link take}
 * reclassifies queued bytes as in-flight rather than releasing them, and they
 * are released on the reader's next call. The process-wide budget therefore
 * covers what the response bodies hold as well as what the queues hold.
 */
class InProcessEphemeralSubscriber implements EphemeralSubscription {
    readonly #maximumFrames: number;
    readonly #maximumBytes: number;
    readonly #ledger: SubscriberLedger;
    #frames: Uint8Array[] = [];
    #queuedBytes = 0;
    #inFlightBytes = 0;
    #droppedFrames = 0;
    #wakePending = false;
    #closed = false;
    #signal: (() => void) | undefined;

    constructor(options: InProcessEphemeralSubscriberOptions) {
        this.#maximumFrames = options.maximumFrames;
        this.#maximumBytes = options.maximumBytes;
        this.#ledger = options.ledger;
    }

    get closed(): boolean {
        return this.#closed;
    }

    /** Frame bytes currently queued for this subscriber, excluding any in flight. */
    get queuedBytes(): number {
        return this.#queuedBytes;
    }

    /** Append one frame, dropping the oldest queued frames if a bound is exceeded. */
    enqueueFrame(frame: Uint8Array): void {
        if (this.#closed) {
            return;
        }
        this.#frames.push(frame);
        this.#queuedBytes += frame.length;
        this.#ledger.retain(frame.length);
        while (
            this.#frames.length > this.#maximumFrames ||
            this.#queuedBytes > this.#maximumBytes
        ) {
            if (!this.dropOldestQueuedFrame()) {
                break;
            }
        }
        this.#notify();
    }

    /**
     * Drop this subscriber's oldest queued frame, counting it like any other
     * overflow drop. Returns whether a frame was there to drop.
     */
    dropOldestQueuedFrame(): boolean {
        const dropped = this.#frames.shift();
        if (dropped === undefined) {
            return false;
        }
        this.#queuedBytes -= dropped.length;
        this.#droppedFrames += 1;
        this.#ledger.release(dropped.length);
        this.#notify();
        return true;
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
        // Coming back for more means the previous batch has left the response
        // body, so it stops counting against the process-wide budget here.
        this.#releaseInFlight();
        if (this.#frames.length === 0 && !this.#wakePending && this.#droppedFrames === 0) {
            return [];
        }
        const messages: EphemeralStreamMessage[] = [];
        for (const bytes of this.#frames) {
            messages.push({ kind: "frame", bytes });
        }
        this.#frames = [];
        // Handing the batch to the reader moves those bytes rather than freeing
        // them: they are still retained by this process until the next call.
        this.#inFlightBytes = this.#queuedBytes;
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
        this.#ledger.release(this.#queuedBytes);
        this.#queuedBytes = 0;
        this.#releaseInFlight();
        this.#ledger.onClose();
        this.#notify();
    }

    #releaseInFlight(): void {
        if (this.#inFlightBytes > 0) {
            this.#ledger.release(this.#inFlightBytes);
            this.#inFlightBytes = 0;
        }
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
 * client would otherwise hold every process-wide slot on a single topic.
 *
 * Those per-subscriber bounds multiplied by the subscriber cap still promise
 * far more memory than a relay has, so retained frame bytes are also bounded in
 * aggregate: every retention is counted, and exceeding
 * `maximumTotalStreamQueueBytes` drops frames from whichever subscriber has
 * been backlogged longest until the total fits again. Those drops are counted
 * and reported exactly like per-subscriber overflow drops, so the path keeps
 * degrading the same way instead of refusing service.
 *
 * A shared implementation could replace this to fan frames across instances;
 * the wake path already works across instances through the relay's
 * {@link WakeSource}.
 */
export class InProcessEphemeralFanout implements EphemeralFanout {
    readonly #maximumConcurrentStreams: number;
    readonly #maximumStreamsPerTopic: number;
    readonly #maximumStreamQueueFrames: number;
    readonly #maximumStreamQueueBytes: number;
    readonly #maximumTotalStreamQueueBytes: number;
    readonly #topics = new Map<string, Set<InProcessEphemeralSubscriber>>();
    /**
     * Subscribers holding queued frames, in the order they became backlogged.
     * The front is the reader that has been behind the longest, which is what
     * the aggregate budget evicts from first.
     */
    readonly #backlogged = new Set<InProcessEphemeralSubscriber>();
    #retainedBytes = 0;
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
        this.#maximumTotalStreamQueueBytes = positiveSafeInteger(
            options.maximumTotalStreamQueueBytes,
            "Maximum total stream queue bytes",
        );
        if (this.#maximumTotalStreamQueueBytes < this.#maximumStreamQueueBytes) {
            throw new Error(
                "Maximum total stream queue bytes cannot be below maximum stream queue bytes",
            );
        }
    }

    get subscriberCount(): number {
        return this.#subscriberCount;
    }

    /**
     * Frame bytes retained across every subscriber right now, queued or handed
     * to a reader that has not come back. Exposed for diagnostics and tests.
     */
    get retainedBytes(): number {
        return this.#retainedBytes;
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
        const subscriber: InProcessEphemeralSubscriber = new InProcessEphemeralSubscriber({
            maximumFrames: this.#maximumStreamQueueFrames,
            maximumBytes: this.#maximumStreamQueueBytes,
            ledger: {
                retain: (bytes): void => {
                    this.#retainedBytes += bytes;
                    this.#backlogged.add(subscriber);
                },
                release: (bytes): void => {
                    this.#retainedBytes -= bytes;
                    if (subscriber.queuedBytes === 0) {
                        this.#backlogged.delete(subscriber);
                    }
                },
                onClose: (): void => {
                    this.#backlogged.delete(subscriber);
                    if (subscribers.delete(subscriber)) {
                        this.#subscriberCount -= 1;
                        if (subscribers.size === 0) {
                            this.#topics.delete(topic);
                        }
                    }
                },
            },
        });
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
            // Enforced per enqueue rather than per publish, so the aggregate
            // budget is never exceeded by more than the frame just accepted.
            this.#enforceTotalBudget();
            delivered += 1;
        }
        return delivered;
    }

    /**
     * Drop the longest-backlogged reader's oldest frames until the retained
     * total fits the aggregate budget again.
     *
     * The frame just enqueued is itself queued and therefore droppable, so this
     * always has something to release and terminates.
     */
    #enforceTotalBudget(): void {
        while (this.#retainedBytes > this.#maximumTotalStreamQueueBytes) {
            const victim = this.#backlogged.values().next().value;
            if (victim === undefined) {
                return;
            }
            if (!victim.dropOldestQueuedFrame()) {
                this.#backlogged.delete(victim);
            }
        }
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
        this.#backlogged.clear();
        this.#retainedBytes = 0;
    }
}
