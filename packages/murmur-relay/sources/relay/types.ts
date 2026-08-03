/** Weighted HTTP operation costs applied to each matching rate-limit key. */
export interface RelayRateLimitCosts {
    /** Signed event publication cost. Defaults to 25. */
    readonly publish?: number;
    /** Upload-link request and signed upload cost. Defaults to 10. */
    readonly upload?: number;
    /** State, event, health, download-link, and signed download cost. Defaults to 1. */
    readonly read?: number;
    /** Ephemeral frame publication cost, charged to the request IP. Defaults to 1. */
    readonly ephemeral?: number;
}

/** Token-bucket configuration for the relay HTTP boundary. */
export interface RelayRateLimitOptions {
    /** Per-key burst capacity. Defaults to 1,000 tokens. */
    readonly capacity?: number;
    /** Per-key refill rate. Defaults to 50 tokens per second. */
    readonly refillTokensPerSecond?: number;
    /** Maximum in-process key buckets. Defaults to 50,000. */
    readonly maximumBuckets?: number;
    /** Weighted costs by operation class. */
    readonly costs?: RelayRateLimitCosts;
}

/** Fully resolved token-bucket configuration. */
export interface ResolvedRelayRateLimitOptions {
    readonly capacity: number;
    readonly refillTokensPerSecond: number;
    readonly maximumBuckets: number;
    readonly costs: {
        readonly publish: number;
        readonly upload: number;
        readonly read: number;
        readonly ephemeral: number;
    };
}

/** Relay limits and retention policy, with production-safe defaults. */
export interface RelayOptions {
    /** Maximum opaque event payload. Defaults to 1 MiB. */
    readonly maximumEventPayloadBytes?: number;
    /** Maximum current snapshot mutation. Defaults to 4 MiB. */
    readonly maximumSnapshotBytes?: number;
    /** Maximum one list element mutation. Defaults to 256 KiB. */
    readonly maximumListElementBytes?: number;
    /** Maximum ordered list operations in one event. Defaults to 256. */
    readonly maximumListOperationsPerEvent?: number;
    /** Maximum live list elements in one topic. Defaults to 100,000. */
    readonly maximumElementsPerTopic?: number;
    /** Maximum permanent ciphertext blob. Defaults to 64 MiB. */
    readonly maximumBlobBytes?: number;
    /** Maximum JSON request body. Defaults to 8 MiB. */
    readonly maximumJsonBodyBytes?: number;
    /** Maximum retained events in one read. Defaults to 256. */
    readonly maximumEventsPerRead?: number;
    /** Maximum list elements in one page. Defaults to 256. */
    readonly maximumListElementsPerPage?: number;
    /** Maximum long-poll duration, never above 30 seconds. Defaults to 30 seconds. */
    readonly maximumLongPollMilliseconds?: number;
    /** Maximum simultaneous parked reads in one process. Defaults to 10,000. */
    readonly maximumConcurrentLongPolls?: number;
    /** Event-log retention window. Defaults to seven days. */
    readonly eventRetentionMilliseconds?: number;
    /** Topic inactivity window. Defaults to thirty days. */
    readonly topicInactivityMilliseconds?: number;
    /** Maximum opaque ephemeral frame accepted for fan-out. Defaults to 128 KiB. */
    readonly maximumEphemeralFrameBytes?: number;
    /** Maximum simultaneous ephemeral streams in one process. Defaults to 10,000. */
    readonly maximumConcurrentStreams?: number;
    /** Maximum queued frames buffered per stream subscriber. Defaults to 64. */
    readonly maximumStreamQueueFrames?: number;
    /** Maximum queued frame bytes buffered per stream subscriber. Defaults to 1 MiB. */
    readonly maximumStreamQueueBytes?: number;
    /** SSE keepalive comment interval for open streams. Defaults to 15,000 ms. */
    readonly streamKeepAliveMilliseconds?: number;
    /** HTTP rate limiting; pass `false` to disable it. Enabled by default. */
    readonly rateLimit?: RelayRateLimitOptions | false;
}

/** Fully resolved immutable policy exposed to the HTTP boundary. */
export interface ResolvedRelayOptions {
    readonly maximumEventPayloadBytes: number;
    readonly maximumSnapshotBytes: number;
    readonly maximumListElementBytes: number;
    readonly maximumListOperationsPerEvent: number;
    readonly maximumElementsPerTopic: number;
    readonly maximumBlobBytes: number;
    readonly maximumJsonBodyBytes: number;
    readonly maximumEventsPerRead: number;
    readonly maximumListElementsPerPage: number;
    readonly maximumLongPollMilliseconds: number;
    readonly maximumConcurrentLongPolls: number;
    readonly eventRetentionMilliseconds: number;
    readonly topicInactivityMilliseconds: number;
    readonly maximumEphemeralFrameBytes: number;
    readonly maximumConcurrentStreams: number;
    readonly maximumStreamQueueFrames: number;
    readonly maximumStreamQueueBytes: number;
    readonly streamKeepAliveMilliseconds: number;
    readonly rateLimit: ResolvedRelayRateLimitOptions | false;
}

/** Counts returned by one retention sweep. */
export interface RelayPruneOutcome {
    readonly events: number;
    readonly topics: number;
}

/** Cross-process signal used only to reduce long-poll latency. */
export interface WakeSource {
    notify(topic: string): Promise<void>;
    subscribe(listener: (topic: string) => void): Promise<void>;
    close(): Promise<void>;
}

/** One item drained from a stream subscriber's bounded queue. */
export type EphemeralStreamMessage =
    | { readonly kind: "frame"; readonly bytes: Uint8Array }
    | { readonly kind: "wake" }
    | { readonly kind: "drop"; readonly frames: number };

/**
 * One live SSE stream subscriber's read side.
 *
 * The producer (frame fan-out and wake delivery) enqueues into a bounded
 * buffer and never awaits this reader, so a stalled consumer can only cause
 * bounded frame drops, never unbounded memory growth. The SSE encoder repeatedly
 * drains {@link take} and parks on {@link waitForActivity} between batches.
 */
export interface EphemeralSubscription {
    /** Remove and return every currently queued message; empty when idle. */
    take(): readonly EphemeralStreamMessage[];
    /** Resolve when a message is queued, the subscription closes, or the keepalive interval elapses. */
    waitForActivity(keepAliveMilliseconds: number): Promise<void>;
    /** Whether the subscription has been closed by the service or the reader. */
    readonly closed: boolean;
    /** Detach the subscriber from its fan-out and release the reader. */
    close(): void;
}

/**
 * In-process fan-out of opaque ephemeral frames to local stream subscribers.
 *
 * This interface is deliberately shaped like {@link WakeSource} and the
 * rate limiter so a shared, cross-instance implementation can be substituted.
 * Frame fan-out is in-process only; cross-instance promptness rides
 * {@link WakeSource} through the `wake` event instead.
 */
export interface EphemeralFanout {
    /** Register a subscriber for a topic, or `undefined` when at capacity. */
    subscribe(topic: string): EphemeralSubscription | undefined;
    /** Enqueue one frame to every local subscriber, returning how many were enqueued. */
    publishFrame(topic: string, frame: Uint8Array): number;
    /** Enqueue one coalesced wake to every local subscriber of a topic. */
    wake(topic: string): void;
    /** Current count of live local subscribers across all topics. */
    readonly subscriberCount: number;
    /** Close every subscriber and stop accepting new ones. */
    close(): void;
}
