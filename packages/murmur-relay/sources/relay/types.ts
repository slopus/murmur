/** Weighted HTTP operation costs applied to each matching rate-limit key. */
export interface RelayRateLimitCosts {
    /** Signed event publication cost. Defaults to 25. */
    readonly publish?: number;
    /** Upload-link request and signed upload cost. Defaults to 10. */
    readonly upload?: number;
    /** State, event, health, download-link, and signed download cost. Defaults to 1. */
    readonly read?: number;
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
