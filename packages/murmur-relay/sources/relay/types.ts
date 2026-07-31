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
