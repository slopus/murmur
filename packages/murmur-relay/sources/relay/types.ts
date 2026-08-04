/** Relay limits with conservative defaults. */
export interface RelayOptions {
    readonly maximumEventPayloadBytes?: number;
    readonly maximumCollapseKeyBytes?: number;
    readonly maximumJsonBodyBytes?: number;
    readonly maximumEventsPerRead?: number;
    readonly maximumLongPollMilliseconds?: number;
    readonly maximumConcurrentLongPolls?: number;
    readonly readChallengeLifetimeMilliseconds?: number;
    readonly maximumOutstandingReadChallenges?: number;
}

/** Fully resolved relay limits. */
export interface ResolvedRelayOptions {
    readonly maximumEventPayloadBytes: number;
    readonly maximumCollapseKeyBytes: number;
    readonly maximumJsonBodyBytes: number;
    readonly maximumEventsPerRead: number;
    readonly maximumLongPollMilliseconds: number;
    readonly maximumConcurrentLongPolls: number;
    readonly readChallengeLifetimeMilliseconds: number;
    readonly maximumOutstandingReadChallenges: number;
}

/** Cross-process signal used only to reduce long-poll latency. */
export interface WakeSource {
    notify(topicId: string): Promise<void>;
    subscribe(listener: (topicId: string) => void): Promise<void>;
    close(): Promise<void>;
}
