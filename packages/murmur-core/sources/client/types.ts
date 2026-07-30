import type { RelayEvent } from "../transport/index.js";

/** A deduplicated delivery awaiting an explicit application acknowledgement. */
export interface ReceivedEvent {
    readonly event: RelayEvent;
    acknowledge(): Promise<void>;
}

/** Result of publishing an event to configured relays. */
export interface PublishResult {
    readonly event: RelayEvent;
    readonly publishedRelayIds: readonly string[];
    readonly failedRelayIds: readonly string[];
}

/** One retained event which every pending relay still rejected. */
export interface RetryOutboundFailure {
    readonly event: RelayEvent;
    readonly error: Error;
}

/** Isolated retry results which never hide later records or incoming sync. */
export interface RetryOutboundReport {
    readonly results: readonly PublishResult[];
    readonly failures: readonly RetryOutboundFailure[];
}
