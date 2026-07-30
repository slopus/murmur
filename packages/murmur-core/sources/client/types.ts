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
