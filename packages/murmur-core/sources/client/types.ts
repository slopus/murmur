import type { StoreTransaction } from "../storage/index.js";
import type {
    ListElement,
    PublishOutcome,
    SignedRelayEvent,
    TopicSnapshot,
} from "../transport/index.js";

/** One retained event whose cursor advances only inside an application transaction. */
export interface ReceivedEvent {
    readonly kind: "event";
    readonly relayId: string;
    readonly seq: bigint;
    readonly event: SignedRelayEvent;
    /**
     * Advance this relay/topic cursor inside the transaction that persists the
     * application effect. Skipping an earlier event is rejected.
     */
    advanceCursor(transaction: StoreTransaction): Promise<void>;
}

/** Explicit signal that incremental state is no longer usable for one topic. */
export interface TopicResetRequired {
    readonly kind: "reset";
    readonly relayId: string;
    readonly topic: string;
    readonly requestedSince: bigint;
    readonly head: bigint;
}

/** Result of one synchronization pass; reset and event states cannot be confused. */
export type SyncResult =
    | {
          readonly status: "events";
          readonly events: readonly ReceivedEvent[];
      }
    | {
          readonly status: "reset";
          readonly resets: readonly TopicResetRequired[];
      };

/** Full permanent topic state loaded before following retained events. */
export interface LoadedTopicState {
    readonly relayId: string;
    readonly topic: string;
    readonly seq: bigint;
    readonly snapshot: TopicSnapshot | null;
    readonly elements: readonly ListElement[];
}

/** One successful relay publication and its idempotency outcome. */
export interface RelayPublishResult {
    readonly relayId: string;
    readonly outcome: PublishOutcome;
}

/** Result of publishing an event to configured relays. */
export interface PublishResult {
    readonly event: SignedRelayEvent;
    readonly publications: readonly RelayPublishResult[];
    readonly publishedRelayIds: readonly string[];
    readonly failedRelayIds: readonly string[];
}

/** One retained event which every pending relay still rejected. */
export interface RetryOutboundFailure {
    readonly event: SignedRelayEvent;
    readonly error: Error;
}

/** Isolated retry results which never hide later records or incoming sync. */
export interface RetryOutboundReport {
    readonly results: readonly PublishResult[];
    readonly failures: readonly RetryOutboundFailure[];
}
