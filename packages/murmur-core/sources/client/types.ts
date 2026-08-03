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

/**
 * Callbacks for one multi-relay topic stream.
 *
 * Every signal is tagged with the originating `relayId` so an application can
 * deduplicate frames that several relays deliver. Nothing here is durable: the
 * client never persists a frame, a cursor, or a retry.
 */
export interface TopicStreamHandlers {
    /** One opaque ephemeral frame decoded from a specific relay. */
    readonly onFrame?: (frame: { relayId: string; bytes: Uint8Array }) => void;
    /** A relay signalled that durable events may be available; synchronize now. */
    readonly onWake?: (relayId: string) => void;
    /** A relay dropped queued frames for this subscriber. */
    readonly onDrop?: (drop: { relayId: string; frames: number }) => void;
    /** One relay connected, disconnected, or failed to connect. */
    readonly onStatus?: (status: { relayId: string; connected: boolean; error?: Error }) => void;
}

/** Handle to one running multi-relay topic stream. */
export interface TopicStream {
    /** Whether at least one configured relay currently has a live stream. */
    readonly connected: boolean;
    /** Stop every relay connection and prevent any further reconnect. */
    close(): void;
}

/** Isolated retry results which never hide later records or incoming sync. */
export interface RetryOutboundReport {
    readonly results: readonly PublishResult[];
    readonly failures: readonly RetryOutboundFailure[];
}
