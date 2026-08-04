import type { StoreTransaction } from "../storage/index.js";
import type { PublishOutcome, SignedRelayEvent, TopicAccess } from "../transport/index.js";

/** One retained event whose cursor advances with the application transaction. */
export interface ReceivedEvent {
    readonly seq: bigint;
    readonly event: SignedRelayEvent;
    /**
     * Advance past this event inside the transaction persisting its application
     * effect. Sequence gaps from expiration and collapse are accepted.
     */
    advanceCursor(transaction: StoreTransaction): Promise<void>;
}

/** One successful single-relay publication. */
export interface PublishResult {
    readonly event: SignedRelayEvent;
    readonly outcome: PublishOutcome;
}

/** One synchronization pass over all locally followed topics. */
export interface SyncResult {
    readonly events: readonly ReceivedEvent[];
}

/** Locally followed topic and its secret read capability, when required. */
export type Subscription = TopicAccess;
