import type { RelayBlob, RelayDelivery, RelayEvent, TopicSubscription } from "@murmur/core";
import type { PruneResult } from "../relay/types.js";

/** Result of atomically recording and fanning out a publication. */
export interface RelayPublishResult {
    readonly disposition: "inserted" | "duplicate";
    readonly recipients: readonly string[];
}

/** Storage operations required by the dumb relay service. */
export interface RelayStore {
    addSubscription(subscription: TopicSubscription, observedAt: number): Promise<number>;
    publish(event: RelayEvent, observedAt: number): Promise<RelayPublishResult>;
    consumeQueueRequest(
        recipientId: string,
        requestId: string,
        expiresAt: number,
        observedAt: number,
    ): Promise<boolean>;
    pull(recipientId: string, maximumDeliveries: number): Promise<readonly RelayDelivery[]>;
    acknowledge(recipientId: string, deliveryId: string): Promise<void>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
    pruneInactiveTopics(olderThan: number): Promise<PruneResult>;
}
