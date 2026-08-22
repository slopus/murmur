import type { SignedDelivery } from "../protocol/index.js";
import type { PublishOutcome } from "../storage/index.js";

/** Oldest persisted manifest still missing at least one recipient insertion. */
export interface PendingFanoutManifest {
    readonly eventId: string;
    readonly delivery: SignedDelivery;
    readonly admissionPrincipal: string;
    readonly pendingRecipients: readonly Uint8Array[];
}

/** Durable source-of-truth operations required by ordered fanout. */
export interface DurableFanoutStore {
    reserve(
        delivery: SignedDelivery,
        admissionPrincipal: string,
        now: number,
    ): Promise<PublishOutcome>;
    oldestPending(now: number): Promise<PendingFanoutManifest | undefined>;
    markDelivered(sender: Uint8Array, deliveryId: string, recipient: Uint8Array): Promise<void>;
    pruneExpired(now: number): Promise<number>;
}

/** Idempotent boundary for inserting one shared event into one device inbox. */
export interface FanoutTarget {
    insert(
        recipient: Uint8Array,
        eventId: string,
        delivery: SignedDelivery,
        admissionPrincipal: string,
    ): Promise<void>;
}

/** Durable alarm or job scheduler used to resume incomplete fanout. */
export interface FanoutRetryScheduler {
    schedule(at: number): Promise<void>;
}

/** Ordered retry timing policy. */
export interface DurableFanoutCoordinatorOptions {
    readonly now?: () => number;
    readonly retryDelayMilliseconds?: number;
    readonly maximumManifestsPerRun?: number;
}

/** Result of one bounded retry/alarm pass. */
export interface FanoutRetryOutcome {
    readonly completedManifests: number;
    readonly pending: boolean;
}
