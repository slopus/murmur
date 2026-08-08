import type { SignedDelivery } from "../protocol/index.js";

/** Maximum expired delivery records removed by one writer transaction. */
export const RELAY_EXPIRATION_BATCH_ITEMS = 100;

/** Atomic publication result for one sender-scoped delivery ID. */
export interface PublishOutcome {
    readonly eventId: string;
    readonly duplicate: boolean;
}

/** Result of one monotonic queue-prefix acknowledgement. */
export interface AcknowledgeOutcome {
    readonly removed: number;
}

/** Per-identity queue bounds enforced atomically across a multicast. */
export interface QueueLimits {
    readonly maximumItems: number;
    readonly maximumBytes: number;
    readonly maximumSenderItems: number;
    readonly maximumSenderBytes: number;
    readonly maximumSenderReferences: number;
    readonly maximumAdmissionReferences: number;
    readonly maximumGlobalItems: number;
    readonly maximumGlobalBytes: number;
    readonly maximumGlobalReferences: number;
}

/** Allocation bound applied while materializing one queue page. */
export interface PageReadConstraints {
    readonly maximumEncodedBytes: number;
}

/** One retained queue reference and its shared delivery. */
export interface QueuedDelivery {
    readonly eventId: string;
    readonly delivery: SignedDelivery;
}

/** One authenticated recipient queue page. */
export interface QueuePage {
    readonly deliveries: readonly QueuedDelivery[];
    readonly head: string | null;
    readonly acknowledgedThrough: string | null;
    readonly exhausted: boolean;
}

/** Atomic persistence operations required by the identity-queue relay. */
export interface RelayStore {
    publish(
        delivery: SignedDelivery,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<PublishOutcome>;
    readQueue(
        recipient: Uint8Array,
        after: string | null,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<QueuePage>;
    acknowledge(recipient: Uint8Array, through: string, now: number): Promise<AcknowledgeOutcome>;
    pruneExpired(now: number): Promise<number>;
    health(): Promise<void>;
    close(): Promise<void>;
}
