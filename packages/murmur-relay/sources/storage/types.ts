import type { SignedDelivery } from "../protocol/index.js";

/** Maximum expired delivery records removed by one writer transaction. */
export const RELAY_EXPIRATION_BATCH_ITEMS = 100;

/** Atomic publication result for one sender-scoped delivery ID. */
export interface PublishOutcome {
    readonly eventId: string;
    readonly duplicate: boolean;
}

/** Result of storing one content-addressed ephemeral invitation. */
export interface StoreInvitationOutcome {
    readonly expiresAt: number;
    readonly duplicate: boolean;
}

/** One unexpired opaque invitation returned by its SHA-256 digest. */
export interface StoredInvitation {
    readonly bundle: Uint8Array;
    readonly expiresAt: number;
}

/** Independent bounds for the five-minute invitation cache. */
export interface InvitationLimits {
    readonly maximumPrincipalItems: number;
    readonly maximumPrincipalBytes: number;
    readonly maximumGlobalItems: number;
    readonly maximumGlobalBytes: number;
    readonly maximumRevocationKeyItems: number;
}

/** Result of atomically replacing live invitations with bounded revocation tombstones. */
export interface RevokeInvitationsOutcome {
    readonly revoked: number;
}

/** Result of one monotonic queue-prefix acknowledgement. */
export interface AcknowledgeOutcome {
    readonly removed: number;
    readonly generation: Uint8Array;
    readonly sequence: number;
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
    readonly sequence: number;
    readonly delivery: SignedDelivery;
}

/** One authenticated recipient queue page. */
export interface QueuePage {
    readonly deliveries: readonly QueuedDelivery[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;
    readonly exhausted: boolean;
}

/** Atomic persistence operations required by the identity-queue relay. */
export interface RelayStore {
    storeInvitation(
        digest: Uint8Array,
        bundle: Uint8Array,
        expiresAt: number,
        now: number,
        limits: InvitationLimits,
        admissionPrincipal: Uint8Array,
        revocationKey?: Uint8Array,
    ): Promise<StoreInvitationOutcome>;
    readInvitation(digest: Uint8Array, now: number): Promise<StoredInvitation | undefined>;
    revokeInvitations(
        revocationKey: Uint8Array,
        digest: Uint8Array | null,
        now: number,
        maximumItems: number,
    ): Promise<RevokeInvitationsOutcome>;
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
    /** Invalidate every known inbox after an operator-declared state restoration. */
    declareRestored(): Promise<number>;
    pruneExpired(now: number): Promise<number>;
    health(): Promise<void>;
    close(): Promise<void>;
}
