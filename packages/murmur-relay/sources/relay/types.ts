import type { QueuedDelivery } from "../storage/index.js";

/** Relay limits with conservative defaults. */
export interface RelayOptions {
    readonly maximumInvitationBytes?: number;
    readonly maximumInvitationTtlMilliseconds?: number;
    readonly maximumInvitationItemsPerAdmissionPrincipal?: number;
    readonly maximumInvitationBytesPerAdmissionPrincipal?: number;
    readonly maximumGlobalInvitationItems?: number;
    readonly maximumGlobalInvitationBytes?: number;
    readonly maximumInvitationItemsPerRevocationKey?: number;
    readonly maximumCiphertextBytes?: number;
    readonly maximumRecipients?: number;
    readonly maximumJsonBodyBytes?: number;
    readonly maximumQueueItems?: number;
    readonly maximumQueueBytes?: number;
    readonly maximumSenderItems?: number;
    readonly maximumSenderBytes?: number;
    readonly maximumSenderReferences?: number;
    readonly maximumAdmissionReferences?: number;
    readonly maximumGlobalItems?: number;
    readonly maximumGlobalBytes?: number;
    readonly maximumGlobalReferences?: number;
    readonly maximumDeliveryTtlMilliseconds?: number;
    readonly maximumAuthenticationSkewMilliseconds?: number;
    readonly maximumDeliveriesPerRead?: number;
    readonly maximumLongPollMilliseconds?: number;
    readonly maximumConcurrentLongPolls?: number;
    readonly maximumConcurrentLongPollsPerIdentity?: number;
}

/** Fully resolved relay limits. */
export interface ResolvedRelayOptions {
    readonly maximumInvitationBytes: number;
    readonly maximumInvitationTtlMilliseconds: number;
    readonly maximumInvitationItemsPerAdmissionPrincipal: number;
    readonly maximumInvitationBytesPerAdmissionPrincipal: number;
    readonly maximumGlobalInvitationItems: number;
    readonly maximumGlobalInvitationBytes: number;
    readonly maximumInvitationItemsPerRevocationKey: number;
    readonly maximumCiphertextBytes: number;
    readonly maximumRecipients: number;
    readonly maximumJsonBodyBytes: number;
    readonly maximumQueueItems: number;
    readonly maximumQueueBytes: number;
    readonly maximumSenderItems: number;
    readonly maximumSenderBytes: number;
    readonly maximumSenderReferences: number;
    readonly maximumAdmissionReferences: number;
    readonly maximumGlobalItems: number;
    readonly maximumGlobalBytes: number;
    readonly maximumGlobalReferences: number;
    readonly maximumDeliveryTtlMilliseconds: number;
    readonly maximumAuthenticationSkewMilliseconds: number;
    readonly maximumDeliveriesPerRead: number;
    readonly maximumLongPollMilliseconds: number;
    readonly maximumConcurrentLongPolls: number;
    readonly maximumConcurrentLongPollsPerIdentity: number;
}

/** Result of caching one opaque signed discovery bundle. */
export interface InvitationUploadOutcome {
    readonly digest: Uint8Array;
    readonly expiresAt: number;
    readonly duplicate: boolean;
}

/** One unexpired invitation fetched by its exact SHA-256 digest. */
export interface InvitationDownload {
    readonly bundle: Uint8Array;
    readonly expiresAt: number;
}

/** Result of one owner-authorized invitation revocation transaction. */
export interface InvitationRevocationOutcome {
    readonly revoked: number;
}

/** One stream control frame proving the current inbox continuity baseline. */
export interface QueueContinuityEvent {
    readonly type: "continuity";
    readonly generation: Uint8Array;
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
}

/** One pull-driven recipient SSE subscription; `null` represents a heartbeat. */
export interface QueueEventSubscription {
    readonly events: AsyncIterable<QueuedDelivery | QueueContinuityEvent | null>;
    close(): void;
}

/** Cross-process signal used only to reduce queue long-poll latency. */
export interface WakeSource {
    notify(queueId: string): Promise<void>;
    subscribe(listener: (queueId: string) => void): Promise<void>;
    close(): Promise<void>;
}
