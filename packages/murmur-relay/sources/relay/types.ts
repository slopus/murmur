import type { QueuedDelivery } from "../storage/index.js";

/** Relay limits with conservative defaults. */
export interface RelayOptions {
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

/** One stream control frame proving the current inbox continuity baseline. */
export interface QueueContinuityEvent {
    readonly type: "continuity";
    readonly generation: Uint8Array;
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
}

/** Ephemeral owner-only hint that one account roster should be read again. */
export interface QueueDeviceRosterChangedEvent {
    readonly type: "device_roster_changed";
    readonly accountKey: Uint8Array;
}

/** One pull-driven recipient SSE subscription; `null` represents a heartbeat. */
export interface QueueEventSubscription {
    readonly events: AsyncIterable<
        QueuedDelivery | QueueContinuityEvent | QueueDeviceRosterChangedEvent | null
    >;
    close(): void;
}

/** Cross-process signal used only to reduce queue long-poll latency. */
export interface WakeSource {
    notify(queueId: string): Promise<void>;
    subscribe(listener: (queueId: string) => void): Promise<void>;
    close(): Promise<void>;
}
