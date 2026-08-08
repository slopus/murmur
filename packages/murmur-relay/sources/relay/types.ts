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

/** Cross-process signal used only to reduce queue long-poll latency. */
export interface WakeSource {
    notify(queueId: string): Promise<void>;
    subscribe(listener: (queueId: string) => void): Promise<void>;
    close(): Promise<void>;
}
