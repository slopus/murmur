/** Relay service configuration. */
export interface RelayOptions {
    /** Topic inactivity window. Defaults to thirty days. */
    readonly topicInactivityMilliseconds?: number;
    /** Maximum opaque event payload. Defaults to one MiB. */
    readonly maximumEventBytes?: number;
    /** Maximum ciphertext blob. Defaults to 64 MiB. */
    readonly maximumBlobBytes?: number;
    /** Maximum complete event envelope. Defaults to two MiB. */
    readonly maximumEnvelopeBytes?: number;
    /** Maximum explicit recipients. Defaults to the core protocol limit. */
    readonly maximumRecipients?: number;
    /** Maximum simultaneous long polls. Defaults to 10,000. */
    readonly maximumWaiters?: number;
    /** Maximum deliveries returned by one pull. Defaults to 16. */
    readonly maximumDeliveryBatch?: number;
}

/** Count of data removed when expiring inactive topics. */
export interface PruneResult {
    readonly topics: number;
    readonly deliveries: number;
}
