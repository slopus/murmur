import type { IdentityPublicKeys } from "../crypto/index.js";

/** Maximum opaque event payload accepted by the default protocol profile. */
export const MAX_RELAY_EVENT_PAYLOAD_BYTES = 1024 * 1024;

/** An opaque, publisher-authenticated event. */
export interface RelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly sender: IdentityPublicKeys;
    readonly recipients: readonly string[];
    readonly createdAt: number;
    readonly payload: Uint8Array;
    readonly signature: Uint8Array;
}

/** Authenticated request to receive publications for a topic. */
export interface TopicSubscription {
    readonly version: 1;
    readonly topic: string;
    readonly subscriber: IdentityPublicKeys;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** One queued copy of an event for one recipient. */
export interface RelayDelivery {
    readonly deliveryId: string;
    readonly event: RelayEvent;
}

/** Blob returned by a relay. Its identifier is the SHA-256 of its ciphertext. */
export interface RelayBlob {
    readonly id: string;
    readonly bytes: Uint8Array;
}

/** Recipient-signed, single-use request to read its queue. */
export interface QueueReadRequest {
    readonly version: 1;
    readonly action: "read";
    readonly requestId: string;
    readonly createdAt: number;
    readonly recipient: IdentityPublicKeys;
    readonly signature: Uint8Array;
}

/** Recipient-signed, single-use request to delete one queued delivery. */
export interface QueueAcknowledgeRequest {
    readonly version: 1;
    readonly action: "acknowledge";
    readonly requestId: string;
    readonly createdAt: number;
    readonly recipient: IdentityPublicKeys;
    readonly deliveryId: string;
    readonly signature: Uint8Array;
}

/** Replaceable relay or peer-to-peer transport. */
export interface RelayTransport {
    readonly id: string;
    publish(event: RelayEvent): Promise<void>;
    subscribe(subscription: TopicSubscription): Promise<void>;
    pull(
        request: QueueReadRequest,
        waitMilliseconds?: number,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]>;
    acknowledge(request: QueueAcknowledgeRequest): Promise<void>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
}
