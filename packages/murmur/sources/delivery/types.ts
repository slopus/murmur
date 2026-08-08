import type { IdentityKeyPair } from "../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";

/** One sender-signed encrypted multicast accepted by the relay. */
export interface SignedDelivery {
    readonly version: 1;
    readonly id: string;
    readonly sender: Uint8Array;
    readonly recipients: readonly Uint8Array[];
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly ciphertext: Uint8Array;
    readonly signature: Uint8Array;
}

/** Signed request for one identity inbox page. */
export interface SignedInboxRead {
    readonly version: 1;
    readonly recipient: Uint8Array;
    readonly after: string | null;
    readonly limit: number;
    readonly waitMilliseconds: number;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** Signed request to trim one processed inbox prefix. */
export interface SignedInboxAck {
    readonly version: 1;
    readonly recipient: Uint8Array;
    readonly through: string;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** Relay publication outcome. */
export interface DeliveryPublishOutcome {
    readonly eventId: string;
    readonly duplicate: boolean;
}

/** One retained delivery reference in an inbox. */
export interface InboxDelivery {
    readonly eventId: string;
    readonly delivery: SignedDelivery;
}

/** One bounded inbox page. */
export interface InboxPage {
    readonly deliveries: readonly InboxDelivery[];
    readonly head: string | null;
    readonly acknowledgedThrough: string | null;
    readonly exhausted: boolean;
}

/** Browser-safe fetch signature used by the HTTP delivery transport. */
export type DeliveryFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Relay-neutral queue operations used by the stateful inbox processor. */
export interface DeliveryTransport {
    publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome>;
    read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage>;
    acknowledge(
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }>;
}

/** Inputs for one exact sender-signed delivery. */
export interface CreateDeliveryOptions {
    readonly id?: string;
    readonly createdAt?: number;
    readonly expiresAt: number;
}

/** Inputs for one signed inbox read. */
export interface CreateInboxReadOptions {
    readonly after?: string | null;
    readonly limit?: number;
    readonly waitMilliseconds?: number;
    readonly createdAt?: number;
}

/** Durable handler invoked inside the cursor transaction. */
export type InboxDeliveryHandler = (
    transaction: StoreTransaction,
    delivery: InboxDelivery,
) => Promise<void>;

/** Inbox processor construction policy. */
export interface InboxProcessorOptions {
    /** Maximum diagnostic rejection summaries retained locally. */
    readonly maximumRejections?: number;
    /** Maximum unexpired sender delivery IDs retained for replay protection. */
    readonly maximumReplayEntries?: number;
    /** Largest accepted sender clock lead. */
    readonly maximumFutureSkewMilliseconds?: number;
    /** Allowed relay clock lead or device clock lag when validating UUIDv7 time. */
    readonly maximumRelayClockSkewMilliseconds?: number;
    /** Local clock used only for signed relay read and acknowledgement requests. */
    readonly now?: () => number;
}

/** One synchronization request. */
export interface InboxSyncOptions {
    readonly limit?: number;
    readonly waitMilliseconds?: number;
    readonly signal?: AbortSignal;
}

/** Durable terminal-rejection summary. */
export interface InboxRejection {
    readonly eventId: string;
    readonly code: string;
}

/** Result of one read/process/ack cycle. */
export interface InboxSyncResult {
    readonly processed: number;
    readonly rejected: number;
    readonly cursor: string | null;
    readonly exhausted: boolean;
}

/** Dependencies required by the stateful inbox processor. */
export interface InboxProcessorDependencies {
    readonly identity: IdentityKeyPair;
    readonly store: MurmurStore;
    readonly transport: DeliveryTransport;
}
