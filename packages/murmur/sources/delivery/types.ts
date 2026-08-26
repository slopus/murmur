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
    /** Relay v2 continuity sequence; omitted only by legacy custom transports. */
    readonly sequence?: number;
    readonly delivery: SignedDelivery;
}

/** One bounded inbox page. */
export interface InboxPage {
    readonly deliveries: readonly InboxDelivery[];
    readonly head: string | null;
    readonly headSequence?: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence?: number;
    readonly generation?: Uint8Array;
    readonly exhausted: boolean;
}

/** Stream control frame proving the current relay inbox generation and head. */
export interface InboxContinuity {
    readonly type: "continuity";
    readonly generation: Uint8Array;
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
}

/** One exact stream delivery or its preceding continuity control frame. */
export type InboxStreamEvent = InboxDelivery | InboxContinuity;

/** Continuity metadata returned after a monotonic acknowledgement. */
export interface InboxAcknowledgement {
    readonly removed: number;
    readonly sequence?: number;
    readonly generation?: Uint8Array;
}

/** Browser-safe fetch signature used by the HTTP delivery transport. */
export type DeliveryFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Signed proof used when requesting a short-lived negotiated relay session. */
export interface SignedRelaySessionRequest {
    readonly version: 1;
    readonly device: Uint8Array;
    readonly createdAt: number;
    readonly nonce: Uint8Array;
    readonly signature: Uint8Array;
}

/** Protocol and endpoint selected by an application authentication server. */
export interface RelaySessionTicket {
    readonly version: 1;
    readonly protocol: "murmur-websocket-v1";
    readonly endpoint: string;
    readonly token: string;
    readonly expiresAt: number;
}

/** Application-provided session issuer, normally backed by its authenticated server. */
export interface RelaySessionProvider {
    issue(request: SignedRelaySessionRequest, signal?: AbortSignal): Promise<RelaySessionTicket>;
}

/** Minimal WebSocket message event used by the browser-safe transport seam. */
export interface DeliveryWebSocketMessageEvent {
    readonly data: unknown;
}

/** Minimal close event used by the browser-safe transport seam. */
export interface DeliveryWebSocketCloseEvent {
    readonly code: number;
    readonly reason: string;
    readonly wasClean: boolean;
}

/** Browser-compatible WebSocket surface required by the negotiated transport. */
export interface DeliveryWebSocket {
    readonly readyState: number;
    onopen: (() => void) | null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null;
    onerror: (() => void) | null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null;
    send(data: string): void;
    close(code?: number, reason?: string): void;
}

/** Factory used to open a WebSocket without imposing a runtime dependency. */
export type DeliveryWebSocketFactory = (
    url: string,
    protocols: readonly string[],
) => DeliveryWebSocket;

/** Fetch-backed temporary-session provider policy. */
export interface HttpRelaySessionProviderOptions {
    readonly fetch?: DeliveryFetch;
    readonly maximumResponseBytes?: number;
    readonly requestTimeoutMilliseconds?: number;
}

/** Negotiated WebSocket transport policy. */
export interface WebSocketDeliveryTransportOptions {
    readonly webSocketFactory?: DeliveryWebSocketFactory;
    readonly now?: () => number;
    readonly requestTimeoutMilliseconds?: number;
    readonly streamHeartbeatTimeoutMilliseconds?: number;
    readonly maximumMessageBytes?: number;
    readonly ticketRefreshSkewMilliseconds?: number;
}

/** Optional lifecycle hooks for opening one delivery event stream. */
export interface DeliveryStreamHooks {
    readonly onConnected?: () => void | Promise<void>;
}

/**
 * Relay-neutral queue extension point used by `MurmurClient` and
 * `InboxProcessor`. Implement this only when the built-in HTTP or negotiated
 * WebSocket transports do not fit the application's relay integration.
 */
export interface DeliveryTransport {
    publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome>;
    read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage>;
    acknowledge(request: SignedInboxAck, signal?: AbortSignal): Promise<InboxAcknowledgement>;
    /** Stream exact queued events in recipient inbox order when supported. */
    stream?(
        request: SignedInboxRead,
        signal?: AbortSignal,
        hooks?: DeliveryStreamHooks,
    ): AsyncIterable<InboxStreamEvent>;
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

/**
 * Durable handler invoked inside the cursor transaction by low-level
 * `InboxProcessor` integrations. Ordinary applications use sync callbacks.
 */
export type InboxDeliveryHandler = (
    transaction: StoreTransaction,
    delivery: InboxDelivery,
) => Promise<void>;

/** Construction policy for advanced applications using `InboxProcessor` directly. */
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

/** One recipient SSE session; a signal is required to define its lifetime. */
export interface InboxStreamOptions {
    readonly signal: AbortSignal;
    readonly onConnected?: () => void | Promise<void>;
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

/** Dependencies required by a custom low-level `InboxProcessor` integration. */
export interface InboxProcessorDependencies {
    readonly identity: IdentityKeyPair;
    readonly store: MurmurStore;
    readonly transport: DeliveryTransport;
}
