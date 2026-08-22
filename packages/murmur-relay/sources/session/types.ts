/** Device-signed proof submitted to the application authentication server. */
export interface SignedRelaySessionRequest {
    readonly version: 1;
    readonly device: Uint8Array;
    readonly createdAt: number;
    readonly nonce: Uint8Array;
    readonly signature: Uint8Array;
}

/** Strict wire representation of one relay-session request. */
export interface SignedRelaySessionRequestJson {
    readonly version: 1;
    readonly device: string;
    readonly createdAt: number;
    readonly nonce: string;
    readonly signature: string;
}

/** Application-selected placement for one already-authenticated device. */
export interface RelaySessionRoute {
    readonly endpoint: string;
    readonly admissionPrincipal: string;
}

/** Verified capability claims carried by a short-lived relay token. */
export interface RelaySessionClaims {
    readonly version: 1;
    readonly protocol: "murmur-websocket-v1";
    readonly device: Uint8Array;
    readonly endpoint: string;
    readonly admissionPrincipal: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly nonce: Uint8Array;
}

/** Application hook that authenticates a user and authorizes their device key. */
export type RelaySessionAuthorizer = (
    request: Request,
    proof: SignedRelaySessionRequest,
) => Promise<RelaySessionRoute | undefined>;

/** Policy for a Fetch-compatible authenticated relay-session endpoint. */
export interface RelaySessionIssuerOptions {
    readonly tokenSecret: Uint8Array;
    readonly authorize: RelaySessionAuthorizer;
    readonly now?: () => number;
    readonly ticketTtlMilliseconds?: number;
    readonly maximumAuthenticationSkewMilliseconds?: number;
    readonly maximumRequestBytes?: number;
}

/** Inputs used when signing one temporary relay capability. */
export interface CreateRelaySessionTokenOptions extends RelaySessionRoute {
    readonly device: Uint8Array;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly nonce?: Uint8Array;
}

/** Policy used while verifying a temporary relay capability. */
export interface VerifyRelaySessionTokenOptions {
    readonly now?: number;
    readonly expectedEndpoint?: string;
    readonly maximumFutureSkewMilliseconds?: number;
}
