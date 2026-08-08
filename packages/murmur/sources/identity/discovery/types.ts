import type { MlsKeyPackage } from "../../mls/keyPackage/index.js";

/** Signed, self-contained material an application may share out of band. */
export interface DiscoveryBundle {
    readonly version: 1;
    readonly identityKey: Uint8Array;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly keyPackages: readonly MlsKeyPackage[];
    readonly signature: Uint8Array;
}

/** Construction policy for one discovery bundle. */
export interface DiscoveryBundleOptions {
    readonly createdAt?: number;
    readonly expiresAt?: number;
}

/** Clock policy used while validating an untrusted discovery bundle. */
export interface DiscoveryBundleValidationOptions {
    readonly now?: number;
    readonly maximumFutureSkewMilliseconds?: number;
}

/** Browser-safe fetch signature used by the discovery-cache transport. */
export type DiscoveryFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Result of uploading one exact signed bundle to the ephemeral cache. */
export interface DiscoveryUploadOutcome {
    readonly digest: Uint8Array;
    readonly expiresAt: number;
    readonly duplicate: boolean;
}

/** Relay-neutral operations for the content-addressed discovery cache. */
export interface DiscoveryTransport {
    upload(bundle: Uint8Array, signal?: AbortSignal): Promise<DiscoveryUploadOutcome>;
    download(digest: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/** Browser-safe HTTP discovery transport policy. */
export interface HttpDiscoveryTransportOptions {
    readonly fetch?: DiscoveryFetch;
    readonly maximumResponseBytes?: number;
    readonly requestTimeoutMilliseconds?: number;
}
