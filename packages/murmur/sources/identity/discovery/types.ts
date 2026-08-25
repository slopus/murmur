import type { MlsKeyPackage } from "../../mls/keyPackage/index.js";
import type { MurmurDeviceRoster } from "../../accounts/index.js";

/** Signed, self-contained material an application may share out of band. */
export interface LegacyDiscoveryBundle {
    readonly version: 1;
    readonly identityKey: Uint8Array;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly keyPackages: readonly MlsKeyPackage[];
    readonly signature: Uint8Array;
}

/** Account-signed discovery material for one independently keyed active device. */
export interface AccountDiscoveryBundle {
    readonly version: 2;
    /** Stable account-signing identity. */
    readonly identityKey: Uint8Array;
    /** Independently keyed device owning the included KeyPackages and inbox. */
    readonly deviceKey: Uint8Array;
    readonly roster: MurmurDeviceRoster;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly keyPackages: readonly MlsKeyPackage[];
    readonly signature: Uint8Array;
}

/** Backward-compatible legacy or account-device discovery material. */
export type DiscoveryBundle = LegacyDiscoveryBundle | AccountDiscoveryBundle;

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

/** Owner-signed registration binding an invitation to a private revocation authority. */
export interface InvitationUploadAuthorization {
    readonly version: 1;
    readonly owner: Uint8Array;
    readonly revocationKey: Uint8Array;
    readonly digest: Uint8Array;
    readonly expiresAt: number;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** Idempotent revocation request signed by a private invitation authority. */
export interface SignedInvitationRevocation {
    readonly version: 1;
    readonly revocationKey: Uint8Array;
    /** One digest, or `null` for every outstanding invitation under this authority. */
    readonly digest: Uint8Array | null;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** Result of one authenticated relay revocation transaction. */
export interface InvitationRevocationOutcome {
    readonly revoked: number;
}

/** Relay-neutral operations for the content-addressed discovery cache. */
export interface DiscoveryTransport {
    upload(bundle: Uint8Array, signal?: AbortSignal): Promise<DiscoveryUploadOutcome>;
    /** Additive owner-authorized upload used by revocable invitations. */
    uploadOwned?(
        bundle: Uint8Array,
        authorization: InvitationUploadAuthorization,
        signal?: AbortSignal,
    ): Promise<DiscoveryUploadOutcome>;
    download(digest: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
    /** Additive authenticated revocation used by revocable invitations. */
    revoke?(
        request: SignedInvitationRevocation,
        signal?: AbortSignal,
    ): Promise<InvitationRevocationOutcome>;
}

/** Browser-safe HTTP discovery transport policy. */
export interface HttpDiscoveryTransportOptions {
    readonly fetch?: DiscoveryFetch;
    readonly maximumResponseBytes?: number;
    readonly requestTimeoutMilliseconds?: number;
}
