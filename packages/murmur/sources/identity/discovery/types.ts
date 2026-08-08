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
