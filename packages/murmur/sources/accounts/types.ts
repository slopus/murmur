import type { IdentityKeyPair } from "../crypto/index.js";

/** One account-authorized independently keyed device. */
export interface MurmurDeviceRosterEntry {
    readonly deviceKey: Uint8Array;
    readonly addedAtRevision: number;
    readonly authorization: Uint8Array;
    readonly status: "active" | "revoked";
    /** Monotonic continuity-reset generation for this physical device. */
    readonly resetGeneration: number;
    readonly revokedAtRevision?: number;
}

/** One complete account-signed, device-countersigned roster revision. */
export interface MurmurDeviceRoster {
    readonly version: 1;
    readonly accountKey: Uint8Array;
    readonly revision: number;
    readonly parentHash: Uint8Array | null;
    readonly issuedAt: number;
    readonly mutationId: Uint8Array;
    readonly authorDeviceKey: Uint8Array;
    readonly devices: readonly MurmurDeviceRosterEntry[];
    readonly accountSignature: Uint8Array;
    readonly authorSignature: Uint8Array;
}

/** Account-signed BasicCredential payload binding one MLS leaf to an account. */
export interface MurmurDeviceCredential {
    readonly version: 1;
    readonly accountKey: Uint8Array;
    readonly deviceKey: Uint8Array;
    readonly addedAtRevision: number;
    readonly authorization: Uint8Array;
}

/** One short-lived provisioning URI payload presented by a new device. */
export interface MurmurDeviceLinkRequest {
    readonly version: 1;
    readonly requestId: Uint8Array;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly ephemeralKey: Uint8Array;
    readonly deviceKey: Uint8Array;
    readonly keyPackage: Uint8Array;
    readonly proof: Uint8Array;
}

/** Private state retained by the new device until provisioning completes. */
export interface MurmurDeviceLinkMaterial {
    readonly request: MurmurDeviceLinkRequest;
    readonly ephemeralSecretKey: Uint8Array;
}

/** Encrypted response returned by an authorizing active device. */
export interface MurmurDeviceProvisioningEnvelope {
    readonly version: 1;
    readonly requestId: Uint8Array;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly authorDeviceKey: Uint8Array;
    readonly ephemeralKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly signature: Uint8Array;
}

/** Decrypted provisioning result owned by the newly linked device. */
export interface MurmurProvisionedAccount {
    readonly account: IdentityKeyPair;
    readonly roster: MurmurDeviceRoster;
}

/** Durable local lifecycle notification for one newly authorized account device. */
export interface MurmurDeviceAdded {
    readonly id: string;
    readonly account: Uint8Array;
    readonly device: Uint8Array;
    readonly rosterRevision: number;
}

/** Durable local lifecycle notification for one revoked account device. */
export interface MurmurDeviceRevoked extends MurmurDeviceAdded {}

/** One active sibling device whose last authenticated activity crossed six months. */
export interface MurmurDormantDevice {
    readonly device: Uint8Array;
    readonly lastActivityAt: number;
    readonly dormantSince: number;
}

/** Inputs for authorizing one verified device-link request. */
export interface MurmurDeviceProvisioningAuthorization {
    readonly request: MurmurDeviceLinkRequest;
    readonly account: IdentityKeyPair;
    readonly authorDevice: IdentityKeyPair;
    readonly roster: MurmurDeviceRoster;
    readonly now?: number;
}
