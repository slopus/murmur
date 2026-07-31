import type { IdentityPublicKeys } from "../crypto/index.js";

/** Small user-controlled contact profile. */
export interface IdentityProfile {
    readonly name: string;
    readonly avatar?: Uint8Array;
    readonly metadata?: Readonly<Record<string, string>>;
}

/** Public identity representation used at transport boundaries. */
export interface SerializedPublicIdentity {
    readonly signingKey: string;
    readonly encryptionKey: string;
}

/** Opaque encrypted profile carried by a relay event. */
export interface EncryptedProfile {
    readonly version: 1;
    readonly recipient: string;
    readonly ephemeralPublicKey: string;
    readonly nonce: string;
    readonly ciphertext: string;
}

/** Result of authenticating and decrypting a contact profile and private data. */
export interface OpenedProfile {
    readonly identity: IdentityPublicKeys;
    readonly profile: IdentityProfile;
    readonly privateData?: Uint8Array;
}

/** Authenticated contact persisted locally by one identity. */
export interface Contact {
    readonly identity: IdentityPublicKeys;
    readonly profile: IdentityProfile;
    readonly addedAt: number;
    readonly updatedAt: number;
}
