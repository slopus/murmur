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

/** Durable friend lifecycle state. Records are retained after removal. */
export type FriendStatus = "active" | "removed";

/** Authenticated identity/profile record retained for the owner's lifetime. */
export interface FriendRecord extends Contact {
    readonly status: FriendStatus;
    readonly statusUpdatedAt: number;
}

/** Visibility options for friend lookups. Removed records are hidden by default. */
export interface FriendQuery {
    readonly includeRemoved?: boolean;
}
