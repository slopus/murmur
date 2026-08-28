/** One-use admission key pair for creating or joining a TreeKEM group. */
export interface TreeKemKeyPair {
    /** Public admission key safe to persist on an untrusted server. */
    readonly publicKey: Uint8Array;
    /** Private one-use admission key which must never leave the member. */
    readonly secretKey: Uint8Array;
}

/** Optional batched membership changes applied by one atomic update. */
export interface TreeKemChanges {
    /** Authenticated admission public keys added in Welcome result order. */
    readonly add?: readonly Uint8Array[];
    /** Original admission public keys of current members to remove. */
    readonly remove?: readonly Uint8Array[];
}

/** Replacement local state and the fresh group secret for one epoch. */
export interface TreeKemResult {
    /** Opaque private state which must never be persisted on a public server. */
    readonly secretState: Uint8Array;
    /** Private shared secret which must never leave retained members. */
    readonly secretKey: Uint8Array;
}

/** Result of updating a path and creating one public group transition. */
export interface TreeKemUpdateResult extends TreeKemResult {
    /** Public authenticated update safe to persist on an untrusted server. */
    readonly publicPacket: Uint8Array;
    /** Public recipient ciphertexts parallel to `TreeKemChanges.add`. */
    readonly publicWelcomes: readonly Uint8Array[];
}
