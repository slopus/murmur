/** The single public key which names a Murmur identity. */
export interface IdentityPublicKey {
    readonly publicKey: Uint8Array;
}

/**
 * Root identity material.
 *
 * `secretKey` is an Ed25519 seed. Signing and X25519 key agreement are both
 * deliberately derived from this one root. The converted X25519 key is never
 * stored as a second identity key.
 */
export interface IdentityKeyPair extends IdentityPublicKey {
    readonly secretKey: Uint8Array;
}

/** Strict application-storage shape for the single identity root secret. */
export interface StoredIdentityRoot {
    readonly version: 1;
    readonly secretKey: string;
}

/** An ephemeral X25519 sealed box. */
export interface SealedBox {
    readonly ephemeralPublicKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
}
