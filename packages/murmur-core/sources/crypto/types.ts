/** Long-lived signing and encryption public keys. */
export interface IdentityPublicKeys {
    readonly signingKey: Uint8Array;
    readonly encryptionKey: Uint8Array;
}

/** Long-lived identity key material. Secret arrays are mutable for zeroing. */
export interface IdentityKeyPair extends IdentityPublicKeys {
    readonly signingSecretKey: Uint8Array;
    readonly encryptionSecretKey: Uint8Array;
}

/** An ephemeral X25519 sealed box. */
export interface SealedBox {
    readonly ephemeralPublicKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
}
