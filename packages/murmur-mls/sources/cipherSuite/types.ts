/** RFC 9180 base-mode ciphertext. */
export interface HpkeCiphertext {
    /** Encapsulated X25519 public key. */
    readonly encapsulatedKey: Uint8Array;
    /** AES-128-GCM ciphertext and authentication tag. */
    readonly ciphertext: Uint8Array;
}

/** X25519 key pair derived for HPKE. */
export interface HpkeKeyPair {
    readonly secretKey: Uint8Array;
    readonly publicKey: Uint8Array;
}
