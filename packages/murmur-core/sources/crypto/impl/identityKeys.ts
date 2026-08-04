import { ed25519 } from "@noble/curves/ed25519";
import { copyBytes, equalBytes, zeroBytes } from "../../utils/index.js";
import type { IdentityKeyPair, IdentityPublicKey } from "../types.js";

const KEY_LENGTH = 32;

/** Reconstruct an identity from exactly one 32-byte root secret. */
export function importIdentityKeyPair(secretKey: Uint8Array): IdentityKeyPair {
    if (secretKey.length !== KEY_LENGTH) {
        throw new Error("Identity root secret must be 32 bytes");
    }
    const secretCopy = copyBytes(secretKey);
    return {
        secretKey: secretCopy,
        publicKey: ed25519.getPublicKey(secretCopy),
    };
}

/** Validate that an identity public key matches its root secret. */
export function validateIdentityKeyPair(identity: IdentityKeyPair): void {
    if (identity.secretKey.length !== KEY_LENGTH || identity.publicKey.length !== KEY_LENGTH) {
        throw new Error("Identity keys must be 32 bytes");
    }
    const derived = ed25519.getPublicKey(identity.secretKey);
    try {
        if (!equalBytes(derived, identity.publicKey)) {
            throw new Error("Identity public key does not match its root secret");
        }
    } finally {
        zeroBytes(derived);
    }
}

/**
 * Convert the public Ed25519 identity point to its X25519 key-agreement form.
 *
 * The returned value is a derived capability, not a second public identity.
 */
export function identityDhPublicKey(identity: IdentityPublicKey): Uint8Array {
    if (identity.publicKey.length !== KEY_LENGTH) {
        throw new Error("Identity public key must be 32 bytes");
    }
    return ed25519.utils.toMontgomery(identity.publicKey);
}
