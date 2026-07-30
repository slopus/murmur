/**
 * Diffie-Hellman key exchange using X25519 (Curve25519).
 *
 * X25519 is the recommended elliptic curve for Diffie-Hellman key agreement
 * in the Signal Protocol. It provides 128 bits of security with 32-byte keys.
 *
 * Key properties:
 * - Private keys: 32 bytes (clamped scalar)
 * - Public keys: 32 bytes (Montgomery x-coordinate)
 * - Shared secrets: 32 bytes
 */

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { getRandomBytes } from "./utils.js";

/** Length of X25519 private key in bytes */
export const DH_PRIVATE_KEY_LENGTH = 32;

/** Length of X25519 public key in bytes */
export const DH_PUBLIC_KEY_LENGTH = 32;

/** Length of X25519 shared secret in bytes */
export const DH_SHARED_SECRET_LENGTH = 32;

/**
 * A Diffie-Hellman key pair for X25519
 */
export interface DHKeyPair {
    /** Private key (32 bytes) - must be kept secret */
    privateKey: Uint8Array;
    /** Public key (32 bytes) - can be shared */
    publicKey: Uint8Array;
}

/**
 * Generate a new X25519 key pair for Diffie-Hellman key exchange.
 *
 * The private key is generated from cryptographically secure random bytes.
 * The public key is derived deterministically from the private key.
 *
 * @returns A new DHKeyPair with 32-byte private and public keys
 *
 * @example
 * ```typescript
 * const keyPair = generateDH()
 * console.log(keyPair.publicKey.length) // 32
 * console.log(keyPair.privateKey.length) // 32
 * ```
 */
export function generateDH(): DHKeyPair {
    const privateKey = getRandomBytes(DH_PRIVATE_KEY_LENGTH);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Derive an X25519 key pair from an Ed25519 private key seed.
 *
 * Uses the standard Ed25519 -> X25519 conversion.
 *
 * @param signingPrivateKey - 32-byte Ed25519 private key seed
 * @returns Deterministic X25519 key pair
 */
export function deriveDhKeyPairFromSigningKey(signingPrivateKey: Uint8Array): DHKeyPair {
    if (signingPrivateKey.length !== DH_PRIVATE_KEY_LENGTH) {
        throw new Error(
            `Invalid signing key length: expected ${DH_PRIVATE_KEY_LENGTH}, got ${signingPrivateKey.length}`,
        );
    }

    const privateKey = ed25519.utils.toMontgomerySecret(signingPrivateKey);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Derive an X25519 public key from an Ed25519 public key.
 *
 * @param signingPublicKey - 32-byte Ed25519 public key
 * @returns 32-byte X25519 public key
 */
export function deriveDhPublicKeyFromSigningPublicKey(signingPublicKey: Uint8Array): Uint8Array {
    if (signingPublicKey.length !== DH_PUBLIC_KEY_LENGTH) {
        throw new Error(
            `Invalid signing public key length: expected ${DH_PUBLIC_KEY_LENGTH}, got ${signingPublicKey.length}`,
        );
    }
    return ed25519.utils.toMontgomery(signingPublicKey);
}

/**
 * Derive public key from a private key.
 *
 * @param privateKey - 32-byte X25519 private key
 * @returns Corresponding 32-byte public key
 * @throws Error if private key is invalid length
 */
export function publicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
    if (privateKey.length !== DH_PRIVATE_KEY_LENGTH) {
        throw new Error(
            `Invalid private key length: expected ${DH_PRIVATE_KEY_LENGTH}, got ${privateKey.length}`,
        );
    }
    return x25519.getPublicKey(privateKey);
}

/**
 * Perform Diffie-Hellman key agreement.
 *
 * Computes the shared secret between a private key and a remote public key.
 * The resulting shared secret is the same whether computed by either party:
 * DH(alice.private, bob.public) === DH(bob.private, alice.public)
 *
 * @param keyPair - Local key pair containing the private key
 * @param remotePublicKey - Remote party's public key (32 bytes)
 * @returns 32-byte shared secret
 * @throws Error if the public key is invalid
 *
 * @example
 * ```typescript
 * const alice = generateDH()
 * const bob = generateDH()
 *
 * const sharedAlice = dh(alice, bob.publicKey)
 * const sharedBob = dh(bob, alice.publicKey)
 *
 * // sharedAlice and sharedBob are identical
 * ```
 */
export function dh(keyPair: DHKeyPair, remotePublicKey: Uint8Array): Uint8Array {
    if (remotePublicKey.length !== DH_PUBLIC_KEY_LENGTH) {
        throw new Error(
            `Invalid public key length: expected ${DH_PUBLIC_KEY_LENGTH}, got ${remotePublicKey.length}`,
        );
    }
    return x25519.getSharedSecret(keyPair.privateKey, remotePublicKey);
}

/**
 * Validate that a public key is well-formed.
 *
 * Checks that the key is the correct length. Note that X25519 accepts
 * any 32-byte input as a valid public key (contributory behavior).
 *
 * @param publicKey - Candidate public key
 * @returns true if the public key appears valid
 */
export function isValidPublicKey(publicKey: Uint8Array): boolean {
    return publicKey.length === DH_PUBLIC_KEY_LENGTH;
}
