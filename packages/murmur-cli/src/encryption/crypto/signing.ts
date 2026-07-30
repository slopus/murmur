/**
 * Ed25519 digital signatures for identity verification.
 *
 * Ed25519 is used for:
 * - Long-term identity keys
 * - Signing prekeys (to prove they belong to the identity)
 * - Authenticating messages to the server
 *
 * Properties:
 * - Private key: 32 bytes (seed)
 * - Public key: 32 bytes
 * - Signature: 64 bytes
 */

import { ed25519 } from "@noble/curves/ed25519";
import { getRandomBytes } from "./utils.js";

/** Length of Ed25519 private key (seed) in bytes */
export const SIGNING_PRIVATE_KEY_LENGTH = 32;

/** Length of Ed25519 public key in bytes */
export const SIGNING_PUBLIC_KEY_LENGTH = 32;

/** Length of Ed25519 signature in bytes */
export const SIGNATURE_LENGTH = 64;

/**
 * An Ed25519 signing key pair for identity.
 */
export interface SigningKeyPair {
    /** Private key seed (32 bytes) - must be kept secret */
    privateKey: Uint8Array;
    /** Public key (32 bytes) - serves as identity */
    publicKey: Uint8Array;
}

/**
 * Generate a new Ed25519 signing key pair.
 *
 * The public key serves as the identity of the party.
 *
 * @returns A new SigningKeyPair
 *
 * @example
 * ```typescript
 * const identity = generateSigningKeyPair()
 * // identity.publicKey is your identity key
 * ```
 */
export function generateSigningKeyPair(): SigningKeyPair {
    const privateKey = getRandomBytes(SIGNING_PRIVATE_KEY_LENGTH);
    const publicKey = ed25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Derive public key from private key.
 *
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 32-byte public key
 */
export function signingPublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
    if (privateKey.length !== SIGNING_PRIVATE_KEY_LENGTH) {
        throw new Error(
            `Invalid private key length: expected ${SIGNING_PRIVATE_KEY_LENGTH}, got ${privateKey.length}`,
        );
    }
    return ed25519.getPublicKey(privateKey);
}

/**
 * Sign a message with an Ed25519 private key.
 *
 * @param message - Message to sign (any bytes)
 * @param privateKey - 32-byte private key
 * @returns 64-byte signature
 *
 * @example
 * ```typescript
 * const signature = sign(message, identity.privateKey)
 * ```
 */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
    if (privateKey.length !== SIGNING_PRIVATE_KEY_LENGTH) {
        throw new Error(
            `Invalid private key length: expected ${SIGNING_PRIVATE_KEY_LENGTH}, got ${privateKey.length}`,
        );
    }
    return ed25519.sign(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 *
 * @param message - Original message that was signed
 * @param signature - 64-byte signature to verify
 * @param publicKey - 32-byte public key of the signer
 * @returns true if signature is valid, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = verify(message, signature, identity.publicKey)
 * if (!isValid) throw new Error('Invalid signature')
 * ```
 */
export function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    if (signature.length !== SIGNATURE_LENGTH) {
        return false;
    }
    if (publicKey.length !== SIGNING_PUBLIC_KEY_LENGTH) {
        return false;
    }
    try {
        return ed25519.verify(signature, message, publicKey);
    } catch {
        return false;
    }
}

/**
 * Validate that a public key is well-formed.
 *
 * @param publicKey - Candidate public key
 * @returns true if the public key appears valid
 */
export function isValidSigningPublicKey(publicKey: Uint8Array): boolean {
    return publicKey.length === SIGNING_PUBLIC_KEY_LENGTH;
}
