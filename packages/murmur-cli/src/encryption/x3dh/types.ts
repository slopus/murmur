/**
 * Type definitions for the X3DH (Extended Triple Diffie-Hellman) protocol.
 *
 * X3DH establishes a shared secret between two parties who may not be
 * online simultaneously. It uses a combination of long-term identity keys,
 * signed prekeys, and one-time prekeys.
 */

import type { SigningKeyPair } from '../crypto/signing.js'
import type { DHKeyPair } from '../crypto/dh.js'

/**
 * Identity key pair using Ed25519 for signing.
 * This is the long-term identity of a party.
 */
export interface IdentityKeyPair extends SigningKeyPair {
    /** DH key pair derived from identity for key agreement */
    dhKeyPair: DHKeyPair
}

/**
 * Signed prekey - a medium-term DH key signed by the identity key.
 * Typically rotated periodically (e.g., weekly or monthly).
 */
export interface SignedPreKey {
    /** Unique identifier for this prekey */
    id: number
    /** X25519 key pair for DH */
    keyPair: DHKeyPair
    /** Ed25519 signature of the public key by identity key */
    signature: Uint8Array
    /** Timestamp when this key was created */
    createdAt: number
}

/**
 * One-time prekey - an ephemeral DH key used only once.
 * Provides forward secrecy for initial messages.
 */
export interface OneTimePreKey {
    /** Unique identifier for this prekey */
    id: number
    /** X25519 key pair for DH */
    keyPair: DHKeyPair
}

/**
 * Prekey bundle published to the server.
 * This is what Alice fetches to initiate a session with Bob.
 */
export interface PreKeyBundle {
    /** Bob's identity public key (Ed25519) */
    identityKey: Uint8Array
    /** Bob's signed prekey public key */
    signedPreKey: Uint8Array
    /** Signature of signedPreKey by identityKey */
    signedPreKeySignature: Uint8Array
    /** Optional one-time prekey public key (may be exhausted) */
    oneTimePreKey?: Uint8Array
}

/**
 * Result of X3DH key agreement from Alice's side.
 */
export interface X3DHSenderResult {
    /** The shared secret (32 bytes) for Double Ratchet initialization */
    sharedSecret: Uint8Array
    /** Alice's ephemeral public key (to send to Bob) */
    ephemeralPublicKey: Uint8Array
    /** Alice's identity DH public key (to send to Bob for DH computation) */
    aliceIdentityDHKey: Uint8Array
    /** Bob's signed prekey public key (for Double Ratchet init) */
    bobSignedPreKey: Uint8Array
}

/**
 * Initial message from Alice to Bob containing key agreement data.
 */
export interface X3DHInitialMessage {
    /** Alice's identity public key */
    identityKey: Uint8Array
    /** Alice's ephemeral public key */
    ephemeralKey: Uint8Array
    /** Bob's signed prekey public key that was used */
    signedPreKey: Uint8Array
    /** Bob's one-time prekey public key that was used (if any) */
    oneTimePreKey?: Uint8Array
    /** The first Double Ratchet encrypted message */
    initialCiphertext: Uint8Array
    /** Header of the first message */
    initialHeader: Uint8Array
}

/**
 * Bob's key material needed to process an initial message.
 */
export interface X3DHReceiverKeys {
    /** Bob's identity key pair */
    identityKeyPair: IdentityKeyPair
    /** Bob's signed prekey (matched by ID) */
    signedPreKey: SignedPreKey
    /** Bob's one-time prekey if referenced (matched by ID) */
    oneTimePreKey?: OneTimePreKey
}

/**
 * Result of X3DH key agreement from Bob's side.
 */
export interface X3DHReceiverResult {
    /** The shared secret (32 bytes) - same as Alice computed */
    sharedSecret: Uint8Array
    /** Alice's identity public key (for verification) */
    aliceIdentityKey: Uint8Array
}

/**
 * Local key store for managing X3DH keys.
 */
export interface X3DHKeyStore {
    /** Our identity key pair */
    identityKeyPair: IdentityKeyPair
    /** Current signed prekey */
    signedPreKey: SignedPreKey
    /** Pool of unused one-time prekeys */
    oneTimePreKeys: Map<number, OneTimePreKey>
    /** Counter for generating unique prekey IDs */
    nextPreKeyId: number
}

/**
 * Serializable version of X3DHKeyStore for persistence.
 */
export interface SerializedX3DHKeyStore {
    identityPrivateKey: string
    identityPublicKey: string
    identityDHPrivateKey: string
    identityDHPublicKey: string
    signedPreKey: {
        id: number
        privateKey: string
        publicKey: string
        signature: string
        createdAt: number
    }
    oneTimePreKeys: Array<{
        id: number
        privateKey: string
        publicKey: string
    }>
    nextPreKeyId: number
}
