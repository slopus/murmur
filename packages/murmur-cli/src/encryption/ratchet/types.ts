/**
 * Type definitions for the Double Ratchet protocol.
 *
 * These types define the state and message structures used in the
 * Signal Protocol's Double Ratchet algorithm.
 */

import type { DHKeyPair } from '../crypto/dh.js'

/**
 * Message header containing ratchet metadata.
 *
 * The header is sent with each message and contains:
 * - The sender's current ratchet public key
 * - Message number in the current sending chain
 * - Number of messages in the previous sending chain (for out-of-order handling)
 */
export interface MessageHeader {
    /** Sender's current DH ratchet public key (32 bytes) */
    publicKey: Uint8Array

    /** Message number in current sending chain (starts at 0) */
    messageNumber: number

    /** Number of messages sent in the previous sending chain */
    previousChainLength: number
}

/**
 * Encrypted message with header and ciphertext.
 *
 * This is the complete message format sent between parties.
 */
export interface EncryptedMessage {
    /** Message header (not encrypted, but authenticated) */
    header: MessageHeader

    /** Encrypted message content with auth tag */
    ciphertext: Uint8Array
}

/**
 * Key for looking up skipped message keys.
 *
 * Messages may arrive out of order. When we skip ahead in a chain,
 * we store the skipped message keys indexed by (ratchet_public_key, message_number).
 */
export interface SkippedKeyIndex {
    /** The DH ratchet public key when this key was valid */
    publicKey: Uint8Array

    /** The message number in that chain */
    messageNumber: number
}

/**
 * Map of skipped message keys for out-of-order message handling.
 *
 * Uses string keys (base64 encoded public key + ":" + message number)
 * because JavaScript Maps use reference equality for object keys.
 */
export type SkippedMessageKeys = Map<string, Uint8Array>

/**
 * Complete Double Ratchet session state.
 *
 * This state must be persisted between messages to maintain the
 * cryptographic ratchet. It contains:
 *
 * - DH Ratchet Keys: Current key pairs for the DH ratchet
 * - Chain Keys: Current keys for sending and receiving chains
 * - Message Counters: Track message numbers for ordering
 * - Skipped Keys: Stored keys for out-of-order messages
 *
 * SECURITY: This state contains secret key material and must be
 * stored securely. Consider encrypting before persistence.
 */
export interface RatchetState {
    /**
     * Our current DH ratchet key pair (DHs in spec).
     * Used to compute new chain keys when we send.
     */
    dhSelf: DHKeyPair

    /**
     * Their current DH ratchet public key (DHr in spec).
     * Null until we receive the first message.
     */
    dhRemote: Uint8Array | null

    /**
     * 32-byte root key (RK in spec).
     * Mixed with DH outputs to derive chain keys.
     */
    rootKey: Uint8Array

    /**
     * 32-byte sending chain key (CKs in spec).
     * Null if we haven't established a sending chain yet.
     */
    sendingChainKey: Uint8Array | null

    /**
     * 32-byte receiving chain key (CKr in spec).
     * Null if we haven't established a receiving chain yet.
     */
    receivingChainKey: Uint8Array | null

    /**
     * Number of messages sent in current sending chain (Ns in spec).
     * Incremented after each message sent.
     */
    sendingMessageNumber: number

    /**
     * Number of messages received in current receiving chain (Nr in spec).
     * Incremented after each message received.
     */
    receivingMessageNumber: number

    /**
     * Number of messages in previous sending chain (PN in spec).
     * Sent in header to help receiver handle out-of-order messages.
     */
    previousSendingChainLength: number

    /**
     * Stored message keys for out-of-order messages (MKSKIPPED in spec).
     * Keys are indexed by (public_key, message_number).
     */
    skippedMessageKeys: SkippedMessageKeys
}

/**
 * Serializable version of RatchetState for persistence.
 *
 * All Uint8Array values are base64 encoded for JSON serialization.
 * The skippedMessageKeys map is converted to an array of entries.
 */
export interface SerializedRatchetState {
    dhSelfPrivateKey: string
    dhSelfPublicKey: string
    dhRemote: string | null
    rootKey: string
    sendingChainKey: string | null
    receivingChainKey: string | null
    sendingMessageNumber: number
    receivingMessageNumber: number
    previousSendingChainLength: number
    skippedMessageKeys: Array<[string, string]>
}

/**
 * Options for creating a new ratchet session.
 */
export interface RatchetInitOptions {
    /**
     * Maximum number of message keys to skip in a single chain.
     * Prevents DoS attacks where attacker sends messages with huge gaps.
     * Default: 1000
     */
    maxSkip?: number
}

/**
 * Default maximum number of skipped messages allowed.
 * Balances tolerance for network reordering with DoS protection.
 */
export const DEFAULT_MAX_SKIP = 1000
