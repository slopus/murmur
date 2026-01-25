/**
 * Type definitions for Murmur sessions.
 *
 * A Session combines X3DH key agreement with Double Ratchet messaging,
 * providing a high-level API for secure communication between agents.
 */

import type { RatchetState, SerializedRatchetState } from '../ratchet/types.js'
import type { X3DHKeyStore, SerializedX3DHKeyStore } from '../x3dh/types.js'

/**
 * Active session with a peer.
 */
export interface Session {
    /** Peer's identity public key (Ed25519) */
    peerIdentityKey: Uint8Array
    /** Double Ratchet state for this session */
    ratchetState: RatchetState
    /** When the session was established */
    establishedAt: number
    /** When the last message was sent/received */
    lastActivityAt: number
}

/**
 * Serializable session for persistence.
 */
export interface SerializedSession {
    peerIdentityKey: string
    ratchetState: SerializedRatchetState
    establishedAt: number
    lastActivityAt: number
}

/**
 * Complete agent state including keys and sessions.
 */
export interface AgentState {
    /** X3DH key store (identity, signed prekey, one-time prekeys) */
    keyStore: X3DHKeyStore
    /** Active sessions keyed by peer identity (base64) */
    sessions: Map<string, Session>
}

/**
 * Serializable agent state for persistence.
 */
export interface SerializedAgentState {
    keyStore: SerializedX3DHKeyStore
    sessions: Array<[string, SerializedSession]>
}

/**
 * Message ready to send to the server.
 */
export interface OutgoingMessage {
    /** Recipient's identity public key */
    recipientId: string
    /** Encrypted message blob (base64) */
    blob: string
    /** Signature of blob + messageId */
    signature: string
}

/**
 * Message received from the server.
 */
export interface IncomingMessage {
    /** Message ID */
    id: string
    /** Sender's identity public key */
    senderId: string
    /** Encrypted message blob (base64) */
    blob: string
    /** Signature */
    signature: string
    /** Server timestamp */
    createdAt: number
}

/**
 * Protocol message.
 *
 * Messages are always type "message". Pre-key fields are included when
 * establishing a new session.
 */
export interface ProtocolMessage {
    /** Message type identifier */
    type: 'message'
    /** Encoded Double Ratchet header */
    header: string
    /** Encrypted ciphertext */
    ciphertext: string
    /** Alice's identity DH public key (for X3DH) */
    identityDHKey?: string
    /** Alice's ephemeral public key (for X3DH) */
    ephemeralKey?: string
    /** Bob's signed prekey public key used */
    signedPreKey?: string
    /** Bob's one-time prekey public key used (if any) */
    oneTimePreKey?: string
}

/**
 * Result of decrypting a message.
 */
export interface DecryptedMessage {
    /** Decrypted plaintext */
    plaintext: Uint8Array
    /** Sender's identity key */
    senderIdentityKey: Uint8Array
}
