/**
 * Type definitions for Murmur storage layer.
 *
 * The storage layer persists:
 * - Agent state (identity keys, prekeys, sessions)
 * - Contacts (encrypted profiles)
 * - Messages (encrypted content)
 */

import type { SerializedAgentState } from '../encryption/session/types.js'

/**
 * Contact information stored locally.
 * The firstName and lastName are decrypted on read using the profile key.
 */
export interface Contact {
    /** Contact's identity public key (base64) */
    identityKey: string
    /** Contact's profile public key for fetching profile */
    profilePublicKey: string
    /** Contact's profile secret key (base64url, optional) */
    profileSecretKey?: string
    /** Decrypted first name */
    firstName: string
    /** Decrypted last name (optional) */
    lastName?: string
    /** When the contact was added */
    addedAt: number
    /** When the contact was last updated */
    updatedAt: number
}

/**
 * Stored contact as saved in database.
 * Profile data is encrypted.
 */
export interface StoredContact {
    /** Contact's identity public key (base64) */
    identityKey: string
    /** Contact's profile public key (base64) */
    profilePublicKey: string
    /** Contact's profile secret key (base64) */
    profileSecretKey?: string
    /** Encrypted profile blob (base64) */
    encryptedProfile: string
    /** When the contact was added */
    addedAt: number
    /** When the contact was last updated */
    updatedAt: number
}

/**
 * Attachment stored alongside a message.
 */
export interface StoredAttachment {
    /** Attachment filename (no path) */
    fileName: string
    /** SHA-256 hash of encrypted bytes (hex) */
    hash: string
    /** AES-GCM IV (base64) */
    iv: string
    /** AES-GCM key (base64) */
    key: string
    /** AES-GCM encrypted payload (base64) */
    ciphertext: string
}

/**
 * Message stored in the database.
 */
export interface StoredMessage {
    /** Unique message ID (cuid2) */
    id: string
    /** Conversation ID (peer's identity key) */
    conversationId: string
    /** Whether this message was sent by us */
    isOutgoing: boolean
    /** Decrypted message text */
    text: string
    /** When the message was created/sent */
    createdAt: number
    /** Whether the message has been read */
    read: boolean
    /** Optional attachments stored with the message */
    attachments?: StoredAttachment[]
}

/**
 * Account information.
 */
export interface Account {
    /** Our identity public key (base64) */
    identityKey: string
    /** Our profile public key (base64) */
    profilePublicKey: string
    /** Our profile secret key (base64) for decrypting our own profile */
    profileSecretKey: string
    /** Our encrypted profile blob */
    encryptedProfile: string
    /** Our first name (decrypted) */
    firstName: string
    /** Our last name (decrypted, optional) */
    lastName?: string
    /** When the account was created */
    createdAt: number
}

/**
 * Full application state for persistence.
 */
export interface AppState {
    /** Account information (null if not set up) */
    account: Account | null
    /** Serialized agent state (encryption keys and sessions) */
    agentState: SerializedAgentState | null
}
