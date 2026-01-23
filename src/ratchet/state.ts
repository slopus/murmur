/**
 * Ratchet state management and serialization.
 *
 * Provides functions for creating, serializing, and deserializing
 * Double Ratchet session state. State must be persisted between
 * messages to maintain cryptographic continuity.
 */

import { generateDH, publicKeyFromPrivate, type DHKeyPair } from '../crypto/dh.js'
import { encodeBase64, decodeBase64 } from '../crypto/utils.js'
import type {
    RatchetState,
    SerializedRatchetState,
    SkippedMessageKeys
} from './types.js'

/**
 * Create a string key for the skipped message keys map.
 *
 * Combines the ratchet public key and message number into a unique
 * string key for Map lookup.
 *
 * @param publicKey - DH ratchet public key when message was sent
 * @param messageNumber - Message number in that chain
 * @returns String key for Map
 */
export function makeSkippedKeyIndex(publicKey: Uint8Array, messageNumber: number): string {
    return `${encodeBase64(publicKey)}:${messageNumber}`
}

/**
 * Parse a skipped key index back to components.
 *
 * @param key - String key from skipped message keys map
 * @returns Object with publicKey and messageNumber
 */
export function parseSkippedKeyIndex(key: string): { publicKey: Uint8Array; messageNumber: number } {
    const separatorIndex = key.lastIndexOf(':')
    if (separatorIndex === -1) {
        throw new Error(`Invalid skipped key index: ${key}`)
    }
    const publicKeyBase64 = key.substring(0, separatorIndex)
    const messageNumber = parseInt(key.substring(separatorIndex + 1), 10)
    if (isNaN(messageNumber)) {
        throw new Error(`Invalid message number in skipped key index: ${key}`)
    }
    return {
        publicKey: decodeBase64(publicKeyBase64),
        messageNumber
    }
}

/**
 * Serialize ratchet state for persistence.
 *
 * Converts all binary data to base64 strings for JSON storage.
 * The state can be safely stored in a database or file system.
 *
 * SECURITY: The serialized state contains secret keys. It should
 * be encrypted before storing in persistent storage.
 *
 * @param state - Ratchet state to serialize
 * @returns JSON-serializable state object
 *
 * @example
 * ```typescript
 * const serialized = serializeState(state)
 * const json = JSON.stringify(serialized)
 * // Store json securely
 * ```
 */
export function serializeState(state: RatchetState): SerializedRatchetState {
    return {
        dhSelfPrivateKey: encodeBase64(state.dhSelf.privateKey),
        dhSelfPublicKey: encodeBase64(state.dhSelf.publicKey),
        dhRemote: state.dhRemote ? encodeBase64(state.dhRemote) : null,
        rootKey: encodeBase64(state.rootKey),
        sendingChainKey: state.sendingChainKey ? encodeBase64(state.sendingChainKey) : null,
        receivingChainKey: state.receivingChainKey ? encodeBase64(state.receivingChainKey) : null,
        sendingMessageNumber: state.sendingMessageNumber,
        receivingMessageNumber: state.receivingMessageNumber,
        previousSendingChainLength: state.previousSendingChainLength,
        skippedMessageKeys: Array.from(state.skippedMessageKeys.entries()).map(
            ([k, v]) => [k, encodeBase64(v)]
        )
    }
}

/**
 * Deserialize ratchet state from storage.
 *
 * Reconstructs the full ratchet state from a serialized representation.
 *
 * @param serialized - Serialized state object (from serializeState)
 * @returns Reconstructed RatchetState
 * @throws Error if serialized data is malformed
 *
 * @example
 * ```typescript
 * const json = loadFromStorage() // Your persistence logic
 * const serialized = JSON.parse(json) as SerializedRatchetState
 * const state = deserializeState(serialized)
 * ```
 */
export function deserializeState(serialized: SerializedRatchetState): RatchetState {
    const dhSelf: DHKeyPair = {
        privateKey: decodeBase64(serialized.dhSelfPrivateKey),
        publicKey: decodeBase64(serialized.dhSelfPublicKey)
    }

    const skippedMessageKeys: SkippedMessageKeys = new Map(
        serialized.skippedMessageKeys.map(([k, v]) => [k, decodeBase64(v)])
    )

    return {
        dhSelf,
        dhRemote: serialized.dhRemote ? decodeBase64(serialized.dhRemote) : null,
        rootKey: decodeBase64(serialized.rootKey),
        sendingChainKey: serialized.sendingChainKey ? decodeBase64(serialized.sendingChainKey) : null,
        receivingChainKey: serialized.receivingChainKey ? decodeBase64(serialized.receivingChainKey) : null,
        sendingMessageNumber: serialized.sendingMessageNumber,
        receivingMessageNumber: serialized.receivingMessageNumber,
        previousSendingChainLength: serialized.previousSendingChainLength,
        skippedMessageKeys
    }
}

/**
 * Create a new empty ratchet state with fresh keys.
 *
 * This creates the initial state structure but does not initialize
 * the chains. Use initializeAlice or initializeBob to set up a session.
 *
 * @param rootKey - Initial 32-byte root key from key agreement
 * @param dhKeyPair - Optional DH key pair (generates new one if not provided)
 * @returns Uninitialized RatchetState
 */
export function createEmptyState(
    rootKey: Uint8Array,
    dhKeyPair?: DHKeyPair
): RatchetState {
    return {
        dhSelf: dhKeyPair ?? generateDH(),
        dhRemote: null,
        rootKey,
        sendingChainKey: null,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map()
    }
}

/**
 * Clone a ratchet state (deep copy).
 *
 * Useful for testing or creating state snapshots.
 *
 * @param state - State to clone
 * @returns Independent copy of the state
 */
export function cloneState(state: RatchetState): RatchetState {
    return {
        dhSelf: {
            privateKey: new Uint8Array(state.dhSelf.privateKey),
            publicKey: new Uint8Array(state.dhSelf.publicKey)
        },
        dhRemote: state.dhRemote ? new Uint8Array(state.dhRemote) : null,
        rootKey: new Uint8Array(state.rootKey),
        sendingChainKey: state.sendingChainKey ? new Uint8Array(state.sendingChainKey) : null,
        receivingChainKey: state.receivingChainKey ? new Uint8Array(state.receivingChainKey) : null,
        sendingMessageNumber: state.sendingMessageNumber,
        receivingMessageNumber: state.receivingMessageNumber,
        previousSendingChainLength: state.previousSendingChainLength,
        skippedMessageKeys: new Map(
            Array.from(state.skippedMessageKeys.entries()).map(
                ([k, v]) => [k, new Uint8Array(v)]
            )
        )
    }
}
