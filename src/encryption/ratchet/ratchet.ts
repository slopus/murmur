/**
 * Double Ratchet Algorithm Implementation.
 *
 * This module implements the Signal Protocol's Double Ratchet algorithm,
 * which provides forward secrecy and break-in recovery for encrypted messaging.
 *
 * The "double ratchet" name comes from two interlocking ratchets:
 * 1. DH Ratchet: Uses Diffie-Hellman key exchanges to introduce new entropy
 * 2. Symmetric Ratchet: Advances chain keys to derive message keys
 *
 * Key properties:
 * - Forward secrecy: Compromised keys cannot decrypt past messages
 * - Break-in recovery: System recovers security after key compromise
 * - Out-of-order tolerance: Messages can arrive in any order
 *
 * Based on: https://signal.org/docs/specifications/doubleratchet/
 */

import { generateDH, dh, type DHKeyPair } from '../crypto/dh.js'
import { kdfRK, kdfCK } from '../crypto/kdf.js'
import { encrypt, decrypt } from '../crypto/aead.js'
import { constantTimeEqual, concatBytes } from '../crypto/utils.js'
import { encodeHeader, createHeader, type HEADER_SIZE } from './header.js'
import { makeSkippedKeyIndex } from './state.js'
import type {
    RatchetState,
    MessageHeader,
    EncryptedMessage,
    RatchetInitOptions
} from './types.js'
import { DEFAULT_MAX_SKIP } from './types.js'

/**
 * Initialize the Double Ratchet as Alice (initiator).
 *
 * Alice is the party who initiates the conversation. She generates
 * her ratchet key pair and performs the initial DH to establish
 * the first sending chain.
 *
 * Prerequisites:
 * - Both parties have agreed on a shared secret (SK) via X3DH or similar
 * - Alice knows Bob's ratchet public key (from key agreement)
 *
 * @param sharedSecret - 32-byte shared secret from key agreement (e.g., X3DH)
 * @param bobPublicKey - Bob's DH ratchet public key
 * @returns Initialized ratchet state for Alice
 *
 * @example
 * ```typescript
 * // After X3DH key agreement
 * const aliceState = initializeAlice(sharedSecret, bobPublicKey)
 * // Alice can now send messages
 * ```
 */
export function initializeAlice(
    sharedSecret: Uint8Array,
    bobPublicKey: Uint8Array
): RatchetState {
    if (sharedSecret.length !== 32) {
        throw new Error(`Invalid shared secret length: expected 32, got ${sharedSecret.length}`)
    }

    // Generate Alice's ratchet key pair
    const dhSelf = generateDH()

    // Perform initial DH to derive first sending chain
    const dhOutput = dh(dhSelf, bobPublicKey)
    const [rootKey, sendingChainKey] = kdfRK(sharedSecret, dhOutput)

    return {
        dhSelf,
        dhRemote: bobPublicKey,
        rootKey,
        sendingChainKey,
        receivingChainKey: null, // Will be set on first received message
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map()
    }
}

/**
 * Initialize the Double Ratchet as Bob (responder).
 *
 * Bob is the party who receives the first message. He uses his
 * pre-existing ratchet key pair (shared during key agreement).
 * He cannot send messages until he receives Alice's first message.
 *
 * Prerequisites:
 * - Both parties have agreed on a shared secret (SK) via X3DH or similar
 * - Bob has his ratchet key pair (used in key agreement)
 *
 * @param sharedSecret - 32-byte shared secret from key agreement
 * @param bobKeyPair - Bob's DH ratchet key pair
 * @returns Initialized ratchet state for Bob
 *
 * @example
 * ```typescript
 * // After X3DH key agreement (Bob uses his signed pre-key)
 * const bobState = initializeBob(sharedSecret, bobSignedPreKey)
 * // Bob waits for Alice's first message before sending
 * ```
 */
export function initializeBob(
    sharedSecret: Uint8Array,
    bobKeyPair: DHKeyPair
): RatchetState {
    if (sharedSecret.length !== 32) {
        throw new Error(`Invalid shared secret length: expected 32, got ${sharedSecret.length}`)
    }

    return {
        dhSelf: bobKeyPair,
        dhRemote: null, // Will be set on first received message
        rootKey: sharedSecret,
        sendingChainKey: null, // Will be set after first DH ratchet
        receivingChainKey: null, // Will be set on first received message
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map()
    }
}

/**
 * Encrypt a message using the Double Ratchet.
 *
 * Performs a symmetric ratchet step on the sending chain to derive
 * a message key, then encrypts the plaintext. The header (containing
 * the current ratchet public key and message number) is authenticated
 * but not encrypted.
 *
 * @param state - Current ratchet state (will be mutated)
 * @param plaintext - Message content to encrypt
 * @param associatedData - Optional additional authenticated data
 * @returns Encrypted message with header
 * @throws Error if sending chain is not initialized
 *
 * @example
 * ```typescript
 * const message = ratchetEncrypt(state, new TextEncoder().encode('Hello!'))
 * // Send message.header and message.ciphertext to recipient
 * ```
 */
export function ratchetEncrypt(
    state: RatchetState,
    plaintext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(0)
): EncryptedMessage {
    // Ensure we have a sending chain
    if (!state.sendingChainKey) {
        throw new Error('Cannot encrypt: sending chain not initialized. ' +
            'Bob must receive a message from Alice before sending.')
    }

    // Symmetric ratchet step: derive message key and advance chain
    const [newChainKey, messageKey] = kdfCK(state.sendingChainKey)
    state.sendingChainKey = newChainKey

    // Create header with current ratchet key and message number
    const header = createHeader(
        state.dhSelf.publicKey,
        state.previousSendingChainLength,
        state.sendingMessageNumber
    )

    // Increment message counter
    state.sendingMessageNumber++

    // Encode header and use as additional authenticated data
    const encodedHeader = encodeHeader(header)
    const fullAD = concatBytes(associatedData, encodedHeader)

    // Encrypt the plaintext
    const ciphertext = encrypt(messageKey, plaintext, fullAD)

    return { header, ciphertext }
}

/**
 * Decrypt a message using the Double Ratchet.
 *
 * Handles three cases:
 * 1. Message from a skipped key (out-of-order message)
 * 2. Message requiring a DH ratchet step (new ratchet key)
 * 3. Message in the current receiving chain
 *
 * @param state - Current ratchet state (will be mutated)
 * @param message - Encrypted message with header
 * @param associatedData - Optional additional authenticated data (must match encryption)
 * @param options - Ratchet options (e.g., maxSkip)
 * @returns Decrypted plaintext
 * @throws Error if decryption fails or message is invalid
 *
 * @example
 * ```typescript
 * const plaintext = ratchetDecrypt(state, message)
 * const text = new TextDecoder().decode(plaintext)
 * ```
 */
export function ratchetDecrypt(
    state: RatchetState,
    message: EncryptedMessage,
    associatedData: Uint8Array = new Uint8Array(0),
    options: RatchetInitOptions = {}
): Uint8Array {
    const maxSkip = options.maxSkip ?? DEFAULT_MAX_SKIP
    const { header, ciphertext } = message

    // Encode header for authentication
    const encodedHeader = encodeHeader(header)
    const fullAD = concatBytes(associatedData, encodedHeader)

    // Case 1: Try to decrypt with a previously skipped message key
    const skippedKey = trySkippedMessageKeys(state, header)
    if (skippedKey) {
        return decrypt(skippedKey, ciphertext, fullAD)
    }

    // Case 2: Check if we need to perform a DH ratchet step
    // This happens when we receive a new ratchet public key from the sender
    const isNewRatchetKey = !state.dhRemote ||
        !constantTimeEqual(header.publicKey, state.dhRemote)

    if (isNewRatchetKey) {
        // Skip any remaining messages in the current receiving chain
        skipMessageKeys(state, header.previousChainLength, maxSkip)
        // Perform the DH ratchet step
        dhRatchet(state, header)
    }

    // Case 3: Skip to the message number and decrypt
    skipMessageKeys(state, header.messageNumber, maxSkip)

    // Derive the message key for this message
    const [newChainKey, messageKey] = kdfCK(state.receivingChainKey)
    state.receivingChainKey = newChainKey
    state.receivingMessageNumber++

    // Decrypt and return
    return decrypt(messageKey, ciphertext, fullAD)
}

/**
 * Try to decrypt using a previously stored skipped message key.
 *
 * When messages arrive out of order, we may have already advanced
 * the chain past this message's position. If so, we stored the
 * message key and can use it now.
 *
 * @param state - Current ratchet state
 * @param header - Message header
 * @returns Message key if found, null otherwise
 */
function trySkippedMessageKeys(
    state: RatchetState,
    header: MessageHeader
): Uint8Array | null {
    const key = makeSkippedKeyIndex(header.publicKey, header.messageNumber)
    const messageKey = state.skippedMessageKeys.get(key)

    if (messageKey) {
        // Remove the key after use (one-time use)
        state.skippedMessageKeys.delete(key)
        return messageKey
    }

    return null
}

/**
 * Skip message keys up to a target message number.
 *
 * When we receive a message with a higher number than expected,
 * we need to advance the chain and store the intermediate keys
 * for potential out-of-order messages.
 *
 * @param state - Current ratchet state (will be mutated)
 * @param until - Target message number to skip to
 * @param maxSkip - Maximum allowed skip (DoS protection)
 * @throws Error if skip would exceed maxSkip limit
 */
function skipMessageKeys(
    state: RatchetState,
    until: number,
    maxSkip: number
): void {
    // Check for DoS: don't skip too many messages
    if (state.receivingMessageNumber + maxSkip < until) {
        throw new Error(
            `Cannot skip ${until - state.receivingMessageNumber} messages ` +
            `(max: ${maxSkip}). Possible attack or severe message loss.`
        )
    }

    // Only skip if we have a receiving chain
    if (state.receivingChainKey && state.dhRemote) {
        while (state.receivingMessageNumber < until) {
            // Derive message key and advance chain
            const [newChainKey, messageKey] = kdfCK(state.receivingChainKey)
            state.receivingChainKey = newChainKey

            // Store the skipped key indexed by (ratchet_key, message_number)
            const key = makeSkippedKeyIndex(state.dhRemote, state.receivingMessageNumber)
            state.skippedMessageKeys.set(key, messageKey)

            state.receivingMessageNumber++
        }
    }
}

/**
 * Perform a DH ratchet step.
 *
 * Called when we receive a message with a new ratchet public key.
 * This introduces new entropy into the key derivation, providing
 * break-in recovery (future messages are secure even if current
 * keys are compromised).
 *
 * The DH ratchet:
 * 1. Saves the current sending chain length
 * 2. Resets message counters
 * 3. Updates the remote public key
 * 4. Derives a new receiving chain from DH output
 * 5. Generates a fresh local key pair
 * 6. Derives a new sending chain from DH output
 *
 * @param state - Current ratchet state (will be mutated)
 * @param header - Message header containing new ratchet public key
 */
function dhRatchet(state: RatchetState, header: MessageHeader): void {
    // Save the number of messages sent in the previous sending chain
    state.previousSendingChainLength = state.sendingMessageNumber

    // Reset message counters for new chains
    state.sendingMessageNumber = 0
    state.receivingMessageNumber = 0

    // Update the remote ratchet public key
    state.dhRemote = header.publicKey

    // Derive new receiving chain key
    // DH: our current private key × their new public key
    const dhOutputReceive = dh(state.dhSelf, state.dhRemote)
    const [rootKey1, receivingChainKey] = kdfRK(state.rootKey, dhOutputReceive)
    state.rootKey = rootKey1
    state.receivingChainKey = receivingChainKey

    // Generate new ratchet key pair for sending
    state.dhSelf = generateDH()

    // Derive new sending chain key
    // DH: our new private key × their public key
    const dhOutputSend = dh(state.dhSelf, state.dhRemote)
    const [rootKey2, sendingChainKey] = kdfRK(state.rootKey, dhOutputSend)
    state.rootKey = rootKey2
    state.sendingChainKey = sendingChainKey
}

/**
 * Get the number of skipped message keys stored in state.
 *
 * Useful for monitoring memory usage and detecting unusual patterns.
 *
 * @param state - Ratchet state
 * @returns Number of stored skipped keys
 */
export function getSkippedKeyCount(state: RatchetState): number {
    return state.skippedMessageKeys.size
}

/**
 * Clear old skipped message keys to free memory.
 *
 * In a real application, you might want to periodically clear
 * skipped keys that are too old to be useful. This is a simple
 * implementation that clears all keys.
 *
 * @param state - Ratchet state (will be mutated)
 * @returns Number of keys cleared
 */
export function clearSkippedKeys(state: RatchetState): number {
    const count = state.skippedMessageKeys.size
    state.skippedMessageKeys.clear()
    return count
}
