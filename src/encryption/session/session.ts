/**
 * Session Manager - High-level API for secure messaging.
 *
 * This module provides a unified interface for:
 * - Managing X3DH key material
 * - Establishing sessions with peers
 * - Encrypting and decrypting messages
 * - Persisting state
 *
 * Usage:
 * 1. Create agent: createAgent()
 * 2. Publish prekey bundle to server
 * 3. Send first message: createPreKeyMessage(agent, peerBundle, plaintext)
 * 4. Send messages: encryptMessage(agent, peerId, plaintext)
 * 5. Receive messages: decryptMessage(agent, senderId, message)
 */

import {
    initializeKeyStore,
    createPreKeyBundle,
    x3dhSender,
    x3dhReceiver,
    serializeKeyStore,
    deserializeKeyStore,
    replenishOneTimePreKeys,
    type X3DHKeyStore,
    type PreKeyBundle,
    type X3DHReceiverKeys
} from '../x3dh/index.js'
import {
    initializeAlice,
    initializeBob,
    ratchetEncrypt,
    ratchetDecrypt,
    serializeState,
    deserializeState,
    type RatchetState,
    type EncryptedMessage
} from '../ratchet/index.js'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes,
    bytesToString,
    concatBytes,
    constantTimeEqual
} from '../crypto/utils.js'
import { deriveDhPublicKeyFromSigningPublicKey } from '../crypto/dh.js'
import { sign, verify } from '../crypto/signing.js'
import type {
    Session,
    SerializedSession,
    AgentState,
    SerializedAgentState,
    ProtocolMessage,
    DecryptedMessage,
    OutgoingMessage
} from './types.js'

/**
 * Create a new agent with fresh keys.
 *
 * @param oneTimePreKeyCount - Number of one-time prekeys to generate (default: 99, server limit is 100 total including signed prekey)
 * @returns New agent state
 *
 * @example
 * ```typescript
 * const agent = createAgent()
 * const bundle = getPreKeyBundle(agent)
 * // Publish bundle to server
 * ```
 */
export function createAgent(oneTimePreKeyCount: number = 99): AgentState {
    return {
        keyStore: initializeKeyStore(oneTimePreKeyCount),
        sessions: new Map()
    }
}

/**
 * Get the agent's identity public key.
 *
 * @param agent - Agent state
 * @returns Base64-encoded identity public key
 */
export function getIdentityKey(agent: AgentState): string {
    return encodeBase64(agent.keyStore.identityKeyPair.publicKey)
}

/**
 * Get a prekey bundle for publishing to the server.
 *
 * @param agent - Agent state
 * @param includeOneTimePreKey - Whether to include a one-time prekey
 * @returns Prekey bundle ready to publish
 */
export function getPreKeyBundle(agent: AgentState, includeOneTimePreKey: boolean = true): PreKeyBundle {
    let oneTimePreKey
    if (includeOneTimePreKey && agent.keyStore.oneTimePreKeys.size > 0) {
        // Get the first available one-time prekey
        const firstEntry = agent.keyStore.oneTimePreKeys.entries().next()
        if (!firstEntry.done) {
            oneTimePreKey = firstEntry.value[1]
        }
    }
    return createPreKeyBundle(
        agent.keyStore.identityKeyPair,
        agent.keyStore.signedPreKey,
        oneTimePreKey
    )
}

/**
 * Create a pre-key message to establish a new session.
 *
 * @param agent - Our agent state
 * @param peerBundle - Peer's prekey bundle (from server)
 * @param initialMessage - First message to send
 * @returns Message to send along with the created session
 *
 * @example
 * ```typescript
 * const peerBundle = await fetchPreKeyBundle(peerId)
 * const { message } = createPreKeyMessage(agent, peerBundle, stringToBytes('Hello!'))
 * await sendMessage(peerId, message)
 * ```
 */
export function createPreKeyMessage(
    agent: AgentState,
    peerBundle: PreKeyBundle,
    initialMessage: Uint8Array
): { message: ProtocolMessage; session: Session } {
    // Perform X3DH
    const x3dhResult = x3dhSender(agent.keyStore.identityKeyPair, peerBundle)

    // Initialize Double Ratchet as Alice
    const ratchetState = initializeAlice(x3dhResult.sharedSecret, x3dhResult.bobSignedPreKey)

    // Create session
    const session: Session = {
        peerIdentityKey: peerBundle.identityKey,
        ratchetState,
        establishedAt: Date.now(),
        lastActivityAt: Date.now()
    }

    // Store session
    const peerIdKey = encodeBase64(peerBundle.identityKey)
    agent.sessions.set(peerIdKey, session)

    // Encrypt first message with Double Ratchet
    const encrypted = ratchetEncrypt(ratchetState, initialMessage)

    const message: ProtocolMessage = {
        type: 'message',
        init: {
            ephemeralKey: encodeBase64(x3dhResult.ephemeralPublicKey),
            preKey: encodeBase64(peerBundle.signedPreKey),
            oneTimePreKey: peerBundle.oneTimePreKey ? encodeBase64(peerBundle.oneTimePreKey) : undefined
        },
        ratchetKey: encodeBase64(encrypted.header.publicKey),
        previousChainLength: encrypted.header.previousChainLength,
        messageNumber: encrypted.header.messageNumber,
        ciphertext: encodeBase64(encrypted.ciphertext)
    }

    return { message, session }
}

/**
 * Find a one-time prekey by public key.
 */
function findOneTimePreKey(store: X3DHKeyStore, publicKey: Uint8Array): X3DHReceiverKeys['oneTimePreKey'] {
    for (const otpk of store.oneTimePreKeys.values()) {
        if (constantTimeEqual(otpk.keyPair.publicKey, publicKey)) {
            return otpk
        }
    }
    return undefined
}

/**
 * Process a pre-key message from a peer.
 *
 * @param agent - Our agent state
 * @param senderId - Sender's identity key (base64)
 * @param message - Pre-key protocol message
 * @returns Decrypted message
 */
export function receivePreKeyMessage(
    agent: AgentState,
    senderId: string,
    message: ProtocolMessage
): DecryptedMessage {
    if (!message.init) {
        throw new Error('Missing pre-key fields in message')
    }

    const senderIdentityKey = decodeBase64(senderId)
    const identityDHKey = deriveDhPublicKeyFromSigningPublicKey(senderIdentityKey)
    const ephemeralKey = decodeBase64(message.init.ephemeralKey)

    if (!message.init.preKey) {
        throw new Error('Missing prekey in message')
    }
    const expectedSignedPreKey = decodeBase64(message.init.preKey)
    if (!constantTimeEqual(expectedSignedPreKey, agent.keyStore.signedPreKey.keyPair.publicKey)) {
        throw new Error('Prekey does not match current key')
    }

    // Get the one-time prekey if used
    let oneTimePreKey
    if (message.init.oneTimePreKey) {
        const expectedOneTimePreKey = decodeBase64(message.init.oneTimePreKey)
        const resolvedOneTimePreKey = findOneTimePreKey(agent.keyStore, expectedOneTimePreKey)
        if (!resolvedOneTimePreKey) {
            throw new Error('Unknown one-time prekey')
        }
        oneTimePreKey = resolvedOneTimePreKey
    }

    // Perform X3DH
    const receiverKeys: X3DHReceiverKeys = {
        identityKeyPair: agent.keyStore.identityKeyPair,
        signedPreKey: agent.keyStore.signedPreKey,
        oneTimePreKey
    }

    const x3dhResult = x3dhReceiver(
        receiverKeys,
        senderIdentityKey,
        identityDHKey,
        ephemeralKey
    )

    // Initialize Double Ratchet as Bob
    const ratchetState = initializeBob(x3dhResult.sharedSecret, agent.keyStore.signedPreKey.keyPair)

    // Create and store session
    const session: Session = {
        peerIdentityKey: senderIdentityKey,
        ratchetState,
        establishedAt: Date.now(),
        lastActivityAt: Date.now()
    }
    agent.sessions.set(senderId, session)

    // Decrypt the first message
    const encryptedMessage = parseEncryptedMessage(message)
    const plaintext = ratchetDecrypt(ratchetState, encryptedMessage)

    return {
        plaintext,
        senderIdentityKey
    }
}

/**
 * Encrypt a message for a peer.
 *
 * @param agent - Our agent state
 * @param peerId - Peer's identity key (base64)
 * @param plaintext - Message to encrypt
 * @returns Regular message to send
 * @throws Error if no session exists with peer
 */
export function encryptMessage(
    agent: AgentState,
    peerId: string,
    plaintext: Uint8Array
): ProtocolMessage {
    const session = agent.sessions.get(peerId)
    if (!session) {
        throw new Error(`No session with peer: ${peerId}`)
    }

    const encrypted = ratchetEncrypt(session.ratchetState, plaintext)
    session.lastActivityAt = Date.now()

    return {
        type: 'message',
        ratchetKey: encodeBase64(encrypted.header.publicKey),
        previousChainLength: encrypted.header.previousChainLength,
        messageNumber: encrypted.header.messageNumber,
        ciphertext: encodeBase64(encrypted.ciphertext)
    }
}

/**
 * Decrypt a message from a peer.
 *
 * @param agent - Our agent state
 * @param senderId - Sender's identity key (base64)
 * @param message - Protocol message (session init or regular)
 * @returns Decrypted message
 */
export function decryptMessage(
    agent: AgentState,
    senderId: string,
    message: ProtocolMessage
): DecryptedMessage {
    if (message.type !== 'message') {
        throw new Error(`Invalid message type: ${message.type}`)
    }

    if (message.init) {
        return receivePreKeyMessage(agent, senderId, message)
    }

    // Handle regular message
    const session = agent.sessions.get(senderId)
    if (!session) {
        throw new Error(`No session with peer: ${senderId}`)
    }

    const encryptedMessage = parseEncryptedMessage(message)
    const plaintext = ratchetDecrypt(session.ratchetState, encryptedMessage)
    session.lastActivityAt = Date.now()

    return {
        plaintext,
        senderIdentityKey: session.peerIdentityKey
    }
}

/**
 * Build an encrypted message from protocol fields.
 */
function parseEncryptedMessage(message: ProtocolMessage): EncryptedMessage {
    if (!message.ratchetKey) {
        throw new Error('Missing ratchet key in message')
    }

    const header = {
        publicKey: decodeBase64(message.ratchetKey),
        previousChainLength: message.previousChainLength,
        messageNumber: message.messageNumber
    }
    const ciphertext = decodeBase64(message.ciphertext)

    return { header, ciphertext }
}

/**
 * Check if we have a session with a peer.
 *
 * @param agent - Agent state
 * @param peerId - Peer's identity key (base64)
 * @returns true if session exists
 */
export function hasSession(agent: AgentState, peerId: string): boolean {
    return agent.sessions.has(peerId)
}

/**
 * Get a session with a peer.
 *
 * @param agent - Agent state
 * @param peerId - Peer's identity key (base64)
 * @returns Session or undefined
 */
export function getSession(agent: AgentState, peerId: string): Session | undefined {
    return agent.sessions.get(peerId)
}

/**
 * Delete a session with a peer.
 *
 * @param agent - Agent state
 * @param peerId - Peer's identity key (base64)
 * @returns true if session was deleted
 */
export function deleteSession(agent: AgentState, peerId: string): boolean {
    return agent.sessions.delete(peerId)
}

/**
 * Serialize agent state for persistence.
 *
 * @param agent - Agent state
 * @returns JSON-serializable object
 */
export function serializeAgent(agent: AgentState): SerializedAgentState {
    const serializedSessions: Array<[string, SerializedSession]> = []

    for (const [peerId, session] of agent.sessions) {
        serializedSessions.push([
            peerId,
            {
                peerIdentityKey: encodeBase64(session.peerIdentityKey),
                ratchetState: serializeState(session.ratchetState),
                establishedAt: session.establishedAt,
                lastActivityAt: session.lastActivityAt
            }
        ])
    }

    return {
        keyStore: serializeKeyStore(agent.keyStore),
        sessions: serializedSessions
    }
}

/**
 * Deserialize agent state from storage.
 *
 * @param serialized - Serialized agent state
 * @returns Restored agent state
 */
export function deserializeAgent(serialized: SerializedAgentState): AgentState {
    const sessions = new Map<string, Session>()

    for (const [peerId, serializedSession] of serialized.sessions) {
        sessions.set(peerId, {
            peerIdentityKey: decodeBase64(serializedSession.peerIdentityKey),
            ratchetState: deserializeState(serializedSession.ratchetState),
            establishedAt: serializedSession.establishedAt,
            lastActivityAt: serializedSession.lastActivityAt
        })
    }

    return {
        keyStore: deserializeKeyStore(serialized.keyStore),
        sessions
    }
}

/**
 * Sign a message for the server.
 *
 * @param agent - Agent state
 * @param blob - Message blob
 * @param messageId - Message ID
 * @returns Base64-encoded signature
 */
export function signMessageForServer(
    agent: AgentState,
    blob: string,
    messageId: string
): string {
    const blobBytes = decodeBase64(blob)
    const messageIdBytes = stringToBytes(messageId)
    const message = new Uint8Array(blobBytes.length + messageIdBytes.length)
    message.set(blobBytes, 0)
    message.set(messageIdBytes, blobBytes.length)
    const signature = sign(message, agent.keyStore.identityKeyPair.privateKey)
    return encodeBase64(signature)
}

/**
 * Verify a message signature from the server.
 *
 * @param senderId - Sender's identity key (base64)
 * @param blob - Message blob
 * @param messageId - Message ID
 * @param signature - Base64-encoded signature
 * @returns true if signature is valid
 */
export function verifyMessageSignature(
    senderId: string,
    blob: string,
    messageId: string,
    signature: string
): boolean {
    const senderKey = decodeBase64(senderId)
    const blobBytes = decodeBase64(blob)
    const messageIdBytes = stringToBytes(messageId)
    const message = new Uint8Array(blobBytes.length + messageIdBytes.length)
    message.set(blobBytes, 0)
    message.set(messageIdBytes, blobBytes.length)
    const signatureBytes = decodeBase64(signature)
    return verify(message, signatureBytes, senderKey)
}

/**
 * Prepare a message for sending to the server.
 *
 * @param agent - Agent state
 * @param peerId - Recipient's identity key (base64)
 * @param plaintext - Message plaintext
 * @param messageId - Unique message ID
 * @param preKeyBundle - Optional prekey bundle for new sessions
 * @returns Outgoing message ready for server API
 */
export function prepareOutgoingMessage(
    agent: AgentState,
    peerId: string,
    plaintext: Uint8Array,
    messageId: string,
    preKeyBundle?: PreKeyBundle
): { outgoing: OutgoingMessage; protocolMessage: ProtocolMessage } {
    let protocolMessage: ProtocolMessage

    if (hasSession(agent, peerId)) {
        protocolMessage = encryptMessage(agent, peerId, plaintext)
    } else if (preKeyBundle) {
        protocolMessage = createPreKeyMessage(agent, preKeyBundle, plaintext).message
    } else {
        throw new Error(`No session with peer: ${peerId}. Provide a prekey bundle.`)
    }

    const blob = encodeBase64(stringToBytes(JSON.stringify(protocolMessage)))
    const signature = signMessageForServer(agent, blob, messageId)

    return {
        outgoing: {
            recipientId: peerId,
            blob,
            signature
        },
        protocolMessage
    }
}

/**
 * Process an incoming message from the server.
 *
 * @param agent - Agent state
 * @param senderId - Sender's identity key (base64)
 * @param blob - Encrypted blob from server
 * @param messageId - Message ID
 * @param signature - Signature from server
 * @returns Decrypted message
 */
export function processIncomingMessage(
    agent: AgentState,
    senderId: string,
    blob: string,
    messageId: string,
    signature: string
): DecryptedMessage {
    // Verify signature
    if (!verifyMessageSignature(senderId, blob, messageId, signature)) {
        throw new Error('Invalid message signature')
    }

    // Decode and parse protocol message
    const protocolMessageJson = bytesToString(decodeBase64(blob))
    const protocolMessage = JSON.parse(protocolMessageJson) as ProtocolMessage

    // Decrypt
    return decryptMessage(agent, senderId, protocolMessage)
}

/**
 * Replenish one-time prekeys if running low.
 *
 * @param agent - Agent state
 * @param targetCount - Desired number of one-time prekeys
 * @returns Array of new prekeys to upload to server
 */
export function replenishPreKeys(agent: AgentState, targetCount: number = 100) {
    return replenishOneTimePreKeys(agent.keyStore, targetCount)
}

/**
 * Get the number of remaining one-time prekeys.
 *
 * @param agent - Agent state
 * @returns Number of available one-time prekeys
 */
export function getOneTimePreKeyCount(agent: AgentState): number {
    return agent.keyStore.oneTimePreKeys.size
}
