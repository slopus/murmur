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
 * 3. Initiate session: initiateSession(agent, peerBundle)
 * 4. Send messages: encryptMessage(agent, peerId, plaintext)
 * 5. Receive messages: decryptMessage(agent, senderId, message)
 */

import {
    initializeKeyStore,
    createPreKeyBundle,
    x3dhSender,
    x3dhReceiver,
    consumeOneTimePreKey,
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
    encodeHeader,
    decodeHeader,
    type RatchetState,
    type EncryptedMessage
} from '../ratchet/index.js'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes,
    bytesToString,
    concatBytes
} from '../crypto/utils.js'
import { sign, verify } from '../crypto/signing.js'
import type {
    Session,
    SerializedSession,
    AgentState,
    SerializedAgentState,
    SessionInitMessage,
    RegularMessage,
    ProtocolMessage,
    DecryptedMessage,
    OutgoingMessage
} from './types.js'

/**
 * Create a new agent with fresh keys.
 *
 * @param oneTimePreKeyCount - Number of one-time prekeys to generate
 * @returns New agent state
 *
 * @example
 * ```typescript
 * const agent = createAgent(100)
 * const bundle = getPreKeyBundle(agent)
 * // Publish bundle to server
 * ```
 */
export function createAgent(oneTimePreKeyCount: number = 100): AgentState {
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
 * Initiate a session with a peer using their prekey bundle.
 *
 * @param agent - Our agent state
 * @param peerBundle - Peer's prekey bundle (from server)
 * @param initialMessage - First message to send
 * @returns Session init message to send to peer
 *
 * @example
 * ```typescript
 * const peerBundle = await fetchPreKeyBundle(peerId)
 * const { message } = initiateSession(agent, peerBundle, 'Hello!')
 * await sendMessage(peerId, message)
 * ```
 */
export function initiateSession(
    agent: AgentState,
    peerBundle: PreKeyBundle,
    initialMessage: Uint8Array
): { sessionInitMessage: SessionInitMessage; session: Session } {
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

    // Create session init message
    const sessionInitMessage: SessionInitMessage = {
        type: 'session_init',
        identityDHKey: encodeBase64(x3dhResult.aliceIdentityDHKey),
        ephemeralKey: encodeBase64(x3dhResult.ephemeralPublicKey),
        signedPreKeyId: x3dhResult.signedPreKeyId,
        oneTimePreKeyId: x3dhResult.oneTimePreKeyId,
        header: encodeBase64(encodeHeader(encrypted.header)),
        ciphertext: encodeBase64(encrypted.ciphertext)
    }

    return { sessionInitMessage, session }
}

/**
 * Process a session init message from a peer.
 *
 * @param agent - Our agent state
 * @param senderId - Sender's identity key (base64)
 * @param message - Session init message
 * @returns Decrypted first message
 */
export function receiveSessionInit(
    agent: AgentState,
    senderId: string,
    message: SessionInitMessage
): DecryptedMessage {
    const senderIdentityKey = decodeBase64(senderId)

    // Get the one-time prekey if used
    let oneTimePreKey
    if (message.oneTimePreKeyId !== undefined) {
        oneTimePreKey = consumeOneTimePreKey(agent.keyStore, message.oneTimePreKeyId)
    }

    // Verify we have the signed prekey
    if (agent.keyStore.signedPreKey.id !== message.signedPreKeyId) {
        throw new Error(`Unknown signed prekey ID: ${message.signedPreKeyId}`)
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
        decodeBase64(message.identityDHKey),
        decodeBase64(message.ephemeralKey)
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
    const header = decodeHeader(decodeBase64(message.header))
    const ciphertext = decodeBase64(message.ciphertext)
    const plaintext = ratchetDecrypt(ratchetState, { header, ciphertext })

    return {
        plaintext,
        senderIdentityKey,
        isSessionInit: true
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
): RegularMessage {
    const session = agent.sessions.get(peerId)
    if (!session) {
        throw new Error(`No session with peer: ${peerId}`)
    }

    const encrypted = ratchetEncrypt(session.ratchetState, plaintext)
    session.lastActivityAt = Date.now()

    return {
        type: 'message',
        header: encodeBase64(encodeHeader(encrypted.header)),
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
    // Handle session init
    if (message.type === 'session_init') {
        return receiveSessionInit(agent, senderId, message)
    }

    // Handle regular message
    const session = agent.sessions.get(senderId)
    if (!session) {
        throw new Error(`No session with peer: ${senderId}`)
    }

    const header = decodeHeader(decodeBase64(message.header))
    const ciphertext = decodeBase64(message.ciphertext)
    const plaintext = ratchetDecrypt(session.ratchetState, { header, ciphertext })
    session.lastActivityAt = Date.now()

    return {
        plaintext,
        senderIdentityKey: session.peerIdentityKey,
        isSessionInit: false
    }
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
    const message = stringToBytes(blob + messageId)
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
    const message = stringToBytes(blob + messageId)
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
 * @returns Outgoing message ready for server API
 */
export function prepareOutgoingMessage(
    agent: AgentState,
    peerId: string,
    plaintext: Uint8Array,
    messageId: string
): { outgoing: OutgoingMessage; protocolMessage: ProtocolMessage } {
    let protocolMessage: ProtocolMessage

    if (!hasSession(agent, peerId)) {
        throw new Error(`No session with peer: ${peerId}. Call initiateSession first.`)
    }

    protocolMessage = encryptMessage(agent, peerId, plaintext)

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
