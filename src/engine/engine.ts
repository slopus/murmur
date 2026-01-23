/**
 * Murmur Messaging Engine.
 *
 * Coordinates between:
 * - Encryption layer (X3DH, Double Ratchet)
 * - API client (server communication)
 * - Storage (SQLite persistence)
 *
 * Provides a high-level API for the UI to use.
 */

import { createId } from '@paralleldrive/cuid2'
import { MurmurApi, type InboxMessage } from './api.js'
import { MurmurDatabase } from '../storage/database.js'
import type { Account, StoredContact, StoredMessage, Contact } from '../storage/types.js'
import {
    createAgent,
    getIdentityKey,
    getPreKeyBundle,
    initiateSession,
    hasSession,
    encryptMessage,
    decryptMessage,
    serializeAgent,
    deserializeAgent,
    prepareOutgoingMessage,
    processIncomingMessage,
    getOneTimePreKeyCount
} from '../encryption/session/session.js'
import type { AgentState, SessionInitMessage, ProtocolMessage } from '../encryption/session/types.js'
import type { PreKeyBundle } from '../encryption/x3dh/types.js'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes,
    bytesToString
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'
import {
    encryptProfile,
    decryptProfile,
    createProfileForRegistration,
    type Profile
} from './profile.js'

/**
 * Conversation with a contact including messages.
 */
export interface Conversation {
    contact: Contact
    messages: StoredMessage[]
    unreadCount: number
    lastMessage?: StoredMessage
}

/**
 * Event types emitted by the engine.
 */
export type EngineEvent =
    | { type: 'message'; message: StoredMessage; contact: Contact }
    | { type: 'contact_added'; contact: Contact }
    | { type: 'sync_complete' }
    | { type: 'error'; error: string }

/**
 * Event listener type.
 */
export type EngineEventListener = (event: EngineEvent) => void

/**
 * Murmur messaging engine.
 */
export class MurmurEngine {
    private db: MurmurDatabase
    private api: MurmurApi
    private agent: AgentState | null = null
    private account: Account | null = null
    private listeners: Set<EngineEventListener> = new Set()
    private syncInterval: ReturnType<typeof setInterval> | null = null

    constructor(dbPath?: string, apiBaseUrl?: string) {
        this.db = new MurmurDatabase(dbPath)
        this.api = new MurmurApi(apiBaseUrl)
    }

    /**
     * Subscribe to engine events.
     */
    on(listener: EngineEventListener): () => void {
        this.listeners.add(listener)
        return () => this.listeners.delete(listener)
    }

    /**
     * Emit an event to all listeners.
     */
    private emit(event: EngineEvent): void {
        for (const listener of this.listeners) {
            try {
                listener(event)
            } catch (error) {
                console.error('Event listener error:', error)
            }
        }
    }

    /**
     * Check if an account exists.
     */
    hasAccount(): boolean {
        return this.db.hasAccount()
    }

    /**
     * Get the current account.
     */
    getAccount(): Account | null {
        return this.account
    }

    /**
     * Initialize the engine with existing account.
     */
    async initialize(): Promise<boolean> {
        this.account = this.db.getAccount()
        if (!this.account) return false

        const serializedAgent = this.db.getAgentState()
        if (!serializedAgent) return false

        this.agent = deserializeAgent(serializedAgent)

        // Login to server
        try {
            await this.api.login(
                this.account.identityKey,
                this.agent.keyStore.identityKeyPair.privateKey
            )
        } catch (error) {
            // Server might be unavailable, continue in offline mode
            console.error('Failed to login:', error)
        }

        return true
    }

    /**
     * Create a new account.
     */
    async createAccount(firstName: string, lastName?: string): Promise<Account> {
        // Create agent with encryption keys (99 one-time + 1 signed = 100 total, server limit)
        this.agent = createAgent()
        const identityKey = getIdentityKey(this.agent)

        // Create profile
        const profile: Profile = { firstName, lastName }
        const {
            profilePublicKey,
            profileSecretKey,
            profileKeySignature,
            encryptedProfile
        } = createProfileForRegistration(profile, this.agent.keyStore.identityKeyPair.privateKey)

        // Register with server
        const { user } = await this.api.register(
            identityKey,
            this.agent.keyStore.identityKeyPair.privateKey,
            profilePublicKey,
            profileKeySignature,
            encryptedProfile
        )

        // Upload prekeys to server
        await this.uploadPreKeys()

        // Create account object
        this.account = {
            identityKey,
            profilePublicKey,
            profileSecretKey,
            encryptedProfile,
            firstName,
            lastName,
            createdAt: user.createdAt
        }

        // Save to database
        this.db.saveAccount(this.account)
        this.db.saveAgentState(serializeAgent(this.agent))

        return this.account
    }

    /**
     * Upload prekeys to server.
     */
    private async uploadPreKeys(): Promise<void> {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        const bundle = getPreKeyBundle(this.agent, false)
        const preKeys: Array<{ publicKey: string; signature: string; oneTime: boolean }> = []

        // Add signed prekey
        preKeys.push({
            publicKey: encodeBase64(bundle.signedPreKey),
            signature: encodeBase64(bundle.signedPreKeySignature),
            oneTime: false
        })

        // Add one-time prekeys
        for (const [_id, otpk] of this.agent.keyStore.oneTimePreKeys) {
            // Sign each one-time prekey with identity key
            const signature = sign(otpk.keyPair.publicKey, this.agent.keyStore.identityKeyPair.privateKey)
            preKeys.push({
                publicKey: encodeBase64(otpk.keyPair.publicKey),
                signature: encodeBase64(signature),
                oneTime: true
            })
        }

        await this.api.uploadPreKeys(preKeys)
    }

    /**
     * Get all contacts.
     */
    getContacts(): Contact[] {
        const storedContacts = this.db.getContacts()
        return storedContacts.map(sc => this.decryptContact(sc))
    }

    /**
     * Decrypt a stored contact's profile.
     */
    private decryptContact(stored: StoredContact): Contact {
        try {
            // Try to decrypt with our profile key (for contacts who shared their key)
            // In a real implementation, we'd need the contact's profile secret
            // For now, we store the decrypted name when adding the contact
            const profile = JSON.parse(bytesToString(decodeBase64(stored.encryptedProfile)))
            return {
                identityKey: stored.identityKey,
                profilePublicKey: stored.profilePublicKey,
                firstName: profile.firstName || 'Unknown',
                lastName: profile.lastName,
                addedAt: stored.addedAt,
                updatedAt: stored.updatedAt
            }
        } catch {
            return {
                identityKey: stored.identityKey,
                profilePublicKey: stored.profilePublicKey,
                firstName: 'Unknown',
                addedAt: stored.addedAt,
                updatedAt: stored.updatedAt
            }
        }
    }

    /**
     * Add a contact by their identity key.
     * This fetches their profile and prekey bundle from the server,
     * and establishes an X3DH session for messaging.
     */
    async addContact(identityKey: string): Promise<Contact> {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        // Fetch profile from server
        const serverProfile = await this.api.getProfile(identityKey)

        // Fetch prekey bundle and establish session
        await this.establishSession(identityKey)

        // For simplicity, we'll store a placeholder profile
        // In a real app, we'd need a key exchange to decrypt their profile
        const profile: Profile = { firstName: identityKey.slice(0, 8) }

        const now = Date.now()
        const storedContact: StoredContact = {
            identityKey,
            profilePublicKey: serverProfile.profilePublicKey,
            encryptedProfile: encodeBase64(stringToBytes(JSON.stringify(profile))),
            addedAt: now,
            updatedAt: now
        }

        this.db.saveContact(storedContact)

        // Save agent state after session establishment
        this.db.saveAgentState(serializeAgent(this.agent))

        const contact: Contact = {
            ...profile,
            identityKey,
            profilePublicKey: serverProfile.profilePublicKey,
            addedAt: now,
            updatedAt: now
        }

        this.emit({ type: 'contact_added', contact })
        return contact
    }

    /**
     * Establish a session with a peer by fetching their prekey bundle.
     */
    private async establishSession(peerIdentityKey: string): Promise<void> {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        // Skip if session already exists
        if (hasSession(this.agent, peerIdentityKey)) {
            return
        }

        // Fetch prekey bundle from server
        const serverBundle = await this.api.getPreKeyBundle(peerIdentityKey)

        // Convert to protocol PreKeyBundle
        // Server doesn't use numeric IDs, so we use placeholders
        const bundle: PreKeyBundle = {
            identityKey: decodeBase64(serverBundle.identityKey),
            signedPreKey: decodeBase64(serverBundle.signedPreKey.publicKey),
            signedPreKeyId: 0, // Server doesn't use IDs
            signedPreKeySignature: decodeBase64(serverBundle.signedPreKey.signature),
            oneTimePreKey: serverBundle.oneTimePreKey
                ? decodeBase64(serverBundle.oneTimePreKey.publicKey)
                : undefined,
            oneTimePreKeyId: serverBundle.oneTimePreKey ? 0 : undefined
        }

        // Initiate session with a placeholder message (we'll send real message later)
        // The first actual message will use the established session
        initiateSession(this.agent, bundle, stringToBytes('session_init'))
    }

    /**
     * Add a contact with known profile info.
     * Used when receiving a message from a new sender.
     */
    addContactWithProfile(
        identityKey: string,
        profilePublicKey: string,
        firstName: string,
        lastName?: string
    ): Contact {
        const now = Date.now()
        const profile: Profile = { firstName, lastName }

        const storedContact: StoredContact = {
            identityKey,
            profilePublicKey,
            encryptedProfile: encodeBase64(stringToBytes(JSON.stringify(profile))),
            addedAt: now,
            updatedAt: now
        }

        this.db.saveContact(storedContact)

        const contact: Contact = {
            ...profile,
            identityKey,
            profilePublicKey,
            addedAt: now,
            updatedAt: now
        }

        this.emit({ type: 'contact_added', contact })
        return contact
    }

    /**
     * Get or create a contact.
     */
    private getOrCreateContact(identityKey: string): Contact {
        const stored = this.db.getContact(identityKey)
        if (stored) {
            return this.decryptContact(stored)
        }

        // Create a placeholder contact
        return this.addContactWithProfile(identityKey, '', identityKey.slice(0, 8))
    }

    /**
     * Get all conversations with unread counts and last messages.
     */
    getConversations(): Conversation[] {
        const contacts = this.getContacts()
        const unreadCounts = this.db.getUnreadCounts()
        const lastMessages = this.db.getLastMessages()

        return contacts.map(contact => ({
            contact,
            messages: [],
            unreadCount: unreadCounts.get(contact.identityKey) ?? 0,
            lastMessage: lastMessages.get(contact.identityKey)
        })).sort((a, b) => {
            // Sort by last message time, most recent first
            const aTime = a.lastMessage?.createdAt ?? a.contact.addedAt
            const bTime = b.lastMessage?.createdAt ?? b.contact.addedAt
            return bTime - aTime
        })
    }

    /**
     * Get messages for a conversation.
     */
    getMessages(contactIdentityKey: string, limit: number = 100): StoredMessage[] {
        return this.db.getMessages(contactIdentityKey, limit)
    }

    /**
     * Send a message to a contact.
     */
    async sendMessage(recipientIdentityKey: string, text: string): Promise<StoredMessage> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }

        const trimmedText = text.trim()
        if (!trimmedText) {
            throw new Error('Message cannot be empty')
        }

        // Ensure we have a session with the recipient
        if (!hasSession(this.agent, recipientIdentityKey)) {
            // Establish session first
            await this.establishSession(recipientIdentityKey)
        }

        // Encrypt the message
        const messageId = createId()
        const plaintext = stringToBytes(trimmedText)
        const { outgoing } = prepareOutgoingMessage(
            this.agent,
            recipientIdentityKey,
            plaintext,
            messageId
        )

        // Send to server
        const serverResult = await this.api.sendMessage(
            outgoing.recipientId,
            outgoing.blob
        )

        // Save agent state after encryption (ratchet advanced)
        this.db.saveAgentState(serializeAgent(this.agent))

        // Save message locally
        const storedMessage: StoredMessage = {
            id: messageId,
            conversationId: recipientIdentityKey,
            isOutgoing: true,
            text: trimmedText,
            createdAt: serverResult.createdAt,
            read: true
        }

        this.db.saveMessage(storedMessage)

        return storedMessage
    }

    /**
     * Process an incoming message from the server.
     */
    private processIncomingServerMessage(inboxMessage: InboxMessage): StoredMessage | null {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        try {
            // Decrypt the message
            const decrypted = processIncomingMessage(
                this.agent,
                inboxMessage.senderId,
                inboxMessage.blob,
                inboxMessage.id,
                inboxMessage.signature
            )

            // Save agent state after decryption (ratchet may have advanced)
            this.db.saveAgentState(serializeAgent(this.agent))

            // Extract text from plaintext
            const text = bytesToString(decrypted.plaintext).trim()

            // Save message
            const storedMessage: StoredMessage = {
                id: inboxMessage.id,
                conversationId: inboxMessage.senderId,
                isOutgoing: false,
                text,
                createdAt: inboxMessage.createdAt,
                read: false
            }

            this.db.saveMessage(storedMessage)

            // Ensure contact exists
            const contact = this.getOrCreateContact(inboxMessage.senderId)

            // Emit event
            this.emit({ type: 'message', message: storedMessage, contact })

            return storedMessage
        } catch (error) {
            console.error('Failed to process message:', error)
            this.emit({ type: 'error', error: `Failed to process message: ${error}` })
            return null
        }
    }

    /**
     * Sync messages from the server.
     */
    async sync(): Promise<void> {
        if (!this.agent || !this.account) {
            return
        }

        try {
            let cursor: string | undefined
            let hasMore = true
            const processedIds: string[] = []

            while (hasMore) {
                const result = await this.api.getInbox(50, cursor)

                for (const msg of result.messages) {
                    const stored = this.processIncomingServerMessage(msg)
                    if (stored) {
                        processedIds.push(msg.id)
                    }
                }

                cursor = result.nextCursor ?? undefined
                hasMore = result.hasMore
            }

            // Acknowledge processed messages
            if (processedIds.length > 0) {
                await this.api.acknowledgeMessages(processedIds)
            }

            this.emit({ type: 'sync_complete' })
        } catch (error) {
            console.error('Sync failed:', error)
            this.emit({ type: 'error', error: `Sync failed: ${error}` })
        }
    }

    /**
     * Start automatic syncing.
     */
    startSync(intervalMs: number = 5000): void {
        if (this.syncInterval) {
            clearInterval(this.syncInterval)
        }

        // Initial sync
        this.sync()

        // Periodic sync
        this.syncInterval = setInterval(() => {
            this.sync()
        }, intervalMs)
    }

    /**
     * Stop automatic syncing.
     */
    stopSync(): void {
        if (this.syncInterval) {
            clearInterval(this.syncInterval)
            this.syncInterval = null
        }
    }

    /**
     * Mark messages as read.
     */
    markAsRead(contactIdentityKey: string): void {
        this.db.markMessagesRead(contactIdentityKey)
    }

    /**
     * Close the engine and release resources.
     */
    close(): void {
        this.stopSync()
        this.db.close()
    }
}
