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

import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { spawn } from 'node:child_process'
import { createId } from '@paralleldrive/cuid2'
import { gcm } from '@noble/ciphers/aes'
import { sha256 } from '@noble/hashes/sha256'
import { MurmurApi, type InboxMessage, type ServerProfile } from './api.js'
import { MurmurDatabase } from '../storage/database.js'
import type { Account, StoredAttachment, StoredContact, StoredMessage, Contact, HookType, StoredHook } from '../storage/types.js'
import { logger } from '../logger.js'
import {
    createAgent,
    getIdentityKey,
    getPreKeyBundle,
    hasSession,
    serializeAgent,
    deserializeAgent,
    prepareOutgoingMessage,
    processIncomingMessage
} from '../encryption/session/session.js'
import type { AgentState } from '../encryption/session/types.js'
import type { PreKeyBundle } from '../encryption/x3dh/types.js'
import {
    encodeBase64,
    decodeBase64,
    encodeBase58,
    stringToBytes,
    bytesToString,
    getRandomBytes,
    zeroBytes
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'
import {
    encryptProfile,
    decryptProfile,
    createProfileForRegistration,
    verifyProfileKeySignature,
    type Profile
} from './profile.js'
import { publicKeyFromPrivate } from '../encryption/crypto/dh.js'

const MAX_MESSAGE_LENGTH = 20000
const ATTACHMENT_KEY_LENGTH = 32
const ATTACHMENT_IV_LENGTH = 12
const MESSAGE_HOOK_TYPE: HookType = 'message'
const MESSAGE_HOOK_REPLY = 'Message rejected by message hook.'
const DEFAULT_ALLOW_KEY = 'default-allow'

type AttachmentPayloadEntry = {
    hash: string
    iv: string
    key: string
}

type AttachmentPayload = Record<string, AttachmentPayloadEntry>
type AttachmentMap = Record<string, string>
type AttachmentSource = {
    path: string
    fileName: string
}

type HookMessagePayload = {
    id: string
    out: boolean
    from: string
    to: string
    text: string
    attachments: string[]
}

function truncateMessageText(text: string): string {
    if (text.length <= MAX_MESSAGE_LENGTH) {
        return text
    }
    return text.slice(0, MAX_MESSAGE_LENGTH)
}

function bytesToHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('hex')
}

function formatProfileSecretKeyForHook(profileSecretKey: string): string {
    const bytes = decodeBase64(profileSecretKey, 'base64url')
    return encodeBase58(bytes)
}

function normalizeAttachmentName(path: string): string {
    const fileName = basename(path)
    if (!fileName || fileName === '.' || fileName === '..') {
        throw new Error(`Invalid attachment path: ${path}`)
    }
    return fileName
}

function collectAttachmentSources(paths: string[]): AttachmentSource[] {
    const sources: AttachmentSource[] = []
    const seenNames = new Set<string>()

    for (const path of paths) {
        const fileName = normalizeAttachmentName(path)
        if (seenNames.has(fileName)) {
            throw new Error(`Attachment filenames must be unique: ${fileName}`)
        }
        seenNames.add(fileName)
        sources.push({ path, fileName })
    }

    return sources
}

function createOutgoingAttachments(sources: AttachmentSource[]): {
    attachmentMap: AttachmentMap
    payload: AttachmentPayload
    stored: StoredAttachment[]
} {
    const attachmentMap: AttachmentMap = {}
    const payload: AttachmentPayload = {}
    const stored: StoredAttachment[] = []

    for (const source of sources) {
        const fileBytes = readFileSync(source.path)
        const key = getRandomBytes(ATTACHMENT_KEY_LENGTH)
        const iv = getRandomBytes(ATTACHMENT_IV_LENGTH)
        const cipher = gcm(key, iv)
        const ciphertextBytes = cipher.encrypt(fileBytes)
        const hash = bytesToHex(sha256(ciphertextBytes))
        if (attachmentMap[hash]) {
            throw new Error(`Duplicate attachment hash detected for ${source.fileName}`)
        }

        const ciphertext = encodeBase64(ciphertextBytes)
        const ivBase64 = encodeBase64(iv)
        const keyBase64 = encodeBase64(key)

        attachmentMap[hash] = ciphertext
        payload[source.fileName] = { hash, iv: ivBase64, key: keyBase64 }
        stored.push({
            fileName: source.fileName,
            hash,
            iv: ivBase64,
            key: keyBase64,
            ciphertext
        })

        zeroBytes(key)
        zeroBytes(iv)
    }

    return { attachmentMap, payload, stored }
}

function parseAttachmentPayload(value: unknown): AttachmentPayload | undefined {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return undefined
    }

    const rawEntries = value as Record<string, unknown>
    const parsed: AttachmentPayload = {}

    for (const [fileName, entry] of Object.entries(rawEntries)) {
        if (!fileName || typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
            continue
        }
        const record = entry as Record<string, unknown>
        const hash = record.hash
        const iv = record.iv
        const key = record.key

        if (typeof hash !== 'string' || typeof iv !== 'string' || typeof key !== 'string') {
            continue
        }

        parsed[fileName] = { hash, iv, key }
    }

    return Object.keys(parsed).length > 0 ? parsed : undefined
}

function buildStoredAttachments(
    payload: AttachmentPayload | undefined,
    attachmentMap: AttachmentMap | undefined
): { stored: StoredAttachment[]; invalid: boolean } {
    if (!payload && attachmentMap) {
        return { stored: [], invalid: true }
    }
    if (!payload) {
        return { stored: [], invalid: false }
    }
    if (!attachmentMap) {
        return { stored: [], invalid: true }
    }

    const stored: StoredAttachment[] = []
    for (const [fileName, meta] of Object.entries(payload)) {
        const ciphertext = attachmentMap[meta.hash]
        if (!ciphertext) {
            return { stored: [], invalid: true }
        }
        const ciphertextBytes = decodeBase64(ciphertext)
        const computedHash = bytesToHex(sha256(ciphertextBytes))
        if (computedHash !== meta.hash) {
            return { stored: [], invalid: true }
        }

        const keyBytes = decodeBase64(meta.key)
        const ivBytes = decodeBase64(meta.iv)
        try {
            const cipher = gcm(keyBytes, ivBytes)
            cipher.decrypt(ciphertextBytes)
        } catch {
            return { stored: [], invalid: true }
        }

        stored.push({
            fileName,
            hash: meta.hash,
            iv: meta.iv,
            key: meta.key,
            ciphertext
        })
    }

    return { stored, invalid: false }
}

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
    private authError: string | null = null

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
                logger.error({ error }, 'Event listener error')
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
     * Get the last authentication error, if any.
     */
    getAuthError(): string | null {
        return this.authError
    }

    /**
     * Get whether to allow messages from unknown contacts.
     */
    getDefaultAllow(): boolean {
        const value = this.db.getSetting(DEFAULT_ALLOW_KEY)
        if (value === null) {
            return true
        }
        return value === 'true'
    }

    /**
     * Set whether to allow messages from unknown contacts.
     */
    setDefaultAllow(allow: boolean): void {
        this.db.setSetting(DEFAULT_ALLOW_KEY, allow ? 'true' : 'false')
    }

    /**
     * Get current settings.
     */
    getSettings(): Record<string, string> {
        return {
            permissions: this.getDefaultAllow() ? 'default-allow' : 'default-deny'
        }
    }

    /**
     * Get configured hooks.
     */
    getHooks(type?: HookType): StoredHook[] {
        return this.db.getHooks(type)
    }

    /**
     * Add a new hook.
     */
    addHook(type: HookType, path: string, args: string[]): StoredHook {
        return this.db.addHook(type, path, args)
    }

    /**
     * Remove a hook by ID.
     */
    removeHook(id: string): number {
        return this.db.removeHook(id)
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
            this.authError = null
        } catch (error) {
            this.authError = error instanceof Error ? error.message : String(error)
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
     * Delete the current account and local data.
     */
    async deleteAccount(): Promise<void> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }
        const account = this.account

        await this.api.deleteAccount()
        this.stopSync()
        this.db.clearAll()
        this.agent = null
        this.account = null
    }

    /**
     * Upload prekeys to server.
     */
    private async uploadPreKeys(): Promise<void> {
        if (!this.agent || !this.account) {
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
        if (stored.profileSecretKey) {
            try {
                const profileSecretKey = decodeBase64(stored.profileSecretKey, 'base64url')
                const profile = decryptProfile(stored.encryptedProfile, profileSecretKey)
                return {
                    identityKey: stored.identityKey,
                    profilePublicKey: stored.profilePublicKey,
                    profileSecretKey: stored.profileSecretKey,
                    firstName: profile.firstName || 'Unknown',
                    lastName: profile.lastName,
                    addedAt: stored.addedAt,
                    updatedAt: stored.updatedAt,
                    blocked: stored.blocked
                }
            } catch {
                // Fall through to legacy decoding.
            }
        }

        try {
            const profile = JSON.parse(bytesToString(decodeBase64(stored.encryptedProfile))) as Profile
            return {
                identityKey: stored.identityKey,
                profilePublicKey: stored.profilePublicKey,
                profileSecretKey: stored.profileSecretKey,
                firstName: profile.firstName || 'Unknown',
                lastName: profile.lastName,
                addedAt: stored.addedAt,
                updatedAt: stored.updatedAt,
                blocked: stored.blocked
            }
        } catch {
            return this.buildPlaceholderContact(stored.identityKey, stored.profilePublicKey, stored.addedAt, stored.updatedAt, stored.blocked)
        }
    }

    /**
     * Add a contact by their profile secret key.
     */
    async addContact(profileSecretKey: string): Promise<Contact> {
        return this.addContactByProfileSecret(profileSecretKey)
    }

    /**
     * Add a contact by their profile secret key.
     */
    async addContactByProfileSecret(profileSecretKey: string): Promise<Contact> {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
        const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
        const serverProfile = await this.api.getProfile(profilePublicKey)

        return this.addContactFromProfile(serverProfile, profileSecretKey)
    }

    /**
     * Remove a contact by their profile secret key.
     */
    removeContactByProfileSecret(profileSecretKey: string): void {
        const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
        const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
        const stored = this.db.getContactByProfilePublicKey(profilePublicKey)
        if (!stored) {
            throw new Error('Contact not found.')
        }
        this.db.deleteContact(stored.identityKey)
    }

    /**
     * Update a contact's blocked status by profile secret key.
     */
    updateContactBlocked(profileSecretKey: string, blocked: boolean): Contact {
        const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
        const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
        const stored = this.db.getContactByProfilePublicKey(profilePublicKey)
        if (!stored) {
            throw new Error('Contact not found.')
        }
        this.db.setContactBlocked(stored.identityKey, blocked)
        const updated = this.db.getContact(stored.identityKey)
        if (!updated) {
            throw new Error('Contact not found after update.')
        }
        return this.decryptContact(updated)
    }

    /**
     * Fetch and parse a peer's prekey bundle.
     */
    private async fetchPreKeyBundle(peerIdentityKey: string): Promise<PreKeyBundle> {
        if (!this.agent) {
            throw new Error('Not initialized')
        }

        // Fetch prekey bundle from server
        const serverBundle = await this.api.getPreKeyBundle(peerIdentityKey)

        // Convert to protocol PreKeyBundle
        // Server doesn't use numeric IDs, so we use placeholders
        const bundle: PreKeyBundle = {
            identityKey: decodeBase64(serverBundle.identityKey),
            signedPreKey: decodeBase64(serverBundle.signedPreKey.publicKey),
            signedPreKeySignature: decodeBase64(serverBundle.signedPreKey.signature),
            oneTimePreKey: serverBundle.oneTimePreKey
                ? decodeBase64(serverBundle.oneTimePreKey.publicKey)
                : undefined
        }
        return bundle
    }

    /**
     * Add a contact using a server profile and shared secret key.
     */
    private addContactFromProfile(
        serverProfile: ServerProfile,
        profileSecretKey: string,
        expectedIdentityKey?: string
    ): Contact {
        if (expectedIdentityKey && serverProfile.id !== expectedIdentityKey) {
            throw new Error('Profile does not match expected identity key')
        }

        const profilePublicKeyBytes = decodeBase64(serverProfile.profilePublicKey)
        const identityKeyBytes = decodeBase64(serverProfile.id)
        const isValid = verifyProfileKeySignature(
            profilePublicKeyBytes,
            serverProfile.profileKeySignature,
            identityKeyBytes
        )

        if (!isValid) {
            throw new Error('Invalid profile key signature')
        }

        const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
        const profile = decryptProfile(serverProfile.encryptedProfile, profileSecretKeyBytes)

        const now = Date.now()
        const existing = this.db.getContact(serverProfile.id)
        const storedContact: StoredContact = {
            identityKey: serverProfile.id,
            profilePublicKey: serverProfile.profilePublicKey,
            profileSecretKey,
            encryptedProfile: serverProfile.encryptedProfile,
            addedAt: now,
            updatedAt: serverProfile.profileUpdatedAt ?? now,
            blocked: existing?.blocked ?? false
        }

        this.db.saveContact(storedContact)

        const contact: Contact = {
            ...profile,
            identityKey: serverProfile.id,
            profilePublicKey: serverProfile.profilePublicKey,
            profileSecretKey,
            addedAt: storedContact.addedAt,
            updatedAt: storedContact.updatedAt,
            blocked: storedContact.blocked
        }

        this.emit({ type: 'contact_added', contact })
        return contact
    }

    /**
     * Get or create a contact.
     */
    private async getOrCreateContact(identityKey: string, profileSecretKey?: string): Promise<Contact> {
        const stored = this.db.getContact(identityKey)
        if (stored && stored.profileSecretKey) {
            return this.decryptContact(stored)
        }

        if (profileSecretKey) {
            const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
            const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
            const serverProfile = await this.api.getProfile(profilePublicKey)
            return this.addContactFromProfile(serverProfile, profileSecretKey, identityKey)
        }

        if (stored) {
            return this.decryptContact(stored)
        }

        throw new Error('Contact not found for incoming message')
    }

    /**
     * Build a placeholder contact when profile data is unavailable.
     */
    private buildPlaceholderContact(
        identityKey: string,
        profilePublicKey: string = '',
        addedAt: number = Date.now(),
        updatedAt: number = Date.now(),
        blocked: boolean = false
    ): Contact {
        return {
            identityKey,
            profilePublicKey,
            firstName: identityKey.slice(0, 8),
            addedAt,
            updatedAt,
            blocked
        }
    }

    /**
     * Run message hooks for an incoming or outgoing message.
     */
    private async runMessageHooks(
        payload: HookMessagePayload,
        writeAttachments: (workspace: string) => void
    ): Promise<{ success: boolean; error?: string }> {
        const hooks = this.db.getHooks(MESSAGE_HOOK_TYPE)
        if (hooks.length === 0) {
            return { success: true }
        }

        const workspace = mkdtempSync(join(tmpdir(), 'murmur-message-hook-'))
        try {
            const messagePath = join(workspace, 'message.json')
            writeFileSync(messagePath, JSON.stringify(payload, null, 2))
            writeAttachments(workspace)

            for (const hook of hooks) {
                await this.executeHook(hook, workspace)
            }

            return { success: true }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            return { success: false, error: message }
        } finally {
            rmSync(workspace, { recursive: true, force: true })
        }
    }

    /**
     * Write decrypted attachments into a workspace folder.
     */
    private writeIncomingAttachments(workspace: string, attachments: StoredAttachment[]): void {
        if (attachments.length === 0) {
            return
        }

        const seenNames = new Set<string>()
        for (const attachment of attachments) {
            const fileName = basename(attachment.fileName)
            if (!fileName || fileName === '.' || fileName === '..') {
                throw new Error(`Invalid attachment name: ${attachment.fileName}`)
            }
            if (seenNames.has(fileName)) {
                throw new Error(`Duplicate attachment name: ${fileName}`)
            }
            seenNames.add(fileName)

            const ciphertextBytes = decodeBase64(attachment.ciphertext)
            const keyBytes = decodeBase64(attachment.key)
            const ivBytes = decodeBase64(attachment.iv)
            try {
                const cipher = gcm(keyBytes, ivBytes)
                const plaintext = cipher.decrypt(ciphertextBytes)
                writeFileSync(join(workspace, fileName), plaintext)
            } finally {
                zeroBytes(keyBytes)
                zeroBytes(ivBytes)
            }
        }
    }

    /**
     * Copy outgoing attachments into the workspace folder.
     */
    private copyOutgoingAttachments(workspace: string, attachments: AttachmentSource[]): void {
        for (const attachment of attachments) {
            copyFileSync(attachment.path, join(workspace, attachment.fileName))
        }
    }

    /**
     * Execute a hook command.
     */
    private async executeHook(hook: StoredHook, workspace: string): Promise<void> {
        await new Promise<void>((resolve, reject) => {
            const child = spawn(hook.path, [...hook.args, workspace], {
                stdio: ['ignore', 'pipe', 'pipe']
            })

            let stdout = ''
            let stderr = ''

            child.stdout.on('data', chunk => {
                stdout += chunk.toString()
            })
            child.stderr.on('data', chunk => {
                stderr += chunk.toString()
            })

            child.on('error', error => {
                reject(error)
            })

            child.on('close', (code, signal) => {
                if (code === 0) {
                    resolve()
                    return
                }
                const output = stderr.trim() || stdout.trim()
                const suffix = output ? `: ${output}` : ''
                const detail = signal ? `signal ${signal}` : `code ${code ?? 'unknown'}`
                reject(new Error(`Hook ${hook.id} failed (${detail})${suffix}`))
            })
        })
    }

    /**
     * Send a verification failure notice and acknowledge the message.
     */
    private async handleMessageHookFailure(inboxMessage: InboxMessage, reason?: string): Promise<void> {
        if (!this.agent || !this.account) {
            return
        }

        if (reason) {
            logger.warn(`message hook rejected ${inboxMessage.id}: ${reason}`)
        } else {
            logger.warn(`message hook rejected ${inboxMessage.id}`)
        }

        try {
            await this.sendMessageHookFailureNotice(inboxMessage.senderId)
        } catch (error) {
            logger.warn(`Failed to send message hook failure notice: ${error instanceof Error ? error.message : String(error)}`)
        }

        try {
            await this.api.acknowledgeMessages([inboxMessage.id])
        } catch (error) {
            logger.warn(`Failed to acknowledge rejected message: ${error instanceof Error ? error.message : String(error)}`)
        } finally {
            this.db.saveAgentState(serializeAgent(this.agent))
        }
    }

    /**
     * Send a verification failure notice without persisting a message.
     */
    private async sendMessageHookFailureNotice(recipientIdentityKey: string): Promise<void> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }

        let preKeyBundle: PreKeyBundle | undefined
        if (!hasSession(this.agent, recipientIdentityKey)) {
            preKeyBundle = await this.fetchPreKeyBundle(recipientIdentityKey)
        }

        const payload = {
            text: MESSAGE_HOOK_REPLY,
            profileSecretKey: this.account.profileSecretKey
        }
        const plaintext = stringToBytes(JSON.stringify(payload))
        const messageId = createId()
        const { outgoing } = prepareOutgoingMessage(
            this.agent,
            recipientIdentityKey,
            plaintext,
            messageId,
            preKeyBundle
        )

        await this.api.sendMessage(outgoing.recipientId, outgoing.blob)
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
     * Get unread incoming messages.
     */
    getUnreadMessages(contactIdentityKey?: string): StoredMessage[] {
        return this.db.getUnreadMessages(contactIdentityKey)
    }

    /**
     * Check if a message exists locally.
     */
    hasMessage(messageId: string): boolean {
        return this.db.hasMessage(messageId)
    }

    /**
     * Send a message to a contact.
     */
    async sendMessage(recipientIdentityKey: string, text: string, attachments: string[] = []): Promise<StoredMessage> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }

        const trimmedText = text.trim()
        if (!trimmedText) {
            throw new Error('Message cannot be empty')
        }
        const finalText = truncateMessageText(trimmedText)

        const storedContact = this.db.getContact(recipientIdentityKey)
        if (!storedContact || !storedContact.profileSecretKey) {
            throw new Error('Contact not found. Add contact with `murmur contacts add <id>` first.')
        }
        if (storedContact.blocked) {
            throw new Error('Contact is blocked.')
        }

        const messageId = createId()
        const attachmentSources = attachments.length > 0 ? collectAttachmentSources(attachments) : []

        const hookPayload: HookMessagePayload = {
            id: messageId,
            out: true,
            from: formatProfileSecretKeyForHook(this.account.profileSecretKey),
            to: formatProfileSecretKeyForHook(storedContact.profileSecretKey),
            text: finalText,
            attachments: attachmentSources.map(entry => entry.fileName)
        }
        const hookResult = await this.runMessageHooks(hookPayload, workspace => {
            this.copyOutgoingAttachments(workspace, attachmentSources)
        })
        if (!hookResult.success) {
            const reason = hookResult.error ? `: ${hookResult.error}` : ''
            throw new Error(`Message hook rejected outgoing message${reason}`)
        }

        const attachmentData = attachmentSources.length > 0 ? createOutgoingAttachments(attachmentSources) : undefined

        let preKeyBundle: PreKeyBundle | undefined
        if (!hasSession(this.agent, recipientIdentityKey)) {
            preKeyBundle = await this.fetchPreKeyBundle(recipientIdentityKey)
        }

        // Encrypt the message
        const payload: { text: string; profileSecretKey: string; attachments?: AttachmentPayload } = {
            text: finalText,
            profileSecretKey: this.account.profileSecretKey
        }
        if (attachmentData) {
            payload.attachments = attachmentData.payload
        }
        const plaintext = stringToBytes(JSON.stringify(payload))
        const { outgoing } = prepareOutgoingMessage(
            this.agent,
            recipientIdentityKey,
            plaintext,
            messageId,
            preKeyBundle,
            attachmentData?.attachmentMap
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
            text: finalText,
            createdAt: serverResult.createdAt,
            read: true
        }
        if (attachmentData && attachmentData.stored.length > 0) {
            storedMessage.attachments = attachmentData.stored
        }

        this.db.saveMessage(storedMessage)

        return storedMessage
    }

    /**
     * Process an incoming message from the server.
     */
    private async processIncomingServerMessage(inboxMessage: InboxMessage): Promise<StoredMessage | null> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }
        const account = this.account

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

            const rawPayload = bytesToString(decrypted.plaintext).trim()
            let text = rawPayload
            let profileSecretKey: string | undefined
            let payloadAttachments: AttachmentPayload | undefined

            try {
                const parsed = JSON.parse(rawPayload) as {
                    text?: unknown
                    profileSecretKey?: unknown
                    attachments?: unknown
                }
                if (parsed && typeof parsed === 'object') {
                    if (typeof parsed.text === 'string') {
                        text = parsed.text.trim()
                    }
                    if (typeof parsed.profileSecretKey === 'string' && parsed.profileSecretKey.trim().length > 0) {
                        profileSecretKey = parsed.profileSecretKey.trim()
                    }
                    payloadAttachments = parseAttachmentPayload(parsed.attachments)
                }
            } catch {
                // Treat as legacy plaintext.
            }
            const hookText = text
            const storedText = truncateMessageText(hookText)

            if (!profileSecretKey) {
                this.emit({ type: 'error', error: 'Missing profile secret key for incoming contact' })
                return null
            }

            const profileSecretKeyBytes = decodeBase64(profileSecretKey, 'base64url')
            const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
            const existingContact = this.db.getContactByProfilePublicKey(profilePublicKey)
            if (existingContact?.blocked) {
                logger.info(`Ignored message from blocked contact: ${inboxMessage.id}`)
                await this.api.acknowledgeMessages([inboxMessage.id])
                return null
            }
            if (!this.getDefaultAllow() && !existingContact) {
                logger.info(`Ignored message from unknown contact: ${inboxMessage.id}`)
                await this.api.acknowledgeMessages([inboxMessage.id])
                return null
            }

            const attachmentResult = buildStoredAttachments(payloadAttachments, decrypted.attachments)
            if (attachmentResult.invalid) {
                this.emit({ type: 'error', error: 'Incoming attachments failed validation or decryption' })
                return null
            }

            const hookPayload: HookMessagePayload = {
                id: inboxMessage.id,
                out: false,
                from: formatProfileSecretKeyForHook(profileSecretKey),
                to: formatProfileSecretKeyForHook(account.profileSecretKey),
                text: hookText,
                attachments: attachmentResult.stored.map(entry => entry.fileName)
            }
            const hookResult = await this.runMessageHooks(hookPayload, workspace => {
                this.writeIncomingAttachments(workspace, attachmentResult.stored)
            })
            if (!hookResult.success) {
                await this.handleMessageHookFailure(inboxMessage, hookResult.error)
                return null
            }

            let contact: Contact
            try {
                const serverProfile = await this.api.getProfile(profilePublicKey)
                contact = this.addContactFromProfile(serverProfile, profileSecretKey, inboxMessage.senderId)
            } catch (error) {
                this.emit({
                    type: 'error',
                    error: `Failed to fetch profile for incoming message: ${error instanceof Error ? error.message : String(error)}`
                })
                return null
            }

            // Save message
            const storedMessage: StoredMessage = {
                id: inboxMessage.id,
                conversationId: inboxMessage.senderId,
                isOutgoing: false,
                text: storedText,
                createdAt: inboxMessage.createdAt,
                read: false
            }

            if (attachmentResult.stored.length > 0) {
                storedMessage.attachments = attachmentResult.stored
            }

            this.db.saveMessage(storedMessage)

            // Emit event
            this.emit({ type: 'message', message: storedMessage, contact })

            return storedMessage
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            logger.error({ error }, 'Failed to process message')
            this.emit({ type: 'error', error: `Failed to process message: ${message}` })
            return null
        }
    }

    /**
     * Sync messages from the server.
     */
    async sync(): Promise<{ success: boolean; error?: string; newMessages: StoredMessage[] }> {
        if (!this.agent || !this.account) {
            return { success: false, error: 'Not initialized', newMessages: [] }
        }
        if (!this.api.getTokens()) {
            const reason = this.authError ? `Not authenticated: ${this.authError}` : 'Not authenticated'
            return { success: false, error: reason, newMessages: [] }
        }

        try {
            let cursor: string | undefined
            let hasMore = true
            const processedIds: string[] = []
            const newMessages: StoredMessage[] = []

            while (hasMore) {
                const result = await this.api.getInbox(50, cursor)

                for (const msg of result.messages) {
                    if (this.db.hasMessage(msg.id)) {
                        processedIds.push(msg.id)
                        continue
                    }
                    const stored = await this.processIncomingServerMessage(msg)
                    if (stored) {
                        processedIds.push(msg.id)
                        newMessages.push(stored)
                    }
                }

                cursor = result.nextCursor ?? undefined
                hasMore = result.hasMore
            }

            if (processedIds.length > 0) {
                await this.api.acknowledgeMessages(processedIds)
            }

            this.emit({ type: 'sync_complete' })
            return { success: true, newMessages }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            this.emit({ type: 'error', error: `Sync failed: ${message}` })
            return { success: false, error: message, newMessages: [] }
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
     * Mark messages as read locally.
     */
    async acknowledgeMessages(messageIds: string[]): Promise<void> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }
        if (messageIds.length === 0) {
            return
        }

        this.db.markMessagesReadById(messageIds)
    }

    /**
     * Listen for server-sent message notifications.
     */
    async streamMessages(
        onEvent: (event: { event: string; data: unknown }) => void | Promise<void>,
        options?: { signal?: AbortSignal }
    ): Promise<void> {
        if (!this.agent || !this.account) {
            throw new Error('Not initialized')
        }
        if (!this.api.getTokens()) {
            const reason = this.authError ? `Not authenticated: ${this.authError}` : 'Not authenticated'
            throw new Error(reason)
        }
        await this.api.streamMessages(onEvent, options)
    }

    /**
     * Save a stored attachment to disk.
     */
    saveAttachmentToPath(messageId: string, fileName: string, outputPath: string): void {
        const attachment = this.db.getAttachment(messageId, fileName)
        if (!attachment) {
            throw new Error('Attachment not found in local storage.')
        }

        const ciphertextBytes = decodeBase64(attachment.ciphertext)
        const computedHash = bytesToHex(sha256(ciphertextBytes))
        if (computedHash !== attachment.hash) {
            throw new Error('Attachment hash mismatch. Data may be corrupted.')
        }

        const key = decodeBase64(attachment.key)
        const iv = decodeBase64(attachment.iv)
        const cipher = gcm(key, iv)
        const plaintext = cipher.decrypt(ciphertextBytes)

        writeFileSync(outputPath, plaintext)
    }

    /**
     * Close the engine and release resources.
     */
    close(): void {
        this.stopSync()
        this.db.close()
    }
}
