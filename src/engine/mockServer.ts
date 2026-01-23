/**
 * Mock server for testing Murmur without a real backend.
 *
 * Simulates the server API for local testing of all chat mechanisms.
 */

import { createId } from '@paralleldrive/cuid2'
import type { InboxMessage, ServerProfile, AuthTokens } from './api.js'

/**
 * Prekey bundle stored in mock server.
 */
interface MockPreKeyBundle {
    identityKey: string
    signedPreKey: string
    signedPreKeyId: number
    signedPreKeySignature: string
    oneTimePreKeys: Array<{ id: number; key: string }>
}

/**
 * User stored in mock server.
 */
interface MockUser {
    identityPublicKey: string
    profilePublicKey: string
    profileKeySignature: string
    encryptedProfile: string
    createdAt: number
    refreshToken: string
    preKeyBundle?: MockPreKeyBundle
}

/**
 * Message stored in mock server.
 */
interface MockMessage {
    id: string
    senderId: string
    recipientId: string
    blob: string
    signature: string
    createdAt: number
    expiresAt: number
    acknowledged: boolean
}

/**
 * Mock server for testing.
 */
export class MockServer {
    private users: Map<string, MockUser> = new Map()
    private messages: Map<string, MockMessage> = new Map()
    private accessTokens: Map<string, string> = new Map() // token -> userId
    private tokenCounter: number = 0
    private messageCounter: number = 0 // For unique timestamps in tests

    /**
     * Generate a mock access token.
     */
    private generateAccessToken(): string {
        return `mock-access-token-${++this.tokenCounter}`
    }

    /**
     * Generate a mock refresh token.
     */
    private generateRefreshToken(): string {
        return `mock-refresh-token-${++this.tokenCounter}`
    }

    /**
     * Register a new user.
     */
    register(
        identityPublicKey: string,
        profilePublicKey: string,
        profileKeySignature: string,
        encryptedProfile: string
    ): { tokens: AuthTokens; user: { id: string; createdAt: number } } {
        // Check if already exists
        const existing = this.users.get(identityPublicKey)
        if (existing) {
            // Return success for idempotency
            const accessToken = this.generateAccessToken()
            this.accessTokens.set(accessToken, identityPublicKey)
            return {
                tokens: {
                    accessToken,
                    refreshToken: existing.refreshToken
                },
                user: {
                    id: identityPublicKey,
                    createdAt: existing.createdAt
                }
            }
        }

        const createdAt = Date.now()
        const refreshToken = this.generateRefreshToken()
        const accessToken = this.generateAccessToken()

        this.users.set(identityPublicKey, {
            identityPublicKey,
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            createdAt,
            refreshToken
        })

        this.accessTokens.set(accessToken, identityPublicKey)

        return {
            tokens: { accessToken, refreshToken },
            user: { id: identityPublicKey, createdAt }
        }
    }

    /**
     * Login an existing user.
     */
    login(identityPublicKey: string): { tokens: AuthTokens; user: { id: string; createdAt: number } } {
        const user = this.users.get(identityPublicKey)
        if (!user) {
            throw new Error('User not found')
        }

        const accessToken = this.generateAccessToken()
        this.accessTokens.set(accessToken, identityPublicKey)

        return {
            tokens: {
                accessToken,
                refreshToken: user.refreshToken
            },
            user: {
                id: identityPublicKey,
                createdAt: user.createdAt
            }
        }
    }

    /**
     * Refresh access token.
     */
    refresh(refreshToken: string): string {
        // Find user with this refresh token
        for (const user of this.users.values()) {
            if (user.refreshToken === refreshToken) {
                const accessToken = this.generateAccessToken()
                this.accessTokens.set(accessToken, user.identityPublicKey)
                return accessToken
            }
        }
        throw new Error('Invalid refresh token')
    }

    /**
     * Verify access token and get user ID.
     */
    private verifyToken(accessToken: string): string {
        const userId = this.accessTokens.get(accessToken)
        if (!userId) {
            throw new Error('Invalid access token')
        }
        return userId
    }

    /**
     * Send a message.
     */
    sendMessage(
        accessToken: string,
        messageId: string,
        recipientId: string,
        blob: string,
        signature: string
    ): { id: string; createdAt: number; expiresAt: number } {
        const senderId = this.verifyToken(accessToken)

        if (!this.users.has(recipientId)) {
            throw new Error('Recipient not found')
        }

        if (this.messages.has(messageId)) {
            throw new Error('Message ID already exists')
        }

        // Use counter to ensure unique timestamps even in rapid succession
        const createdAt = Date.now() + this.messageCounter++
        const expiresAt = createdAt + 30 * 24 * 60 * 60 * 1000 // 30 days

        this.messages.set(messageId, {
            id: messageId,
            senderId,
            recipientId,
            blob,
            signature,
            createdAt,
            expiresAt,
            acknowledged: false
        })

        return { id: messageId, createdAt, expiresAt }
    }

    /**
     * Get inbox messages.
     */
    getInbox(
        accessToken: string,
        limit: number = 50,
        cursor?: string
    ): { messages: InboxMessage[]; nextCursor: string | null; hasMore: boolean } {
        const userId = this.verifyToken(accessToken)

        // Get unacknowledged messages for this user
        const userMessages: MockMessage[] = []
        for (const msg of this.messages.values()) {
            if (msg.recipientId === userId && !msg.acknowledged) {
                userMessages.push(msg)
            }
        }

        // Sort by createdAt ascending
        userMessages.sort((a, b) => a.createdAt - b.createdAt)

        // Apply cursor (skip messages at or before cursor time)
        let startIndex = 0
        if (cursor) {
            const cursorTime = parseInt(cursor, 10)
            // Find first message with createdAt > cursorTime
            for (let i = 0; i < userMessages.length; i++) {
                if (userMessages[i].createdAt > cursorTime) {
                    startIndex = i
                    break
                }
                startIndex = userMessages.length // No messages after cursor
            }
        }

        const sliced = userMessages.slice(startIndex, startIndex + limit)
        const hasMore = startIndex + sliced.length < userMessages.length
        const nextCursor = sliced.length > 0
            ? String(sliced[sliced.length - 1].createdAt)
            : null

        return {
            messages: sliced.map(m => ({
                id: m.id,
                senderId: m.senderId,
                blob: m.blob,
                signature: m.signature,
                createdAt: m.createdAt,
                expiresAt: m.expiresAt
            })),
            nextCursor,
            hasMore
        }
    }

    /**
     * Acknowledge messages.
     */
    acknowledgeMessages(
        accessToken: string,
        messageIds: string[]
    ): { acknowledged: number; failed: Array<{ messageId: string; error: string }> } {
        const userId = this.verifyToken(accessToken)

        let acknowledged = 0
        const failed: Array<{ messageId: string; error: string }> = []

        for (const messageId of messageIds) {
            const msg = this.messages.get(messageId)
            if (!msg) {
                failed.push({ messageId, error: 'Message not found' })
            } else if (msg.recipientId !== userId) {
                failed.push({ messageId, error: 'Not your message' })
            } else {
                msg.acknowledged = true
                acknowledged++
            }
        }

        return { acknowledged, failed }
    }

    /**
     * Get profile.
     */
    getProfile(accessToken: string, identityPublicKey: string): ServerProfile {
        this.verifyToken(accessToken)

        const user = this.users.get(identityPublicKey)
        if (!user) {
            throw new Error('User not found')
        }

        return {
            id: identityPublicKey,
            profilePublicKey: user.profilePublicKey,
            profileKeySignature: user.profileKeySignature,
            encryptedProfile: user.encryptedProfile,
            profileUpdatedAt: user.createdAt
        }
    }

    /**
     * Get own profile.
     */
    getMyProfile(accessToken: string): ServerProfile & { createdAt: number } {
        const userId = this.verifyToken(accessToken)
        const user = this.users.get(userId)!

        return {
            id: userId,
            profilePublicKey: user.profilePublicKey,
            profileKeySignature: user.profileKeySignature,
            encryptedProfile: user.encryptedProfile,
            profileUpdatedAt: user.createdAt,
            createdAt: user.createdAt
        }
    }

    /**
     * Update profile.
     */
    updateProfile(
        accessToken: string,
        profilePublicKey: string,
        profileKeySignature: string,
        encryptedProfile: string
    ): void {
        const userId = this.verifyToken(accessToken)
        const user = this.users.get(userId)!

        user.profilePublicKey = profilePublicKey
        user.profileKeySignature = profileKeySignature
        user.encryptedProfile = encryptedProfile
    }

    /**
     * Upload prekey bundle.
     */
    uploadPreKeyBundle(
        accessToken: string,
        identityKey: string,
        signedPreKey: string,
        signedPreKeyId: number,
        signedPreKeySignature: string,
        oneTimePreKeys: Array<{ id: number; key: string }>
    ): void {
        const userId = this.verifyToken(accessToken)
        const user = this.users.get(userId)!

        user.preKeyBundle = {
            identityKey,
            signedPreKey,
            signedPreKeyId,
            signedPreKeySignature,
            oneTimePreKeys: [...oneTimePreKeys]
        }
    }

    /**
     * Get prekey bundle for a user.
     * Consumes one one-time prekey if available.
     */
    getPreKeyBundle(
        accessToken: string,
        identityPublicKey: string
    ): {
        identityKey: string
        signedPreKey: string
        signedPreKeyId: number
        signedPreKeySignature: string
        oneTimePreKey?: string
        oneTimePreKeyId?: number
    } {
        this.verifyToken(accessToken)

        const user = this.users.get(identityPublicKey)
        if (!user) {
            throw new Error('User not found')
        }

        if (!user.preKeyBundle) {
            throw new Error('No prekey bundle available')
        }

        const bundle = user.preKeyBundle
        let oneTimePreKey: string | undefined
        let oneTimePreKeyId: number | undefined

        // Consume one one-time prekey if available
        if (bundle.oneTimePreKeys.length > 0) {
            const otpk = bundle.oneTimePreKeys.shift()!
            oneTimePreKey = otpk.key
            oneTimePreKeyId = otpk.id
        }

        return {
            identityKey: bundle.identityKey,
            signedPreKey: bundle.signedPreKey,
            signedPreKeyId: bundle.signedPreKeyId,
            signedPreKeySignature: bundle.signedPreKeySignature,
            oneTimePreKey,
            oneTimePreKeyId
        }
    }

    /**
     * Clear all data.
     */
    reset(): void {
        this.users.clear()
        this.messages.clear()
        this.accessTokens.clear()
        this.tokenCounter = 0
        this.messageCounter = 0
    }

    /**
     * Get user count (for testing).
     */
    getUserCount(): number {
        return this.users.size
    }

    /**
     * Get message count (for testing).
     */
    getMessageCount(): number {
        return this.messages.size
    }
}

/**
 * Create a mock API client that uses the mock server.
 */
export function createMockApi(server: MockServer) {
    let accessToken: string | null = null
    let refreshToken: string | null = null

    return {
        async register(
            identityPublicKey: string,
            _identityPrivateKey: Uint8Array,
            profilePublicKey: string,
            profileKeySignature: string,
            encryptedProfile: string
        ) {
            const result = server.register(
                identityPublicKey,
                profilePublicKey,
                profileKeySignature,
                encryptedProfile
            )
            accessToken = result.tokens.accessToken
            refreshToken = result.tokens.refreshToken
            return result
        },

        async login(identityPublicKey: string, _identityPrivateKey: Uint8Array) {
            const result = server.login(identityPublicKey)
            accessToken = result.tokens.accessToken
            refreshToken = result.tokens.refreshToken
            return result
        },

        async refresh() {
            if (!refreshToken) throw new Error('No refresh token')
            accessToken = server.refresh(refreshToken)
            return accessToken
        },

        async sendMessage(recipientId: string, blob: string) {
            if (!accessToken) throw new Error('Not authenticated')
            const messageId = createId()
            return server.sendMessage(accessToken, messageId, recipientId, blob, 'mock-signature')
        },

        async getInbox(limit?: number, cursor?: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getInbox(accessToken, limit, cursor)
        },

        async acknowledgeMessages(messageIds: string[]) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.acknowledgeMessages(accessToken, messageIds)
        },

        async getProfile(identityPublicKey: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getProfile(accessToken, identityPublicKey)
        },

        async getMyProfile() {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getMyProfile(accessToken)
        },

        async updateProfile(
            profilePublicKey: string,
            profileKeySignature: string,
            encryptedProfile: string
        ) {
            if (!accessToken) throw new Error('Not authenticated')
            server.updateProfile(accessToken, profilePublicKey, profileKeySignature, encryptedProfile)
        },

        async uploadPreKeyBundle(
            identityKey: string,
            signedPreKey: string,
            signedPreKeyId: number,
            signedPreKeySignature: string,
            oneTimePreKeys: Array<{ id: number; key: string }>
        ) {
            if (!accessToken) throw new Error('Not authenticated')
            server.uploadPreKeyBundle(
                accessToken,
                identityKey,
                signedPreKey,
                signedPreKeyId,
                signedPreKeySignature,
                oneTimePreKeys
            )
        },

        async getPreKeyBundle(identityPublicKey: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getPreKeyBundle(accessToken, identityPublicKey)
        },

        getTokens() {
            if (!accessToken || !refreshToken) return null
            return { accessToken, refreshToken }
        },

        setCredentials(_key: Uint8Array, at: string, rt: string) {
            accessToken = at
            refreshToken = rt
        }
    }
}
