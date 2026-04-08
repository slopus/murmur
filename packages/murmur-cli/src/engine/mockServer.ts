/**
 * Mock server for testing Murmur without a real backend.
 *
 * Simulates the server API for local testing of all chat mechanisms.
 */

import type {
    FeedKeyRecord,
    FeedTimelineItem,
    FollowedFeedRecord,
    InboxMessage,
    OwnedFeedRecord,
    ServerProfile,
    AuthTokens
} from './api.js'

/**
 * Prekey stored in mock server.
 */
interface MockPreKey {
    publicKey: string
    signature: string
    oneTime: boolean
    createdAt: number
    allocated: boolean
}

/**
 * Prekey data stored for a user.
 */
interface MockPreKeyData {
    signedPreKey: MockPreKey | null
    oneTimePreKeys: MockPreKey[]
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
    preKeyData?: MockPreKeyData
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

interface MockFeedMemberKey {
    epoch: number
    encryptedKey: string
}

interface MockFeedItem {
    itemId: string
    feedId: string
    authorId: string
    epoch: number
    blob: string
    signature: string
    createdAt: number
}

interface MockFeed {
    id: string
    ownerId: string
    metadata: string
    currentEpoch: number
    createdAt: number
    updatedAt: number
    members: Map<string, MockFeedMemberKey[]>
    items: Map<string, MockFeedItem>
}

/**
 * Mock server for testing.
 */
export class MockServer {
    private users: Map<string, MockUser> = new Map()
    private messages: Map<string, MockMessage> = new Map()
    private feeds: Map<string, MockFeed> = new Map()
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
     * Delete a user account.
     */
    deleteAccount(accessToken: string): void {
        const userId = this.verifyToken(accessToken)
        this.users.delete(userId)

        for (const [token, ownerId] of Array.from(this.accessTokens.entries())) {
            if (ownerId === userId) {
                this.accessTokens.delete(token)
            }
        }

        for (const [messageId, message] of Array.from(this.messages.entries())) {
            if (message.senderId === userId || message.recipientId === userId) {
                this.messages.delete(messageId)
            }
        }

        for (const [feedId, feed] of Array.from(this.feeds.entries())) {
            if (feed.ownerId === userId) {
                this.feeds.delete(feedId)
                continue
            }
            feed.members.delete(userId)
            if (feed.members.size === 0 && feed.items.size === 0) {
                this.feeds.set(feedId, feed)
            }
        }
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
     * Get profile by profile public key.
     */
    getProfile(accessToken: string, profilePublicKey: string): ServerProfile {
        this.verifyToken(accessToken)

        let matched: MockUser | undefined
        for (const user of this.users.values()) {
            if (user.profilePublicKey === profilePublicKey) {
                matched = user
                break
            }
        }

        if (!matched) {
            throw new Error('User not found')
        }

        return {
            id: matched.identityPublicKey,
            profilePublicKey: matched.profilePublicKey,
            profileKeySignature: matched.profileKeySignature,
            encryptedProfile: matched.encryptedProfile,
            profileUpdatedAt: matched.createdAt
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
     * Upload prekeys.
     */
    uploadPreKeys(
        accessToken: string,
        preKeys: Array<{ publicKey: string; signature: string; oneTime: boolean }>
    ): { uploaded: number } {
        const userId = this.verifyToken(accessToken)
        const user = this.users.get(userId)!

        if (!user.preKeyData) {
            user.preKeyData = { signedPreKey: null, oneTimePreKeys: [] }
        }

        const now = Date.now()
        for (const pk of preKeys) {
            const mockPreKey: MockPreKey = {
                publicKey: pk.publicKey,
                signature: pk.signature,
                oneTime: pk.oneTime,
                createdAt: now,
                allocated: false
            }

            if (pk.oneTime) {
                user.preKeyData.oneTimePreKeys.push(mockPreKey)
            } else {
                // Replace signed prekey
                user.preKeyData.signedPreKey = mockPreKey
            }
        }

        return { uploaded: preKeys.length }
    }

    /**
     * Get prekey bundle for a user.
     * Allocates one one-time prekey if available.
     */
    getPreKeyBundle(
        accessToken: string,
        identityPublicKey: string
    ): {
        identityKey: string
        signedPreKey: {
            publicKey: string
            signature: string
            createdAt: number
        }
        oneTimePreKey: {
            publicKey: string
            signature: string
        } | null
    } {
        this.verifyToken(accessToken)

        const user = this.users.get(identityPublicKey)
        if (!user) {
            throw new Error('User not found')
        }

        if (!user.preKeyData || !user.preKeyData.signedPreKey) {
            throw new Error('No prekey bundle available')
        }

        const signedPreKey = user.preKeyData.signedPreKey
        let oneTimePreKey: { publicKey: string; signature: string } | null = null

        // Find and allocate one unallocated one-time prekey
        for (const otpk of user.preKeyData.oneTimePreKeys) {
            if (!otpk.allocated) {
                otpk.allocated = true
                oneTimePreKey = {
                    publicKey: otpk.publicKey,
                    signature: otpk.signature
                }
                break
            }
        }

        return {
            identityKey: identityPublicKey,
            signedPreKey: {
                publicKey: signedPreKey.publicKey,
                signature: signedPreKey.signature,
                createdAt: signedPreKey.createdAt
            },
            oneTimePreKey
        }
    }

    /**
     * Get unallocated one-time prekey count.
     */
    getOneTimePreKeyCount(accessToken: string): number {
        const userId = this.verifyToken(accessToken)
        const user = this.users.get(userId)!

        if (!user.preKeyData) {
            return 0
        }

        return user.preKeyData.oneTimePreKeys.filter(pk => !pk.allocated).length
    }

    createFeed(accessToken: string, feedId: string, metadata: string): { feedId: string; createdAt: number } {
        const ownerId = this.verifyToken(accessToken)
        if (this.feeds.has(feedId)) {
            throw new Error('Feed ID already exists')
        }

        const createdAt = Date.now() + this.messageCounter++
        this.feeds.set(feedId, {
            id: feedId,
            ownerId,
            metadata,
            currentEpoch: 0,
            createdAt,
            updatedAt: createdAt,
            members: new Map(),
            items: new Map()
        })

        return { feedId, createdAt }
    }

    updateFeed(accessToken: string, feedId: string, metadata: string): { feedId: string; updatedAt: number } {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }

        feed.metadata = metadata
        feed.updatedAt = Date.now() + this.messageCounter++
        return { feedId, updatedAt: feed.updatedAt }
    }

    deleteFeed(accessToken: string, feedId: string): void {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }
        this.feeds.delete(feedId)
    }

    getOwnedFeeds(accessToken: string): OwnedFeedRecord[] {
        const ownerId = this.verifyToken(accessToken)
        return Array.from(this.feeds.values())
            .filter(feed => feed.ownerId === ownerId)
            .sort((a, b) => b.updatedAt - a.updatedAt)
            .map(feed => ({
                feedId: feed.id,
                metadata: feed.metadata,
                epoch: feed.currentEpoch,
                createdAt: feed.createdAt,
                updatedAt: feed.updatedAt
            }))
    }

    addFeedMembers(
        accessToken: string,
        feedId: string,
        epoch: number,
        members: Array<{ memberId: string; encryptedKey: string }>
    ): { added: number } {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }
        if (epoch !== feed.currentEpoch) {
            throw new Error(`Epoch mismatch. Current epoch is ${feed.currentEpoch}`)
        }

        let added = 0
        for (const member of members) {
            if (!this.users.has(member.memberId)) {
                throw new Error('One or more feed members were not found')
            }
            const keys = feed.members.get(member.memberId) ?? []
            if (!keys.some(entry => entry.epoch === epoch)) {
                keys.push({ epoch, encryptedKey: member.encryptedKey })
                feed.members.set(member.memberId, keys)
                added += 1
            }
        }
        feed.updatedAt = Date.now() + this.messageCounter++
        return { added }
    }

    removeFeedMembers(accessToken: string, feedId: string, memberIds: string[]): { removed: number } {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }

        let removed = 0
        for (const memberId of memberIds) {
            if (feed.members.delete(memberId)) {
                removed += 1
            }
        }
        feed.updatedAt = Date.now() + this.messageCounter++
        return { removed }
    }

    rotateFeedKeys(
        accessToken: string,
        feedId: string,
        epoch: number,
        members: Array<{ memberId: string; encryptedKey: string }>
    ): { epoch: number } {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }
        if (epoch !== feed.currentEpoch + 1) {
            throw new Error(`Epoch must advance to ${feed.currentEpoch + 1}`)
        }

        const activeMembers = Array.from(feed.members.keys()).sort()
        const providedMembers = Array.from(new Set(members.map(member => member.memberId))).sort()
        if (activeMembers.length !== providedMembers.length || activeMembers.some((memberId, index) => memberId !== providedMembers[index])) {
            throw new Error('Rotation members must match the current feed membership')
        }

        for (const member of members) {
            const keys = feed.members.get(member.memberId) ?? []
            keys.push({ epoch, encryptedKey: member.encryptedKey })
            feed.members.set(member.memberId, keys)
        }
        feed.currentEpoch = epoch
        feed.updatedAt = Date.now() + this.messageCounter++
        return { epoch }
    }

    postFeedItem(
        accessToken: string,
        feedId: string,
        itemId: string,
        epoch: number,
        blob: string,
        signature: string
    ): { itemId: string; createdAt: number } {
        const authorId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== authorId) {
            throw new Error('Not authorized for this feed')
        }
        if (epoch !== feed.currentEpoch) {
            throw new Error(`Epoch mismatch. Current epoch is ${feed.currentEpoch}`)
        }
        if (feed.items.has(itemId)) {
            throw new Error('Feed item ID already exists')
        }

        const createdAt = Date.now() + this.messageCounter++
        feed.items.set(itemId, {
            itemId,
            feedId,
            authorId,
            epoch,
            blob,
            signature,
            createdAt
        })
        feed.updatedAt = createdAt
        return { itemId, createdAt }
    }

    deleteFeedItem(accessToken: string, feedId: string, itemId: string): void {
        const ownerId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== ownerId) {
            throw new Error('Not authorized for this feed')
        }
        if (!feed.items.delete(itemId)) {
            throw new Error('Feed item not found')
        }
    }

    getFollowedFeeds(accessToken: string): FollowedFeedRecord[] {
        const memberId = this.verifyToken(accessToken)
        return Array.from(this.feeds.values())
            .filter(feed => feed.members.has(memberId))
            .map(feed => ({
                feedId: feed.id,
                ownerId: feed.ownerId,
                epoch: feed.currentEpoch
            }))
    }

    getFeedKeys(accessToken: string): FeedKeyRecord[] {
        const memberId = this.verifyToken(accessToken)
        return Array.from(this.feeds.values())
            .flatMap(feed => (feed.members.get(memberId) ?? []).map(entry => ({
                feedId: feed.id,
                epoch: entry.epoch,
                encryptedKey: entry.encryptedKey
            })))
            .sort((a, b) => a.feedId.localeCompare(b.feedId) || a.epoch - b.epoch)
    }

    getFeedTimeline(
        accessToken: string,
        limit: number = 50,
        cursor?: string
    ): { items: FeedTimelineItem[]; nextCursor: string | null; hasMore: boolean } {
        const userId = this.verifyToken(accessToken)
        const cursorTime = cursor ? Number.parseInt(Buffer.from(cursor, 'base64').toString('utf-8'), 10) : undefined
        const items = Array.from(this.feeds.values())
            .filter(feed => feed.ownerId === userId || feed.members.has(userId))
            .flatMap(feed => Array.from(feed.items.values()))
            .filter(item => cursorTime === undefined || item.createdAt < cursorTime)
            .sort((a, b) => b.createdAt - a.createdAt || b.itemId.localeCompare(a.itemId))

        const page = items.slice(0, limit)
        const hasMore = items.length > limit
        const nextCursor = hasMore && page.length > 0
            ? Buffer.from(String(page[page.length - 1].createdAt), 'utf-8').toString('base64')
            : null

        return {
            items: page.map(item => ({
                feedId: item.feedId,
                itemId: item.itemId,
                authorId: item.authorId,
                epoch: item.epoch,
                blob: item.blob,
                signature: item.signature,
                createdAt: item.createdAt
            })),
            nextCursor,
            hasMore
        }
    }

    getFeedItems(
        accessToken: string,
        feedId: string,
        limit: number = 50,
        cursor?: string
    ): { items: FeedTimelineItem[]; nextCursor: string | null; hasMore: boolean } {
        const userId = this.verifyToken(accessToken)
        const feed = this.feeds.get(feedId)
        if (!feed) {
            throw new Error('Feed not found')
        }
        if (feed.ownerId !== userId && !feed.members.has(userId)) {
            throw new Error('Not authorized for this feed')
        }

        const cursorTime = cursor ? Number.parseInt(Buffer.from(cursor, 'base64').toString('utf-8'), 10) : undefined
        const items = Array.from(feed.items.values())
            .filter(item => cursorTime === undefined || item.createdAt < cursorTime)
            .sort((a, b) => b.createdAt - a.createdAt || b.itemId.localeCompare(a.itemId))
        const page = items.slice(0, limit)
        const hasMore = items.length > limit
        const nextCursor = hasMore && page.length > 0
            ? Buffer.from(String(page[page.length - 1].createdAt), 'utf-8').toString('base64')
            : null

        return {
            items: page.map(item => ({
                feedId: item.feedId,
                itemId: item.itemId,
                authorId: item.authorId,
                epoch: item.epoch,
                blob: item.blob,
                signature: item.signature,
                createdAt: item.createdAt
            })),
            nextCursor,
            hasMore
        }
    }

    /**
     * Clear all data.
     */
    reset(): void {
        this.users.clear()
        this.messages.clear()
        this.feeds.clear()
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

        async deleteAccount() {
            if (!accessToken) throw new Error('Not authenticated')
            server.deleteAccount(accessToken)
            accessToken = null
            refreshToken = null
        },

        async sendMessage(recipientId: string, blob: string, messageId: string) {
            if (!accessToken) throw new Error('Not authenticated')
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

        async getProfile(profilePublicKey: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getProfile(accessToken, profilePublicKey)
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

        async uploadPreKeys(
            preKeys: Array<{ publicKey: string; signature: string; oneTime: boolean }>
        ) {
            if (!accessToken) throw new Error('Not authenticated')
            server.uploadPreKeys(accessToken, preKeys)
        },

        async getPreKeyBundle(identityPublicKey: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getPreKeyBundle(accessToken, identityPublicKey)
        },

        async getOneTimePreKeyCount() {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getOneTimePreKeyCount(accessToken)
        },

        getTokens() {
            if (!accessToken || !refreshToken) return null
            return { accessToken, refreshToken }
        },

        async createFeed(feedId: string, metadata: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.createFeed(accessToken, feedId, metadata)
        },

        async updateFeed(feedId: string, metadata: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.updateFeed(accessToken, feedId, metadata)
        },

        async deleteFeed(feedId: string) {
            if (!accessToken) throw new Error('Not authenticated')
            server.deleteFeed(accessToken, feedId)
        },

        async getOwnedFeeds() {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getOwnedFeeds(accessToken)
        },

        async addFeedMembers(feedId: string, epoch: number, members: Array<{ memberId: string; encryptedKey: string }>) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.addFeedMembers(accessToken, feedId, epoch, members).added
        },

        async removeFeedMembers(feedId: string, memberIds: string[]) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.removeFeedMembers(accessToken, feedId, memberIds).removed
        },

        async rotateFeedKeys(feedId: string, epoch: number, members: Array<{ memberId: string; encryptedKey: string }>) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.rotateFeedKeys(accessToken, feedId, epoch, members).epoch
        },

        async postFeedItem(feedId: string, itemId: string, epoch: number, blob: string, signature: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.postFeedItem(accessToken, feedId, itemId, epoch, blob, signature)
        },

        async deleteFeedItem(feedId: string, itemId: string) {
            if (!accessToken) throw new Error('Not authenticated')
            server.deleteFeedItem(accessToken, feedId, itemId)
        },

        async getFollowedFeeds() {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getFollowedFeeds(accessToken)
        },

        async getFeedKeys() {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getFeedKeys(accessToken)
        },

        async getFeedTimeline(limit?: number, cursor?: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getFeedTimeline(accessToken, limit, cursor)
        },

        async getFeedItems(feedId: string, limit?: number, cursor?: string) {
            if (!accessToken) throw new Error('Not authenticated')
            return server.getFeedItems(accessToken, feedId, limit, cursor)
        },

        setCredentials(_key: Uint8Array, at: string, rt: string) {
            accessToken = at
            refreshToken = rt
        }
    }
}
