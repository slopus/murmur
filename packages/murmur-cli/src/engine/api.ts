/**
 * Murmur Server API Client.
 *
 * Handles communication with the Murmur backend server at:
 * https://murmur.cluster-fluster.com
 */

import {
    encodeBase64,
    decodeBase64,
    stringToBytes
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'
import { logger } from '../logger.js'

/** Base URL for the Murmur server */
const API_BASE = 'https://murmur.cluster-fluster.com'
const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000

function isDuplicateMessageIdError(error: unknown): boolean {
    if (!(error instanceof Error)) {
        return false
    }
    const message = error.message.toLowerCase()
    return message.includes('message id already exists') || message.includes('duplicate message')
}

function shouldRetrySend(error: unknown): boolean {
    if (!(error instanceof Error)) {
        return true
    }
    const message = error.message.toLowerCase()
    if (message.startsWith('http 4') && !message.startsWith('http 429')) {
        return false
    }
    if (message.includes('recipient not found')) {
        return false
    }
    if (message.includes('invalid message id')) {
        return false
    }
    return true
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
}

function buildApiErrorMessage(
    status: number,
    errorData: { error?: string; retryAfter?: number }
): string {
    const message = errorData.error || `HTTP ${status}`
    if (typeof errorData.retryAfter === 'number' && Number.isFinite(errorData.retryAfter) && errorData.retryAfter > 0) {
        return `${message} Rate limit resets in ${errorData.retryAfter}s.`
    }
    return message
}

/**
 * Authentication tokens from the server.
 */
export interface AuthTokens {
    accessToken: string
    refreshToken: string
}

/**
 * User info returned from auth endpoints.
 */
export interface UserInfo {
    id: string
    createdAt: number
}

/**
 * Message from the server inbox.
 */
export interface InboxMessage {
    id: string
    senderId: string
    blob: string
    signature: string
    createdAt: number
    expiresAt: number
}

/**
 * Profile data from the server.
 */
export interface ServerProfile {
    id: string
    profilePublicKey: string
    profileKeySignature: string
    encryptedProfile: string
    profileUpdatedAt: number
}

/**
 * Public profile (username-based).
 */
export interface PublicProfile {
    username: string
    identityKey: string
    description: string
    avatar: { image: string; thumbhash: string } | null
    createdAt: number
    updatedAt: number
}

/**
 * Prekey from server upload.
 */
export interface PreKeyUpload {
    publicKey: string
    signature: string
    oneTime: boolean
}

/**
 * Prekey bundle from the server.
 */
export interface ServerPreKeyBundle {
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
}

/**
 * Murmur API client.
 * Handles all communication with the server including authentication.
 */
export class MurmurApi {
    private accessToken: string | null = null
    private refreshToken: string | null = null
    private identityPrivateKey: Uint8Array | null = null

    constructor(
        private baseUrl: string = API_BASE
    ) {}

    /**
     * Set credentials for authenticated requests.
     */
    setCredentials(
        identityPrivateKey: Uint8Array,
        accessToken: string,
        refreshToken: string
    ): void {
        this.identityPrivateKey = identityPrivateKey
        this.accessToken = accessToken
        this.refreshToken = refreshToken
    }

    /**
     * Get current tokens.
     */
    getTokens(): AuthTokens | null {
        if (!this.accessToken || !this.refreshToken) return null
        return {
            accessToken: this.accessToken,
            refreshToken: this.refreshToken
        }
    }

    /**
     * Sign string data with the identity key.
     */
    private sign(data: string): string {
        if (!this.identityPrivateKey) {
            throw new Error('Identity private key not set')
        }
        const signature = sign(stringToBytes(data), this.identityPrivateKey)
        return encodeBase64(signature)
    }

    /**
     * Sign raw bytes with the identity key.
     */
    private signBytes(data: Uint8Array): string {
        if (!this.identityPrivateKey) {
            throw new Error('Identity private key not set')
        }
        const signature = sign(data, this.identityPrivateKey)
        return encodeBase64(signature)
    }

    /**
     * Make an authenticated request with timeout.
     */
    private async request<T>(
        method: string,
        path: string,
        body?: unknown,
        requireAuth: boolean = true,
        timeoutMs: number = 30000,
        allowRetry: boolean = true
    ): Promise<T> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json'
        }

        if (requireAuth) {
            if (!this.accessToken) {
                throw new Error('Not authenticated')
            }
            headers['Authorization'] = `Bearer ${this.accessToken}`
        }

        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), timeoutMs)

        try {
            const response = await fetch(`${this.baseUrl}${path}`, {
                method,
                headers,
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal
            })

            if (response.status === 401 && requireAuth && allowRetry && this.refreshToken) {
                logger.warn('Access token expired. Attempting refresh...')
                try {
                    await this.refresh()
                    logger.info('Access token refreshed.')
                } catch {
                    logger.error('Access token refresh failed.')
                    // Fall through to normal error handling.
                }
                return this.request(method, path, body, requireAuth, timeoutMs, false)
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as {
                    error?: string
                    retryAfter?: number
                }
                throw new Error(buildApiErrorMessage(response.status, errorData))
            }

            return response.json() as Promise<T>
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                throw new Error('Request timed out')
            }
            throw error
        } finally {
            clearTimeout(timeout)
        }
    }

    /**
     * Stream message notifications via SSE.
     */
    async streamMessages(
        onEvent: (event: { event: string; data: unknown }) => void | Promise<void>,
        options?: { signal?: AbortSignal }
    ): Promise<void> {
        if (!this.accessToken) {
            throw new Error('Not authenticated')
        }
        let refreshed = false

        while (true) {
            const response = await fetch(`${this.baseUrl}/v1/messages/stream`, {
                method: 'GET',
                headers: {
                    'Accept': 'text/event-stream',
                    'Authorization': `Bearer ${this.accessToken}`
                },
                signal: options?.signal
            })

            if (response.status === 401 && this.refreshToken && !refreshed) {
                logger.warn('Realtime stream unauthorized. Refreshing token...')
                await this.refresh()
                logger.info('Realtime stream token refreshed.')
                refreshed = true
                continue
            }

            if (!response.ok) {
                const errorText = await response.text().catch(() => '')
                throw new Error(errorText || `HTTP ${response.status}`)
            }

            if (!response.body) {
                throw new Error('SSE response missing body')
            }

            const reader = response.body.getReader()
            const decoder = new TextDecoder()
            let buffer = ''
            let eventName = 'message'
            let dataLines: string[] = []

            const dispatchEvent = async (): Promise<void> => {
                if (dataLines.length === 0) {
                    eventName = 'message'
                    return
                }
                const dataText = dataLines.join('\n')
                let data: unknown = dataText
                try {
                    data = JSON.parse(dataText)
                } catch {
                    // Leave as raw string.
                }
                await onEvent({ event: eventName, data })
                eventName = 'message'
                dataLines = []
            }

            try {
                while (true) {
                    const { value, done } = await reader.read()
                    if (done) {
                        break
                    }
                    buffer += decoder.decode(value, { stream: true })

                    let newlineIndex = buffer.indexOf('\n')
                    while (newlineIndex >= 0) {
                        let line = buffer.slice(0, newlineIndex)
                        if (line.endsWith('\r')) {
                            line = line.slice(0, -1)
                        }
                        buffer = buffer.slice(newlineIndex + 1)

                        if (line === '') {
                            await dispatchEvent()
                        } else if (line.startsWith('event:')) {
                            eventName = line.slice(6).trim() || 'message'
                        } else if (line.startsWith('data:')) {
                            dataLines.push(line.slice(5).trimStart())
                        }

                        newlineIndex = buffer.indexOf('\n')
                    }
                }
                await dispatchEvent()
            } finally {
                reader.releaseLock()
            }

            return
        }
    }

    /**
     * Register a new account.
     */
    async register(
        identityPublicKey: string,
        identityPrivateKey: Uint8Array,
        profilePublicKey: string,
        profileKeySignature: string,
        encryptedProfile: string
    ): Promise<{ tokens: AuthTokens; user: UserInfo }> {
        const timestamp = Date.now()

        // Sign the entire request
        const requestBody = {
            identityPublicKey,
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            timestamp
        }
        const requestJson = JSON.stringify(requestBody)
        const signature = encodeBase64(sign(stringToBytes(requestJson), identityPrivateKey))

        const response = await this.request<{
            success: boolean
            accessToken: string
            refreshToken: string
            user: UserInfo
        }>('POST', '/v1/auth/register', {
            ...requestBody,
            signature
        }, false)

        this.identityPrivateKey = identityPrivateKey
        this.accessToken = response.accessToken
        this.refreshToken = response.refreshToken

        return {
            tokens: {
                accessToken: response.accessToken,
                refreshToken: response.refreshToken
            },
            user: response.user
        }
    }

    /**
     * Login with existing identity.
     */
    async login(
        identityPublicKey: string,
        identityPrivateKey: Uint8Array
    ): Promise<{ tokens: AuthTokens; user: UserInfo }> {
        const timestamp = Date.now()
        const message = `${identityPublicKey}:${timestamp}`
        const signature = encodeBase64(sign(stringToBytes(message), identityPrivateKey))

        const response = await this.request<{
            success: boolean
            accessToken: string
            refreshToken: string
            user: UserInfo
        }>('POST', '/v1/auth/login', {
            identityPublicKey,
            timestamp,
            signature
        }, false)

        this.identityPrivateKey = identityPrivateKey
        this.accessToken = response.accessToken
        this.refreshToken = response.refreshToken

        return {
            tokens: {
                accessToken: response.accessToken,
                refreshToken: response.refreshToken
            },
            user: response.user
        }
    }

    /**
     * Refresh access token.
     */
    async refresh(): Promise<string> {
        if (!this.refreshToken) {
            throw new Error('No refresh token')
        }

        const response = await this.request<{
            success: boolean
            accessToken: string
        }>('POST', '/v1/auth/refresh', {
            refreshToken: this.refreshToken
        }, false, 30000, false)

        this.accessToken = response.accessToken
        return response.accessToken
    }

    /**
     * Send a message.
     */
    async sendMessage(
        recipientId: string,
        blob: string,
        messageId: string,
        retries: number = 3
    ): Promise<{ id: string; createdAt: number; expiresAt: number }> {
        // Server verifies signature of: blobBytes + messageIdBytes (concatenated raw bytes)
        const blobBytes = decodeBase64(blob)
        const messageIdBytes = stringToBytes(messageId)
        const messageToSign = new Uint8Array(blobBytes.length + messageIdBytes.length)
        messageToSign.set(blobBytes, 0)
        messageToSign.set(messageIdBytes, blobBytes.length)
        const signature = this.signBytes(messageToSign)

        const attempts = Math.max(1, Math.floor(retries))
        let lastError: unknown
        for (let attempt = 1; attempt <= attempts; attempt += 1) {
            try {
                const response = await this.request<{
                    success: boolean
                    message: {
                        id: string
                        createdAt: number
                        expiresAt: number
                    }
                }>('POST', '/v1/messages/send', {
                    messageId,
                    recipientId,
                    blob,
                    signature
                })
                return response.message
            } catch (error) {
                if (isDuplicateMessageIdError(error)) {
                    const now = Date.now()
                    return {
                        id: messageId,
                        createdAt: now,
                        expiresAt: now + MESSAGE_TTL_MS
                    }
                }
                lastError = error
                if (!shouldRetrySend(error) || attempt === attempts) {
                    throw error
                }
                const delayMs = 250 * attempt
                logger.warn(`Send failed (attempt ${attempt} of ${attempts}). Retrying...`)
                await sleep(delayMs)
            }
        }
        throw lastError ?? new Error('Failed to send message')
    }

    /**
     * Get inbox messages.
     */
    async getInbox(
        limit: number = 50,
        cursor?: string
    ): Promise<{ messages: InboxMessage[]; nextCursor: string | null; hasMore: boolean }> {
        let path = `/v1/messages/inbox?limit=${limit}`
        if (cursor) {
            path += `&cursor=${encodeURIComponent(cursor)}`
        }

        return this.request<{
            messages: InboxMessage[]
            nextCursor: string | null
            hasMore: boolean
        }>('GET', path)
    }

    /**
     * Get a specific message by ID.
     */
    async getMessage(messageId: string): Promise<InboxMessage> {
        return this.request<InboxMessage>(
            'GET',
            `/v1/messages/${encodeURIComponent(messageId)}`
        )
    }

    /**
     * Acknowledge (delete) messages.
     */
    async acknowledgeMessages(messageIds: string[]): Promise<{
        acknowledged: number
        failed: Array<{ messageId: string; error: string }>
    }> {
        const response = await this.request<{
            success: boolean
            acknowledged: number
            failed: Array<{ messageId: string; error: string }>
        }>('POST', '/v1/messages/ack', { messageIds })

        return {
            acknowledged: response.acknowledged,
            failed: response.failed
        }
    }

    /**
     * Get own profile.
     */
    async getMyProfile(): Promise<ServerProfile & { createdAt: number }> {
        return this.request<ServerProfile & { createdAt: number }>('GET', '/v1/profile/me')
    }

    /**
     * Delete the current account.
     */
    async deleteAccount(): Promise<void> {
        const timestamp = Date.now()
        const requestBody = { timestamp }
        const signature = this.sign(JSON.stringify(requestBody))

        await this.request<{ success: boolean }>('POST', '/v1/account/delete', {
            ...requestBody,
            signature
        })
    }

    /**
     * Get another user's profile by profile public key.
     */
    async getProfile(profilePublicKey: string): Promise<ServerProfile> {
        return this.request<ServerProfile>(
            'GET',
            `/v1/profile/${encodeURIComponent(profilePublicKey)}`
        )
    }

    /**
     * Get another user's profile by profile public key without auth.
     */
    async getPublicProfile(profilePublicKey: string): Promise<ServerProfile> {
        return this.request<ServerProfile>(
            'GET',
            `/v1/profile/${encodeURIComponent(profilePublicKey)}`,
            undefined,
            false
        )
    }

    /**
     * Update own profile.
     */
    async updateProfile(
        profilePublicKey: string,
        profileKeySignature: string,
        encryptedProfile: string
    ): Promise<void> {
        const timestamp = Date.now()

        const requestBody = {
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            timestamp
        }
        const signature = this.sign(JSON.stringify(requestBody))

        await this.request<{ success: boolean }>('POST', '/v1/profile/update', {
            ...requestBody,
            signature
        })
    }

    /**
     * Commit a public profile (username-based).
     */
    async commitPublicProfile(
        username: string,
        description: string,
        avatar?: { image: string; thumbhash: string }
    ): Promise<PublicProfile> {
        const normalizedUsername = username.trim().toLowerCase()
        const normalizedDescription = description.trim()
        const timestamp = Date.now()

        const requestBody: {
            username: string
            description: string
            avatar?: { image: string; thumbhash: string }
            timestamp: number
        } = {
            username: normalizedUsername,
            description: normalizedDescription,
            timestamp
        }
        if (avatar) {
            requestBody.avatar = avatar
        }
        const signature = this.sign(JSON.stringify(requestBody))

        return this.request<PublicProfile>('POST', '/v1/public-profile/commit', {
            ...requestBody,
            signature
        })
    }

    /**
     * Get public profile by username (no auth).
     */
    async getPublicProfileByUsername(username: string): Promise<PublicProfile> {
        const normalizedUsername = username.trim().toLowerCase()
        return this.request<PublicProfile>(
            'GET',
            `/v1/public-profile/${encodeURIComponent(normalizedUsername)}`,
            undefined,
            false
        )
    }

    /**
     * Upload prekeys.
     */
    async uploadPreKeys(preKeys: PreKeyUpload[]): Promise<void> {
        const timestamp = Date.now()

        const requestBody = {
            preKeys,
            timestamp
        }
        const signature = this.sign(JSON.stringify(requestBody))

        await this.request<{ success: boolean }>('POST', '/v1/prekeys/upload', {
            ...requestBody,
            signature
        })
    }

    /**
     * Get prekey bundle for another user.
     */
    async getPreKeyBundle(identityPublicKey: string): Promise<ServerPreKeyBundle> {
        return this.request<ServerPreKeyBundle>(
            'GET',
            `/v1/prekeys/${encodeURIComponent(identityPublicKey)}`
        )
    }

    /**
     * Get count of unallocated one-time prekeys.
     */
    async getOneTimePreKeyCount(): Promise<number> {
        const result = await this.request<{ count: number }>('GET', '/v1/prekeys/onetime/count')
        return result.count
    }
}
