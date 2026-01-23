/**
 * Murmur Server API Client.
 *
 * Handles communication with the Murmur backend server at:
 * https://murmur.cluster-fluster.com
 */

import { createId } from '@paralleldrive/cuid2'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'

/** Base URL for the Murmur server */
const API_BASE = 'https://murmur.cluster-fluster.com'

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
 * Prekey bundle from the server.
 */
export interface ServerPreKeyBundle {
    identityKey: string
    signedPreKey: string
    signedPreKeyId: number
    signedPreKeySignature: string
    oneTimePreKey?: string
    oneTimePreKeyId?: number
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
     * Sign data with the identity key.
     */
    private sign(data: string): string {
        if (!this.identityPrivateKey) {
            throw new Error('Identity private key not set')
        }
        const signature = sign(stringToBytes(data), this.identityPrivateKey)
        return encodeBase64(signature)
    }

    /**
     * Make an authenticated request.
     */
    private async request<T>(
        method: string,
        path: string,
        body?: unknown,
        requireAuth: boolean = true
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

        const response = await fetch(`${this.baseUrl}${path}`, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined
        })

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string }
            throw new Error(errorData.error || `HTTP ${response.status}`)
        }

        return response.json() as Promise<T>
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
        }, false)

        this.accessToken = response.accessToken
        return response.accessToken
    }

    /**
     * Send a message.
     */
    async sendMessage(
        recipientId: string,
        blob: string
    ): Promise<{ id: string; createdAt: number; expiresAt: number }> {
        const messageId = createId()
        const signatureData = blob + messageId
        const signature = this.sign(signatureData)

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
     * Get another user's profile.
     */
    async getProfile(identityPublicKey: string): Promise<ServerProfile> {
        return this.request<ServerProfile>(
            'GET',
            `/v1/profile/${encodeURIComponent(identityPublicKey)}`
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
     * Upload prekey bundle.
     */
    async uploadPreKeyBundle(
        identityKey: string,
        signedPreKey: string,
        signedPreKeyId: number,
        signedPreKeySignature: string,
        oneTimePreKeys: Array<{ id: number; key: string }>
    ): Promise<void> {
        const timestamp = Date.now()

        const requestBody = {
            identityKey,
            signedPreKey,
            signedPreKeyId,
            signedPreKeySignature,
            oneTimePreKeys,
            timestamp
        }
        const signature = this.sign(JSON.stringify(requestBody))

        await this.request<{ success: boolean }>('POST', '/v1/keys/upload', {
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
            `/v1/keys/${encodeURIComponent(identityPublicKey)}`
        )
    }
}
