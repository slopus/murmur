/**
 * Tests for mock server.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { createId } from '@paralleldrive/cuid2'
import { MockServer, createMockApi } from './mockServer.js'

describe('MockServer', () => {
    let server: MockServer

    beforeEach(() => {
        server = new MockServer()
    })

    describe('Registration and Login', () => {
        it('should register a new user', () => {
            const result = server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            expect(result.tokens.accessToken).toBeDefined()
            expect(result.tokens.refreshToken).toBeDefined()
            expect(result.user.id).toBe('identity-key-1')
            expect(result.user.createdAt).toBeGreaterThan(0)
            expect(server.getUserCount()).toBe(1)
        })

        it('should be idempotent on re-registration', () => {
            const result1 = server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            const result2 = server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            expect(result2.user.id).toBe(result1.user.id)
            expect(result2.user.createdAt).toBe(result1.user.createdAt)
            expect(server.getUserCount()).toBe(1)
        })

        it('should login existing user', () => {
            server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            const result = server.login('identity-key-1')

            expect(result.tokens.accessToken).toBeDefined()
            expect(result.user.id).toBe('identity-key-1')
        })

        it('should fail login for non-existent user', () => {
            expect(() => server.login('nonexistent')).toThrow('User not found')
        })

        it('should refresh access token', () => {
            const result = server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            const newToken = server.refresh(result.tokens.refreshToken)

            expect(newToken).toBeDefined()
            expect(newToken).not.toBe(result.tokens.accessToken)
        })

        it('should fail refresh with invalid token', () => {
            expect(() => server.refresh('invalid-token')).toThrow('Invalid refresh token')
        })

        it('should delete an account', () => {
            const result = server.register(
                'identity-key-1',
                'profile-public-key-1',
                'profile-signature-1',
                'encrypted-profile-1'
            )

            expect(server.getUserCount()).toBe(1)

            server.deleteAccount(result.tokens.accessToken)

            expect(server.getUserCount()).toBe(0)
            expect(() => server.login('identity-key-1')).toThrow('User not found')
        })
    })

    describe('Messages', () => {
        let aliceToken: string
        let bobToken: string

        beforeEach(() => {
            const aliceResult = server.register('alice-id', 'ppk', 'sig', 'ep')
            aliceToken = aliceResult.tokens.accessToken

            const bobResult = server.register('bob-id', 'ppk', 'sig', 'ep')
            bobToken = bobResult.tokens.accessToken
        })

        it('should send a message', () => {
            const result = server.sendMessage(
                aliceToken,
                'msg-1',
                'bob-id',
                'encrypted-blob',
                'signature'
            )

            expect(result.id).toBe('msg-1')
            expect(result.createdAt).toBeGreaterThan(0)
            expect(result.expiresAt).toBeGreaterThan(result.createdAt)
            expect(server.getMessageCount()).toBe(1)
        })

        it('should fail send to non-existent recipient', () => {
            expect(() => server.sendMessage(
                aliceToken,
                'msg-1',
                'nonexistent',
                'blob',
                'sig'
            )).toThrow('Recipient not found')
        })

        it('should fail send with duplicate message ID', () => {
            server.sendMessage(aliceToken, 'msg-1', 'bob-id', 'blob', 'sig')

            expect(() => server.sendMessage(
                aliceToken,
                'msg-1',
                'bob-id',
                'blob2',
                'sig2'
            )).toThrow('Message ID already exists')
        })

        it('should get inbox messages', () => {
            server.sendMessage(aliceToken, 'msg-1', 'bob-id', 'hello', 'sig1')
            server.sendMessage(aliceToken, 'msg-2', 'bob-id', 'world', 'sig2')

            const inbox = server.getInbox(bobToken)

            expect(inbox.messages).toHaveLength(2)
            expect(inbox.messages[0].id).toBe('msg-1')
            expect(inbox.messages[1].id).toBe('msg-2')
            expect(inbox.hasMore).toBe(false)
        })

        it('should paginate inbox', () => {
            for (let i = 0; i < 5; i++) {
                server.sendMessage(aliceToken, `msg-${i}`, 'bob-id', `blob-${i}`, 'sig')
            }

            const page1 = server.getInbox(bobToken, 2)
            expect(page1.messages).toHaveLength(2)
            expect(page1.hasMore).toBe(true)

            const page2 = server.getInbox(bobToken, 2, page1.nextCursor!)
            expect(page2.messages).toHaveLength(2)
            expect(page2.hasMore).toBe(true)

            const page3 = server.getInbox(bobToken, 2, page2.nextCursor!)
            expect(page3.messages).toHaveLength(1)
            expect(page3.hasMore).toBe(false)
        })

        it('should acknowledge messages', () => {
            server.sendMessage(aliceToken, 'msg-1', 'bob-id', 'blob', 'sig')
            server.sendMessage(aliceToken, 'msg-2', 'bob-id', 'blob', 'sig')

            expect(server.getInbox(bobToken).messages).toHaveLength(2)

            const result = server.acknowledgeMessages(bobToken, ['msg-1'])

            expect(result.acknowledged).toBe(1)
            expect(result.failed).toHaveLength(0)
            expect(server.getInbox(bobToken).messages).toHaveLength(1)
        })

        it('should report failed acknowledgments', () => {
            server.sendMessage(aliceToken, 'msg-1', 'bob-id', 'blob', 'sig')

            const result = server.acknowledgeMessages(bobToken, ['msg-1', 'nonexistent'])

            expect(result.acknowledged).toBe(1)
            expect(result.failed).toHaveLength(1)
            expect(result.failed[0].messageId).toBe('nonexistent')
        })

        it('should not acknowledge other users messages', () => {
            server.sendMessage(aliceToken, 'msg-1', 'bob-id', 'blob', 'sig')

            const result = server.acknowledgeMessages(aliceToken, ['msg-1'])

            expect(result.acknowledged).toBe(0)
            expect(result.failed).toHaveLength(1)
            expect(result.failed[0].error).toBe('Not your message')
        })
    })

    describe('Profiles', () => {
        let aliceToken: string

        beforeEach(() => {
            const result = server.register(
                'alice-id',
                'alice-profile-key',
                'alice-sig',
                'alice-encrypted-profile'
            )
            aliceToken = result.tokens.accessToken
            server.register('bob-id', 'bob-profile-key', 'bob-sig', 'bob-profile')
        })

        it('should get own profile', () => {
            const profile = server.getMyProfile(aliceToken)

            expect(profile.id).toBe('alice-id')
            expect(profile.profilePublicKey).toBe('alice-profile-key')
            expect(profile.encryptedProfile).toBe('alice-encrypted-profile')
        })

        it('should get other user profile', () => {
            const profile = server.getProfile(aliceToken, 'bob-profile-key')

            expect(profile.id).toBe('bob-id')
            expect(profile.profilePublicKey).toBe('bob-profile-key')
        })

        it('should fail get profile for non-existent user', () => {
            expect(() => server.getProfile(aliceToken, 'nonexistent')).toThrow('User not found')
        })

        it('should update profile', () => {
            server.updateProfile(
                aliceToken,
                'new-profile-key',
                'new-sig',
                'new-encrypted-profile'
            )

            const profile = server.getMyProfile(aliceToken)
            expect(profile.profilePublicKey).toBe('new-profile-key')
            expect(profile.encryptedProfile).toBe('new-encrypted-profile')
        })
    })

    describe('Feeds', () => {
        let aliceToken: string
        let bobToken: string
        let carolToken: string

        beforeEach(() => {
            aliceToken = server.register('alice-id', 'alice-profile', 'sig', 'profile').tokens.accessToken
            bobToken = server.register('bob-id', 'bob-profile', 'sig', 'profile').tokens.accessToken
            carolToken = server.register('carol-id', 'carol-profile', 'sig', 'profile').tokens.accessToken
        })

        it('should manage feed membership, key rotation, and timeline pagination', () => {
            const created = server.createFeed(aliceToken, 'feed-1', 'meta-1')
            expect(created.feedId).toBe('feed-1')

            expect(server.addFeedMembers(aliceToken, 'feed-1', 0, [
                { memberId: 'bob-id', encryptedKey: 'bob-key-0' },
                { memberId: 'carol-id', encryptedKey: 'carol-key-0' }
            ]).added).toBe(2)

            server.postFeedItem(aliceToken, 'feed-1', 'item-1', 0, 'blob-1', 'sig-1')

            expect(server.getFollowedFeeds(bobToken)).toEqual([
                { feedId: 'feed-1', ownerId: 'alice-id', epoch: 0 }
            ])
            expect(server.getFeedKeys(bobToken)).toEqual([
                { feedId: 'feed-1', epoch: 0, encryptedKey: 'bob-key-0' }
            ])

            expect(server.removeFeedMembers(aliceToken, 'feed-1', ['carol-id']).removed).toBe(1)
            expect(server.rotateFeedKeys(aliceToken, 'feed-1', 1, [
                { memberId: 'bob-id', encryptedKey: 'bob-key-1' }
            ]).epoch).toBe(1)
            server.postFeedItem(aliceToken, 'feed-1', 'item-2', 1, 'blob-2', 'sig-2')

            const timeline = server.getFeedTimeline(bobToken, 1)
            expect(timeline.items.map(item => item.itemId)).toEqual(['item-2'])
            expect(timeline.hasMore).toBe(true)

            const nextPage = server.getFeedTimeline(bobToken, 2, timeline.nextCursor ?? undefined)
            expect(nextPage.items.map(item => item.itemId)).toEqual(['item-1'])
            expect(server.getFeedKeys(carolToken)).toEqual([])
        })
    })

    describe('Prekey Bundles', () => {
        let aliceToken: string
        let bobToken: string

        beforeEach(() => {
            const aliceResult = server.register('alice-id', 'ppk', 'sig', 'ep')
            aliceToken = aliceResult.tokens.accessToken

            const bobResult = server.register('bob-id', 'ppk', 'sig', 'ep')
            bobToken = bobResult.tokens.accessToken
        })

        it('should upload prekeys', () => {
            server.uploadPreKeys(aliceToken, [
                { publicKey: 'signed-prekey', signature: 'spk-signature', oneTime: false },
                { publicKey: 'otpk-1', signature: 'otpk-sig-1', oneTime: true },
                { publicKey: 'otpk-2', signature: 'otpk-sig-2', oneTime: true }
            ])

            // Should be able to fetch the bundle
            const bundle = server.getPreKeyBundle(bobToken, 'alice-id')
            expect(bundle.identityKey).toBe('alice-id')
            expect(bundle.signedPreKey.publicKey).toBe('signed-prekey')
            expect(bundle.signedPreKey.signature).toBe('spk-signature')
        })

        it('should allocate one-time prekeys on fetch', () => {
            server.uploadPreKeys(aliceToken, [
                { publicKey: 'signed-prekey', signature: 'spk-signature', oneTime: false },
                { publicKey: 'otpk-1', signature: 'otpk-sig-1', oneTime: true },
                { publicKey: 'otpk-2', signature: 'otpk-sig-2', oneTime: true }
            ])

            // First fetch gets first one-time prekey
            const bundle1 = server.getPreKeyBundle(bobToken, 'alice-id')
            expect(bundle1.oneTimePreKey?.publicKey).toBe('otpk-1')
            expect(bundle1.oneTimePreKey?.signature).toBe('otpk-sig-1')

            // Second fetch gets second one-time prekey
            const bundle2 = server.getPreKeyBundle(bobToken, 'alice-id')
            expect(bundle2.oneTimePreKey?.publicKey).toBe('otpk-2')
            expect(bundle2.oneTimePreKey?.signature).toBe('otpk-sig-2')

            // Third fetch has no one-time prekeys left
            const bundle3 = server.getPreKeyBundle(bobToken, 'alice-id')
            expect(bundle3.oneTimePreKey).toBeNull()
            expect(bundle3.signedPreKey.publicKey).toBe('signed-prekey')
        })

        it('should get one-time prekey count', () => {
            server.uploadPreKeys(aliceToken, [
                { publicKey: 'signed-prekey', signature: 'spk-signature', oneTime: false },
                { publicKey: 'otpk-1', signature: 'otpk-sig-1', oneTime: true },
                { publicKey: 'otpk-2', signature: 'otpk-sig-2', oneTime: true }
            ])

            expect(server.getOneTimePreKeyCount(aliceToken)).toBe(2)

            // Allocate one
            server.getPreKeyBundle(bobToken, 'alice-id')
            expect(server.getOneTimePreKeyCount(aliceToken)).toBe(1)

            // Allocate another
            server.getPreKeyBundle(bobToken, 'alice-id')
            expect(server.getOneTimePreKeyCount(aliceToken)).toBe(0)
        })

        it('should fail to get bundle for user without bundle', () => {
            expect(() => server.getPreKeyBundle(aliceToken, 'bob-id')).toThrow('No prekey bundle available')
        })

        it('should fail to get bundle for non-existent user', () => {
            expect(() => server.getPreKeyBundle(aliceToken, 'nonexistent')).toThrow('User not found')
        })
    })
})

describe('createMockApi', () => {
    let server: MockServer
    let api: ReturnType<typeof createMockApi>

    beforeEach(() => {
        server = new MockServer()
        api = createMockApi(server)
    })

    it('should register via mock API', async () => {
        const result = await api.register(
            'alice-id',
            new Uint8Array(32),
            'ppk',
            'sig',
            'ep'
        )

        expect(result.user.id).toBe('alice-id')
        expect(api.getTokens()).not.toBeNull()
    })

    it('should login via mock API', async () => {
        await api.register('alice-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        const api2 = createMockApi(server)
        const result = await api2.login('alice-id', new Uint8Array(32))

        expect(result.user.id).toBe('alice-id')
    })

    it('should send and receive messages via mock API', async () => {
        await api.register('alice-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        const bobApi = createMockApi(server)
        await bobApi.register('bob-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        await api.sendMessage('bob-id', 'hello-blob', createId())

        const inbox = await bobApi.getInbox()
        expect(inbox.messages).toHaveLength(1)
        expect(inbox.messages[0].blob).toBe('hello-blob')

        await bobApi.acknowledgeMessages([inbox.messages[0].id])

        const inbox2 = await bobApi.getInbox()
        expect(inbox2.messages).toHaveLength(0)
    })

    it('should reuse provided message id', async () => {
        await api.register('alice-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        const bobApi = createMockApi(server)
        await bobApi.register('bob-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        const messageId = createId()
        const result = await api.sendMessage('bob-id', 'hello-blob', messageId)

        expect(result.id).toBe(messageId)
    })

    it('should upload and fetch prekey bundle via mock API', async () => {
        await api.register('alice-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        const bobApi = createMockApi(server)
        await bobApi.register('bob-id', new Uint8Array(32), 'ppk', 'sig', 'ep')

        // Alice uploads her prekeys
        await api.uploadPreKeys([
            { publicKey: 'signed-prekey', signature: 'spk-sig', oneTime: false },
            { publicKey: 'otpk-1', signature: 'otpk-sig-1', oneTime: true },
            { publicKey: 'otpk-2', signature: 'otpk-sig-2', oneTime: true }
        ])

        // Bob fetches Alice's prekey bundle
        const bundle = await bobApi.getPreKeyBundle('alice-id')
        expect(bundle.identityKey).toBe('alice-id')
        expect(bundle.signedPreKey.publicKey).toBe('signed-prekey')
        expect(bundle.oneTimePreKey?.publicKey).toBe('otpk-1')
    })
})
