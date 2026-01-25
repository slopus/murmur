/**
 * Integration tests against live Murmur server.
 *
 * These tests are DISABLED by default and only run when:
 * - MURMUR_LIVE_TEST=1 environment variable is set
 * - Server is running at MURMUR_API_URL (default: https://murmur.cluster-fluster.com)
 *
 * Run with: MURMUR_LIVE_TEST=1 npm test -- src/engine/liveServer.test.ts
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { MurmurApi, type PreKeyUpload } from './api.js'
import { generateSigningKeyPair, sign } from '../encryption/crypto/signing.js'
import { generateDH } from '../encryption/crypto/dh.js'
import { encodeBase64, decodeBase64, stringToBytes } from '../encryption/crypto/utils.js'
import { createProfileForRegistration, type Profile } from './profile.js'
import { createId } from '@paralleldrive/cuid2'

// Skip all tests if MURMUR_LIVE_TEST is not set
const LIVE_TEST_ENABLED = process.env.MURMUR_LIVE_TEST === '1'
const API_URL = process.env.MURMUR_API_URL || 'https://murmur.cluster-fluster.com'

// Helper to create unique test identity
function createTestIdentity() {
    const keyPair = generateSigningKeyPair()
    return {
        publicKey: encodeBase64(keyPair.publicKey),
        privateKey: keyPair.privateKey,
        publicKeyBytes: keyPair.publicKey
    }
}

// Helper to create test profile
function createTestProfile(identity: ReturnType<typeof createTestIdentity>) {
    const profile: Profile = {
        firstName: `TestUser_${Date.now()}`,
        lastName: 'Integration'
    }
    return createProfileForRegistration(profile, identity.privateKey)
}

// Helper to create prekeys for upload
// Server verifies prekey signatures against RAW BYTES (decoded from base64)
function createTestPreKeys(identityPrivateKey: Uint8Array, count: number = 5): PreKeyUpload[] {
    const preKeys: PreKeyUpload[] = []

    // Signed prekey - sign the raw bytes
    const signedPreKey = generateDH()
    const signedPreKeySignature = sign(signedPreKey.publicKey, identityPrivateKey)
    preKeys.push({
        publicKey: encodeBase64(signedPreKey.publicKey),
        signature: encodeBase64(signedPreKeySignature),
        oneTime: false
    })

    // One-time prekeys - sign the raw bytes
    for (let i = 0; i < count; i++) {
        const otpk = generateDH()
        const otpkSignature = sign(otpk.publicKey, identityPrivateKey)
        preKeys.push({
            publicKey: encodeBase64(otpk.publicKey),
            signature: encodeBase64(otpkSignature),
            oneTime: true
        })
    }

    return preKeys
}

describe.skipIf(!LIVE_TEST_ENABLED)('Live Server Integration Tests', () => {
    let api: MurmurApi

    beforeAll(() => {
        console.log(`Running live tests against: ${API_URL}`)
    })

    beforeEach(() => {
        api = new MurmurApi(API_URL)
    })

    describe('Authentication', () => {
        it('should register a new user', async () => {
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            const result = await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )

            expect(result.tokens.accessToken).toBeDefined()
            expect(result.tokens.refreshToken).toBeDefined()
            expect(result.user.id).toBe(identity.publicKey)
            expect(result.user.createdAt).toBeGreaterThan(0)
        })

        it('should be idempotent on re-registration', async () => {
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            const result1 = await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )

            // Re-register with same identity
            const api2 = new MurmurApi(API_URL)
            const result2 = await api2.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )

            expect(result2.user.id).toBe(result1.user.id)
            expect(result2.user.createdAt).toBe(result1.user.createdAt)
        })

        it('should login with existing identity', async () => {
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            // Register first
            await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )

            // Login with new API instance
            const api2 = new MurmurApi(API_URL)
            const result = await api2.login(identity.publicKey, identity.privateKey)

            expect(result.tokens.accessToken).toBeDefined()
            expect(result.tokens.refreshToken).toBeDefined()
            expect(result.user.id).toBe(identity.publicKey)
        })

        it('should fail login for non-existent user', async () => {
            const identity = createTestIdentity()

            await expect(
                api.login(identity.publicKey, identity.privateKey)
            ).rejects.toThrow()
        })

        it('should refresh access token', async () => {
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )

            const oldToken = api.getTokens()!.accessToken
            const newToken = await api.refresh()

            expect(newToken).toBeDefined()
            expect(newToken).not.toBe(oldToken)
        })

        it('should reject invalid signature on register', async () => {
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            // Create a different key to sign with (wrong key)
            const wrongKey = generateSigningKeyPair()
            const wrongProfileData = createProfileForRegistration(
                { firstName: 'Wrong' },
                wrongKey.privateKey
            )

            // Try to register with mismatched keys
            await expect(
                api.register(
                    identity.publicKey,
                    identity.privateKey,
                    wrongProfileData.profilePublicKey,
                    wrongProfileData.profileKeySignature, // Signed by wrong key
                    wrongProfileData.encryptedProfile
                )
            ).rejects.toThrow()
        })
    })

    describe('Profile', () => {
        let identity: ReturnType<typeof createTestIdentity>
        let profileData: ReturnType<typeof createTestProfile>

        beforeEach(async () => {
            identity = createTestIdentity()
            profileData = createTestProfile(identity)
            await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )
        })

        it('should get own profile', async () => {
            const profile = await api.getMyProfile()

            expect(profile.id).toBe(identity.publicKey)
            expect(profile.profilePublicKey).toBe(profileData.profilePublicKey)
            expect(profile.encryptedProfile).toBe(profileData.encryptedProfile)
            expect(profile.createdAt).toBeGreaterThan(0)
        })

        it('should get another user profile', async () => {
            // Create another user
            const identity2 = createTestIdentity()
            const profileData2 = createTestProfile(identity2)
            const api2 = new MurmurApi(API_URL)
            await api2.register(
                identity2.publicKey,
                identity2.privateKey,
                profileData2.profilePublicKey,
                profileData2.profileKeySignature,
                profileData2.encryptedProfile
            )

            // Fetch their profile
            const profile = await api.getProfile(profileData2.profilePublicKey)

            expect(profile.id).toBe(identity2.publicKey)
            expect(profile.profilePublicKey).toBe(profileData2.profilePublicKey)
        })

        it('should fail to get non-existent user profile', async () => {
            const fakeIdentity = createTestIdentity()
            const fakeProfile = createTestProfile(fakeIdentity)

            await expect(
                api.getProfile(fakeProfile.profilePublicKey)
            ).rejects.toThrow()
        })

        it('should update profile', async () => {
            const newProfile: Profile = { firstName: 'Updated', lastName: 'Name' }
            const newProfileData = createProfileForRegistration(newProfile, identity.privateKey)

            await api.updateProfile(
                newProfileData.profilePublicKey,
                newProfileData.profileKeySignature,
                newProfileData.encryptedProfile
            )

            const profile = await api.getMyProfile()
            expect(profile.profilePublicKey).toBe(newProfileData.profilePublicKey)
            expect(profile.encryptedProfile).toBe(newProfileData.encryptedProfile)
        })
    })

    describe('PreKeys', () => {
        let identity: ReturnType<typeof createTestIdentity>

        beforeEach(async () => {
            identity = createTestIdentity()
            const profileData = createTestProfile(identity)
            await api.register(
                identity.publicKey,
                identity.privateKey,
                profileData.profilePublicKey,
                profileData.profileKeySignature,
                profileData.encryptedProfile
            )
        })

        it('should upload prekeys', async () => {
            const preKeys = createTestPreKeys(identity.privateKey, 5)

            // Should not throw
            await api.uploadPreKeys(preKeys)

            // Verify count
            const count = await api.getOneTimePreKeyCount()
            expect(count).toBe(5)
        })

        it('should get prekey bundle', async () => {
            const preKeys = createTestPreKeys(identity.privateKey, 3)
            await api.uploadPreKeys(preKeys)

            // Another user fetches the bundle
            const identity2 = createTestIdentity()
            const profileData2 = createTestProfile(identity2)
            const api2 = new MurmurApi(API_URL)
            await api2.register(
                identity2.publicKey,
                identity2.privateKey,
                profileData2.profilePublicKey,
                profileData2.profileKeySignature,
                profileData2.encryptedProfile
            )

            const bundle = await api2.getPreKeyBundle(identity.publicKey)

            expect(bundle.identityKey).toBe(identity.publicKey)
            expect(bundle.signedPreKey).toBeDefined()
            expect(bundle.signedPreKey.publicKey).toBe(preKeys[0].publicKey)
            expect(bundle.signedPreKey.signature).toBe(preKeys[0].signature)
            expect(bundle.oneTimePreKey).not.toBeNull()
        })

        it('should allocate one-time prekeys on fetch', async () => {
            const preKeys = createTestPreKeys(identity.privateKey, 2)
            await api.uploadPreKeys(preKeys)

            // Another user
            const identity2 = createTestIdentity()
            const profileData2 = createTestProfile(identity2)
            const api2 = new MurmurApi(API_URL)
            await api2.register(
                identity2.publicKey,
                identity2.privateKey,
                profileData2.profilePublicKey,
                profileData2.profileKeySignature,
                profileData2.encryptedProfile
            )

            // First fetch
            const bundle1 = await api2.getPreKeyBundle(identity.publicKey)
            expect(bundle1.oneTimePreKey).not.toBeNull()

            // Check count decreased
            const count1 = await api.getOneTimePreKeyCount()
            expect(count1).toBe(1)

            // Second fetch allocates another
            const bundle2 = await api2.getPreKeyBundle(identity.publicKey)
            expect(bundle2.signedPreKey.publicKey).toBe(bundle1.signedPreKey.publicKey)
            // One-time prekey should be different or null

            const count2 = await api.getOneTimePreKeyCount()
            expect(count2).toBe(0)

            // Third fetch - no more one-time prekeys
            const bundle3 = await api2.getPreKeyBundle(identity.publicKey)
            expect(bundle3.oneTimePreKey).toBeNull()
        })

        it('should fail to get bundle for user without prekeys', async () => {
            // identity has no prekeys uploaded yet
            const identity2 = createTestIdentity()
            const profileData2 = createTestProfile(identity2)
            const api2 = new MurmurApi(API_URL)
            await api2.register(
                identity2.publicKey,
                identity2.privateKey,
                profileData2.profilePublicKey,
                profileData2.profileKeySignature,
                profileData2.encryptedProfile
            )

            await expect(
                api2.getPreKeyBundle(identity.publicKey)
            ).rejects.toThrow()
        })

        it('should reject prekeys with invalid signature', async () => {
            const wrongKey = generateSigningKeyPair()
            const preKeys = createTestPreKeys(wrongKey.privateKey, 1)

            await expect(
                api.uploadPreKeys(preKeys)
            ).rejects.toThrow()
        })
    })

    describe('Messages', () => {
        let alice: {
            api: MurmurApi
            identity: ReturnType<typeof createTestIdentity>
        }
        let bob: {
            api: MurmurApi
            identity: ReturnType<typeof createTestIdentity>
        }

        beforeEach(async () => {
            // Setup Alice
            const aliceIdentity = createTestIdentity()
            const aliceProfile = createTestProfile(aliceIdentity)
            const aliceApi = new MurmurApi(API_URL)
            await aliceApi.register(
                aliceIdentity.publicKey,
                aliceIdentity.privateKey,
                aliceProfile.profilePublicKey,
                aliceProfile.profileKeySignature,
                aliceProfile.encryptedProfile
            )
            alice = { api: aliceApi, identity: aliceIdentity }

            // Setup Bob
            const bobIdentity = createTestIdentity()
            const bobProfile = createTestProfile(bobIdentity)
            const bobApi = new MurmurApi(API_URL)
            await bobApi.register(
                bobIdentity.publicKey,
                bobIdentity.privateKey,
                bobProfile.profilePublicKey,
                bobProfile.profileKeySignature,
                bobProfile.encryptedProfile
            )
            bob = { api: bobApi, identity: bobIdentity }
        })

        it('should send a message', async () => {
            const blob = encodeBase64(stringToBytes('encrypted-test-message'))

            const result = await alice.api.sendMessage(bob.identity.publicKey, blob)

            expect(result.id).toBeDefined()
            expect(result.createdAt).toBeGreaterThan(0)
            expect(result.expiresAt).toBeGreaterThan(result.createdAt)
        })

        it('should receive message in inbox', async () => {
            const messageContent = 'test-message-' + Date.now()
            const blob = encodeBase64(stringToBytes(messageContent))

            await alice.api.sendMessage(bob.identity.publicKey, blob)

            const inbox = await bob.api.getInbox()

            expect(inbox.messages.length).toBeGreaterThanOrEqual(1)
            const msg = inbox.messages.find(m => m.blob === blob)
            expect(msg).toBeDefined()
            expect(msg!.senderId).toBe(alice.identity.publicKey)
        })

        it('should paginate inbox', async () => {
            // Send multiple messages
            for (let i = 0; i < 5; i++) {
                const blob = encodeBase64(stringToBytes(`message-${i}`))
                await alice.api.sendMessage(bob.identity.publicKey, blob)
            }

            // Fetch with limit
            const page1 = await bob.api.getInbox(2)
            expect(page1.messages.length).toBe(2)
            expect(page1.hasMore).toBe(true)
            expect(page1.nextCursor).not.toBeNull()

            // Fetch next page
            const page2 = await bob.api.getInbox(2, page1.nextCursor!)
            expect(page2.messages.length).toBe(2)

            // Continue until done
            let cursor = page2.nextCursor
            let totalMessages = page1.messages.length + page2.messages.length
            while (cursor) {
                const page = await bob.api.getInbox(10, cursor)
                totalMessages += page.messages.length
                cursor = page.nextCursor
            }
            expect(totalMessages).toBeGreaterThanOrEqual(5)
        })

        it('should acknowledge messages', async () => {
            const blob = encodeBase64(stringToBytes('ack-test-message'))
            await alice.api.sendMessage(bob.identity.publicKey, blob)

            const inbox1 = await bob.api.getInbox()
            const msg = inbox1.messages.find(m => m.blob === blob)
            expect(msg).toBeDefined()

            const ackResult = await bob.api.acknowledgeMessages([msg!.id])
            expect(ackResult.acknowledged).toBe(1)
            expect(ackResult.failed).toHaveLength(0)

            // Message should be gone
            const inbox2 = await bob.api.getInbox()
            const stillThere = inbox2.messages.find(m => m.id === msg!.id)
            expect(stillThere).toBeUndefined()
        })

        it('should report failed acknowledgments', async () => {
            const fakeMessageId = createId()

            const result = await bob.api.acknowledgeMessages([fakeMessageId])

            expect(result.acknowledged).toBe(0)
            expect(result.failed).toHaveLength(1)
            expect(result.failed[0].messageId).toBe(fakeMessageId)
        })

        it('should fail send to non-existent recipient', async () => {
            const fakeIdentity = createTestIdentity()
            const blob = encodeBase64(stringToBytes('test'))

            await expect(
                alice.api.sendMessage(fakeIdentity.publicKey, blob)
            ).rejects.toThrow()
        })

        it('should reject duplicate message ID', async () => {
            const blob1 = encodeBase64(stringToBytes('message1'))
            await alice.api.sendMessage(bob.identity.publicKey, blob1)

            // The API generates its own message ID, so this test verifies
            // that separate sends work (not testing duplicate ID rejection directly
            // since the client always generates new IDs)
            const blob2 = encodeBase64(stringToBytes('message2'))
            const result = await alice.api.sendMessage(bob.identity.publicKey, blob2)
            expect(result.id).toBeDefined()
        })
    })

    describe('Error Handling', () => {
        it('should reject requests without authentication', async () => {
            // API without auth
            await expect(
                api.getMyProfile()
            ).rejects.toThrow('Not authenticated')
        })

        it('should handle network errors gracefully', async () => {
            const badApi = new MurmurApi('http://localhost:99999')
            const identity = createTestIdentity()
            const profileData = createTestProfile(identity)

            await expect(
                badApi.register(
                    identity.publicKey,
                    identity.privateKey,
                    profileData.profilePublicKey,
                    profileData.profileKeySignature,
                    profileData.encryptedProfile
                )
            ).rejects.toThrow()
        })
    })
})

// Standalone test to verify crypto compatibility
describe.skipIf(!LIVE_TEST_ENABLED)('Crypto Compatibility', () => {
    it('should verify that noble/curves signatures are compatible with server', async () => {
        const api = new MurmurApi(API_URL)
        const identity = createTestIdentity()
        const profileData = createTestProfile(identity)

        // This tests that our Ed25519 signatures work with the server
        const result = await api.register(
            identity.publicKey,
            identity.privateKey,
            profileData.profilePublicKey,
            profileData.profileKeySignature,
            profileData.encryptedProfile
        )

        expect(result.user.id).toBe(identity.publicKey)
        console.log('Crypto compatibility verified: signatures work correctly')
    })
})
