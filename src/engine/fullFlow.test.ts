/**
 * Full end-to-end flow tests.
 *
 * Tests the complete message encryption/decryption flow using
 * the session API and mock server.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { MockServer, createMockApi } from './mockServer.js'
import {
    createAgent,
    getIdentityKey,
    getPreKeyBundle,
    createPreKeyMessage,
    serializeAgent,
    deserializeAgent,
    prepareOutgoingMessage,
    processIncomingMessage,
    signMessageForServer
} from '../encryption/session/session.js'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes,
    bytesToString
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'
import { createProfileForRegistration, type Profile } from './profile.js'
import type { PreKeyBundle } from '../encryption/x3dh/types.js'

describe('Full end-to-end encrypted messaging flow', () => {
    let server: MockServer

    beforeEach(() => {
        server = new MockServer()
    })

    it('should complete full registration and messaging flow', async () => {
        // === ALICE SETUP ===
        // Create agent with encryption keys
        const aliceAgent = createAgent(10)
        const aliceIdentity = getIdentityKey(aliceAgent)

        // Create profile
        const aliceProfile: Profile = { firstName: 'Alice', lastName: 'Agent' }
        const aliceProfileData = createProfileForRegistration(
            aliceProfile,
            aliceAgent.keyStore.identityKeyPair.privateKey
        )

        // Register with server
        const aliceAuth = server.register(
            aliceIdentity,
            aliceProfileData.profilePublicKey,
            aliceProfileData.profileKeySignature,
            aliceProfileData.encryptedProfile
        )
        const aliceToken = aliceAuth.tokens.accessToken

        // === BOB SETUP ===
        const bobAgent = createAgent(10)
        const bobIdentity = getIdentityKey(bobAgent)

        const bobProfile: Profile = { firstName: 'Bob' }
        const bobProfileData = createProfileForRegistration(
            bobProfile,
            bobAgent.keyStore.identityKeyPair.privateKey
        )

        const bobAuth = server.register(
            bobIdentity,
            bobProfileData.profilePublicKey,
            bobProfileData.profileKeySignature,
            bobProfileData.encryptedProfile
        )
        const bobToken = bobAuth.tokens.accessToken

        // === SESSION ESTABLISHMENT ===
        // Alice gets Bob's prekey bundle (normally from server, we use agent directly)
        const bobBundle = getPreKeyBundle(bobAgent, true)

        // Alice sends a pre-key message with the initial payload
        const { message: preKeyMessage } = createPreKeyMessage(
            aliceAgent,
            bobBundle,
            stringToBytes('Hello Bob! This is our first secure message.')
        )

        // Alice sends message through server
        const sessionMsgBlob = encodeBase64(stringToBytes(JSON.stringify(preKeyMessage)))
        const sessionMsgId = 'session-init-1'
        const sessionMsgSig = signMessageForServer(aliceAgent, sessionMsgBlob, sessionMsgId)

        server.sendMessage(aliceToken, sessionMsgId, bobIdentity, sessionMsgBlob, sessionMsgSig)

        // Bob receives and processes session init
        const bobInbox = server.getInbox(bobToken)
        expect(bobInbox.messages).toHaveLength(1)

        const inboxMsg = bobInbox.messages[0]
        const decrypted = processIncomingMessage(
            bobAgent,
            inboxMsg.senderId,
            inboxMsg.blob,
            inboxMsg.id,
            inboxMsg.signature
        )

        expect(bytesToString(decrypted.plaintext)).toBe('Hello Bob! This is our first secure message.')
        // Acknowledge
        server.acknowledgeMessages(bobToken, [inboxMsg.id])

        // === BIDIRECTIONAL MESSAGING ===
        // Now both have sessions established

        // Alice sends another message
        const msg2 = prepareOutgoingMessage(
            aliceAgent,
            bobIdentity,
            stringToBytes('How are you?'),
            'msg-2'
        )
        server.sendMessage(aliceToken, 'msg-2', bobIdentity, msg2.outgoing.blob, msg2.outgoing.signature)

        // Bob decrypts
        const bobInbox2 = server.getInbox(bobToken)
        const dec2 = processIncomingMessage(
            bobAgent,
            bobInbox2.messages[0].senderId,
            bobInbox2.messages[0].blob,
            bobInbox2.messages[0].id,
            bobInbox2.messages[0].signature
        )
        expect(bytesToString(dec2.plaintext)).toBe('How are you?')
        server.acknowledgeMessages(bobToken, [bobInbox2.messages[0].id])

        // Bob replies - but he needs to establish his sending session first
        // Since he received from Alice, he now has a session to send back
        const msg3 = prepareOutgoingMessage(
            bobAgent,
            aliceIdentity,
            stringToBytes("I'm doing great, thanks!"),
            'msg-3'
        )
        server.sendMessage(bobToken, 'msg-3', aliceIdentity, msg3.outgoing.blob, msg3.outgoing.signature)

        // Alice receives
        const aliceInbox = server.getInbox(aliceToken)
        const dec3 = processIncomingMessage(
            aliceAgent,
            aliceInbox.messages[0].senderId,
            aliceInbox.messages[0].blob,
            aliceInbox.messages[0].id,
            aliceInbox.messages[0].signature
        )
        expect(bytesToString(dec3.plaintext)).toBe("I'm doing great, thanks!")
    })

    it('should handle multiple message exchange with ratcheting', async () => {
        // Setup agents
        const aliceAgent = createAgent(10)
        const bobAgent = createAgent(10)

        const aliceIdentity = getIdentityKey(aliceAgent)
        const bobIdentity = getIdentityKey(bobAgent)

        // Register
        const aliceProfile = createProfileForRegistration(
            { firstName: 'Alice' },
            aliceAgent.keyStore.identityKeyPair.privateKey
        )
        const bobProfile = createProfileForRegistration(
            { firstName: 'Bob' },
            bobAgent.keyStore.identityKeyPair.privateKey
        )

        const aliceToken = server.register(
            aliceIdentity,
            aliceProfile.profilePublicKey,
            aliceProfile.profileKeySignature,
            aliceProfile.encryptedProfile
        ).tokens.accessToken

        const bobToken = server.register(
            bobIdentity,
            bobProfile.profilePublicKey,
            bobProfile.profileKeySignature,
            bobProfile.encryptedProfile
        ).tokens.accessToken

        // Establish session
        const bobBundle = getPreKeyBundle(bobAgent, true)
        const { message: preKeyMessage } = createPreKeyMessage(
            aliceAgent,
            bobBundle,
            stringToBytes('Init')
        )

        // Send pre-key message through server
        const initBlob = encodeBase64(stringToBytes(JSON.stringify(preKeyMessage)))
        const initMsgId = 'init-msg'
        const initSig = signMessageForServer(aliceAgent, initBlob, initMsgId)
        server.sendMessage(aliceToken, initMsgId, bobIdentity, initBlob, initSig)

        // Bob processes init
        const inbox = server.getInbox(bobToken)
        processIncomingMessage(
            bobAgent,
            inbox.messages[0].senderId,
            inbox.messages[0].blob,
            inbox.messages[0].id,
            inbox.messages[0].signature
        )
        server.acknowledgeMessages(bobToken, [inbox.messages[0].id])

        // Exchange 20 messages back and forth
        for (let i = 0; i < 10; i++) {
            // Alice -> Bob
            const msgA = prepareOutgoingMessage(
                aliceAgent,
                bobIdentity,
                stringToBytes(`Alice message ${i}`),
                `alice-msg-${i}`
            )
            server.sendMessage(aliceToken, `alice-msg-${i}`, bobIdentity, msgA.outgoing.blob, msgA.outgoing.signature)

            const bobInbox = server.getInbox(bobToken)
            const decA = processIncomingMessage(
                bobAgent,
                bobInbox.messages[0].senderId,
                bobInbox.messages[0].blob,
                bobInbox.messages[0].id,
                bobInbox.messages[0].signature
            )
            expect(bytesToString(decA.plaintext)).toBe(`Alice message ${i}`)
            server.acknowledgeMessages(bobToken, [bobInbox.messages[0].id])

            // Bob -> Alice
            const msgB = prepareOutgoingMessage(
                bobAgent,
                aliceIdentity,
                stringToBytes(`Bob message ${i}`),
                `bob-msg-${i}`
            )
            server.sendMessage(bobToken, `bob-msg-${i}`, aliceIdentity, msgB.outgoing.blob, msgB.outgoing.signature)

            const aliceInbox = server.getInbox(aliceToken)
            const decB = processIncomingMessage(
                aliceAgent,
                aliceInbox.messages[0].senderId,
                aliceInbox.messages[0].blob,
                aliceInbox.messages[0].id,
                aliceInbox.messages[0].signature
            )
            expect(bytesToString(decB.plaintext)).toBe(`Bob message ${i}`)
            server.acknowledgeMessages(aliceToken, [aliceInbox.messages[0].id])
        }
    })

    it('should persist and restore agent state across restarts', async () => {
        // Setup
        const aliceAgent = createAgent(10)
        const bobAgent = createAgent(10)

        const aliceIdentity = getIdentityKey(aliceAgent)
        const bobIdentity = getIdentityKey(bobAgent)

        const aliceProfile = createProfileForRegistration(
            { firstName: 'Alice' },
            aliceAgent.keyStore.identityKeyPair.privateKey
        )
        const bobProfile = createProfileForRegistration(
            { firstName: 'Bob' },
            bobAgent.keyStore.identityKeyPair.privateKey
        )

        const aliceToken = server.register(
            aliceIdentity,
            aliceProfile.profilePublicKey,
            aliceProfile.profileKeySignature,
            aliceProfile.encryptedProfile
        ).tokens.accessToken

        const bobToken = server.register(
            bobIdentity,
            bobProfile.profilePublicKey,
            bobProfile.profileKeySignature,
            bobProfile.encryptedProfile
        ).tokens.accessToken

        // Establish session and exchange a message
        const bobBundle = getPreKeyBundle(bobAgent, true)
        const { message: preKeyMessage } = createPreKeyMessage(
            aliceAgent,
            bobBundle,
            stringToBytes('Hello')
        )

        const initBlob = encodeBase64(stringToBytes(JSON.stringify(preKeyMessage)))
        const initMsgId = 'init'
        const initSig = signMessageForServer(aliceAgent, initBlob, initMsgId)
        server.sendMessage(aliceToken, initMsgId, bobIdentity, initBlob, initSig)

        const bobInbox = server.getInbox(bobToken)
        processIncomingMessage(
            bobAgent,
            bobInbox.messages[0].senderId,
            bobInbox.messages[0].blob,
            bobInbox.messages[0].id,
            bobInbox.messages[0].signature
        )
        server.acknowledgeMessages(bobToken, [bobInbox.messages[0].id])

        // Serialize both agents (simulate app restart)
        const aliceSerialized = serializeAgent(aliceAgent)
        const bobSerialized = serializeAgent(bobAgent)

        // Deserialize (simulate app restart)
        const aliceRestored = deserializeAgent(aliceSerialized)
        const bobRestored = deserializeAgent(bobSerialized)

        // Continue messaging with restored agents
        const msg = prepareOutgoingMessage(
            aliceRestored,
            bobIdentity,
            stringToBytes('Message after restart'),
            'after-restart'
        )
        server.sendMessage(aliceToken, 'after-restart', bobIdentity, msg.outgoing.blob, msg.outgoing.signature)

        const bobInbox2 = server.getInbox(bobToken)
        const dec = processIncomingMessage(
            bobRestored,
            bobInbox2.messages[0].senderId,
            bobInbox2.messages[0].blob,
            bobInbox2.messages[0].id,
            bobInbox2.messages[0].signature
        )
        expect(bytesToString(dec.plaintext)).toBe('Message after restart')
    })

    it('should establish session via server prekey bundle fetch', async () => {
        // This tests the full flow including prekey bundle upload and fetch via server
        // Uses direct server calls (not mock API) to verify signatures properly

        // === BOB SETUP (recipient) ===
        const bobAgent = createAgent(10)
        const bobIdentity = getIdentityKey(bobAgent)
        const bobBundle = getPreKeyBundle(bobAgent, false)

        const bobProfile = createProfileForRegistration(
            { firstName: 'Bob' },
            bobAgent.keyStore.identityKeyPair.privateKey
        )

        const bobAuth = server.register(
            bobIdentity,
            bobProfile.profilePublicKey,
            bobProfile.profileKeySignature,
            bobProfile.encryptedProfile
        )
        const bobToken = bobAuth.tokens.accessToken

        // Bob uploads his prekeys using new format
        const preKeys: Array<{ publicKey: string; signature: string; oneTime: boolean }> = []

        // Add signed prekey
        preKeys.push({
            publicKey: encodeBase64(bobBundle.signedPreKey),
            signature: encodeBase64(bobBundle.signedPreKeySignature),
            oneTime: false
        })

        // Add one-time prekeys
        for (const [_id, otpk] of bobAgent.keyStore.oneTimePreKeys) {
            const sig = sign(otpk.keyPair.publicKey, bobAgent.keyStore.identityKeyPair.privateKey)
            preKeys.push({
                publicKey: encodeBase64(otpk.keyPair.publicKey),
                signature: encodeBase64(sig),
                oneTime: true
            })
        }

        server.uploadPreKeys(bobToken, preKeys)

        // === ALICE SETUP (initiator) ===
        const aliceAgent = createAgent(10)
        const aliceIdentity = getIdentityKey(aliceAgent)

        const aliceProfile = createProfileForRegistration(
            { firstName: 'Alice' },
            aliceAgent.keyStore.identityKeyPair.privateKey
        )

        const aliceAuth = server.register(
            aliceIdentity,
            aliceProfile.profilePublicKey,
            aliceProfile.profileKeySignature,
            aliceProfile.encryptedProfile
        )
        const aliceToken = aliceAuth.tokens.accessToken

        // Alice fetches Bob's prekey bundle from server
        const serverBundle = server.getPreKeyBundle(aliceToken, bobIdentity)

        // Server doesn't use IDs, so we need to find the matching ID from Bob's key store
        // This is necessary because the X3DH protocol expects to match prekeys by ID
        let matchingOneTimePreKeyId: number | undefined
        if (serverBundle.oneTimePreKey) {
            const serverOtpkBytes = decodeBase64(serverBundle.oneTimePreKey.publicKey)
            for (const [id, otpk] of bobAgent.keyStore.oneTimePreKeys) {
                if (encodeBase64(otpk.keyPair.publicKey) === encodeBase64(serverOtpkBytes)) {
                    matchingOneTimePreKeyId = id
                    break
                }
            }
        }

        // Convert server bundle to protocol bundle
        const fetchedBundle: PreKeyBundle = {
            identityKey: decodeBase64(serverBundle.identityKey),
            signedPreKey: decodeBase64(serverBundle.signedPreKey.publicKey),
            signedPreKeyId: bobAgent.keyStore.signedPreKey.id, // Use Bob's actual signed prekey ID
            signedPreKeySignature: decodeBase64(serverBundle.signedPreKey.signature),
            oneTimePreKey: serverBundle.oneTimePreKey
                ? decodeBase64(serverBundle.oneTimePreKey.publicKey)
                : undefined,
            oneTimePreKeyId: matchingOneTimePreKeyId
        }

        // Verify we got a one-time prekey
        expect(fetchedBundle.oneTimePreKey).toBeDefined()
        expect(matchingOneTimePreKeyId).toBeDefined()

        // Alice initiates session using fetched bundle
        const { message: preKeyMessage } = createPreKeyMessage(
            aliceAgent,
            fetchedBundle,
            stringToBytes('Hello via server bundle!')
        )

        // Send through server with proper signature
        const initBlob = encodeBase64(stringToBytes(JSON.stringify(preKeyMessage)))
        const initMsgId = 'server-init'
        const initSig = signMessageForServer(aliceAgent, initBlob, initMsgId)
        server.sendMessage(aliceToken, initMsgId, bobIdentity, initBlob, initSig)

        // Bob receives and decrypts
        const bobInbox = server.getInbox(bobToken)
        expect(bobInbox.messages).toHaveLength(1)

        const msg = bobInbox.messages[0]
        const decrypted = processIncomingMessage(
            bobAgent,
            msg.senderId,
            msg.blob,
            msg.id,
            msg.signature
        )

        expect(bytesToString(decrypted.plaintext)).toBe('Hello via server bundle!')
        server.acknowledgeMessages(bobToken, [msg.id])

        // Continue with regular messaging
        const msg2 = prepareOutgoingMessage(
            aliceAgent,
            bobIdentity,
            stringToBytes('Second message!'),
            'msg-2'
        )
        server.sendMessage(aliceToken, 'msg-2', bobIdentity, msg2.outgoing.blob, msg2.outgoing.signature)

        const bobInbox2 = server.getInbox(bobToken)
        expect(bobInbox2.messages).toHaveLength(1)

        const dec2 = processIncomingMessage(
            bobAgent,
            bobInbox2.messages[0].senderId,
            bobInbox2.messages[0].blob,
            bobInbox2.messages[0].id,
            bobInbox2.messages[0].signature
        )
        expect(bytesToString(dec2.plaintext)).toBe('Second message!')
    })
})
