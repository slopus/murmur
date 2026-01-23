/**
 * Full end-to-end flow tests.
 *
 * Tests the complete message encryption/decryption flow using
 * the session API and mock server.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { MockServer } from './mockServer.js'
import {
    createAgent,
    getIdentityKey,
    getPreKeyBundle,
    initiateSession,
    receiveSessionInit,
    serializeAgent,
    deserializeAgent,
    prepareOutgoingMessage,
    processIncomingMessage
} from '../encryption/session/session.js'
import {
    encodeBase64,
    stringToBytes,
    bytesToString
} from '../encryption/crypto/utils.js'
import { sign } from '../encryption/crypto/signing.js'
import { createProfileForRegistration, type Profile } from './profile.js'

describe('Full end-to-end encrypted messaging flow', () => {
    let server: MockServer

    beforeEach(() => {
        server = new MockServer()
    })

    it('should complete full registration and messaging flow', async () => {
        // === ALICE SETUP ===
        // Create agent with encryption keys
        const aliceAgent = createAgent(100)
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
        const bobAgent = createAgent(100)
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

        // Alice initiates session with initial message
        const { sessionInitMessage } = initiateSession(
            aliceAgent,
            bobBundle,
            stringToBytes('Hello Bob! This is our first secure message.')
        )

        // Alice sends session init message through server
        const sessionMsgBlob = encodeBase64(stringToBytes(JSON.stringify(sessionInitMessage)))
        const sessionMsgId = 'session-init-1'
        const sessionMsgSig = encodeBase64(sign(
            stringToBytes(sessionMsgBlob + sessionMsgId),
            aliceAgent.keyStore.identityKeyPair.privateKey
        ))

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
        expect(decrypted.isSessionInit).toBe(true)

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
        const { sessionInitMessage } = initiateSession(
            aliceAgent,
            bobBundle,
            stringToBytes('Init')
        )

        // Send session init through server
        const initBlob = encodeBase64(stringToBytes(JSON.stringify(sessionInitMessage)))
        const initSig = encodeBase64(sign(
            stringToBytes(initBlob + 'init-msg'),
            aliceAgent.keyStore.identityKeyPair.privateKey
        ))
        server.sendMessage(aliceToken, 'init-msg', bobIdentity, initBlob, initSig)

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
        const { sessionInitMessage } = initiateSession(
            aliceAgent,
            bobBundle,
            stringToBytes('Hello')
        )

        const initBlob = encodeBase64(stringToBytes(JSON.stringify(sessionInitMessage)))
        const initSig = encodeBase64(sign(
            stringToBytes(initBlob + 'init'),
            aliceAgent.keyStore.identityKeyPair.privateKey
        ))
        server.sendMessage(aliceToken, 'init', bobIdentity, initBlob, initSig)

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
})
