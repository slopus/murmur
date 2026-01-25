/**
 * Tests for Session management.
 */

import { describe, it, expect } from 'vitest'
import {
    createAgent,
    getIdentityKey,
    getPreKeyBundle,
    createPreKeyMessage,
    receivePreKeyMessage,
    encryptMessage,
    decryptMessage,
    hasSession,
    getSession,
    deleteSession,
    serializeAgent,
    deserializeAgent,
    signMessageForServer,
    verifyMessageSignature,
    prepareOutgoingMessage,
    processIncomingMessage,
    replenishPreKeys,
    getOneTimePreKeyCount
} from './session.js'
import { stringToBytes, bytesToString } from '../crypto/utils.js'

describe('Agent creation', () => {
    it('should create agent with keys', () => {
        const agent = createAgent(10)

        expect(agent.keyStore).toBeDefined()
        expect(agent.keyStore.identityKeyPair).toBeDefined()
        expect(agent.keyStore.signedPreKey).toBeDefined()
        expect(agent.keyStore.oneTimePreKeys.size).toBe(10)
        expect(agent.sessions.size).toBe(0)
    })

    it('should generate unique identity keys', () => {
        const agent1 = createAgent()
        const agent2 = createAgent()

        expect(getIdentityKey(agent1)).not.toBe(getIdentityKey(agent2))
    })
})

describe('Prekey bundle', () => {
    it('should create bundle with one-time prekey', () => {
        const agent = createAgent(10)
        const bundle = getPreKeyBundle(agent, true)

        expect(bundle.identityKey).toBeDefined()
        expect(bundle.signedPreKey).toBeDefined()
        expect(bundle.signedPreKeySignature).toBeDefined()
        expect(bundle.oneTimePreKey).toBeDefined()
    })

    it('should create bundle without one-time prekey', () => {
        const agent = createAgent(10)
        const bundle = getPreKeyBundle(agent, false)

        expect(bundle.oneTimePreKey).toBeUndefined()
    })

    it('should handle empty one-time prekey pool', () => {
        const agent = createAgent(0)
        const bundle = getPreKeyBundle(agent, true)

        expect(bundle.oneTimePreKey).toBeUndefined()
    })
})

describe('Session establishment', () => {
    it('should establish session via createPreKeyMessage', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        const bobBundle = getPreKeyBundle(bob, true)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Hello Bob!'))

        expect(message.type).toBe('message')
        expect(message.identityDHKey).toBeDefined()
        expect(message.ephemeralKey).toBeDefined()
        expect(message.header).toBeDefined()
        expect(message.ciphertext).toBeDefined()

        // Alice should have session
        expect(hasSession(alice, getIdentityKey(bob))).toBe(true)
    })

    it('should establish session via receivePreKeyMessage', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        const bobBundle = getPreKeyBundle(bob, true)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Hello Bob!'))

        // Bob receives and processes
        const result = receivePreKeyMessage(bob, getIdentityKey(alice), message)

        expect(bytesToString(result.plaintext)).toBe('Hello Bob!')
        expect(hasSession(bob, getIdentityKey(alice))).toBe(true)
    })

    it('should retain one-time prekeys after pre-key message', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        const initialCount = getOneTimePreKeyCount(bob)
        const bobBundle = getPreKeyBundle(bob, true)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Hello'))

        receivePreKeyMessage(bob, getIdentityKey(alice), message)

        expect(getOneTimePreKeyCount(bob)).toBe(initialCount)
    })
})

describe('Message exchange', () => {
    function setupSession() {
        const alice = createAgent(10)
        const bob = createAgent(10)

        const bobBundle = getPreKeyBundle(bob, true)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Hello'))
        receivePreKeyMessage(bob, getIdentityKey(alice), message)

        return { alice, bob }
    }

    it('should encrypt and decrypt messages', () => {
        const { alice, bob } = setupSession()

        // Alice sends
        const msg1 = encryptMessage(alice, getIdentityKey(bob), stringToBytes('Message 1'))
        expect(msg1.type).toBe('message')

        // Bob decrypts
        const dec1 = decryptMessage(bob, getIdentityKey(alice), msg1)
        expect(bytesToString(dec1.plaintext)).toBe('Message 1')
    })

    it('should support bidirectional messaging', () => {
        const { alice, bob } = setupSession()

        // Alice → Bob
        const msg1 = encryptMessage(alice, getIdentityKey(bob), stringToBytes('From Alice'))
        const dec1 = decryptMessage(bob, getIdentityKey(alice), msg1)
        expect(bytesToString(dec1.plaintext)).toBe('From Alice')

        // Bob → Alice
        const msg2 = encryptMessage(bob, getIdentityKey(alice), stringToBytes('From Bob'))
        const dec2 = decryptMessage(alice, getIdentityKey(bob), msg2)
        expect(bytesToString(dec2.plaintext)).toBe('From Bob')
    })

    it('should handle multiple messages', () => {
        const { alice, bob } = setupSession()

        for (let i = 0; i < 10; i++) {
            const msg = encryptMessage(alice, getIdentityKey(bob), stringToBytes(`Message ${i}`))
            const dec = decryptMessage(bob, getIdentityKey(alice), msg)
            expect(bytesToString(dec.plaintext)).toBe(`Message ${i}`)
        }
    })

    it('should throw when encrypting without session', () => {
        const alice = createAgent()
        const fakeId = 'nonexistent'

        expect(() => encryptMessage(alice, fakeId, stringToBytes('test'))).toThrow()
    })

    it('should throw when decrypting without session', () => {
        const alice = createAgent()
        const fakeMessage = { type: 'message' as const, header: 'x', ciphertext: 'y' }

        expect(() => decryptMessage(alice, 'nonexistent', fakeMessage)).toThrow()
    })
})

describe('Session management', () => {
    it('should check session existence', () => {
        const alice = createAgent()
        const bob = createAgent()

        expect(hasSession(alice, getIdentityKey(bob))).toBe(false)

        const bobBundle = getPreKeyBundle(bob)
        createPreKeyMessage(alice, bobBundle, stringToBytes('Hi'))

        expect(hasSession(alice, getIdentityKey(bob))).toBe(true)
    })

    it('should get session', () => {
        const alice = createAgent()
        const bob = createAgent()

        expect(getSession(alice, getIdentityKey(bob))).toBeUndefined()

        const bobBundle = getPreKeyBundle(bob)
        createPreKeyMessage(alice, bobBundle, stringToBytes('Hi'))

        const session = getSession(alice, getIdentityKey(bob))
        expect(session).toBeDefined()
        expect(session!.establishedAt).toBeLessThanOrEqual(Date.now())
    })

    it('should delete session', () => {
        const alice = createAgent()
        const bob = createAgent()

        const bobBundle = getPreKeyBundle(bob)
        createPreKeyMessage(alice, bobBundle, stringToBytes('Hi'))

        expect(hasSession(alice, getIdentityKey(bob))).toBe(true)
        expect(deleteSession(alice, getIdentityKey(bob))).toBe(true)
        expect(hasSession(alice, getIdentityKey(bob))).toBe(false)
    })
})

describe('State persistence', () => {
    it('should serialize and deserialize agent', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        // Establish session
        const bobBundle = getPreKeyBundle(bob)
        createPreKeyMessage(alice, bobBundle, stringToBytes('Hi'))

        // Serialize
        const serialized = serializeAgent(alice)
        const json = JSON.stringify(serialized)

        // Deserialize
        const restored = deserializeAgent(JSON.parse(json))

        expect(getIdentityKey(restored)).toBe(getIdentityKey(alice))
        expect(hasSession(restored, getIdentityKey(bob))).toBe(true)
    })

    it('should continue messaging after restore', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        // Setup session
        const bobBundle = getPreKeyBundle(bob)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('First'))
        receivePreKeyMessage(bob, getIdentityKey(alice), message)

        // Exchange a message
        const msg1 = encryptMessage(alice, getIdentityKey(bob), stringToBytes('Before restore'))
        decryptMessage(bob, getIdentityKey(alice), msg1)

        // Serialize both
        const aliceSerialized = serializeAgent(alice)
        const bobSerialized = serializeAgent(bob)

        // Restore both
        const aliceRestored = deserializeAgent(aliceSerialized)
        const bobRestored = deserializeAgent(bobSerialized)

        // Continue conversation
        const msg2 = encryptMessage(aliceRestored, getIdentityKey(bob), stringToBytes('After restore'))
        const dec = decryptMessage(bobRestored, getIdentityKey(alice), msg2)
        expect(bytesToString(dec.plaintext)).toBe('After restore')
    })
})

describe('Server message signing', () => {
    it('should sign messages', () => {
        const agent = createAgent()
        const blob = 'encrypted-blob'
        const messageId = 'msg123'

        const signature = signMessageForServer(agent, blob, messageId)
        expect(signature).toBeDefined()
        expect(signature.length).toBeGreaterThan(0)
    })

    it('should verify valid signatures', () => {
        const agent = createAgent()
        const blob = 'encrypted-blob'
        const messageId = 'msg123'

        const signature = signMessageForServer(agent, blob, messageId)
        const isValid = verifyMessageSignature(getIdentityKey(agent), blob, messageId, signature)

        expect(isValid).toBe(true)
    })

    it('should reject invalid signatures', () => {
        const agent = createAgent()
        const other = createAgent()
        const blob = 'encrypted-blob'
        const messageId = 'msg123'

        const signature = signMessageForServer(agent, blob, messageId)
        const isValid = verifyMessageSignature(getIdentityKey(other), blob, messageId, signature)

        expect(isValid).toBe(false)
    })

    it('should reject tampered messages', () => {
        const agent = createAgent()
        const blob = 'encrypted-blob'
        const messageId = 'msg123'

        const signature = signMessageForServer(agent, blob, messageId)
        const isValid = verifyMessageSignature(getIdentityKey(agent), 'tampered-blob', messageId, signature)

        expect(isValid).toBe(false)
    })
})

describe('Full server message flow', () => {
    it('should prepare and process messages', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        // Setup session
        const bobBundle = getPreKeyBundle(bob)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Init'))
        receivePreKeyMessage(bob, getIdentityKey(alice), message)

        // Alice prepares message for server
        const messageId = 'test-msg-1'
        const { outgoing } = prepareOutgoingMessage(
            alice,
            getIdentityKey(bob),
            stringToBytes('Hello via server'),
            messageId
        )

        expect(outgoing.recipientId).toBe(getIdentityKey(bob))
        expect(outgoing.blob).toBeDefined()
        expect(outgoing.signature).toBeDefined()

        // Bob processes message from server
        const result = processIncomingMessage(
            bob,
            getIdentityKey(alice),
            outgoing.blob,
            messageId,
            outgoing.signature
        )

        expect(bytesToString(result.plaintext)).toBe('Hello via server')
    })

    it('should reject messages with invalid signature', () => {
        const alice = createAgent(10)
        const bob = createAgent(10)

        // Setup session
        const bobBundle = getPreKeyBundle(bob)
        const { message } = createPreKeyMessage(alice, bobBundle, stringToBytes('Init'))
        receivePreKeyMessage(bob, getIdentityKey(alice), message)

        // Alice prepares message
        const messageId = 'test-msg-1'
        const { outgoing } = prepareOutgoingMessage(
            alice,
            getIdentityKey(bob),
            stringToBytes('Hello'),
            messageId
        )

        // Tamper with signature
        expect(() => processIncomingMessage(
            bob,
            getIdentityKey(alice),
            outgoing.blob,
            messageId,
            'invalid-signature'
        )).toThrow('Invalid message signature')
    })
})

describe('Prekey replenishment', () => {
    it('should replenish one-time prekeys', () => {
        const agent = createAgent(5)
        expect(getOneTimePreKeyCount(agent)).toBe(5)

        const newKeys = replenishPreKeys(agent, 10)
        expect(newKeys.length).toBe(5)
        expect(getOneTimePreKeyCount(agent)).toBe(10)
    })

    it('should not replenish if already at target', () => {
        const agent = createAgent(10)
        const newKeys = replenishPreKeys(agent, 5)

        expect(newKeys.length).toBe(0)
        expect(getOneTimePreKeyCount(agent)).toBe(10)
    })
})
