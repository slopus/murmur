/**
 * Tests for Double Ratchet algorithm.
 *
 * These tests verify the core functionality of the ratchet:
 * - Basic encryption/decryption
 * - DH ratchet stepping
 * - Out-of-order message handling
 * - Forward secrecy properties
 * - Error handling
 */

import { describe, it, expect } from 'vitest'
import {
    initializeAlice,
    initializeBob,
    ratchetEncrypt,
    ratchetDecrypt,
    getSkippedKeyCount,
    clearSkippedKeys
} from './ratchet.js'
import { serializeState, deserializeState, cloneState } from './state.js'
import { generateDH } from '../crypto/dh.js'
import { getRandomBytes, stringToBytes, bytesToString, constantTimeEqual } from '../crypto/utils.js'

/**
 * Helper to create initialized Alice and Bob states.
 */
function createSession() {
    const sharedSecret = getRandomBytes(32)
    const bobKeyPair = generateDH()

    const alice = initializeAlice(sharedSecret, bobKeyPair.publicKey)
    const bob = initializeBob(sharedSecret, bobKeyPair)

    return { alice, bob, sharedSecret }
}

describe('Session initialization', () => {
    it('should initialize Alice with sending chain', () => {
        const { alice } = createSession()

        expect(alice.dhSelf).toBeDefined()
        expect(alice.dhRemote).toBeDefined()
        expect(alice.rootKey).toBeDefined()
        expect(alice.sendingChainKey).not.toBeNull()
        expect(alice.receivingChainKey).toBeNull() // Not set until first receive
        expect(alice.sendingMessageNumber).toBe(0)
    })

    it('should initialize Bob without sending chain', () => {
        const { bob } = createSession()

        expect(bob.dhSelf).toBeDefined()
        expect(bob.dhRemote).toBeNull() // Not set until first receive
        expect(bob.rootKey).toBeDefined()
        expect(bob.sendingChainKey).toBeNull() // Not set until first receive
        expect(bob.receivingChainKey).toBeNull()
        expect(bob.sendingMessageNumber).toBe(0)
    })

    it('should throw on invalid shared secret length', () => {
        const bobKeyPair = generateDH()

        expect(() => initializeAlice(getRandomBytes(16), bobKeyPair.publicKey)).toThrow()
        expect(() => initializeBob(getRandomBytes(16), bobKeyPair)).toThrow()
    })
})

describe('Basic encryption/decryption', () => {
    it('should encrypt and decrypt a single message', () => {
        const { alice, bob } = createSession()
        const plaintext = stringToBytes('Hello, Bob!')

        const message = ratchetEncrypt(alice, plaintext)
        const decrypted = ratchetDecrypt(bob, message)

        expect(bytesToString(decrypted)).toBe('Hello, Bob!')
    })

    it('should encrypt and decrypt multiple messages from Alice', () => {
        const { alice, bob } = createSession()

        for (let i = 0; i < 5; i++) {
            const plaintext = stringToBytes(`Message ${i}`)
            const message = ratchetEncrypt(alice, plaintext)
            const decrypted = ratchetDecrypt(bob, message)
            expect(bytesToString(decrypted)).toBe(`Message ${i}`)
        }
    })

    it('should allow Bob to send after receiving', () => {
        const { alice, bob } = createSession()

        // Alice sends first
        const msg1 = ratchetEncrypt(alice, stringToBytes('Hello Bob'))
        ratchetDecrypt(bob, msg1)

        // Now Bob can send
        const msg2 = ratchetEncrypt(bob, stringToBytes('Hello Alice'))
        const decrypted = ratchetDecrypt(alice, msg2)

        expect(bytesToString(decrypted)).toBe('Hello Alice')
    })

    it('should handle ping-pong conversation', () => {
        const { alice, bob } = createSession()
        const messages = [
            { sender: 'alice', text: 'Hello Bob' },
            { sender: 'bob', text: 'Hi Alice' },
            { sender: 'alice', text: 'How are you?' },
            { sender: 'bob', text: 'Good, thanks!' },
            { sender: 'alice', text: 'Great!' }
        ]

        for (const { sender, text } of messages) {
            if (sender === 'alice') {
                const msg = ratchetEncrypt(alice, stringToBytes(text))
                const dec = ratchetDecrypt(bob, msg)
                expect(bytesToString(dec)).toBe(text)
            } else {
                const msg = ratchetEncrypt(bob, stringToBytes(text))
                const dec = ratchetDecrypt(alice, msg)
                expect(bytesToString(dec)).toBe(text)
            }
        }
    })

    it('should handle empty messages', () => {
        const { alice, bob } = createSession()
        const plaintext = new Uint8Array(0)

        const message = ratchetEncrypt(alice, plaintext)
        const decrypted = ratchetDecrypt(bob, message)

        expect(decrypted.length).toBe(0)
    })

    it('should handle large messages', () => {
        const { alice, bob } = createSession()
        const plaintext = getRandomBytes(100000) // 100KB

        const message = ratchetEncrypt(alice, plaintext)
        const decrypted = ratchetDecrypt(bob, message)

        expect(constantTimeEqual(decrypted, plaintext)).toBe(true)
    })

    it('should handle binary data', () => {
        const { alice, bob } = createSession()
        const plaintext = new Uint8Array([0x00, 0xff, 0x7f, 0x80, 0xfe, 0x01])

        const message = ratchetEncrypt(alice, plaintext)
        const decrypted = ratchetDecrypt(bob, message)

        expect(constantTimeEqual(decrypted, plaintext)).toBe(true)
    })
})

describe('Associated data', () => {
    it('should authenticate associated data', () => {
        const { alice, bob } = createSession()
        const plaintext = stringToBytes('Secret')
        const ad = stringToBytes('public context')

        const message = ratchetEncrypt(alice, plaintext, ad)
        const decrypted = ratchetDecrypt(bob, message, ad)

        expect(bytesToString(decrypted)).toBe('Secret')
    })

    it('should fail with wrong associated data', () => {
        const { alice, bob } = createSession()
        const plaintext = stringToBytes('Secret')
        const ad1 = stringToBytes('correct AD')
        const ad2 = stringToBytes('wrong AD')

        const message = ratchetEncrypt(alice, plaintext, ad1)

        expect(() => ratchetDecrypt(bob, message, ad2)).toThrow()
    })
})

describe('Out-of-order messages', () => {
    it('should handle skipped messages', () => {
        const { alice, bob } = createSession()

        // Alice sends 3 messages
        const msg1 = ratchetEncrypt(alice, stringToBytes('Message 1'))
        const msg2 = ratchetEncrypt(alice, stringToBytes('Message 2'))
        const msg3 = ratchetEncrypt(alice, stringToBytes('Message 3'))

        // Bob receives them out of order: 3, 1, 2
        expect(bytesToString(ratchetDecrypt(bob, msg3))).toBe('Message 3')
        expect(getSkippedKeyCount(bob)).toBe(2) // Skipped msg1 and msg2

        expect(bytesToString(ratchetDecrypt(bob, msg1))).toBe('Message 1')
        expect(getSkippedKeyCount(bob)).toBe(1) // msg2 still skipped

        expect(bytesToString(ratchetDecrypt(bob, msg2))).toBe('Message 2')
        expect(getSkippedKeyCount(bob)).toBe(0) // All consumed
    })

    it('should handle heavily out-of-order messages', () => {
        const { alice, bob } = createSession()

        // Alice sends 10 messages
        const messages = []
        for (let i = 0; i < 10; i++) {
            messages.push({
                index: i,
                encrypted: ratchetEncrypt(alice, stringToBytes(`Message ${i}`))
            })
        }

        // Shuffle the messages
        const shuffled = [...messages].sort(() => Math.random() - 0.5)

        // Bob decrypts in shuffled order
        for (const { index, encrypted } of shuffled) {
            const decrypted = ratchetDecrypt(bob, encrypted)
            expect(bytesToString(decrypted)).toBe(`Message ${index}`)
        }

        // All skipped keys should be consumed
        expect(getSkippedKeyCount(bob)).toBe(0)
    })

    it('should throw when skip exceeds maxSkip', () => {
        const { alice, bob } = createSession()

        // Send one message, then skip many
        ratchetEncrypt(alice, stringToBytes('First'))

        // Skip 100 messages
        for (let i = 0; i < 100; i++) {
            ratchetEncrypt(alice, stringToBytes(`Skip ${i}`))
        }

        const farAhead = ratchetEncrypt(alice, stringToBytes('Far ahead'))

        // Should throw with default maxSkip (1000) - this is fine
        // But with very low maxSkip, it should fail
        expect(() => ratchetDecrypt(bob, farAhead, undefined, { maxSkip: 50 })).toThrow()
    })

    it('should handle out-of-order across DH ratchets', () => {
        const { alice, bob } = createSession()

        // Alice sends msg1
        const msg1 = ratchetEncrypt(alice, stringToBytes('From Alice 1'))

        // Bob receives and replies (DH ratchet)
        ratchetDecrypt(bob, msg1)
        const msg2 = ratchetEncrypt(bob, stringToBytes('From Bob 1'))

        // Alice receives and sends more (another DH ratchet)
        ratchetDecrypt(alice, msg2)
        const msg3 = ratchetEncrypt(alice, stringToBytes('From Alice 2'))
        const msg4 = ratchetEncrypt(alice, stringToBytes('From Alice 3'))

        // Bob receives msg4 before msg3 (out of order within same chain)
        expect(bytesToString(ratchetDecrypt(bob, msg4))).toBe('From Alice 3')
        expect(bytesToString(ratchetDecrypt(bob, msg3))).toBe('From Alice 2')
    })
})

describe('Message replay protection', () => {
    it('should fail to decrypt same message twice', () => {
        const { alice, bob } = createSession()

        const message = ratchetEncrypt(alice, stringToBytes('Hello'))

        // First decryption succeeds
        ratchetDecrypt(bob, message)

        // Second decryption fails (message key already consumed)
        expect(() => ratchetDecrypt(bob, message)).toThrow()
    })

    it('should fail to decrypt out-of-order message twice', () => {
        const { alice, bob } = createSession()

        const msg1 = ratchetEncrypt(alice, stringToBytes('First'))
        const msg2 = ratchetEncrypt(alice, stringToBytes('Second'))

        // Receive second first (stores key for first)
        ratchetDecrypt(bob, msg2)

        // Receive first
        ratchetDecrypt(bob, msg1)

        // Try to receive first again - should fail
        expect(() => ratchetDecrypt(bob, msg1)).toThrow()
    })
})

describe('Error handling', () => {
    it('should throw when Bob tries to send before receiving', () => {
        const sharedSecret = getRandomBytes(32)
        const bobKeyPair = generateDH()
        const bob = initializeBob(sharedSecret, bobKeyPair)

        expect(() => ratchetEncrypt(bob, stringToBytes('Hello'))).toThrow()
    })

    it('should throw on tampered ciphertext', () => {
        const { alice, bob } = createSession()

        const message = ratchetEncrypt(alice, stringToBytes('Secret'))
        message.ciphertext[0] ^= 0x01 // Flip a bit

        expect(() => ratchetDecrypt(bob, message)).toThrow()
    })

    it('should throw on tampered header', () => {
        const { alice, bob } = createSession()

        const message = ratchetEncrypt(alice, stringToBytes('Secret'))
        // Modify the public key in header
        message.header.publicKey = generateDH().publicKey

        expect(() => ratchetDecrypt(bob, message)).toThrow()
    })
})

describe('State persistence', () => {
    it('should serialize and restore state correctly', () => {
        const { alice, bob } = createSession()

        // Exchange some messages
        const msg1 = ratchetEncrypt(alice, stringToBytes('Hello'))
        ratchetDecrypt(bob, msg1)
        const msg2 = ratchetEncrypt(bob, stringToBytes('Hi'))
        ratchetDecrypt(alice, msg2)

        // Serialize both states
        const aliceSerialized = serializeState(alice)
        const bobSerialized = serializeState(bob)

        // Restore states
        const aliceRestored = deserializeState(aliceSerialized)
        const bobRestored = deserializeState(bobSerialized)

        // Continue conversation with restored states
        const msg3 = ratchetEncrypt(aliceRestored, stringToBytes('Restored Alice'))
        const decrypted = ratchetDecrypt(bobRestored, msg3)

        expect(bytesToString(decrypted)).toBe('Restored Alice')
    })

    it('should preserve skipped keys across serialization', () => {
        const { alice, bob } = createSession()

        // Alice sends 3 messages
        const msg1 = ratchetEncrypt(alice, stringToBytes('One'))
        const msg2 = ratchetEncrypt(alice, stringToBytes('Two'))
        const msg3 = ratchetEncrypt(alice, stringToBytes('Three'))

        // Bob receives only msg3 (skips msg1, msg2)
        ratchetDecrypt(bob, msg3)
        expect(getSkippedKeyCount(bob)).toBe(2)

        // Serialize and restore Bob's state
        const bobSerialized = serializeState(bob)
        const bobRestored = deserializeState(bobSerialized)

        // Should still have skipped keys
        expect(getSkippedKeyCount(bobRestored)).toBe(2)

        // Should be able to decrypt skipped messages
        expect(bytesToString(ratchetDecrypt(bobRestored, msg1))).toBe('One')
        expect(bytesToString(ratchetDecrypt(bobRestored, msg2))).toBe('Two')
    })
})

describe('Forward secrecy', () => {
    it('should not decrypt past messages with current state', () => {
        const { alice, bob } = createSession()

        // Alice sends a message
        const msg1 = ratchetEncrypt(alice, stringToBytes('Past message'))

        // Bob receives it
        ratchetDecrypt(bob, msg1)

        // Exchange more messages to advance the ratchet
        const msg2 = ratchetEncrypt(bob, stringToBytes('Reply'))
        ratchetDecrypt(alice, msg2)

        const msg3 = ratchetEncrypt(alice, stringToBytes('Current'))
        ratchetDecrypt(bob, msg3)

        // Clone Bob's current state (simulating key compromise)
        const bobCompromised = cloneState(bob)

        // The compromised state should not be able to decrypt msg1
        // because the keys have been ratcheted forward
        expect(() => ratchetDecrypt(bobCompromised, msg1)).toThrow()
    })
})

describe('Skipped key management', () => {
    it('should clear skipped keys', () => {
        const { alice, bob } = createSession()

        // Create some skipped keys
        const msg1 = ratchetEncrypt(alice, stringToBytes('One'))
        const msg2 = ratchetEncrypt(alice, stringToBytes('Two'))
        const msg3 = ratchetEncrypt(alice, stringToBytes('Three'))

        ratchetDecrypt(bob, msg3) // Skip 1 and 2
        expect(getSkippedKeyCount(bob)).toBe(2)

        // Clear skipped keys
        const cleared = clearSkippedKeys(bob)
        expect(cleared).toBe(2)
        expect(getSkippedKeyCount(bob)).toBe(0)

        // Now msg1 and msg2 cannot be decrypted
        expect(() => ratchetDecrypt(bob, msg1)).toThrow()
        expect(() => ratchetDecrypt(bob, msg2)).toThrow()
    })
})

describe('DH ratchet advancement', () => {
    it('should advance DH ratchet on each direction change', () => {
        const { alice, bob } = createSession()

        // Track Alice's public key
        let aliceLastPubKey = alice.dhSelf.publicKey

        // Alice sends (no change expected yet)
        const msg1 = ratchetEncrypt(alice, stringToBytes('A1'))
        expect(constantTimeEqual(alice.dhSelf.publicKey, aliceLastPubKey)).toBe(true)

        // Bob receives and replies (Alice will ratchet on receive)
        ratchetDecrypt(bob, msg1)
        const msg2 = ratchetEncrypt(bob, stringToBytes('B1'))

        // Alice receives (DH ratchet - new key pair)
        ratchetDecrypt(alice, msg2)
        expect(constantTimeEqual(alice.dhSelf.publicKey, aliceLastPubKey)).toBe(false)
        aliceLastPubKey = alice.dhSelf.publicKey

        // Alice sends again (same key pair)
        const msg3 = ratchetEncrypt(alice, stringToBytes('A2'))
        expect(constantTimeEqual(alice.dhSelf.publicKey, aliceLastPubKey)).toBe(true)

        // Verify decryption still works
        expect(bytesToString(ratchetDecrypt(bob, msg3))).toBe('A2')
    })
})
