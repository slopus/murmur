/**
 * Integration tests for complete X3DH → Double Ratchet flow.
 *
 * These tests verify the full protocol works end-to-end:
 * 1. X3DH key agreement to establish shared secret
 * 2. Double Ratchet initialization from shared secret
 * 3. Bidirectional message exchange
 * 4. State persistence and recovery
 */

import { describe, it, expect } from 'vitest'
import {
    // X3DH
    initializeKeyStore,
    createPreKeyBundle,
    x3dhSender,
    x3dhReceiver,
    consumeOneTimePreKey,
    serializeKeyStore,
    deserializeKeyStore,
    type X3DHReceiverKeys
} from './encryption/x3dh/index.js'
import {
    // Double Ratchet
    initializeAlice,
    initializeBob,
    ratchetEncrypt,
    ratchetDecrypt,
    serializeState,
    deserializeState,
    type RatchetState
} from './encryption/ratchet/index.js'
import {
    stringToBytes,
    bytesToString,
    constantTimeEqual
} from './encryption/crypto/utils.js'
import type { DHKeyPair } from './encryption/crypto/dh.js'

function findOneTimePreKeyId(
    store: ReturnType<typeof initializeKeyStore>,
    publicKey?: Uint8Array
): number | undefined {
    if (!publicKey) return undefined
    for (const [id, otpk] of store.oneTimePreKeys) {
        if (constantTimeEqual(otpk.keyPair.publicKey, publicKey)) {
            return id
        }
    }
    return undefined
}

/**
 * Complete session state combining X3DH keys and ratchet state.
 */
interface Session {
    ratchetState: RatchetState
    peerIdentityKey: Uint8Array
}

describe('Full Protocol Integration', () => {
    it('should complete X3DH → Double Ratchet conversation', () => {
        // === SETUP ===
        // Bob publishes his prekey bundle (normally done once, stored on server)
        const bobKeyStore = initializeKeyStore(10)
        const bobBundle = createPreKeyBundle(
            bobKeyStore.identityKeyPair,
            bobKeyStore.signedPreKey,
            bobKeyStore.oneTimePreKeys.get(1)
        )

        // Alice fetches Bob's bundle (normally from server)
        const aliceKeyStore = initializeKeyStore(10)

        // === X3DH KEY AGREEMENT ===
        // Alice initiates session
        const aliceX3DHResult = x3dhSender(aliceKeyStore.identityKeyPair, bobBundle)

        // Bob receives Alice's initiation
        const usedOTPKId = findOneTimePreKeyId(bobKeyStore, bobBundle.oneTimePreKey)
        const usedOTPK = usedOTPKId ? consumeOneTimePreKey(bobKeyStore, usedOTPKId) : undefined
        const bobReceiverKeys: X3DHReceiverKeys = {
            identityKeyPair: bobKeyStore.identityKeyPair,
            signedPreKey: bobKeyStore.signedPreKey,
            oneTimePreKey: usedOTPK
        }
        const bobX3DHResult = x3dhReceiver(
            bobReceiverKeys,
            aliceKeyStore.identityKeyPair.publicKey,
            aliceX3DHResult.aliceIdentityDHKey,
            aliceX3DHResult.ephemeralPublicKey
        )

        // Verify shared secrets match
        expect(constantTimeEqual(aliceX3DHResult.sharedSecret, bobX3DHResult.sharedSecret)).toBe(true)

        // === DOUBLE RATCHET INITIALIZATION ===
        // Alice uses Bob's signed prekey as the initial ratchet key
        const bobRatchetKeyPair: DHKeyPair = bobKeyStore.signedPreKey.keyPair

        const aliceSession: Session = {
            ratchetState: initializeAlice(aliceX3DHResult.sharedSecret, aliceX3DHResult.bobSignedPreKey),
            peerIdentityKey: bobKeyStore.identityKeyPair.publicKey
        }

        const bobSession: Session = {
            ratchetState: initializeBob(bobX3DHResult.sharedSecret, bobRatchetKeyPair),
            peerIdentityKey: aliceKeyStore.identityKeyPair.publicKey
        }

        // === MESSAGE EXCHANGE ===
        // Alice sends first message
        const msg1Plain = 'Hello Bob! This is Alice.'
        const msg1Encrypted = ratchetEncrypt(aliceSession.ratchetState, stringToBytes(msg1Plain))
        const msg1Decrypted = ratchetDecrypt(bobSession.ratchetState, msg1Encrypted)
        expect(bytesToString(msg1Decrypted)).toBe(msg1Plain)

        // Bob replies
        const msg2Plain = 'Hi Alice! Nice to meet you securely.'
        const msg2Encrypted = ratchetEncrypt(bobSession.ratchetState, stringToBytes(msg2Plain))
        const msg2Decrypted = ratchetDecrypt(aliceSession.ratchetState, msg2Encrypted)
        expect(bytesToString(msg2Decrypted)).toBe(msg2Plain)

        // Alice sends another message
        const msg3Plain = 'Our conversation is end-to-end encrypted!'
        const msg3Encrypted = ratchetEncrypt(aliceSession.ratchetState, stringToBytes(msg3Plain))
        const msg3Decrypted = ratchetDecrypt(bobSession.ratchetState, msg3Encrypted)
        expect(bytesToString(msg3Decrypted)).toBe(msg3Plain)

        // Bob sends multiple messages
        for (let i = 0; i < 5; i++) {
            const msgPlain = `Bob message ${i}`
            const msgEncrypted = ratchetEncrypt(bobSession.ratchetState, stringToBytes(msgPlain))
            const msgDecrypted = ratchetDecrypt(aliceSession.ratchetState, msgEncrypted)
            expect(bytesToString(msgDecrypted)).toBe(msgPlain)
        }
    })

    it('should handle out-of-order messages after X3DH', () => {
        // Setup X3DH
        const bobKeyStore = initializeKeyStore(10)
        const aliceKeyStore = initializeKeyStore(10)
        const bobBundle = createPreKeyBundle(
            bobKeyStore.identityKeyPair,
            bobKeyStore.signedPreKey,
            bobKeyStore.oneTimePreKeys.get(1)
        )

        // Key agreement
        const aliceX3DH = x3dhSender(aliceKeyStore.identityKeyPair, bobBundle)
        const bobX3DH = x3dhReceiver(
            {
                identityKeyPair: bobKeyStore.identityKeyPair,
                signedPreKey: bobKeyStore.signedPreKey,
                oneTimePreKey: (() => {
                    const otpkId = findOneTimePreKeyId(bobKeyStore, bobBundle.oneTimePreKey)
                    return otpkId ? consumeOneTimePreKey(bobKeyStore, otpkId) : undefined
                })()
            },
            aliceKeyStore.identityKeyPair.publicKey,
            aliceX3DH.aliceIdentityDHKey,
            aliceX3DH.ephemeralPublicKey
        )

        // Initialize ratchets
        const aliceRatchet = initializeAlice(aliceX3DH.sharedSecret, aliceX3DH.bobSignedPreKey)
        const bobRatchet = initializeBob(bobX3DH.sharedSecret, bobKeyStore.signedPreKey.keyPair)

        // Alice sends 3 messages
        const msg1 = ratchetEncrypt(aliceRatchet, stringToBytes('Message 1'))
        const msg2 = ratchetEncrypt(aliceRatchet, stringToBytes('Message 2'))
        const msg3 = ratchetEncrypt(aliceRatchet, stringToBytes('Message 3'))

        // Bob receives out of order: 3, 1, 2
        expect(bytesToString(ratchetDecrypt(bobRatchet, msg3))).toBe('Message 3')
        expect(bytesToString(ratchetDecrypt(bobRatchet, msg1))).toBe('Message 1')
        expect(bytesToString(ratchetDecrypt(bobRatchet, msg2))).toBe('Message 2')
    })

    it('should persist and restore session state', () => {
        // Setup X3DH
        const bobKeyStore = initializeKeyStore(10)
        const aliceKeyStore = initializeKeyStore(10)
        const bobBundle = createPreKeyBundle(
            bobKeyStore.identityKeyPair,
            bobKeyStore.signedPreKey
        )

        // Key agreement
        const aliceX3DH = x3dhSender(aliceKeyStore.identityKeyPair, bobBundle)
        const bobX3DH = x3dhReceiver(
            {
                identityKeyPair: bobKeyStore.identityKeyPair,
                signedPreKey: bobKeyStore.signedPreKey
            },
            aliceKeyStore.identityKeyPair.publicKey,
            aliceX3DH.aliceIdentityDHKey,
            aliceX3DH.ephemeralPublicKey
        )

        // Initialize and exchange some messages
        let aliceRatchet = initializeAlice(aliceX3DH.sharedSecret, aliceX3DH.bobSignedPreKey)
        let bobRatchet = initializeBob(bobX3DH.sharedSecret, bobKeyStore.signedPreKey.keyPair)

        const msg1 = ratchetEncrypt(aliceRatchet, stringToBytes('Before persistence'))
        ratchetDecrypt(bobRatchet, msg1)

        const msg2 = ratchetEncrypt(bobRatchet, stringToBytes('Reply'))
        ratchetDecrypt(aliceRatchet, msg2)

        // Serialize both states
        const aliceSerialized = serializeState(aliceRatchet)
        const bobSerialized = serializeState(bobRatchet)

        // Simulate restart - deserialize states
        aliceRatchet = deserializeState(aliceSerialized)
        bobRatchet = deserializeState(bobSerialized)

        // Continue conversation with restored states
        const msg3 = ratchetEncrypt(aliceRatchet, stringToBytes('After restore'))
        const decrypted = ratchetDecrypt(bobRatchet, msg3)
        expect(bytesToString(decrypted)).toBe('After restore')

        const msg4 = ratchetEncrypt(bobRatchet, stringToBytes('Bob after restore'))
        const decrypted2 = ratchetDecrypt(aliceRatchet, msg4)
        expect(bytesToString(decrypted2)).toBe('Bob after restore')
    })

    it('should persist and restore X3DH key store', () => {
        // Create and populate key store
        const originalStore = initializeKeyStore(50)

        // Use some one-time prekeys
        consumeOneTimePreKey(originalStore, 1)
        consumeOneTimePreKey(originalStore, 2)
        consumeOneTimePreKey(originalStore, 3)

        // Serialize
        const serialized = serializeKeyStore(originalStore)
        const json = JSON.stringify(serialized)

        // Deserialize
        const parsed = JSON.parse(json)
        const restoredStore = deserializeKeyStore(parsed)

        // Verify state matches
        expect(constantTimeEqual(
            restoredStore.identityKeyPair.publicKey,
            originalStore.identityKeyPair.publicKey
        )).toBe(true)
        expect(restoredStore.signedPreKey.id).toBe(originalStore.signedPreKey.id)
        expect(restoredStore.oneTimePreKeys.size).toBe(47) // 50 - 3 consumed
        expect(restoredStore.nextPreKeyId).toBe(originalStore.nextPreKeyId)

        // Create bundle from restored store and verify it works
        const bundle = createPreKeyBundle(
            restoredStore.identityKeyPair,
            restoredStore.signedPreKey,
            restoredStore.oneTimePreKeys.get(4)
        )

        const peerStore = initializeKeyStore(5)
        const x3dhResult = x3dhSender(peerStore.identityKeyPair, bundle)

        // Verify shared secret can be computed
        expect(x3dhResult.sharedSecret.length).toBe(32)
    })

    it('should establish multiple independent sessions', () => {
        // Bob's server-side keys
        const bobKeyStore = initializeKeyStore(100)

        // Alice and Charlie both want to talk to Bob
        const aliceKeyStore = initializeKeyStore(10)
        const charlieKeyStore = initializeKeyStore(10)

        // Alice establishes session (uses OTPK 1)
        const aliceBundle = createPreKeyBundle(
            bobKeyStore.identityKeyPair,
            bobKeyStore.signedPreKey,
            bobKeyStore.oneTimePreKeys.get(1)
        )
        const aliceX3DH = x3dhSender(aliceKeyStore.identityKeyPair, aliceBundle)

        // Charlie establishes session (uses OTPK 2)
        const charlieBundle = createPreKeyBundle(
            bobKeyStore.identityKeyPair,
            bobKeyStore.signedPreKey,
            bobKeyStore.oneTimePreKeys.get(2)
        )
        const charlieX3DH = x3dhSender(charlieKeyStore.identityKeyPair, charlieBundle)

        // Shared secrets should be different
        expect(constantTimeEqual(aliceX3DH.sharedSecret, charlieX3DH.sharedSecret)).toBe(false)

        // Bob processes both sessions
        const aliceOTPK = consumeOneTimePreKey(bobKeyStore, 1)
        const charlieOTPK = consumeOneTimePreKey(bobKeyStore, 2)

        const bobAliceX3DH = x3dhReceiver(
            {
                identityKeyPair: bobKeyStore.identityKeyPair,
                signedPreKey: bobKeyStore.signedPreKey,
                oneTimePreKey: aliceOTPK
            },
            aliceKeyStore.identityKeyPair.publicKey,
            aliceX3DH.aliceIdentityDHKey,
            aliceX3DH.ephemeralPublicKey
        )

        const bobCharlieX3DH = x3dhReceiver(
            {
                identityKeyPair: bobKeyStore.identityKeyPair,
                signedPreKey: bobKeyStore.signedPreKey,
                oneTimePreKey: charlieOTPK
            },
            charlieKeyStore.identityKeyPair.publicKey,
            charlieX3DH.aliceIdentityDHKey,
            charlieX3DH.ephemeralPublicKey
        )

        // Each session has matching shared secrets
        expect(constantTimeEqual(aliceX3DH.sharedSecret, bobAliceX3DH.sharedSecret)).toBe(true)
        expect(constantTimeEqual(charlieX3DH.sharedSecret, bobCharlieX3DH.sharedSecret)).toBe(true)

        // Initialize Double Ratchet for both sessions
        const aliceRatchet = initializeAlice(aliceX3DH.sharedSecret, aliceX3DH.bobSignedPreKey)
        const charlieRatchet = initializeAlice(charlieX3DH.sharedSecret, charlieX3DH.bobSignedPreKey)

        const bobAliceRatchet = initializeBob(bobAliceX3DH.sharedSecret, bobKeyStore.signedPreKey.keyPair)
        const bobCharlieRatchet = initializeBob(bobCharlieX3DH.sharedSecret, bobKeyStore.signedPreKey.keyPair)

        // Messages in one session don't affect the other
        const aliceMsg = ratchetEncrypt(aliceRatchet, stringToBytes('Hi Bob, from Alice'))
        const charlieMsg = ratchetEncrypt(charlieRatchet, stringToBytes('Hi Bob, from Charlie'))

        expect(bytesToString(ratchetDecrypt(bobAliceRatchet, aliceMsg))).toBe('Hi Bob, from Alice')
        expect(bytesToString(ratchetDecrypt(bobCharlieRatchet, charlieMsg))).toBe('Hi Bob, from Charlie')

        // Cross-session decryption should fail
        expect(() => ratchetDecrypt(bobCharlieRatchet, aliceMsg)).toThrow()
    })
})
