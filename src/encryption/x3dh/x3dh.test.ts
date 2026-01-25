/**
 * Tests for X3DH key agreement protocol.
 */

import { describe, it, expect } from 'vitest'
import {
    generateIdentityKeyPair,
    generateSignedPreKey,
    generateOneTimePreKey,
    generateOneTimePreKeys,
    createPreKeyBundle,
    verifyPreKeyBundle,
    x3dhSender,
    x3dhReceiver,
    initializeKeyStore,
    serializeKeyStore,
    deserializeKeyStore,
    consumeOneTimePreKey,
    replenishOneTimePreKeys
} from './x3dh.js'
import { constantTimeEqual } from '../crypto/utils.js'
import type { X3DHReceiverKeys } from './types.js'

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

describe('Identity key generation', () => {
    it('should generate identity key pair', () => {
        const identity = generateIdentityKeyPair()

        expect(identity.privateKey.length).toBe(32)
        expect(identity.publicKey.length).toBe(32)
        expect(identity.dhKeyPair.privateKey.length).toBe(32)
        expect(identity.dhKeyPair.publicKey.length).toBe(32)
    })

    it('should generate different identities each time', () => {
        const id1 = generateIdentityKeyPair()
        const id2 = generateIdentityKeyPair()

        expect(constantTimeEqual(id1.publicKey, id2.publicKey)).toBe(false)
    })
})

describe('Signed prekey generation', () => {
    it('should generate signed prekey', () => {
        const identity = generateIdentityKeyPair()
        const prekey = generateSignedPreKey(identity, 1)

        expect(prekey.id).toBe(1)
        expect(prekey.keyPair.publicKey.length).toBe(32)
        expect(prekey.signature.length).toBe(64)
        expect(prekey.createdAt).toBeLessThanOrEqual(Date.now())
    })

    it('should generate verifiable signatures', () => {
        const identity = generateIdentityKeyPair()
        const prekey = generateSignedPreKey(identity, 42)

        const bundle = createPreKeyBundle(identity, prekey)
        expect(verifyPreKeyBundle(bundle)).toBe(true)
    })
})

describe('One-time prekey generation', () => {
    it('should generate one-time prekey', () => {
        const otpk = generateOneTimePreKey(5)

        expect(otpk.id).toBe(5)
        expect(otpk.keyPair.publicKey.length).toBe(32)
    })

    it('should generate batch of one-time prekeys', () => {
        const prekeys = generateOneTimePreKeys(10, 5)

        expect(prekeys.length).toBe(5)
        expect(prekeys[0].id).toBe(10)
        expect(prekeys[4].id).toBe(14)
    })
})

describe('Prekey bundle', () => {
    it('should create bundle without one-time prekey', () => {
        const identity = generateIdentityKeyPair()
        const signedPreKey = generateSignedPreKey(identity, 1)
        const bundle = createPreKeyBundle(identity, signedPreKey)

        expect(bundle.identityKey).toEqual(identity.publicKey)
        expect(bundle.signedPreKey).toEqual(signedPreKey.keyPair.publicKey)
        expect(bundle.oneTimePreKey).toBeUndefined()
    })

    it('should create bundle with one-time prekey', () => {
        const identity = generateIdentityKeyPair()
        const signedPreKey = generateSignedPreKey(identity, 1)
        const oneTimePreKey = generateOneTimePreKey(100)
        const bundle = createPreKeyBundle(identity, signedPreKey, oneTimePreKey)

        expect(bundle.oneTimePreKey).toEqual(oneTimePreKey.keyPair.publicKey)
    })

    it('should verify valid bundle', () => {
        const identity = generateIdentityKeyPair()
        const signedPreKey = generateSignedPreKey(identity, 1)
        const bundle = createPreKeyBundle(identity, signedPreKey)

        expect(verifyPreKeyBundle(bundle)).toBe(true)
    })

    it('should reject bundle with tampered signature', () => {
        const identity = generateIdentityKeyPair()
        const signedPreKey = generateSignedPreKey(identity, 1)
        const bundle = createPreKeyBundle(identity, signedPreKey)

        bundle.signedPreKeySignature[0] ^= 0x01

        expect(verifyPreKeyBundle(bundle)).toBe(false)
    })

    it('should reject bundle with wrong identity key', () => {
        const identity = generateIdentityKeyPair()
        const wrongIdentity = generateIdentityKeyPair()
        const signedPreKey = generateSignedPreKey(identity, 1)
        const bundle = createPreKeyBundle(identity, signedPreKey)

        bundle.identityKey = wrongIdentity.publicKey

        expect(verifyPreKeyBundle(bundle)).toBe(false)
    })
})

describe('X3DH key agreement', () => {
    it('should establish shared secret without one-time prekey', () => {
        // Bob generates keys
        const bobIdentity = generateIdentityKeyPair()
        const bobSignedPreKey = generateSignedPreKey(bobIdentity, 1)
        const bobBundle = createPreKeyBundle(bobIdentity, bobSignedPreKey)

        // Alice generates keys and performs X3DH
        const aliceIdentity = generateIdentityKeyPair()
        const senderResult = x3dhSender(aliceIdentity, bobBundle)

        // Bob receives and computes shared secret
        const bobKeys: X3DHReceiverKeys = {
            identityKeyPair: bobIdentity,
            signedPreKey: bobSignedPreKey
        }
        const receiverResult = x3dhReceiver(
            bobKeys,
            aliceIdentity.publicKey,
            senderResult.aliceIdentityDHKey,
            senderResult.ephemeralPublicKey
        )

        // Both should have the same shared secret
        expect(senderResult.sharedSecret.length).toBe(32)
        expect(receiverResult.sharedSecret.length).toBe(32)
        expect(constantTimeEqual(senderResult.sharedSecret, receiverResult.sharedSecret)).toBe(true)
    })

    it('should establish shared secret with one-time prekey', () => {
        // Bob generates keys with one-time prekey
        const bobIdentity = generateIdentityKeyPair()
        const bobSignedPreKey = generateSignedPreKey(bobIdentity, 1)
        const bobOneTimePreKey = generateOneTimePreKey(100)
        const bobBundle = createPreKeyBundle(bobIdentity, bobSignedPreKey, bobOneTimePreKey)

        // Alice performs X3DH
        const aliceIdentity = generateIdentityKeyPair()
        const senderResult = x3dhSender(aliceIdentity, bobBundle)

        // Bob computes shared secret
        const bobKeys: X3DHReceiverKeys = {
            identityKeyPair: bobIdentity,
            signedPreKey: bobSignedPreKey,
            oneTimePreKey: bobOneTimePreKey
        }
        const receiverResult = x3dhReceiver(
            bobKeys,
            aliceIdentity.publicKey,
            senderResult.aliceIdentityDHKey,
            senderResult.ephemeralPublicKey
        )

        // Shared secrets should match
        expect(constantTimeEqual(senderResult.sharedSecret, receiverResult.sharedSecret)).toBe(true)
    })

    it('should throw on invalid bundle signature', () => {
        const bobIdentity = generateIdentityKeyPair()
        const bobSignedPreKey = generateSignedPreKey(bobIdentity, 1)
        const bobBundle = createPreKeyBundle(bobIdentity, bobSignedPreKey)

        // Tamper with signature
        bobBundle.signedPreKeySignature[0] ^= 0x01

        const aliceIdentity = generateIdentityKeyPair()
        expect(() => x3dhSender(aliceIdentity, bobBundle)).toThrow('Invalid prekey bundle signature')
    })

    it('should produce different secrets with different ephemeral keys', () => {
        const bobIdentity = generateIdentityKeyPair()
        const bobSignedPreKey = generateSignedPreKey(bobIdentity, 1)
        const bobBundle = createPreKeyBundle(bobIdentity, bobSignedPreKey)

        const aliceIdentity = generateIdentityKeyPair()
        const result1 = x3dhSender(aliceIdentity, bobBundle)
        const result2 = x3dhSender(aliceIdentity, bobBundle)

        // Different ephemeral keys = different shared secrets
        expect(constantTimeEqual(result1.ephemeralPublicKey, result2.ephemeralPublicKey)).toBe(false)
        expect(constantTimeEqual(result1.sharedSecret, result2.sharedSecret)).toBe(false)
    })

    it('should produce different secrets with vs without one-time prekey', () => {
        const bobIdentity = generateIdentityKeyPair()
        const bobSignedPreKey = generateSignedPreKey(bobIdentity, 1)
        const bobOneTimePreKey = generateOneTimePreKey(100)

        const bundleWithOTPK = createPreKeyBundle(bobIdentity, bobSignedPreKey, bobOneTimePreKey)
        const bundleWithoutOTPK = createPreKeyBundle(bobIdentity, bobSignedPreKey)

        const aliceIdentity = generateIdentityKeyPair()
        const result1 = x3dhSender(aliceIdentity, bundleWithOTPK)
        const result2 = x3dhSender(aliceIdentity, bundleWithoutOTPK)

        // Using OTPK changes the shared secret
        expect(constantTimeEqual(result1.sharedSecret, result2.sharedSecret)).toBe(false)
    })
})

describe('Key store management', () => {
    it('should initialize key store', () => {
        const store = initializeKeyStore(10)

        expect(store.identityKeyPair).toBeDefined()
        expect(store.signedPreKey).toBeDefined()
        expect(store.oneTimePreKeys.size).toBe(10)
        expect(store.nextPreKeyId).toBe(11)
    })

    it('should serialize and deserialize key store', () => {
        const store = initializeKeyStore(5)
        const serialized = serializeKeyStore(store)
        const deserialized = deserializeKeyStore(serialized)

        expect(constantTimeEqual(
            deserialized.identityKeyPair.publicKey,
            store.identityKeyPair.publicKey
        )).toBe(true)

        expect(deserialized.signedPreKey.id).toBe(store.signedPreKey.id)
        expect(deserialized.oneTimePreKeys.size).toBe(5)
        expect(deserialized.nextPreKeyId).toBe(6)
    })

    it('should consume one-time prekey', () => {
        const store = initializeKeyStore(5)
        const otpk = consumeOneTimePreKey(store, 1)

        expect(otpk).toBeDefined()
        expect(otpk!.id).toBe(1)
        expect(store.oneTimePreKeys.has(1)).toBe(false)
        expect(store.oneTimePreKeys.size).toBe(4)
    })

    it('should return undefined for non-existent prekey', () => {
        const store = initializeKeyStore(5)
        const otpk = consumeOneTimePreKey(store, 999)

        expect(otpk).toBeUndefined()
    })

    it('should replenish one-time prekeys', () => {
        const store = initializeKeyStore(3)

        // Consume some keys
        consumeOneTimePreKey(store, 1)
        consumeOneTimePreKey(store, 2)
        expect(store.oneTimePreKeys.size).toBe(1)

        // Replenish to 5
        const newKeys = replenishOneTimePreKeys(store, 5)

        expect(newKeys.length).toBe(4)
        expect(store.oneTimePreKeys.size).toBe(5)
    })

    it('should not replenish if already at target', () => {
        const store = initializeKeyStore(10)
        const newKeys = replenishOneTimePreKeys(store, 5)

        expect(newKeys.length).toBe(0)
        expect(store.oneTimePreKeys.size).toBe(10)
    })
})

describe('Full session establishment', () => {
    it('should establish session and verify with key store', () => {
        // Bob sets up his key store
        const bobStore = initializeKeyStore(10)
        const bobBundle = createPreKeyBundle(
            bobStore.identityKeyPair,
            bobStore.signedPreKey,
            bobStore.oneTimePreKeys.get(1)
        )

        // Alice sets up and initiates
        const aliceStore = initializeKeyStore(10)
        const senderResult = x3dhSender(aliceStore.identityKeyPair, bobBundle)

        // Bob processes the session initiation
        const usedOTPKId = findOneTimePreKeyId(bobStore, bobBundle.oneTimePreKey)
        const usedOTPK = usedOTPKId ? consumeOneTimePreKey(bobStore, usedOTPKId) : undefined
        expect(usedOTPK).toBeDefined()

        const bobKeys: X3DHReceiverKeys = {
            identityKeyPair: bobStore.identityKeyPair,
            signedPreKey: bobStore.signedPreKey,
            oneTimePreKey: usedOTPK
        }

        const receiverResult = x3dhReceiver(
            bobKeys,
            aliceStore.identityKeyPair.publicKey,
            senderResult.aliceIdentityDHKey,
            senderResult.ephemeralPublicKey
        )

        // Verify shared secret matches
        expect(constantTimeEqual(senderResult.sharedSecret, receiverResult.sharedSecret)).toBe(true)

        // Verify OTPK was consumed
        expect(bobStore.oneTimePreKeys.has(1)).toBe(false)
    })
})
