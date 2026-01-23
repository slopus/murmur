/**
 * Tests for Diffie-Hellman key exchange (X25519).
 */

import { describe, it, expect } from 'vitest'
import {
    generateDH,
    dh,
    publicKeyFromPrivate,
    isValidPublicKey,
    DH_PRIVATE_KEY_LENGTH,
    DH_PUBLIC_KEY_LENGTH,
    DH_SHARED_SECRET_LENGTH
} from './dh.js'
import { constantTimeEqual } from './utils.js'

describe('DH key generation', () => {
    it('should generate key pair with correct lengths', () => {
        const keyPair = generateDH()
        expect(keyPair.privateKey.length).toBe(DH_PRIVATE_KEY_LENGTH)
        expect(keyPair.publicKey.length).toBe(DH_PUBLIC_KEY_LENGTH)
    })

    it('should generate different key pairs each time', () => {
        const kp1 = generateDH()
        const kp2 = generateDH()
        expect(constantTimeEqual(kp1.privateKey, kp2.privateKey)).toBe(false)
        expect(constantTimeEqual(kp1.publicKey, kp2.publicKey)).toBe(false)
    })

    it('should derive correct public key from private key', () => {
        const keyPair = generateDH()
        const derivedPublic = publicKeyFromPrivate(keyPair.privateKey)
        expect(constantTimeEqual(derivedPublic, keyPair.publicKey)).toBe(true)
    })
})

describe('DH key agreement', () => {
    it('should produce same shared secret for both parties', () => {
        const alice = generateDH()
        const bob = generateDH()

        const sharedAlice = dh(alice, bob.publicKey)
        const sharedBob = dh(bob, alice.publicKey)

        expect(sharedAlice.length).toBe(DH_SHARED_SECRET_LENGTH)
        expect(sharedBob.length).toBe(DH_SHARED_SECRET_LENGTH)
        expect(constantTimeEqual(sharedAlice, sharedBob)).toBe(true)
    })

    it('should produce different secrets with different key pairs', () => {
        const alice = generateDH()
        const bob1 = generateDH()
        const bob2 = generateDH()

        const shared1 = dh(alice, bob1.publicKey)
        const shared2 = dh(alice, bob2.publicKey)

        expect(constantTimeEqual(shared1, shared2)).toBe(false)
    })

    it('should throw on invalid public key length', () => {
        const alice = generateDH()
        const shortKey = new Uint8Array(16)
        const longKey = new Uint8Array(64)

        expect(() => dh(alice, shortKey)).toThrow()
        expect(() => dh(alice, longKey)).toThrow()
    })
})

describe('Public key validation', () => {
    it('should validate correct public key', () => {
        const keyPair = generateDH()
        expect(isValidPublicKey(keyPair.publicKey)).toBe(true)
    })

    it('should reject wrong length keys', () => {
        expect(isValidPublicKey(new Uint8Array(0))).toBe(false)
        expect(isValidPublicKey(new Uint8Array(16))).toBe(false)
        expect(isValidPublicKey(new Uint8Array(31))).toBe(false)
        expect(isValidPublicKey(new Uint8Array(33))).toBe(false)
    })

    it('should accept any 32-byte key (X25519 contributory)', () => {
        // X25519 accepts any 32 bytes as a valid public key
        const allZeros = new Uint8Array(32)
        const allOnes = new Uint8Array(32).fill(0xff)
        expect(isValidPublicKey(allZeros)).toBe(true)
        expect(isValidPublicKey(allOnes)).toBe(true)
    })
})

describe('Private key derivation', () => {
    it('should throw on invalid private key length', () => {
        expect(() => publicKeyFromPrivate(new Uint8Array(16))).toThrow()
        expect(() => publicKeyFromPrivate(new Uint8Array(31))).toThrow()
        expect(() => publicKeyFromPrivate(new Uint8Array(33))).toThrow()
    })

    it('should produce deterministic public keys', () => {
        const privateKey = new Uint8Array(32).fill(0x42)
        const pub1 = publicKeyFromPrivate(privateKey)
        const pub2 = publicKeyFromPrivate(privateKey)
        expect(constantTimeEqual(pub1, pub2)).toBe(true)
    })
})
