/**
 * Tests for Ed25519 digital signatures.
 */

import { describe, it, expect } from 'vitest'
import {
    generateSigningKeyPair,
    signingPublicKeyFromPrivate,
    sign,
    verify,
    isValidSigningPublicKey,
    SIGNING_PRIVATE_KEY_LENGTH,
    SIGNING_PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH
} from './signing.js'
import { constantTimeEqual, stringToBytes } from './utils.js'

describe('Signing key generation', () => {
    it('should generate key pair with correct lengths', () => {
        const keyPair = generateSigningKeyPair()
        expect(keyPair.privateKey.length).toBe(SIGNING_PRIVATE_KEY_LENGTH)
        expect(keyPair.publicKey.length).toBe(SIGNING_PUBLIC_KEY_LENGTH)
    })

    it('should generate different key pairs each time', () => {
        const kp1 = generateSigningKeyPair()
        const kp2 = generateSigningKeyPair()
        expect(constantTimeEqual(kp1.privateKey, kp2.privateKey)).toBe(false)
        expect(constantTimeEqual(kp1.publicKey, kp2.publicKey)).toBe(false)
    })

    it('should derive correct public key from private key', () => {
        const keyPair = generateSigningKeyPair()
        const derivedPublic = signingPublicKeyFromPrivate(keyPair.privateKey)
        expect(constantTimeEqual(derivedPublic, keyPair.publicKey)).toBe(true)
    })
})

describe('Signing and verification', () => {
    it('should sign and verify a message', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Hello, World!')

        const signature = sign(message, keyPair.privateKey)
        expect(signature.length).toBe(SIGNATURE_LENGTH)

        const isValid = verify(message, signature, keyPair.publicKey)
        expect(isValid).toBe(true)
    })

    it('should fail verification with wrong public key', () => {
        const keyPair1 = generateSigningKeyPair()
        const keyPair2 = generateSigningKeyPair()
        const message = stringToBytes('Secret message')

        const signature = sign(message, keyPair1.privateKey)
        const isValid = verify(message, signature, keyPair2.publicKey)

        expect(isValid).toBe(false)
    })

    it('should fail verification with tampered message', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Original message')

        const signature = sign(message, keyPair.privateKey)

        const tamperedMessage = stringToBytes('Tampered message')
        const isValid = verify(tamperedMessage, signature, keyPair.publicKey)

        expect(isValid).toBe(false)
    })

    it('should fail verification with tampered signature', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Hello')

        const signature = sign(message, keyPair.privateKey)
        signature[0] ^= 0x01 // Flip a bit

        const isValid = verify(message, signature, keyPair.publicKey)
        expect(isValid).toBe(false)
    })

    it('should handle empty messages', () => {
        const keyPair = generateSigningKeyPair()
        const message = new Uint8Array(0)

        const signature = sign(message, keyPair.privateKey)
        const isValid = verify(message, signature, keyPair.publicKey)

        expect(isValid).toBe(true)
    })

    it('should handle large messages', () => {
        const keyPair = generateSigningKeyPair()
        const message = new Uint8Array(10000).fill(0x42)

        const signature = sign(message, keyPair.privateKey)
        const isValid = verify(message, signature, keyPair.publicKey)

        expect(isValid).toBe(true)
    })

    it('should produce deterministic signatures', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Test message')

        const sig1 = sign(message, keyPair.privateKey)
        const sig2 = sign(message, keyPair.privateKey)

        // Ed25519 signatures are deterministic
        expect(constantTimeEqual(sig1, sig2)).toBe(true)
    })
})

describe('Public key validation', () => {
    it('should validate correct public key', () => {
        const keyPair = generateSigningKeyPair()
        expect(isValidSigningPublicKey(keyPair.publicKey)).toBe(true)
    })

    it('should reject wrong length keys', () => {
        expect(isValidSigningPublicKey(new Uint8Array(0))).toBe(false)
        expect(isValidSigningPublicKey(new Uint8Array(16))).toBe(false)
        expect(isValidSigningPublicKey(new Uint8Array(31))).toBe(false)
        expect(isValidSigningPublicKey(new Uint8Array(33))).toBe(false)
    })
})

describe('Error handling', () => {
    it('should throw on invalid private key length', () => {
        expect(() => signingPublicKeyFromPrivate(new Uint8Array(16))).toThrow()
        expect(() => sign(new Uint8Array(10), new Uint8Array(16))).toThrow()
    })

    it('should return false for invalid signature length', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Test')

        expect(verify(message, new Uint8Array(32), keyPair.publicKey)).toBe(false)
        expect(verify(message, new Uint8Array(128), keyPair.publicKey)).toBe(false)
    })

    it('should return false for invalid public key length', () => {
        const keyPair = generateSigningKeyPair()
        const message = stringToBytes('Test')
        const signature = sign(message, keyPair.privateKey)

        expect(verify(message, signature, new Uint8Array(16))).toBe(false)
    })
})
