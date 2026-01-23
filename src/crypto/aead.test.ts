/**
 * Tests for AEAD encryption (ChaCha20-Poly1305).
 */

import { describe, it, expect } from 'vitest'
import {
    encrypt,
    decrypt,
    encryptJson,
    decryptJson,
    AEAD_KEY_LENGTH,
    AEAD_TAG_LENGTH
} from './aead.js'
import { getRandomBytes, stringToBytes, bytesToString, constantTimeEqual } from './utils.js'

describe('AEAD encryption', () => {
    it('should encrypt and decrypt correctly', () => {
        const messageKey = getRandomBytes(32)
        const plaintext = stringToBytes('Hello, World!')
        const ad = stringToBytes('associated data')

        const ciphertext = encrypt(messageKey, plaintext, ad)
        const decrypted = decrypt(messageKey, ciphertext, ad)

        expect(bytesToString(decrypted)).toBe('Hello, World!')
    })

    it('should produce ciphertext longer than plaintext by tag length', () => {
        const messageKey = getRandomBytes(32)
        const plaintext = getRandomBytes(100)
        const ad = new Uint8Array(0)

        const ciphertext = encrypt(messageKey, plaintext, ad)
        expect(ciphertext.length).toBe(plaintext.length + AEAD_TAG_LENGTH)
    })

    it('should produce different ciphertext for different keys', () => {
        const key1 = getRandomBytes(32)
        const key2 = getRandomBytes(32)
        const plaintext = stringToBytes('Hello')
        const ad = new Uint8Array(0)

        const ct1 = encrypt(key1, plaintext, ad)
        const ct2 = encrypt(key2, plaintext, ad)

        expect(constantTimeEqual(ct1, ct2)).toBe(false)
    })

    it('should produce same ciphertext for same key (deterministic nonce)', () => {
        // Since nonce is derived from message key, same key = same ciphertext
        const key = getRandomBytes(32)
        const plaintext = stringToBytes('Hello')
        const ad = new Uint8Array(0)

        const ct1 = encrypt(key, plaintext, ad)
        const ct2 = encrypt(key, plaintext, ad)

        expect(constantTimeEqual(ct1, ct2)).toBe(true)
    })

    it('should fail decryption with wrong key', () => {
        const correctKey = getRandomBytes(32)
        const wrongKey = getRandomBytes(32)
        const plaintext = stringToBytes('Secret message')
        const ad = new Uint8Array(0)

        const ciphertext = encrypt(correctKey, plaintext, ad)

        expect(() => decrypt(wrongKey, ciphertext, ad)).toThrow()
    })

    it('should fail decryption with wrong associated data', () => {
        const key = getRandomBytes(32)
        const plaintext = stringToBytes('Secret message')
        const ad1 = stringToBytes('correct AD')
        const ad2 = stringToBytes('wrong AD')

        const ciphertext = encrypt(key, plaintext, ad1)

        expect(() => decrypt(key, ciphertext, ad2)).toThrow()
    })

    it('should fail decryption with tampered ciphertext', () => {
        const key = getRandomBytes(32)
        const plaintext = stringToBytes('Secret message')
        const ad = new Uint8Array(0)

        const ciphertext = encrypt(key, plaintext, ad)

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01

        expect(() => decrypt(key, ciphertext, ad)).toThrow()
    })

    it('should handle empty plaintext', () => {
        const key = getRandomBytes(32)
        const plaintext = new Uint8Array(0)
        const ad = stringToBytes('some AD')

        const ciphertext = encrypt(key, plaintext, ad)
        const decrypted = decrypt(key, ciphertext, ad)

        expect(decrypted.length).toBe(0)
    })

    it('should handle empty associated data', () => {
        const key = getRandomBytes(32)
        const plaintext = stringToBytes('Hello')
        const ad = new Uint8Array(0)

        const ciphertext = encrypt(key, plaintext, ad)
        const decrypted = decrypt(key, ciphertext, ad)

        expect(bytesToString(decrypted)).toBe('Hello')
    })

    it('should handle large plaintext', () => {
        const key = getRandomBytes(32)
        const plaintext = getRandomBytes(10000)
        const ad = getRandomBytes(100)

        const ciphertext = encrypt(key, plaintext, ad)
        const decrypted = decrypt(key, ciphertext, ad)

        expect(constantTimeEqual(decrypted, plaintext)).toBe(true)
    })
})

describe('JSON encryption', () => {
    it('should encrypt and decrypt JSON objects', () => {
        const key = getRandomBytes(32)
        const data = { message: 'Hello', count: 42, nested: { value: true } }
        const ad = new Uint8Array(0)

        const ciphertext = encryptJson(key, data, ad)
        const decrypted = decryptJson(key, ciphertext, ad)

        expect(decrypted).toEqual(data)
    })

    it('should encrypt and decrypt arrays', () => {
        const key = getRandomBytes(32)
        const data = [1, 2, 3, 'hello', { key: 'value' }]
        const ad = new Uint8Array(0)

        const ciphertext = encryptJson(key, data, ad)
        const decrypted = decryptJson(key, ciphertext, ad)

        expect(decrypted).toEqual(data)
    })

    it('should encrypt and decrypt primitives', () => {
        const key = getRandomBytes(32)
        const ad = new Uint8Array(0)

        expect(decryptJson(key, encryptJson(key, 'string', ad), ad)).toBe('string')
        expect(decryptJson(key, encryptJson(key, 42, ad), ad)).toBe(42)
        expect(decryptJson(key, encryptJson(key, true, ad), ad)).toBe(true)
        expect(decryptJson(key, encryptJson(key, null, ad), ad)).toBe(null)
    })

    it('should handle Unicode in JSON', () => {
        const key = getRandomBytes(32)
        const data = { greeting: '你好', emoji: '🚀' }
        const ad = new Uint8Array(0)

        const ciphertext = encryptJson(key, data, ad)
        const decrypted = decryptJson(key, ciphertext, ad)

        expect(decrypted).toEqual(data)
    })
})
