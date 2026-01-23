/**
 * Tests for Key Derivation Functions (KDF).
 */

import { describe, it, expect } from 'vitest'
import {
    kdfRK,
    kdfCK,
    hkdfExpand,
    ROOT_KEY_LENGTH,
    CHAIN_KEY_LENGTH,
    MESSAGE_KEY_LENGTH
} from './kdf.js'
import { constantTimeEqual, getRandomBytes } from './utils.js'

describe('KDF_RK (Root Key derivation)', () => {
    it('should derive root key and chain key of correct length', () => {
        const rootKey = getRandomBytes(ROOT_KEY_LENGTH)
        const dhOutput = getRandomBytes(32)

        const [newRootKey, chainKey] = kdfRK(rootKey, dhOutput)

        expect(newRootKey.length).toBe(ROOT_KEY_LENGTH)
        expect(chainKey.length).toBe(CHAIN_KEY_LENGTH)
    })

    it('should produce deterministic output', () => {
        const rootKey = new Uint8Array(32).fill(0x01)
        const dhOutput = new Uint8Array(32).fill(0x02)

        const [rk1, ck1] = kdfRK(rootKey, dhOutput)
        const [rk2, ck2] = kdfRK(rootKey, dhOutput)

        expect(constantTimeEqual(rk1, rk2)).toBe(true)
        expect(constantTimeEqual(ck1, ck2)).toBe(true)
    })

    it('should produce different outputs for different inputs', () => {
        const rootKey = getRandomBytes(32)
        const dhOutput1 = getRandomBytes(32)
        const dhOutput2 = getRandomBytes(32)

        const [rk1, ck1] = kdfRK(rootKey, dhOutput1)
        const [rk2, ck2] = kdfRK(rootKey, dhOutput2)

        expect(constantTimeEqual(rk1, rk2)).toBe(false)
        expect(constantTimeEqual(ck1, ck2)).toBe(false)
    })

    it('should throw on invalid root key length', () => {
        const shortKey = new Uint8Array(16)
        const dhOutput = getRandomBytes(32)
        expect(() => kdfRK(shortKey, dhOutput)).toThrow()
    })

    it('should throw on invalid DH output length', () => {
        const rootKey = getRandomBytes(32)
        const shortDH = new Uint8Array(16)
        expect(() => kdfRK(rootKey, shortDH)).toThrow()
    })

    it('should produce different root key and chain key', () => {
        const rootKey = getRandomBytes(32)
        const dhOutput = getRandomBytes(32)

        const [newRootKey, chainKey] = kdfRK(rootKey, dhOutput)

        // Root key and chain key should be different
        expect(constantTimeEqual(newRootKey, chainKey)).toBe(false)
    })
})

describe('KDF_CK (Chain Key derivation)', () => {
    it('should derive chain key and message key of correct length', () => {
        const chainKey = getRandomBytes(CHAIN_KEY_LENGTH)

        const [newChainKey, messageKey] = kdfCK(chainKey)

        expect(newChainKey.length).toBe(CHAIN_KEY_LENGTH)
        expect(messageKey.length).toBe(MESSAGE_KEY_LENGTH)
    })

    it('should produce deterministic output', () => {
        const chainKey = new Uint8Array(32).fill(0x03)

        const [ck1, mk1] = kdfCK(chainKey)
        const [ck2, mk2] = kdfCK(chainKey)

        expect(constantTimeEqual(ck1, ck2)).toBe(true)
        expect(constantTimeEqual(mk1, mk2)).toBe(true)
    })

    it('should produce different outputs for different chain keys', () => {
        const ck1 = getRandomBytes(32)
        const ck2 = getRandomBytes(32)

        const [newCk1, mk1] = kdfCK(ck1)
        const [newCk2, mk2] = kdfCK(ck2)

        expect(constantTimeEqual(newCk1, newCk2)).toBe(false)
        expect(constantTimeEqual(mk1, mk2)).toBe(false)
    })

    it('should throw on null chain key', () => {
        expect(() => kdfCK(null)).toThrow()
    })

    it('should throw on invalid chain key length', () => {
        expect(() => kdfCK(new Uint8Array(16))).toThrow()
        expect(() => kdfCK(new Uint8Array(64))).toThrow()
    })

    it('should produce different chain key and message key', () => {
        const chainKey = getRandomBytes(32)
        const [newChainKey, messageKey] = kdfCK(chainKey)

        // They should be different
        expect(constantTimeEqual(newChainKey, messageKey)).toBe(false)
    })

    it('should advance chain correctly (forward secrecy)', () => {
        // Simulate a chain of 5 messages
        let chainKey = getRandomBytes(32)
        const messageKeys: Uint8Array[] = []

        for (let i = 0; i < 5; i++) {
            const [newChainKey, messageKey] = kdfCK(chainKey)
            messageKeys.push(messageKey)
            chainKey = newChainKey
        }

        // All message keys should be different
        for (let i = 0; i < messageKeys.length; i++) {
            for (let j = i + 1; j < messageKeys.length; j++) {
                expect(constantTimeEqual(messageKeys[i], messageKeys[j])).toBe(false)
            }
        }
    })
})

describe('HKDF expand', () => {
    it('should derive requested number of bytes', () => {
        const secret = getRandomBytes(32)

        expect(hkdfExpand(secret, undefined, 'test', 16).length).toBe(16)
        expect(hkdfExpand(secret, undefined, 'test', 32).length).toBe(32)
        expect(hkdfExpand(secret, undefined, 'test', 64).length).toBe(64)
    })

    it('should produce deterministic output', () => {
        const secret = new Uint8Array(32).fill(0x42)
        const salt = new Uint8Array(16).fill(0x01)

        const out1 = hkdfExpand(secret, salt, 'info', 32)
        const out2 = hkdfExpand(secret, salt, 'info', 32)

        expect(constantTimeEqual(out1, out2)).toBe(true)
    })

    it('should produce different output for different info', () => {
        const secret = getRandomBytes(32)

        const out1 = hkdfExpand(secret, undefined, 'info1', 32)
        const out2 = hkdfExpand(secret, undefined, 'info2', 32)

        expect(constantTimeEqual(out1, out2)).toBe(false)
    })

    it('should work without salt', () => {
        const secret = getRandomBytes(32)
        const output = hkdfExpand(secret, undefined, 'test', 32)
        expect(output.length).toBe(32)
    })
})
