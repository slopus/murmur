/**
 * Tests for message header encoding/decoding.
 */

import { describe, it, expect } from 'vitest'
import {
    encodeHeader,
    decodeHeader,
    createHeader,
    HEADER_SIZE
} from './header.js'
import { generateDH, DH_PUBLIC_KEY_LENGTH } from '../crypto/dh.js'
import { constantTimeEqual } from '../crypto/utils.js'

describe('Header encoding', () => {
    it('should encode header to correct size', () => {
        const keyPair = generateDH()
        const header = createHeader(keyPair.publicKey, 0, 0)
        const encoded = encodeHeader(header)

        expect(encoded.length).toBe(HEADER_SIZE)
    })

    it('should encode and decode correctly', () => {
        const keyPair = generateDH()
        const original = createHeader(keyPair.publicKey, 5, 10)

        const encoded = encodeHeader(original)
        const decoded = decodeHeader(encoded)

        expect(constantTimeEqual(decoded.publicKey, original.publicKey)).toBe(true)
        expect(decoded.previousChainLength).toBe(5)
        expect(decoded.messageNumber).toBe(10)
    })

    it('should handle zero values', () => {
        const keyPair = generateDH()
        const original = createHeader(keyPair.publicKey, 0, 0)

        const encoded = encodeHeader(original)
        const decoded = decodeHeader(encoded)

        expect(decoded.previousChainLength).toBe(0)
        expect(decoded.messageNumber).toBe(0)
    })

    it('should handle large message numbers', () => {
        const keyPair = generateDH()
        const original = createHeader(keyPair.publicKey, 1000000, 999999)

        const encoded = encodeHeader(original)
        const decoded = decodeHeader(encoded)

        expect(decoded.previousChainLength).toBe(1000000)
        expect(decoded.messageNumber).toBe(999999)
    })

    it('should handle max uint32 values', () => {
        const keyPair = generateDH()
        const maxVal = 0xffffffff >>> 0 // Max uint32
        const original = createHeader(keyPair.publicKey, maxVal, maxVal)

        const encoded = encodeHeader(original)
        const decoded = decodeHeader(encoded)

        expect(decoded.previousChainLength).toBe(maxVal)
        expect(decoded.messageNumber).toBe(maxVal)
    })

    it('should throw on null public key', () => {
        const header = {
            publicKey: null as unknown as Uint8Array,
            previousChainLength: 0,
            messageNumber: 0
        }
        expect(() => encodeHeader(header)).toThrow()
    })

    it('should throw on invalid public key length', () => {
        const shortKey = new Uint8Array(16)
        const header = createHeader(shortKey, 0, 0)
        expect(() => encodeHeader(header)).toThrow()
    })

    it('should throw on negative message number', () => {
        const keyPair = generateDH()
        const header = createHeader(keyPair.publicKey, 0, -1)
        expect(() => encodeHeader(header)).toThrow()
    })

    it('should throw on negative previous chain length', () => {
        const keyPair = generateDH()
        const header = createHeader(keyPair.publicKey, -1, 0)
        expect(() => encodeHeader(header)).toThrow()
    })

    it('should throw on non-integer message number', () => {
        const keyPair = generateDH()
        const header = createHeader(keyPair.publicKey, 0, 1.5)
        expect(() => encodeHeader(header)).toThrow()
    })
})

describe('Header decoding', () => {
    it('should throw on wrong size', () => {
        const short = new Uint8Array(HEADER_SIZE - 1)
        const long = new Uint8Array(HEADER_SIZE + 1)

        expect(() => decodeHeader(short)).toThrow()
        expect(() => decodeHeader(long)).toThrow()
    })

    it('should decode any valid-sized header', () => {
        const data = new Uint8Array(HEADER_SIZE)
        data.fill(0x42)

        const decoded = decodeHeader(data)
        expect(decoded.publicKey.length).toBe(DH_PUBLIC_KEY_LENGTH)
    })
})

describe('createHeader helper', () => {
    it('should create header with correct values', () => {
        const keyPair = generateDH()
        const header = createHeader(keyPair.publicKey, 3, 7)

        expect(constantTimeEqual(header.publicKey, keyPair.publicKey)).toBe(true)
        expect(header.previousChainLength).toBe(3)
        expect(header.messageNumber).toBe(7)
    })
})
