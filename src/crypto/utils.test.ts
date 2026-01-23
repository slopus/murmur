/**
 * Tests for cryptographic utility functions.
 */

import { describe, it, expect } from 'vitest'
import {
    encodeBase64,
    decodeBase64,
    encodeBase64Url,
    getRandomBytes,
    constantTimeEqual,
    concatBytes,
    stringToBytes,
    bytesToString,
    zeroBytes,
    numberToBytes,
    bytesToNumber
} from './utils.js'

describe('Base64 encoding', () => {
    it('should encode and decode base64 correctly', () => {
        const original = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
        const encoded = encodeBase64(original)
        expect(encoded).toBe('SGVsbG8=')

        const decoded = decodeBase64(encoded)
        expect(decoded).toEqual(original)
    })

    it('should handle empty arrays', () => {
        const empty = new Uint8Array(0)
        const encoded = encodeBase64(empty)
        expect(encoded).toBe('')

        const decoded = decodeBase64(encoded)
        expect(decoded).toEqual(empty)
    })

    it('should encode and decode base64url correctly', () => {
        // Test with bytes that produce + and / in standard base64
        const data = new Uint8Array([0xfb, 0xff, 0xfe])
        const standardBase64 = encodeBase64(data, 'base64')
        expect(standardBase64).toContain('+') // Should have + or /

        const base64url = encodeBase64(data, 'base64url')
        expect(base64url).not.toContain('+')
        expect(base64url).not.toContain('/')
        expect(base64url).not.toContain('=')

        // Should decode back correctly
        const decoded = decodeBase64(base64url, 'base64url')
        expect(decoded).toEqual(data)
    })

    it('should roundtrip random bytes', () => {
        const random = getRandomBytes(100)
        const encoded = encodeBase64(random)
        const decoded = decodeBase64(encoded)
        expect(decoded).toEqual(random)
    })
})

describe('Random bytes', () => {
    it('should generate correct length', () => {
        expect(getRandomBytes(0).length).toBe(0)
        expect(getRandomBytes(1).length).toBe(1)
        expect(getRandomBytes(32).length).toBe(32)
        expect(getRandomBytes(100).length).toBe(100)
    })

    it('should generate different values each time', () => {
        const a = getRandomBytes(32)
        const b = getRandomBytes(32)
        // Extremely unlikely to be equal
        expect(a).not.toEqual(b)
    })
})

describe('Constant time comparison', () => {
    it('should return true for equal arrays', () => {
        const a = new Uint8Array([1, 2, 3, 4, 5])
        const b = new Uint8Array([1, 2, 3, 4, 5])
        expect(constantTimeEqual(a, b)).toBe(true)
    })

    it('should return false for different arrays', () => {
        const a = new Uint8Array([1, 2, 3, 4, 5])
        const b = new Uint8Array([1, 2, 3, 4, 6])
        expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should return false for different lengths', () => {
        const a = new Uint8Array([1, 2, 3])
        const b = new Uint8Array([1, 2, 3, 4])
        expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should return true for empty arrays', () => {
        expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
    })
})

describe('Byte concatenation', () => {
    it('should concatenate arrays', () => {
        const a = new Uint8Array([1, 2])
        const b = new Uint8Array([3, 4])
        const c = new Uint8Array([5])
        expect(concatBytes(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5]))
    })

    it('should handle empty arrays', () => {
        const a = new Uint8Array([1, 2])
        const empty = new Uint8Array(0)
        expect(concatBytes(a, empty)).toEqual(a)
        expect(concatBytes(empty, a)).toEqual(a)
        expect(concatBytes(empty, empty)).toEqual(empty)
    })

    it('should handle single array', () => {
        const a = new Uint8Array([1, 2, 3])
        expect(concatBytes(a)).toEqual(a)
    })
})

describe('String/bytes conversion', () => {
    it('should convert string to bytes and back', () => {
        const str = 'Hello, World!'
        const bytes = stringToBytes(str)
        const back = bytesToString(bytes)
        expect(back).toBe(str)
    })

    it('should handle Unicode correctly', () => {
        const str = '你好世界 🌍'
        const bytes = stringToBytes(str)
        const back = bytesToString(bytes)
        expect(back).toBe(str)
    })

    it('should handle empty string', () => {
        const bytes = stringToBytes('')
        expect(bytes.length).toBe(0)
        expect(bytesToString(bytes)).toBe('')
    })
})

describe('Zero bytes', () => {
    it('should zero out array', () => {
        const arr = new Uint8Array([1, 2, 3, 4, 5])
        zeroBytes(arr)
        expect(arr).toEqual(new Uint8Array([0, 0, 0, 0, 0]))
    })

    it('should handle empty array', () => {
        const arr = new Uint8Array(0)
        zeroBytes(arr) // Should not throw
        expect(arr.length).toBe(0)
    })
})

describe('Number/bytes conversion', () => {
    it('should convert numbers to big-endian bytes', () => {
        expect(numberToBytes(0)).toEqual(new Uint8Array([0, 0, 0, 0]))
        expect(numberToBytes(1)).toEqual(new Uint8Array([0, 0, 0, 1]))
        expect(numberToBytes(256)).toEqual(new Uint8Array([0, 0, 1, 0]))
        expect(numberToBytes(0x12345678)).toEqual(new Uint8Array([0x12, 0x34, 0x56, 0x78]))
    })

    it('should convert bytes back to numbers', () => {
        expect(bytesToNumber(new Uint8Array([0, 0, 0, 0]))).toBe(0)
        expect(bytesToNumber(new Uint8Array([0, 0, 0, 1]))).toBe(1)
        expect(bytesToNumber(new Uint8Array([0, 0, 1, 0]))).toBe(256)
        expect(bytesToNumber(new Uint8Array([0x12, 0x34, 0x56, 0x78]))).toBe(0x12345678)
    })

    it('should roundtrip', () => {
        const values = [0, 1, 255, 256, 65535, 16777215, 0xffffffff >>> 0]
        for (const v of values) {
            expect(bytesToNumber(numberToBytes(v))).toBe(v)
        }
    })

    it('should throw for wrong byte length', () => {
        expect(() => bytesToNumber(new Uint8Array([1, 2, 3]))).toThrow()
        expect(() => bytesToNumber(new Uint8Array([1, 2, 3, 4, 5]))).toThrow()
    })
})
