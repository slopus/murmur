/**
 * Cryptographic utility functions for Murmur.
 *
 * Provides base64 encoding/decoding, random byte generation, and
 * byte array manipulation utilities used throughout the protocol.
 */

import { randomBytes as cryptoRandomBytes } from 'node:crypto'

/**
 * Encode a Uint8Array to base64 string
 * @param buffer - The buffer to encode
 * @param variant - The encoding variant ('base64' or 'base64url')
 * @returns Base64 encoded string
 */
export function encodeBase64(buffer: Uint8Array, variant: 'base64' | 'base64url' = 'base64'): string {
    if (variant === 'base64url') {
        return encodeBase64Url(buffer)
    }
    return Buffer.from(buffer).toString('base64')
}

/**
 * Encode a Uint8Array to base64url string (URL-safe base64)
 * Base64URL uses '-' instead of '+', '_' instead of '/', and removes padding
 * @param buffer - The buffer to encode
 * @returns Base64url encoded string
 */
export function encodeBase64Url(buffer: Uint8Array): string {
    return Buffer.from(buffer)
        .toString('base64')
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '')
}

/**
 * Decode a base64 string to a Uint8Array
 * @param base64 - The base64 string to decode
 * @param variant - The encoding variant ('base64' or 'base64url')
 * @returns The decoded Uint8Array
 */
export function decodeBase64(base64: string, variant: 'base64' | 'base64url' = 'base64'): Uint8Array {
    if (variant === 'base64url') {
        // Convert base64url to base64
        const base64Standard = base64
            .replaceAll('-', '+')
            .replaceAll('_', '/')
            + '='.repeat((4 - base64.length % 4) % 4)
        return new Uint8Array(Buffer.from(base64Standard, 'base64'))
    }
    return new Uint8Array(Buffer.from(base64, 'base64'))
}

/**
 * Generate cryptographically secure random bytes
 * @param size - Number of random bytes to generate
 * @returns Uint8Array of random bytes
 */
export function getRandomBytes(size: number): Uint8Array {
    return new Uint8Array(cryptoRandomBytes(size))
}

/**
 * Constant-time comparison of two byte arrays
 * Prevents timing attacks by always comparing all bytes
 * @param a - First byte array
 * @param b - Second byte array
 * @returns true if arrays are equal, false otherwise
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false
    }
    let result = 0
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i]
    }
    return result === 0
}

/**
 * Concatenate multiple Uint8Arrays into a single array
 * @param arrays - Arrays to concatenate
 * @returns Combined Uint8Array
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0)
    const result = new Uint8Array(totalLength)
    let offset = 0
    for (const arr of arrays) {
        result.set(arr, offset)
        offset += arr.length
    }
    return result
}

/**
 * Convert a UTF-8 string to Uint8Array
 * @param str - String to encode
 * @returns UTF-8 encoded bytes
 */
export function stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str)
}

/**
 * Convert Uint8Array to UTF-8 string
 * @param bytes - Bytes to decode
 * @returns Decoded string
 */
export function bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes)
}

/**
 * Zero out a byte array (for secure key deletion)
 * @param arr - Array to zero
 */
export function zeroBytes(arr: Uint8Array): void {
    arr.fill(0)
}

/**
 * Convert a number to 4-byte big-endian representation
 * @param num - Number to convert (must be non-negative integer < 2^32)
 * @returns 4-byte Uint8Array
 */
export function numberToBytes(num: number): Uint8Array {
    const bytes = new Uint8Array(4)
    bytes[0] = (num >>> 24) & 0xff
    bytes[1] = (num >>> 16) & 0xff
    bytes[2] = (num >>> 8) & 0xff
    bytes[3] = num & 0xff
    return bytes
}

/**
 * Convert 4-byte big-endian representation to number
 * @param bytes - 4-byte array
 * @returns Number (unsigned 32-bit integer)
 */
export function bytesToNumber(bytes: Uint8Array): number {
    if (bytes.length !== 4) {
        throw new Error('Expected 4 bytes for number conversion')
    }
    // Use >>> 0 to ensure unsigned 32-bit result
    return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0
}
