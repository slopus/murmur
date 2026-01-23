/**
 * Message header encoding and decoding.
 *
 * The header contains ratchet metadata needed to derive the correct
 * message key for decryption. It is authenticated (as associated data)
 * but not encrypted in the standard Double Ratchet.
 *
 * Header format (44 bytes total):
 * - Public key: 32 bytes (DH ratchet key)
 * - Previous chain length: 4 bytes (big-endian uint32)
 * - Message number: 4 bytes (big-endian uint32)
 * - Reserved: 4 bytes (for future extensions)
 */

import { concatBytes, numberToBytes, bytesToNumber } from '../crypto/utils.js'
import { DH_PUBLIC_KEY_LENGTH } from '../crypto/dh.js'
import type { MessageHeader } from './types.js'

/** Total size of encoded header in bytes */
export const HEADER_SIZE = 44

/**
 * Encode a message header to bytes.
 *
 * The header format is designed to be self-describing and parseable
 * without external context. The public key must not be null.
 *
 * @param header - Message header to encode
 * @returns 44-byte encoded header
 * @throws Error if public key is missing or wrong length
 *
 * @example
 * ```typescript
 * const header: MessageHeader = {
 *   publicKey: dhKeyPair.publicKey,
 *   messageNumber: 5,
 *   previousChainLength: 3
 * }
 * const encoded = encodeHeader(header)
 * // encoded is 44 bytes
 * ```
 */
export function encodeHeader(header: MessageHeader): Uint8Array {
    if (!header.publicKey) {
        throw new Error('Header public key must not be null')
    }
    if (header.publicKey.length !== DH_PUBLIC_KEY_LENGTH) {
        throw new Error(`Invalid public key length: expected ${DH_PUBLIC_KEY_LENGTH}, got ${header.publicKey.length}`)
    }

    // Validate message numbers are non-negative integers
    if (header.messageNumber < 0 || !Number.isInteger(header.messageNumber)) {
        throw new Error(`Invalid message number: ${header.messageNumber}`)
    }
    if (header.previousChainLength < 0 || !Number.isInteger(header.previousChainLength)) {
        throw new Error(`Invalid previous chain length: ${header.previousChainLength}`)
    }

    const pnBytes = numberToBytes(header.previousChainLength)
    const nBytes = numberToBytes(header.messageNumber)
    const reserved = new Uint8Array(4) // Reserved for future use

    return concatBytes(header.publicKey, pnBytes, nBytes, reserved)
}

/**
 * Decode bytes to a message header.
 *
 * @param data - 44-byte encoded header
 * @returns Decoded MessageHeader
 * @throws Error if data is wrong length or malformed
 *
 * @example
 * ```typescript
 * const header = decodeHeader(encodedHeader)
 * console.log(header.messageNumber) // e.g., 5
 * ```
 */
export function decodeHeader(data: Uint8Array): MessageHeader {
    if (data.length !== HEADER_SIZE) {
        throw new Error(`Invalid header length: expected ${HEADER_SIZE}, got ${data.length}`)
    }

    const publicKey = data.slice(0, DH_PUBLIC_KEY_LENGTH)
    const previousChainLength = bytesToNumber(data.slice(32, 36))
    const messageNumber = bytesToNumber(data.slice(36, 40))
    // Bytes 40-43 are reserved

    return {
        publicKey,
        messageNumber,
        previousChainLength
    }
}

/**
 * Create a header from ratchet state for sending.
 *
 * @param publicKey - Current sending DH public key
 * @param previousChainLength - Number of messages in previous chain
 * @param messageNumber - Current message number in sending chain
 * @returns MessageHeader ready to encode
 */
export function createHeader(
    publicKey: Uint8Array,
    previousChainLength: number,
    messageNumber: number
): MessageHeader {
    return {
        publicKey,
        previousChainLength,
        messageNumber
    }
}
