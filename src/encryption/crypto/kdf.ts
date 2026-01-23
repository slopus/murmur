/**
 * Key Derivation Functions (KDF) for the Double Ratchet protocol.
 *
 * This module implements the KDF chains required by the Signal Protocol:
 * - KDF_RK: Root key derivation (mixing in DH outputs)
 * - KDF_CK: Chain key derivation (symmetric ratchet step)
 *
 * We use HKDF with SHA-256 as recommended by the Signal Protocol specification.
 * HMAC-SHA256 is used for chain key derivation with single-byte constants.
 */

import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { hmac } from '@noble/hashes/hmac'
import { concatBytes, stringToBytes } from './utils.js'

/** Length of root key in bytes */
export const ROOT_KEY_LENGTH = 32

/** Length of chain key in bytes */
export const CHAIN_KEY_LENGTH = 32

/** Length of message key in bytes */
export const MESSAGE_KEY_LENGTH = 32

/** HKDF info string for root chain derivation */
const HKDF_INFO_ROOT = stringToBytes('MurmurRatchet')

/** Constant for deriving message key from chain key */
const CHAIN_KEY_CONSTANT_MESSAGE = new Uint8Array([0x01])

/** Constant for deriving next chain key from chain key */
const CHAIN_KEY_CONSTANT_CHAIN = new Uint8Array([0x02])

/**
 * KDF for the root chain (KDF_RK).
 *
 * Derives a new root key and chain key from the current root key and a
 * Diffie-Hellman output. This is called during the DH ratchet step.
 *
 * Uses HKDF-SHA256:
 * - Salt: current root key (32 bytes)
 * - IKM: DH shared secret (32 bytes)
 * - Info: "MurmurRatchet"
 * - Output: 64 bytes split into (root_key, chain_key)
 *
 * @param rootKey - Current 32-byte root key (used as HKDF salt)
 * @param dhOutput - 32-byte Diffie-Hellman shared secret
 * @returns Tuple of [new_root_key, new_chain_key], each 32 bytes
 *
 * @example
 * ```typescript
 * const dhOutput = dh(myKeyPair, theirPublicKey)
 * const [newRootKey, chainKey] = kdfRK(currentRootKey, dhOutput)
 * ```
 */
export function kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
    if (rootKey.length !== ROOT_KEY_LENGTH) {
        throw new Error(`Invalid root key length: expected ${ROOT_KEY_LENGTH}, got ${rootKey.length}`)
    }
    if (dhOutput.length !== 32) {
        throw new Error(`Invalid DH output length: expected 32, got ${dhOutput.length}`)
    }

    // HKDF: extract-then-expand
    // Salt = rootKey, IKM = dhOutput, info = "MurmurRatchet"
    // Output 64 bytes: first 32 = new root key, second 32 = chain key
    const output = hkdf(sha256, dhOutput, rootKey, HKDF_INFO_ROOT, 64)

    const newRootKey = output.slice(0, ROOT_KEY_LENGTH)
    const chainKey = output.slice(ROOT_KEY_LENGTH, ROOT_KEY_LENGTH + CHAIN_KEY_LENGTH)

    return [newRootKey, chainKey]
}

/**
 * KDF for the chain key (KDF_CK).
 *
 * Advances the symmetric ratchet by one step, deriving a new chain key
 * and a message key from the current chain key.
 *
 * Uses HMAC-SHA256 with single-byte constants:
 * - Message key: HMAC(chain_key, 0x01)
 * - Next chain key: HMAC(chain_key, 0x02)
 *
 * This ensures the message key cannot be derived from the next chain key,
 * providing forward secrecy for individual messages.
 *
 * @param chainKey - Current 32-byte chain key
 * @returns Tuple of [new_chain_key, message_key], each 32 bytes
 * @throws Error if chain key is null/undefined (must have receiving chain)
 *
 * @example
 * ```typescript
 * const [newChainKey, messageKey] = kdfCK(currentChainKey)
 * // Use messageKey for encryption/decryption
 * // Store newChainKey for next message
 * ```
 */
export function kdfCK(chainKey: Uint8Array | null): [Uint8Array, Uint8Array] {
    if (!chainKey) {
        throw new Error('Chain key is null - receiving chain not initialized')
    }
    if (chainKey.length !== CHAIN_KEY_LENGTH) {
        throw new Error(`Invalid chain key length: expected ${CHAIN_KEY_LENGTH}, got ${chainKey.length}`)
    }

    // Derive message key: HMAC(ck, 0x01)
    const messageKey = hmac(sha256, chainKey, CHAIN_KEY_CONSTANT_MESSAGE)

    // Derive next chain key: HMAC(ck, 0x02)
    const newChainKey = hmac(sha256, chainKey, CHAIN_KEY_CONSTANT_CHAIN)

    return [newChainKey, messageKey]
}

/**
 * Derive multiple keys from initial keying material using HKDF.
 *
 * Used during session initialization to derive root key and initial chain keys
 * from a shared secret established via key agreement (e.g., X3DH).
 *
 * @param sharedSecret - Shared secret from key agreement
 * @param salt - Optional salt (defaults to zeros)
 * @param info - Context info string
 * @param length - Number of bytes to derive
 * @returns Derived key material
 */
export function hkdfExpand(
    sharedSecret: Uint8Array,
    salt: Uint8Array | undefined,
    info: string,
    length: number
): Uint8Array {
    const infoBytes = stringToBytes(info)
    return hkdf(sha256, sharedSecret, salt, infoBytes, length)
}
