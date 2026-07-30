/**
 * Authenticated Encryption with Associated Data (AEAD) using ChaCha20-Poly1305.
 *
 * ChaCha20-Poly1305 is used for message encryption in the Double Ratchet protocol.
 * It provides both confidentiality and authenticity:
 * - ChaCha20: Stream cipher for encryption
 * - Poly1305: MAC for authentication
 *
 * Properties:
 * - Key size: 32 bytes
 * - Nonce size: 12 bytes (standard IETF variant)
 * - Auth tag: 16 bytes (appended to ciphertext)
 *
 * We derive the nonce from the message key using HKDF to ensure uniqueness
 * without requiring separate nonce transmission.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, stringToBytes } from "./utils.js";

/** Length of encryption key in bytes */
export const AEAD_KEY_LENGTH = 32;

/** Length of nonce in bytes (IETF ChaCha20-Poly1305) */
export const AEAD_NONCE_LENGTH = 12;

/** Length of authentication tag in bytes */
export const AEAD_TAG_LENGTH = 16;

/** HKDF info for deriving encryption key from message key */
const HKDF_INFO_ENCRYPTION = stringToBytes("MurmurEncryption");

/** HKDF info for deriving nonce from message key */
const HKDF_INFO_NONCE = stringToBytes("MurmurNonce");

/**
 * Derive encryption key and nonce from a message key.
 *
 * The message key from KDF_CK is used as HKDF input to derive:
 * - 32-byte encryption key
 * - 12-byte nonce
 *
 * This approach is recommended by the Signal Protocol specification
 * as an alternative to transmitting nonces.
 *
 * @param messageKey - 32-byte message key from KDF_CK
 * @returns Object with encryptionKey and nonce
 */
function deriveKeyAndNonce(messageKey: Uint8Array): {
    encryptionKey: Uint8Array;
    nonce: Uint8Array;
} {
    // Use message key as input key material with no salt
    const encryptionKey = hkdf(
        sha256,
        messageKey,
        undefined,
        HKDF_INFO_ENCRYPTION,
        AEAD_KEY_LENGTH,
    );
    const nonce = hkdf(sha256, messageKey, undefined, HKDF_INFO_NONCE, AEAD_NONCE_LENGTH);

    return { encryptionKey, nonce };
}

/**
 * Encrypt plaintext using ChaCha20-Poly1305.
 *
 * The message key is used to derive both the encryption key and nonce,
 * ensuring each message key produces a unique (key, nonce) pair.
 *
 * Associated data is authenticated but not encrypted, allowing the
 * header to be verified as part of the ciphertext authentication.
 *
 * @param messageKey - 32-byte message key from the chain
 * @param plaintext - Data to encrypt
 * @param associatedData - Additional data to authenticate (e.g., header)
 * @returns Ciphertext with authentication tag appended (length = plaintext.length + 16)
 *
 * @example
 * ```typescript
 * const ciphertext = encrypt(messageKey, plaintext, header)
 * // ciphertext includes 16-byte auth tag at end
 * ```
 */
export function encrypt(
    messageKey: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array,
): Uint8Array {
    const { encryptionKey, nonce } = deriveKeyAndNonce(messageKey);

    const cipher = chacha20poly1305(encryptionKey, nonce, associatedData);
    return cipher.encrypt(plaintext);
}

/**
 * Decrypt ciphertext using ChaCha20-Poly1305.
 *
 * Verifies the authentication tag before returning plaintext.
 * Throws an error if authentication fails (ciphertext was tampered with
 * or wrong key was used).
 *
 * @param messageKey - 32-byte message key from the chain
 * @param ciphertext - Encrypted data with auth tag (from encrypt())
 * @param associatedData - Additional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 *
 * @example
 * ```typescript
 * try {
 *   const plaintext = decrypt(messageKey, ciphertext, header)
 * } catch (e) {
 *   // Authentication failed - wrong key or tampered data
 * }
 * ```
 */
export function decrypt(
    messageKey: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
): Uint8Array {
    const { encryptionKey, nonce } = deriveKeyAndNonce(messageKey);

    const cipher = chacha20poly1305(encryptionKey, nonce, associatedData);
    return cipher.decrypt(ciphertext);
}

/**
 * Encrypt a JSON-serializable value.
 *
 * Convenience function that handles JSON serialization.
 *
 * @param messageKey - 32-byte message key
 * @param data - JSON-serializable data
 * @param associatedData - Additional authenticated data
 * @returns Ciphertext bytes
 */
export function encryptJson(
    messageKey: Uint8Array,
    data: unknown,
    associatedData: Uint8Array,
): Uint8Array {
    const plaintext = stringToBytes(JSON.stringify(data));
    return encrypt(messageKey, plaintext, associatedData);
}

/**
 * Decrypt to a JSON value.
 *
 * @param messageKey - 32-byte message key
 * @param ciphertext - Encrypted data
 * @param associatedData - Additional authenticated data
 * @returns Parsed JSON value
 * @throws Error if decryption or JSON parsing fails
 */
export function decryptJson<T = unknown>(
    messageKey: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
): T {
    const plaintext = decrypt(messageKey, ciphertext, associatedData);
    return JSON.parse(new TextDecoder().decode(plaintext));
}
