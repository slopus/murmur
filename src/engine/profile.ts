/**
 * Profile encryption and decryption.
 *
 * Profiles contain firstName and optional lastName, encrypted with a profile key.
 * The profile key is derived from a secret that only the owner knows.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha'
import { generateDH, publicKeyFromPrivate, type DHKeyPair } from '../encryption/crypto/dh.js'
import { generateSigningKeyPair, sign, verify } from '../encryption/crypto/signing.js'
import {
    encodeBase64,
    decodeBase64,
    stringToBytes,
    bytesToString,
    getRandomBytes
} from '../encryption/crypto/utils.js'
import { hkdfExpand } from '../encryption/crypto/kdf.js'

/**
 * Profile data structure.
 */
export interface Profile {
    firstName: string
    lastName?: string
}

/**
 * Generate a new profile key pair.
 * The private key is used to decrypt, public key is used to fetch from server.
 */
export function generateProfileKeyPair(): DHKeyPair {
    return generateDH()
}

/**
 * Derive encryption key from profile secret key.
 */
function deriveProfileEncryptionKey(profileSecretKey: Uint8Array): Uint8Array {
    return hkdfExpand(profileSecretKey, undefined, 'murmur-profile-encryption', 32)
}

/**
 * Encrypt a profile with the profile secret key.
 */
export function encryptProfile(profile: Profile, profileSecretKey: Uint8Array): string {
    const plaintext = stringToBytes(JSON.stringify(profile))
    const key = deriveProfileEncryptionKey(profileSecretKey)
    const nonce = getRandomBytes(12)

    // Use chacha20poly1305 directly with explicit nonce
    const cipher = chacha20poly1305(key, nonce)
    const ciphertext = cipher.encrypt(plaintext)

    // Combine nonce + ciphertext (ciphertext includes auth tag)
    const combined = new Uint8Array(nonce.length + ciphertext.length)
    combined.set(nonce)
    combined.set(ciphertext, nonce.length)

    return encodeBase64(combined)
}

/**
 * Decrypt a profile with the profile secret key.
 */
export function decryptProfile(encryptedProfile: string, profileSecretKey: Uint8Array): Profile {
    const combined = decodeBase64(encryptedProfile)
    const nonce = combined.slice(0, 12)
    const ciphertext = combined.slice(12)
    const key = deriveProfileEncryptionKey(profileSecretKey)

    // Use chacha20poly1305 directly with explicit nonce
    const cipher = chacha20poly1305(key, nonce)
    const plaintext = cipher.decrypt(ciphertext)

    return JSON.parse(bytesToString(plaintext))
}

/**
 * Sign the profile public key with the identity key.
 * This proves the profile belongs to this identity.
 * Signs the raw public key bytes.
 */
export function signProfileKey(
    profilePublicKey: Uint8Array,
    identityPrivateKey: Uint8Array
): string {
    // Sign the raw bytes of the profile public key
    const signature = sign(profilePublicKey, identityPrivateKey)
    return encodeBase64(signature)
}

/**
 * Verify a profile key signature.
 * Verifies against the raw public key bytes.
 */
export function verifyProfileKeySignature(
    profilePublicKey: Uint8Array,
    signature: string,
    identityPublicKey: Uint8Array
): boolean {
    // Verify against raw bytes, matching signProfileKey
    return verify(profilePublicKey, decodeBase64(signature), identityPublicKey)
}

/**
 * Create profile data for registration.
 */
export function createProfileForRegistration(
    profile: Profile,
    identityPrivateKey: Uint8Array
): {
    profileKeyPair: DHKeyPair
    profilePublicKey: string
    profileSecretKey: string
    profileKeySignature: string
    encryptedProfile: string
} {
    const profileKeyPair = generateProfileKeyPair()
    const profilePublicKey = encodeBase64(profileKeyPair.publicKey)
    const profileSecretKey = encodeBase64(profileKeyPair.privateKey, 'base64url')
    const profileKeySignature = signProfileKey(profileKeyPair.publicKey, identityPrivateKey)
    const encryptedProfile = encryptProfile(profile, profileKeyPair.privateKey)

    return {
        profileKeyPair,
        profilePublicKey,
        profileSecretKey,
        profileKeySignature,
        encryptedProfile
    }
}
