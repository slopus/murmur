import { gcm } from '@noble/ciphers/aes'
import { sha256 } from '@noble/hashes/sha256'
import { dh, deriveDhKeyPairFromSigningKey, generateDH } from '../crypto/dh.js'
import { hkdfExpand } from '../crypto/kdf.js'
import {
    bytesToString,
    concatBytes,
    getRandomBytes,
    numberToBytes,
    stringToBytes
} from '../crypto/utils.js'
import type { FeedItemContent, FeedMetadata } from './types.js'

const FEED_KEY_INFO_PREFIX = 'murmur-feed-key:'
const FEED_KEY_LENGTH = 32
const FEED_IV_LENGTH = 12
const SEALED_BOX_INFO = 'murmur-feed-sealed-box'
const METADATA_SALT = sha256(stringToBytes('murmur-feed-metadata'))

function encodeFeedIdSalt(feedId: string): Uint8Array {
    return stringToBytes(feedId)
}

function deriveMetadataKey(identityPrivateKey: Uint8Array, feedId: string): Uint8Array {
    return hkdfExpand(identityPrivateKey, METADATA_SALT, `murmur-feed-metadata:${feedId}`, FEED_KEY_LENGTH)
}

function encryptBytes(payload: Uint8Array, key: Uint8Array): Uint8Array {
    const iv = getRandomBytes(FEED_IV_LENGTH)
    const ciphertext = gcm(key, iv).encrypt(payload)
    return concatBytes(iv, ciphertext)
}

function decryptBytes(blob: Uint8Array, key: Uint8Array): Uint8Array {
    if (blob.length <= FEED_IV_LENGTH) {
        throw new Error('Invalid encrypted feed blob')
    }
    const iv = blob.slice(0, FEED_IV_LENGTH)
    const ciphertext = blob.slice(FEED_IV_LENGTH)
    return gcm(key, iv).decrypt(ciphertext)
}

export function deriveFeedKey(identityPrivateKey: Uint8Array, feedId: string, epoch: number): Uint8Array {
    if (!Number.isInteger(epoch) || epoch < 0) {
        throw new Error(`Invalid feed epoch: ${epoch}`)
    }
    return hkdfExpand(
        identityPrivateKey,
        encodeFeedIdSalt(feedId),
        `${FEED_KEY_INFO_PREFIX}${epoch}`,
        FEED_KEY_LENGTH
    )
}

export function encryptFeedKey(feedKey: Uint8Array, recipientDhPublicKey: Uint8Array): Uint8Array {
    if (feedKey.length !== FEED_KEY_LENGTH) {
        throw new Error(`Invalid feed key length: expected ${FEED_KEY_LENGTH}, got ${feedKey.length}`)
    }

    const ephemeral = generateDH()
    const sharedSecret = dh(ephemeral, recipientDhPublicKey)
    const wrappingKey = hkdfExpand(sharedSecret, ephemeral.publicKey, SEALED_BOX_INFO, FEED_KEY_LENGTH)
    const encrypted = encryptBytes(feedKey, wrappingKey)
    return concatBytes(ephemeral.publicKey, encrypted)
}

export function decryptFeedKey(encryptedKey: Uint8Array, recipientIdentityPrivateKey: Uint8Array): Uint8Array {
    if (encryptedKey.length <= 32 + FEED_IV_LENGTH) {
        throw new Error('Invalid encrypted feed key')
    }

    const recipientDh = deriveDhKeyPairFromSigningKey(recipientIdentityPrivateKey)
    const ephemeralPublicKey = encryptedKey.slice(0, 32)
    const ciphertext = encryptedKey.slice(32)
    const sharedSecret = dh(recipientDh, ephemeralPublicKey)
    const wrappingKey = hkdfExpand(sharedSecret, ephemeralPublicKey, SEALED_BOX_INFO, FEED_KEY_LENGTH)
    return decryptBytes(ciphertext, wrappingKey)
}

export function encryptFeedItem(content: FeedItemContent, feedKey: Uint8Array): Uint8Array {
    return encryptBytes(stringToBytes(JSON.stringify(content)), feedKey)
}

export function decryptFeedItem(blob: Uint8Array, feedKey: Uint8Array): FeedItemContent {
    const plaintext = decryptBytes(blob, feedKey)
    return JSON.parse(bytesToString(plaintext)) as FeedItemContent
}

export function encryptFeedMetadata(metadata: FeedMetadata, identityPrivateKey: Uint8Array, feedId: string): Uint8Array {
    return encryptBytes(stringToBytes(JSON.stringify(metadata)), deriveMetadataKey(identityPrivateKey, feedId))
}

export function decryptFeedMetadata(blob: Uint8Array, identityPrivateKey: Uint8Array, feedId: string): FeedMetadata {
    const plaintext = decryptBytes(blob, deriveMetadataKey(identityPrivateKey, feedId))
    return JSON.parse(bytesToString(plaintext)) as FeedMetadata
}

export function encodeFeedEpoch(epoch: number): Uint8Array {
    return numberToBytes(epoch)
}
