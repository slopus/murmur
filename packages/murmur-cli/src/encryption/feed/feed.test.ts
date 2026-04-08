import { describe, expect, it } from 'vitest'
import { createId } from '@paralleldrive/cuid2'
import { generateSigningKeyPair } from '../crypto/signing.js'
import { deriveDhKeyPairFromSigningKey } from '../crypto/dh.js'
import {
    decryptFeedItem,
    decryptFeedKey,
    decryptFeedMetadata,
    deriveFeedKey,
    encryptFeedItem,
    encryptFeedKey,
    encryptFeedMetadata
} from './feed.js'

describe('feed crypto', () => {
    it('derives deterministic feed keys per feed and epoch', () => {
        const alice = generateSigningKeyPair()
        const feedId = createId()

        const epoch0a = deriveFeedKey(alice.privateKey, feedId, 0)
        const epoch0b = deriveFeedKey(alice.privateKey, feedId, 0)
        const epoch1 = deriveFeedKey(alice.privateKey, feedId, 1)
        const otherFeed = deriveFeedKey(alice.privateKey, createId(), 0)

        expect(epoch0a).toEqual(epoch0b)
        expect(epoch0a).not.toEqual(epoch1)
        expect(epoch0a).not.toEqual(otherFeed)
    })

    it('encrypts a feed key to a recipient identity', () => {
        const alice = generateSigningKeyPair()
        const bob = generateSigningKeyPair()
        const bobDh = deriveDhKeyPairFromSigningKey(bob.privateKey)
        const feedKey = deriveFeedKey(alice.privateKey, createId(), 0)

        const encrypted = encryptFeedKey(feedKey, bobDh.publicKey)
        const decrypted = decryptFeedKey(encrypted, bob.privateKey)

        expect(decrypted).toEqual(feedKey)
    })

    it('encrypts and decrypts feed items', () => {
        const alice = generateSigningKeyPair()
        const feedKey = deriveFeedKey(alice.privateKey, createId(), 0)

        const blob = encryptFeedItem({
            text: 'hello from the feed',
            attachments: {
                'photo.png': {
                    hash: 'hash',
                    iv: 'iv',
                    key: 'key',
                    ciphertext: 'ciphertext'
                }
            }
        }, feedKey)

        expect(decryptFeedItem(blob, feedKey)).toEqual({
            text: 'hello from the feed',
            attachments: {
                'photo.png': {
                    hash: 'hash',
                    iv: 'iv',
                    key: 'key',
                    ciphertext: 'ciphertext'
                }
            }
        })
    })

    it('encrypts metadata so only the owner identity can decrypt it', () => {
        const alice = generateSigningKeyPair()
        const bob = generateSigningKeyPair()
        const feedId = createId()
        const blob = encryptFeedMetadata({
            name: 'Close Friends',
            description: 'Internal notes'
        }, alice.privateKey, feedId)

        expect(decryptFeedMetadata(blob, alice.privateKey, feedId)).toEqual({
            name: 'Close Friends',
            description: 'Internal notes'
        })
        expect(() => decryptFeedMetadata(blob, bob.privateKey, feedId)).toThrow()
    })
})
