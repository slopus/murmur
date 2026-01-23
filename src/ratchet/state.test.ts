/**
 * Tests for ratchet state management.
 */

import { describe, it, expect } from 'vitest'
import {
    serializeState,
    deserializeState,
    createEmptyState,
    cloneState,
    makeSkippedKeyIndex,
    parseSkippedKeyIndex
} from './state.js'
import { generateDH } from '../crypto/dh.js'
import { getRandomBytes, constantTimeEqual, encodeBase64 } from '../crypto/utils.js'
import type { RatchetState } from './types.js'

describe('State serialization', () => {
    it('should serialize and deserialize empty state', () => {
        const rootKey = getRandomBytes(32)
        const state = createEmptyState(rootKey)

        const serialized = serializeState(state)
        const deserialized = deserializeState(serialized)

        expect(constantTimeEqual(deserialized.rootKey, state.rootKey)).toBe(true)
        expect(constantTimeEqual(deserialized.dhSelf.privateKey, state.dhSelf.privateKey)).toBe(true)
        expect(constantTimeEqual(deserialized.dhSelf.publicKey, state.dhSelf.publicKey)).toBe(true)
        expect(deserialized.dhRemote).toBeNull()
        expect(deserialized.sendingChainKey).toBeNull()
        expect(deserialized.receivingChainKey).toBeNull()
    })

    it('should serialize and deserialize full state', () => {
        const state: RatchetState = {
            dhSelf: generateDH(),
            dhRemote: generateDH().publicKey,
            rootKey: getRandomBytes(32),
            sendingChainKey: getRandomBytes(32),
            receivingChainKey: getRandomBytes(32),
            sendingMessageNumber: 42,
            receivingMessageNumber: 17,
            previousSendingChainLength: 5,
            skippedMessageKeys: new Map()
        }

        // Add some skipped keys
        const pubKey = generateDH().publicKey
        state.skippedMessageKeys.set(makeSkippedKeyIndex(pubKey, 3), getRandomBytes(32))
        state.skippedMessageKeys.set(makeSkippedKeyIndex(pubKey, 5), getRandomBytes(32))

        const serialized = serializeState(state)
        const deserialized = deserializeState(serialized)

        expect(constantTimeEqual(deserialized.rootKey, state.rootKey)).toBe(true)
        expect(constantTimeEqual(deserialized.dhSelf.privateKey, state.dhSelf.privateKey)).toBe(true)
        expect(constantTimeEqual(deserialized.dhRemote!, state.dhRemote!)).toBe(true)
        expect(constantTimeEqual(deserialized.sendingChainKey!, state.sendingChainKey!)).toBe(true)
        expect(constantTimeEqual(deserialized.receivingChainKey!, state.receivingChainKey!)).toBe(true)
        expect(deserialized.sendingMessageNumber).toBe(42)
        expect(deserialized.receivingMessageNumber).toBe(17)
        expect(deserialized.previousSendingChainLength).toBe(5)
        expect(deserialized.skippedMessageKeys.size).toBe(2)
    })

    it('should produce JSON-serializable output', () => {
        const state = createEmptyState(getRandomBytes(32))
        const serialized = serializeState(state)

        // Should not throw
        const json = JSON.stringify(serialized)
        const parsed = JSON.parse(json)

        expect(parsed.dhSelfPrivateKey).toBeDefined()
        expect(typeof parsed.dhSelfPrivateKey).toBe('string')
    })
})

describe('createEmptyState', () => {
    it('should create state with provided root key', () => {
        const rootKey = getRandomBytes(32)
        const state = createEmptyState(rootKey)

        expect(constantTimeEqual(state.rootKey, rootKey)).toBe(true)
    })

    it('should generate new DH key pair if not provided', () => {
        const state1 = createEmptyState(getRandomBytes(32))
        const state2 = createEmptyState(getRandomBytes(32))

        expect(constantTimeEqual(state1.dhSelf.publicKey, state2.dhSelf.publicKey)).toBe(false)
    })

    it('should use provided DH key pair', () => {
        const keyPair = generateDH()
        const state = createEmptyState(getRandomBytes(32), keyPair)

        expect(constantTimeEqual(state.dhSelf.publicKey, keyPair.publicKey)).toBe(true)
        expect(constantTimeEqual(state.dhSelf.privateKey, keyPair.privateKey)).toBe(true)
    })

    it('should initialize counters to zero', () => {
        const state = createEmptyState(getRandomBytes(32))

        expect(state.sendingMessageNumber).toBe(0)
        expect(state.receivingMessageNumber).toBe(0)
        expect(state.previousSendingChainLength).toBe(0)
    })

    it('should initialize chains to null', () => {
        const state = createEmptyState(getRandomBytes(32))

        expect(state.dhRemote).toBeNull()
        expect(state.sendingChainKey).toBeNull()
        expect(state.receivingChainKey).toBeNull()
    })

    it('should initialize empty skipped keys map', () => {
        const state = createEmptyState(getRandomBytes(32))

        expect(state.skippedMessageKeys.size).toBe(0)
    })
})

describe('cloneState', () => {
    it('should create independent copy', () => {
        const original = createEmptyState(getRandomBytes(32))
        original.sendingChainKey = getRandomBytes(32)
        original.sendingMessageNumber = 5

        const clone = cloneState(original)

        // Modify original
        original.sendingMessageNumber = 10
        original.sendingChainKey![0] = 0xff

        // Clone should be unchanged
        expect(clone.sendingMessageNumber).toBe(5)
        expect(clone.sendingChainKey![0]).not.toBe(0xff)
    })

    it('should clone skipped keys map', () => {
        const original = createEmptyState(getRandomBytes(32))
        const pubKey = generateDH().publicKey
        original.skippedMessageKeys.set(makeSkippedKeyIndex(pubKey, 1), getRandomBytes(32))

        const clone = cloneState(original)

        // Modify original map
        original.skippedMessageKeys.clear()

        // Clone should still have the key
        expect(clone.skippedMessageKeys.size).toBe(1)
    })

    it('should handle null values', () => {
        const original = createEmptyState(getRandomBytes(32))
        const clone = cloneState(original)

        expect(clone.dhRemote).toBeNull()
        expect(clone.sendingChainKey).toBeNull()
        expect(clone.receivingChainKey).toBeNull()
    })
})

describe('Skipped key index', () => {
    it('should create unique keys for different public keys', () => {
        const pk1 = generateDH().publicKey
        const pk2 = generateDH().publicKey

        const key1 = makeSkippedKeyIndex(pk1, 5)
        const key2 = makeSkippedKeyIndex(pk2, 5)

        expect(key1).not.toBe(key2)
    })

    it('should create unique keys for different message numbers', () => {
        const pk = generateDH().publicKey

        const key1 = makeSkippedKeyIndex(pk, 1)
        const key2 = makeSkippedKeyIndex(pk, 2)

        expect(key1).not.toBe(key2)
    })

    it('should parse back correctly', () => {
        const pk = generateDH().publicKey
        const msgNum = 42

        const key = makeSkippedKeyIndex(pk, msgNum)
        const parsed = parseSkippedKeyIndex(key)

        expect(constantTimeEqual(parsed.publicKey, pk)).toBe(true)
        expect(parsed.messageNumber).toBe(msgNum)
    })

    it('should throw on invalid key format', () => {
        expect(() => parseSkippedKeyIndex('invalid')).toThrow()
        expect(() => parseSkippedKeyIndex('base64:notanumber')).toThrow()
    })

    it('should handle message number 0', () => {
        const pk = generateDH().publicKey
        const key = makeSkippedKeyIndex(pk, 0)
        const parsed = parseSkippedKeyIndex(key)

        expect(parsed.messageNumber).toBe(0)
    })
})
