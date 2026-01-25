/**
 * X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol.
 *
 * X3DH provides:
 * - Mutual authentication using identity keys
 * - Forward secrecy using ephemeral keys
 * - Asynchronous operation (parties need not be online simultaneously)
 *
 * The protocol flow:
 * 1. Bob publishes a prekey bundle to the server
 * 2. Alice fetches Bob's bundle and computes a shared secret
 * 3. Alice sends an initial message with her ephemeral key
 * 4. Bob computes the same shared secret and can decrypt
 *
 * Based on: https://signal.org/docs/specifications/x3dh/
 */

import { generateDH, dh, publicKeyFromPrivate, deriveDhKeyPairFromSigningKey, type DHKeyPair } from '../crypto/dh.js'
import {
    generateSigningKeyPair,
    sign,
    verify,
    signingPublicKeyFromPrivate,
    type SigningKeyPair
} from '../crypto/signing.js'
import { hkdfExpand } from '../crypto/kdf.js'
import { concatBytes, encodeBase64, decodeBase64 } from '../crypto/utils.js'
import type {
    IdentityKeyPair,
    SignedPreKey,
    OneTimePreKey,
    PreKeyBundle,
    X3DHSenderResult,
    X3DHReceiverKeys,
    X3DHReceiverResult,
    X3DHKeyStore,
    SerializedX3DHKeyStore
} from './types.js'

/** HKDF info string for X3DH shared secret derivation */
const X3DH_INFO = 'MurmurX3DH'

/** 32 zero bytes prepended to DH outputs per X3DH spec */
const ZERO_BYTES = new Uint8Array(32)

/**
 * Generate a new identity key pair.
 *
 * Creates both an Ed25519 signing key pair (for identity/signing)
 * and derives an X25519 key pair (for DH in the protocol).
 *
 * @returns Complete identity key pair
 *
 * @example
 * ```typescript
 * const identity = generateIdentityKeyPair()
 * // identity.publicKey is your Ed25519 identity
 * // identity.dhKeyPair is for X3DH key agreement
 * ```
 */
export function generateIdentityKeyPair(): IdentityKeyPair {
    const signingKeyPair = generateSigningKeyPair()
    // Derive DH key pair from signing private key
    const dhKeyPair = deriveDhKeyPairFromSigningKey(signingKeyPair.privateKey)

    return {
        ...signingKeyPair,
        dhKeyPair
    }
}

/**
 * Generate a signed prekey.
 *
 * The prekey is signed by the identity key to prove ownership.
 * Should be rotated periodically (e.g., weekly).
 *
 * @param identityKeyPair - Identity key pair for signing
 * @param id - Unique ID for this prekey
 * @returns Signed prekey
 *
 * @example
 * ```typescript
 * const signedPreKey = generateSignedPreKey(identity, 1)
 * // Upload signedPreKey.keyPair.publicKey and signedPreKey.signature to server
 * ```
 */
export function generateSignedPreKey(
    identityKeyPair: IdentityKeyPair,
    id: number
): SignedPreKey {
    const keyPair = generateDH()
    const signature = sign(keyPair.publicKey, identityKeyPair.privateKey)

    return {
        id,
        keyPair,
        signature,
        createdAt: Date.now()
    }
}

/**
 * Generate a one-time prekey.
 *
 * One-time prekeys provide additional forward secrecy and should
 * be used only once then deleted.
 *
 * @param id - Unique ID for this prekey
 * @returns One-time prekey
 */
export function generateOneTimePreKey(id: number): OneTimePreKey {
    return {
        id,
        keyPair: generateDH()
    }
}

/**
 * Generate multiple one-time prekeys.
 *
 * @param startId - Starting ID for the batch
 * @param count - Number of prekeys to generate
 * @returns Array of one-time prekeys
 */
export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
    const preKeys: OneTimePreKey[] = []
    for (let i = 0; i < count; i++) {
        preKeys.push(generateOneTimePreKey(startId + i))
    }
    return preKeys
}

/**
 * Create a prekey bundle for publishing to the server.
 *
 * @param identityKeyPair - Identity key pair
 * @param signedPreKey - Signed prekey
 * @param oneTimePreKey - Optional one-time prekey
 * @returns Bundle ready to publish
 */
export function createPreKeyBundle(
    identityKeyPair: IdentityKeyPair,
    signedPreKey: SignedPreKey,
    oneTimePreKey?: OneTimePreKey
): PreKeyBundle {
    return {
        identityKey: identityKeyPair.publicKey,
        signedPreKey: signedPreKey.keyPair.publicKey,
        signedPreKeySignature: signedPreKey.signature,
        oneTimePreKey: oneTimePreKey?.keyPair.publicKey
    }
}

/**
 * Verify a prekey bundle's signature.
 *
 * Always verify the bundle before using it to ensure the signed prekey
 * actually belongs to the claimed identity.
 *
 * @param bundle - Prekey bundle to verify
 * @returns true if signature is valid
 */
export function verifyPreKeyBundle(bundle: PreKeyBundle): boolean {
    return verify(bundle.signedPreKey, bundle.signedPreKeySignature, bundle.identityKey)
}

/**
 * Perform X3DH key agreement as the sender (Alice).
 *
 * Alice fetches Bob's prekey bundle and computes a shared secret.
 * She generates an ephemeral key pair for this specific session.
 *
 * Simplified X3DH with 2-3 DH operations:
 * 1. DH(IK_A, SPK_B) - Alice's identity DH key × Bob's signed prekey
 * 2. DH(EK_A, SPK_B) - Alice's ephemeral × Bob's signed prekey
 * 3. DH(EK_A, OPK_B) - Alice's ephemeral × Bob's one-time prekey (optional)
 *
 * @param aliceIdentity - Alice's identity key pair
 * @param bobBundle - Bob's prekey bundle (from server)
 * @returns X3DH result with shared secret and keys to send
 * @throws Error if bundle signature verification fails
 *
 * @example
 * ```typescript
 * const bundle = await fetchPreKeyBundle(bobId)
 * const x3dhResult = x3dhSender(aliceIdentity, bundle)
 * // Use x3dhResult.sharedSecret for Double Ratchet
 * // Send x3dhResult.ephemeralPublicKey to Bob
 * ```
 */
export function x3dhSender(
    aliceIdentity: IdentityKeyPair,
    bobBundle: PreKeyBundle
): X3DHSenderResult {
    // Verify the bundle first
    if (!verifyPreKeyBundle(bobBundle)) {
        throw new Error('Invalid prekey bundle signature')
    }

    // Generate ephemeral key pair for this session
    const ephemeralKeyPair = generateDH()

    // Perform DH calculations
    // DH1: IK_A × SPK_B (Alice's identity DH key with Bob's signed prekey)
    const dh1 = dh(aliceIdentity.dhKeyPair, bobBundle.signedPreKey)

    // DH2: EK_A × SPK_B (Alice's ephemeral with Bob's signed prekey)
    const dh2 = dh(ephemeralKeyPair, bobBundle.signedPreKey)

    // Concatenate DH outputs (with leading zeros per spec)
    let dhConcat: Uint8Array
    if (bobBundle.oneTimePreKey) {
        // DH3: EK_A × OPK_B (Alice's ephemeral with Bob's one-time prekey)
        const dh3 = dh(ephemeralKeyPair, bobBundle.oneTimePreKey)
        dhConcat = concatBytes(ZERO_BYTES, dh1, dh2, dh3)
    } else {
        dhConcat = concatBytes(ZERO_BYTES, dh1, dh2)
    }

    // Derive shared secret using HKDF
    const sharedSecret = hkdfExpand(dhConcat, undefined, X3DH_INFO, 32)

    return {
        sharedSecret,
        ephemeralPublicKey: ephemeralKeyPair.publicKey,
        bobSignedPreKey: bobBundle.signedPreKey,
        // Also include Alice's identity DH public key for Bob to compute DH1
        aliceIdentityDHKey: aliceIdentity.dhKeyPair.publicKey
    }
}

/**
 * Perform X3DH key agreement as the receiver (Bob).
 *
 * Bob receives Alice's initial message and computes the same shared secret.
 *
 * @param bobKeys - Bob's keys (identity, signed prekey, optional one-time prekey)
 * @param aliceIdentityKey - Alice's Ed25519 identity public key (for verification)
 * @param aliceIdentityDHKey - Alice's X25519 identity DH public key
 * @param aliceEphemeralKey - Alice's ephemeral public key
 * @returns X3DH result with shared secret
 *
 * @example
 * ```typescript
 * const bobKeys = {
 *   identityKeyPair: bobIdentity,
 *   signedPreKey: bobSignedPreKey,
 *   oneTimePreKey: bobOneTimePreKey
 * }
 * const result = x3dhReceiver(bobKeys, message.identityKey, message.identityDHKey, message.ephemeralKey)
 * // Use result.sharedSecret for Double Ratchet
 * // Delete oneTimePreKey after use!
 * ```
 */
export function x3dhReceiver(
    bobKeys: X3DHReceiverKeys,
    aliceIdentityKey: Uint8Array,
    aliceIdentityDHKey: Uint8Array,
    aliceEphemeralKey: Uint8Array
): X3DHReceiverResult {
    // Perform DH calculations (mirror of sender)
    // DH1: SPK_B × IK_A_DH (Bob's signed prekey with Alice's identity DH key)
    const dh1 = dh(bobKeys.signedPreKey.keyPair, aliceIdentityDHKey)

    // DH2: SPK_B × EK_A (Bob's signed prekey with Alice's ephemeral)
    const dh2 = dh(bobKeys.signedPreKey.keyPair, aliceEphemeralKey)

    // Concatenate DH outputs
    let dhConcat: Uint8Array
    if (bobKeys.oneTimePreKey) {
        // DH3: OPK_B × EK_A (Bob's one-time prekey with Alice's ephemeral)
        const dh3 = dh(bobKeys.oneTimePreKey.keyPair, aliceEphemeralKey)
        dhConcat = concatBytes(ZERO_BYTES, dh1, dh2, dh3)
    } else {
        dhConcat = concatBytes(ZERO_BYTES, dh1, dh2)
    }

    // Derive shared secret using HKDF
    const sharedSecret = hkdfExpand(dhConcat, undefined, X3DH_INFO, 32)

    return {
        sharedSecret,
        aliceIdentityKey
    }
}

/**
 * Initialize a new X3DH key store.
 *
 * Creates all the keys needed to participate in X3DH:
 * - Identity key pair
 * - Initial signed prekey
 * - Initial batch of one-time prekeys
 *
 * @param oneTimePreKeyCount - Number of one-time prekeys to generate (default: 99)
 * @returns Initialized key store
 */
export function initializeKeyStore(oneTimePreKeyCount: number = 99): X3DHKeyStore {
    const identityKeyPair = generateIdentityKeyPair()
    const signedPreKey = generateSignedPreKey(identityKeyPair, 0)
    const oneTimePreKeys = new Map<number, OneTimePreKey>()

    for (let i = 0; i < oneTimePreKeyCount; i++) {
        const otpk = generateOneTimePreKey(i + 1)
        oneTimePreKeys.set(otpk.id, otpk)
    }

    return {
        identityKeyPair,
        signedPreKey,
        oneTimePreKeys,
        nextPreKeyId: oneTimePreKeyCount + 1
    }
}

/**
 * Serialize key store for persistence.
 *
 * @param store - Key store to serialize
 * @returns JSON-serializable object
 */
export function serializeKeyStore(store: X3DHKeyStore): SerializedX3DHKeyStore {
    return {
        identityPrivateKey: encodeBase64(store.identityKeyPair.privateKey),
        identityPublicKey: encodeBase64(store.identityKeyPair.publicKey),
        identityDHPrivateKey: encodeBase64(store.identityKeyPair.dhKeyPair.privateKey),
        identityDHPublicKey: encodeBase64(store.identityKeyPair.dhKeyPair.publicKey),
        signedPreKey: {
            id: store.signedPreKey.id,
            privateKey: encodeBase64(store.signedPreKey.keyPair.privateKey),
            publicKey: encodeBase64(store.signedPreKey.keyPair.publicKey),
            signature: encodeBase64(store.signedPreKey.signature),
            createdAt: store.signedPreKey.createdAt
        },
        oneTimePreKeys: Array.from(store.oneTimePreKeys.values()).map(otpk => ({
            id: otpk.id,
            privateKey: encodeBase64(otpk.keyPair.privateKey),
            publicKey: encodeBase64(otpk.keyPair.publicKey)
        })),
        nextPreKeyId: store.nextPreKeyId
    }
}

/**
 * Deserialize key store from storage.
 *
 * @param serialized - Serialized key store
 * @returns Reconstructed key store
 */
export function deserializeKeyStore(serialized: SerializedX3DHKeyStore): X3DHKeyStore {
    const identityKeyPair: IdentityKeyPair = {
        privateKey: decodeBase64(serialized.identityPrivateKey),
        publicKey: decodeBase64(serialized.identityPublicKey),
        dhKeyPair: {
            privateKey: decodeBase64(serialized.identityDHPrivateKey),
            publicKey: decodeBase64(serialized.identityDHPublicKey)
        }
    }

    const signedPreKey: SignedPreKey = {
        id: serialized.signedPreKey.id,
        keyPair: {
            privateKey: decodeBase64(serialized.signedPreKey.privateKey),
            publicKey: decodeBase64(serialized.signedPreKey.publicKey)
        },
        signature: decodeBase64(serialized.signedPreKey.signature),
        createdAt: serialized.signedPreKey.createdAt
    }

    const oneTimePreKeys = new Map<number, OneTimePreKey>()
    for (const otpk of serialized.oneTimePreKeys) {
        oneTimePreKeys.set(otpk.id, {
            id: otpk.id,
            keyPair: {
                privateKey: decodeBase64(otpk.privateKey),
                publicKey: decodeBase64(otpk.publicKey)
            }
        })
    }

    return {
        identityKeyPair,
        signedPreKey,
        oneTimePreKeys,
        nextPreKeyId: serialized.nextPreKeyId
    }
}

/**
 * Consume a one-time prekey (mark as used and remove).
 *
 * One-time prekeys must be deleted after use to maintain forward secrecy.
 *
 * @param store - Key store
 * @param id - ID of the one-time prekey to consume
 * @returns The consumed one-time prekey, or undefined if not found
 */
export function consumeOneTimePreKey(
    store: X3DHKeyStore,
    id: number
): OneTimePreKey | undefined {
    const otpk = store.oneTimePreKeys.get(id)
    if (otpk) {
        store.oneTimePreKeys.delete(id)
    }
    return otpk
}

/**
 * Replenish one-time prekeys if running low.
 *
 * @param store - Key store
 * @param targetCount - Desired number of one-time prekeys
 * @returns Array of newly generated prekeys (to upload to server)
 */
export function replenishOneTimePreKeys(
    store: X3DHKeyStore,
    targetCount: number
): OneTimePreKey[] {
    const currentCount = store.oneTimePreKeys.size
    if (currentCount >= targetCount) {
        return []
    }

    const toGenerate = targetCount - currentCount
    const newKeys: OneTimePreKey[] = []

    for (let i = 0; i < toGenerate; i++) {
        const otpk = generateOneTimePreKey(store.nextPreKeyId++)
        store.oneTimePreKeys.set(otpk.id, otpk)
        newKeys.push(otpk)
    }

    return newKeys
}
