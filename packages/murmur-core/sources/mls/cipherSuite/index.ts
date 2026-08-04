import { gcm } from "@noble/ciphers/aes";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { expand as hkdfExpand, extract as hkdfExtract } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
    concatBytes,
    equalBytes,
    hashBytes,
    utf8Encode,
    verifyBytes,
    zeroBytes,
} from "../internal.js";
import { encodeOpaqueV, encodeUint16 } from "../encoding/index.js";
import { hpkeOpenBase, hpkeSealBase } from "./impl/hpke.js";
import type { HpkeCiphertext, HpkeKeyPair } from "./types.js";

export type { HpkeCiphertext, HpkeKeyPair } from "./types.js";
export { deriveHpkeKeyPair, hpkeOpenBase, hpkeSealBase } from "./impl/hpke.js";

export const MLS_PROTOCOL_VERSION = 1;
export const MLS_CIPHER_SUITE = 0x0001;
export const MLS_HASH_LENGTH = 32;
export const MLS_AEAD_KEY_LENGTH = 16;
export const MLS_AEAD_NONCE_LENGTH = 12;

const EMPTY = new Uint8Array();
const MLS_PREFIX = "MLS 1.0 ";
const HPKE_PUBLIC_KEY_VALIDATION_SECRET = new Uint8Array(32).fill(7);
const X25519_FIELD_MODULUS = (1n << 255n) - 19n;

/**
 * Deserialize and canonicalize an RFC 9180 X25519 public key.
 *
 * RFC 7748 masks the most significant input bit. Performing one DH operation
 * also rejects low-order keys which would produce all-zero output.
 */
export function canonicalizeHpkePublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length !== 32) {
        throw new Error("HPKE public key must be 32 bytes");
    }
    let coordinate = 0n;
    for (let index = 31; index >= 0; index -= 1) {
        const byte = index === 31 ? (publicKey[index] ?? 0) & 0x7f : (publicKey[index] ?? 0);
        coordinate = (coordinate << 8n) | BigInt(byte);
    }
    coordinate %= X25519_FIELD_MODULUS;
    const canonical = new Uint8Array(32);
    for (let index = 0; index < canonical.length; index += 1) {
        canonical[index] = Number(coordinate & 0xffn);
        coordinate >>= 8n;
    }
    x25519.getSharedSecret(HPKE_PUBLIC_KEY_VALIDATION_SECRET, canonical);
    return canonical;
}

/** Validate that an X25519 HPKE private key owns the supplied public key. */
export function isHpkeKeyPair(keyPair: HpkeKeyPair): boolean {
    try {
        return (
            keyPair.secretKey.length === 32 &&
            equalBytes(
                canonicalizeHpkePublicKey(x25519.getPublicKey(keyPair.secretKey)),
                canonicalizeHpkePublicKey(keyPair.publicKey),
            )
        );
    } catch {
        return false;
    }
}

/** RFC 9420 ExpandWithLabel for cipher suite 0x0001. */
export function mlsExpandWithLabel(
    secret: Uint8Array,
    label: string,
    context: Uint8Array,
    length: number,
): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || length > 0xffff) {
        throw new Error("MLS expansion length must fit uint16");
    }
    const kdfLabel = concatBytes(
        encodeUint16(length),
        encodeOpaqueV(utf8Encode(`${MLS_PREFIX}${label}`)),
        encodeOpaqueV(context),
    );
    return hkdfExpand(sha256, secret, kdfLabel, length);
}

/** RFC 9420 DeriveSecret. */
export function mlsDeriveSecret(secret: Uint8Array, label: string): Uint8Array {
    return mlsExpandWithLabel(secret, label, EMPTY, MLS_HASH_LENGTH);
}

/** HKDF-Extract used by the RFC 9420 key schedule. */
export function mlsExtract(salt: Uint8Array, inputKeyMaterial: Uint8Array): Uint8Array {
    return hkdfExtract(sha256, inputKeyMaterial, salt);
}

/** RFC 9420 MAC for cipher suite 0x0001. */
export function mlsMac(key: Uint8Array, content: Uint8Array): Uint8Array {
    return hmac(sha256, key, content);
}

/** Verify an RFC 9420 MAC in constant time. */
export function mlsVerifyMac(
    key: Uint8Array,
    content: Uint8Array,
    authenticationTag: Uint8Array,
): boolean {
    return (
        authenticationTag.length === MLS_HASH_LENGTH &&
        equalBytes(mlsMac(key, content), authenticationTag)
    );
}

/** AES-128-GCM seal for the MLS cipher suite. */
export function mlsAeadSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    authenticatedData: Uint8Array,
    plaintext: Uint8Array,
): Uint8Array {
    if (key.length !== MLS_AEAD_KEY_LENGTH || nonce.length !== MLS_AEAD_NONCE_LENGTH) {
        throw new Error("Invalid MLS AEAD key or nonce");
    }
    return gcm(key, nonce, authenticatedData).encrypt(plaintext);
}

/** AES-128-GCM open for the MLS cipher suite. */
export function mlsAeadOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    authenticatedData: Uint8Array,
    ciphertext: Uint8Array,
): Uint8Array {
    if (key.length !== MLS_AEAD_KEY_LENGTH || nonce.length !== MLS_AEAD_NONCE_LENGTH) {
        throw new Error("Invalid MLS AEAD key or nonce");
    }
    return gcm(key, nonce, authenticatedData).decrypt(ciphertext);
}

function signContent(label: string, content: Uint8Array): Uint8Array {
    return concatBytes(encodeOpaqueV(utf8Encode(`${MLS_PREFIX}${label}`)), encodeOpaqueV(content));
}

/** RFC 9420 SignWithLabel using Ed25519. */
export function mlsSignWithLabel(
    signingSecretKey: Uint8Array,
    label: string,
    content: Uint8Array,
): Uint8Array {
    if (signingSecretKey.length !== 32) {
        throw new Error("MLS Ed25519 signing secret key must be 32 bytes");
    }
    return ed25519.sign(signContent(label, content), signingSecretKey);
}

/** RFC 9420 VerifyWithLabel using Ed25519. */
export function mlsVerifyWithLabel(
    signingPublicKey: Uint8Array,
    label: string,
    content: Uint8Array,
    signature: Uint8Array,
): boolean {
    return verifyBytes({ publicKey: signingPublicKey }, signContent(label, content), signature);
}

/** RFC 9420 RefHash. */
export function mlsReferenceHash(label: string, value: Uint8Array): Uint8Array {
    return hashBytes(
        concatBytes(encodeOpaqueV(utf8Encode(`${MLS_PREFIX}${label}`)), encodeOpaqueV(value)),
    );
}

function hpkeLabelInfo(label: string, context: Uint8Array): Uint8Array {
    return concatBytes(encodeOpaqueV(utf8Encode(`${MLS_PREFIX}${label}`)), encodeOpaqueV(context));
}

/** RFC 9420 EncryptWithLabel over the suite's HPKE base mode. */
export function mlsEncryptWithLabel(
    recipientPublicKey: Uint8Array,
    label: string,
    context: Uint8Array,
    plaintext: Uint8Array,
): HpkeCiphertext {
    return hpkeSealBase(recipientPublicKey, hpkeLabelInfo(label, context), EMPTY, plaintext);
}

/** RFC 9420 DecryptWithLabel over the suite's HPKE base mode. */
export function mlsDecryptWithLabel(
    recipientKeyPair: HpkeKeyPair,
    label: string,
    context: Uint8Array,
    encrypted: HpkeCiphertext,
): Uint8Array {
    return hpkeOpenBase(recipientKeyPair, hpkeLabelInfo(label, context), EMPTY, encrypted);
}

/** Zero an HPKE secret key after a KeyPackage is consumed. */
export function destroyHpkeKeyPair(keyPair: HpkeKeyPair): void {
    zeroBytes(keyPair.secretKey);
}
