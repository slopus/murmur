import { gcm } from "@noble/ciphers/aes";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { expand as hkdfExpand, extract as hkdfExtract } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { concatBytes, encodeUint16, equalBytes, utf8Encode } from "./bytes.js";

export interface HpkeKeyPair {
    readonly secretKey: Uint8Array;
    readonly publicKey: Uint8Array;
}

export interface HpkeCiphertext {
    readonly encapsulatedKey: Uint8Array;
    readonly ciphertext: Uint8Array;
}

const EMPTY = new Uint8Array();
const HPKE_VERSION = utf8Encode("HPKE-v1");
const KEM_SUITE_ID = concatBytes(utf8Encode("KEM"), new Uint8Array([0x00, 0x20]));
const HPKE_SUITE_ID = concatBytes(
    utf8Encode("HPKE"),
    new Uint8Array([0x00, 0x20, 0x00, 0x01, 0x00, 0x01]),
);
const MLS_PREFIX = "MLS 1.0 ";
const SIGNATURE_DOMAIN = utf8Encode("@slopus/treekem signature v1");
const HASH_DOMAIN = utf8Encode("@slopus/treekem hash v1");
const PUBLIC_KEY_VALIDATION_SECRET = new Uint8Array(32).fill(7);
const X25519_FIELD_MODULUS = (1n << 255n) - 19n;

function labeledExtract(
    suiteId: Uint8Array,
    salt: Uint8Array,
    label: string,
    inputKeyMaterial: Uint8Array,
): Uint8Array {
    return hkdfExtract(
        sha256,
        concatBytes(HPKE_VERSION, suiteId, utf8Encode(label), inputKeyMaterial),
        salt,
    );
}

function labeledExpand(
    suiteId: Uint8Array,
    pseudorandomKey: Uint8Array,
    label: string,
    info: Uint8Array,
    length: number,
): Uint8Array {
    return hkdfExpand(
        sha256,
        pseudorandomKey,
        concatBytes(encodeUint16(length), HPKE_VERSION, suiteId, utf8Encode(label), info),
        length,
    );
}

/** Canonicalize and reject invalid or low-order X25519 public keys. */
export function canonicalizePublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length !== 32) {
        throw new Error("TreeKEM public encryption key must be 32 bytes");
    }
    let coordinate = 0n;
    for (let index = publicKey.length - 1; index >= 0; index -= 1) {
        const byte =
            index === publicKey.length - 1
                ? (publicKey[index] ?? 0) & 0x7f
                : (publicKey[index] ?? 0);
        coordinate = (coordinate << 8n) | BigInt(byte);
    }
    coordinate %= X25519_FIELD_MODULUS;
    const canonical = new Uint8Array(32);
    for (let index = 0; index < canonical.length; index += 1) {
        canonical[index] = Number(coordinate & 0xffn);
        coordinate >>= 8n;
    }
    x25519.getSharedSecret(PUBLIC_KEY_VALIDATION_SECRET, canonical);
    return canonical;
}

/** RFC 9180 DHKEM(X25519, HKDF-SHA-256) DeriveKeyPair. */
export function deriveHpkeKeyPair(inputKeyMaterial: Uint8Array): HpkeKeyPair {
    const derivationKey = labeledExtract(KEM_SUITE_ID, EMPTY, "dkp_prk", inputKeyMaterial);
    try {
        const secretKey = labeledExpand(KEM_SUITE_ID, derivationKey, "sk", EMPTY, 32);
        try {
            return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
        } catch (error: unknown) {
            secretKey.fill(0);
            throw error;
        }
    } finally {
        derivationKey.fill(0);
    }
}

/** Return the public X25519 key for a stored private node key. */
export function publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== 32) {
        throw new Error("TreeKEM private encryption key must be 32 bytes");
    }
    return x25519.getPublicKey(secretKey);
}

function extractAndExpand(dhSecret: Uint8Array, kemContext: Uint8Array): Uint8Array {
    const extractionKey = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dhSecret);
    try {
        return labeledExpand(KEM_SUITE_ID, extractionKey, "shared_secret", kemContext, 32);
    } finally {
        extractionKey.fill(0);
    }
}

function hpkeKeySchedule(
    sharedSecret: Uint8Array,
    info: Uint8Array,
): { readonly key: Uint8Array; readonly nonce: Uint8Array } {
    const temporary: Uint8Array[] = [];
    let key: Uint8Array | undefined;
    let nonce: Uint8Array | undefined;
    try {
        const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
        temporary.push(pskIdHash);
        const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
        temporary.push(infoHash);
        const context = concatBytes(new Uint8Array([0]), pskIdHash, infoHash);
        temporary.push(context);
        const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
        temporary.push(secret);
        key = labeledExpand(HPKE_SUITE_ID, secret, "key", context, 16);
        nonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", context, 12);
        return { key, nonce };
    } catch (error: unknown) {
        key?.fill(0);
        nonce?.fill(0);
        throw error;
    } finally {
        for (const value of temporary) {
            value.fill(0);
        }
    }
}

/** RFC 9180 base-mode encryption. */
export function hpkeSeal(
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    plaintext: Uint8Array,
): HpkeCiphertext {
    const recipient = canonicalizePublicKey(recipientPublicKey);
    const ephemeralSecretKey = randomBytes(32);
    const temporary: Uint8Array[] = [ephemeralSecretKey];
    try {
        const encapsulatedKey = x25519.getPublicKey(ephemeralSecretKey);
        const dhSecret = x25519.getSharedSecret(ephemeralSecretKey, recipient);
        temporary.push(dhSecret);
        const sharedSecret = extractAndExpand(dhSecret, concatBytes(encapsulatedKey, recipient));
        temporary.push(sharedSecret);
        const context = hpkeKeySchedule(sharedSecret, info);
        try {
            return {
                encapsulatedKey,
                ciphertext: gcm(context.key, context.nonce, EMPTY).encrypt(plaintext),
            };
        } finally {
            context.key.fill(0);
            context.nonce.fill(0);
        }
    } finally {
        for (const value of temporary) {
            value.fill(0);
        }
    }
}

/** RFC 9180 base-mode decryption. */
export function hpkeOpen(
    recipientKeyPair: HpkeKeyPair,
    info: Uint8Array,
    encrypted: HpkeCiphertext,
): Uint8Array {
    if (recipientKeyPair.secretKey.length !== 32 || encrypted.encapsulatedKey.length !== 32) {
        throw new Error("Invalid TreeKEM HPKE key");
    }
    const recipient = canonicalizePublicKey(recipientKeyPair.publicKey);
    if (!equalBytes(publicKeyFromSecret(recipientKeyPair.secretKey), recipient)) {
        throw new Error("TreeKEM HPKE private key does not match its public key");
    }
    const temporary: Uint8Array[] = [];
    try {
        const dhSecret = x25519.getSharedSecret(
            recipientKeyPair.secretKey,
            encrypted.encapsulatedKey,
        );
        temporary.push(dhSecret);
        const sharedSecret = extractAndExpand(
            dhSecret,
            concatBytes(encrypted.encapsulatedKey, recipient),
        );
        temporary.push(sharedSecret);
        const context = hpkeKeySchedule(sharedSecret, info);
        try {
            return gcm(context.key, context.nonce, EMPTY).decrypt(encrypted.ciphertext);
        } finally {
            context.key.fill(0);
            context.nonce.fill(0);
        }
    } finally {
        for (const value of temporary) {
            value.fill(0);
        }
    }
}

function encodeOpaque(value: Uint8Array): Uint8Array {
    return concatBytes(encodeUint16(value.length), value);
}

function expandWithLabel(secret: Uint8Array, label: string, context: Uint8Array): Uint8Array {
    return hkdfExpand(
        sha256,
        secret,
        concatBytes(
            encodeUint16(32),
            encodeOpaque(utf8Encode(`${MLS_PREFIX}${label}`)),
            encodeOpaque(context),
        ),
        32,
    );
}

/** Derive one path node key pair from a path secret. */
export function deriveNodeKeyPair(pathSecret: Uint8Array): HpkeKeyPair {
    const nodeSecret = expandWithLabel(pathSecret, "node", EMPTY);
    try {
        return deriveHpkeKeyPair(nodeSecret);
    } finally {
        nodeSecret.fill(0);
    }
}

/** Advance one level toward the root. */
export function deriveNextPathSecret(pathSecret: Uint8Array): Uint8Array {
    return expandWithLabel(pathSecret, "path", EMPTY);
}

/** Derive the embedding application's fresh epoch secret. */
export function deriveSharedSecret(commitSecret: Uint8Array, context: Uint8Array): Uint8Array {
    return expandWithLabel(commitSecret, "treekem shared", context);
}

/** Generate an independently owned 32-byte cryptographic secret. */
export function generateSecret(): Uint8Array {
    return randomBytes(32);
}

/** Derive an Ed25519 public key from its secret seed. */
export function signingPublicKey(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== 32) {
        throw new Error("TreeKEM signing secret key must be 32 bytes");
    }
    return ed25519.getPublicKey(secretKey);
}

/** Sign a canonical package structure with domain separation. */
export function sign(secretKey: Uint8Array, content: Uint8Array): Uint8Array {
    return ed25519.sign(concatBytes(SIGNATURE_DOMAIN, content), secretKey);
}

/** Verify a canonical package structure with domain separation. */
export function verify(publicKey: Uint8Array, content: Uint8Array, signature: Uint8Array): boolean {
    return (
        publicKey.length === 32 &&
        signature.length === 64 &&
        ed25519.verify(signature, concatBytes(SIGNATURE_DOMAIN, content), publicKey)
    );
}

/** Hash public protocol structures with domain separation. */
export function hash(...values: readonly Uint8Array[]): Uint8Array {
    return sha256(concatBytes(HASH_DOMAIN, ...values));
}
