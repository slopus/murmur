import { gcm } from "@noble/ciphers/aes";
import { x25519 } from "@noble/curves/ed25519";
import { expand as hkdfExpand, extract as hkdfExtract } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { concatBytes, utf8Encode, zeroBytes } from "@murmur/core";
import type { HpkeCiphertext, HpkeKeyPair } from "../types.js";

const EMPTY = new Uint8Array();
const HPKE_VERSION = utf8Encode("HPKE-v1");
const KEM_SUITE_ID = concatBytes(utf8Encode("KEM"), new Uint8Array([0x00, 0x20]));
const HPKE_SUITE_ID = concatBytes(
    utf8Encode("HPKE"),
    new Uint8Array([0x00, 0x20, 0x00, 0x01, 0x00, 0x01]),
);

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
        concatBytes(
            new Uint8Array([length >>> 8, length & 0xff]),
            HPKE_VERSION,
            suiteId,
            utf8Encode(label),
            info,
        ),
        length,
    );
}

/** RFC 9180 DHKEM(X25519, HKDF-SHA-256) DeriveKeyPair. */
export function deriveHpkeKeyPair(inputKeyMaterial: Uint8Array): HpkeKeyPair {
    const derivationKey = labeledExtract(KEM_SUITE_ID, EMPTY, "dkp_prk", inputKeyMaterial);
    try {
        const secretKey = labeledExpand(KEM_SUITE_ID, derivationKey, "sk", EMPTY, 32);
        try {
            return {
                secretKey,
                publicKey: x25519.getPublicKey(secretKey),
            };
        } catch (error: unknown) {
            zeroBytes(secretKey);
            throw error;
        }
    } finally {
        zeroBytes(derivationKey);
    }
}

function extractAndExpand(dhSecret: Uint8Array, kemContext: Uint8Array): Uint8Array {
    const extractionKey = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dhSecret);
    try {
        return labeledExpand(KEM_SUITE_ID, extractionKey, "shared_secret", kemContext, 32);
    } finally {
        zeroBytes(extractionKey);
    }
}

function keySchedule(
    sharedSecret: Uint8Array,
    info: Uint8Array,
): {
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
} {
    const temporarySecrets: Uint8Array[] = [];
    let key: Uint8Array | undefined;
    let nonce: Uint8Array | undefined;
    try {
        const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
        temporarySecrets.push(pskIdHash);
        const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
        temporarySecrets.push(infoHash);
        const context = concatBytes(new Uint8Array([0]), pskIdHash, infoHash);
        temporarySecrets.push(context);
        const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
        temporarySecrets.push(secret);
        key = labeledExpand(HPKE_SUITE_ID, secret, "key", context, 16);
        nonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", context, 12);
        return { key, nonce };
    } catch (error: unknown) {
        if (key !== undefined) {
            zeroBytes(key);
        }
        if (nonce !== undefined) {
            zeroBytes(nonce);
        }
        throw error;
    } finally {
        for (const secret of temporarySecrets) {
            zeroBytes(secret);
        }
    }
}

/** RFC 9180 base-mode seal for the MLS cipher suite. */
export function hpkeSealBase(
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    associatedData: Uint8Array,
    plaintext: Uint8Array,
): HpkeCiphertext {
    if (recipientPublicKey.length !== 32) {
        throw new Error("HPKE recipient public key must be 32 bytes");
    }
    const ephemeralSecretKey = randomBytes(32);
    const temporarySecrets: Uint8Array[] = [ephemeralSecretKey];
    try {
        const encapsulatedKey = x25519.getPublicKey(ephemeralSecretKey);
        const dhSecret = x25519.getSharedSecret(ephemeralSecretKey, recipientPublicKey);
        temporarySecrets.push(dhSecret);
        const sharedSecret = extractAndExpand(
            dhSecret,
            concatBytes(encapsulatedKey, recipientPublicKey),
        );
        temporarySecrets.push(sharedSecret);
        const context = keySchedule(sharedSecret, info);
        try {
            return {
                encapsulatedKey,
                ciphertext: gcm(context.key, context.nonce, associatedData).encrypt(plaintext),
            };
        } finally {
            zeroBytes(context.key);
            zeroBytes(context.nonce);
        }
    } finally {
        for (const secret of temporarySecrets) {
            zeroBytes(secret);
        }
    }
}

/** RFC 9180 base-mode open for the MLS cipher suite. */
export function hpkeOpenBase(
    recipientKeyPair: HpkeKeyPair,
    info: Uint8Array,
    associatedData: Uint8Array,
    encrypted: HpkeCiphertext,
): Uint8Array {
    if (
        recipientKeyPair.secretKey.length !== 32 ||
        recipientKeyPair.publicKey.length !== 32 ||
        encrypted.encapsulatedKey.length !== 32
    ) {
        throw new Error("HPKE keys must be 32 bytes");
    }
    const temporarySecrets: Uint8Array[] = [];
    try {
        const dhSecret = x25519.getSharedSecret(
            recipientKeyPair.secretKey,
            encrypted.encapsulatedKey,
        );
        temporarySecrets.push(dhSecret);
        const sharedSecret = extractAndExpand(
            dhSecret,
            concatBytes(encrypted.encapsulatedKey, recipientKeyPair.publicKey),
        );
        temporarySecrets.push(sharedSecret);
        const context = keySchedule(sharedSecret, info);
        try {
            return gcm(context.key, context.nonce, associatedData).decrypt(encrypted.ciphertext);
        } finally {
            zeroBytes(context.key);
            zeroBytes(context.nonce);
        }
    } finally {
        for (const secret of temporarySecrets) {
            zeroBytes(secret);
        }
    }
}
