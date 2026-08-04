import { gcm } from "@noble/ciphers/aes";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { concatBytes, utf8Encode, zeroBytes } from "../../utils/index.js";
import type { IdentityKeyPair, IdentityPublicKey, SealedBox } from "../types.js";
import { identityDhPublicKey, validateIdentityKeyPair } from "./identityKeys.js";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const INFO = utf8Encode("murmur/identity-sealed-box/v1");

function deriveBoxKey(
    sharedSecret: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array,
): Uint8Array {
    return hkdf(
        sha256,
        sharedSecret,
        concatBytes(ephemeralPublicKey, recipientPublicKey),
        INFO,
        KEY_LENGTH,
    );
}

/** Encrypt bytes to the X25519 capability converted from one identity key. */
export function sealBox(
    recipient: IdentityPublicKey,
    plaintext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(),
): SealedBox {
    const recipientPublicKey = identityDhPublicKey(recipient);
    const ephemeralSecretKey = randomBytes(KEY_LENGTH);
    let sharedSecret: Uint8Array | undefined;
    let key: Uint8Array | undefined;
    try {
        const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey);
        sharedSecret = x25519.getSharedSecret(ephemeralSecretKey, recipientPublicKey);
        key = deriveBoxKey(sharedSecret, ephemeralPublicKey, recipientPublicKey);
        const nonce = randomBytes(NONCE_LENGTH);
        return {
            ephemeralPublicKey,
            nonce,
            ciphertext: gcm(key, nonce, associatedData).encrypt(plaintext),
        };
    } finally {
        zeroBytes(recipientPublicKey);
        zeroBytes(ephemeralSecretKey);
        if (sharedSecret !== undefined) {
            zeroBytes(sharedSecret);
        }
        if (key !== undefined) {
            zeroBytes(key);
        }
    }
}

/** Decrypt a box addressed to the X25519 capability derived from one root. */
export function openBox(
    recipient: IdentityKeyPair,
    box: SealedBox,
    associatedData: Uint8Array = new Uint8Array(),
): Uint8Array {
    validateIdentityKeyPair(recipient);
    if (box.ephemeralPublicKey.length !== KEY_LENGTH || box.nonce.length !== NONCE_LENGTH) {
        throw new Error("Invalid sealed box key or nonce length");
    }

    const recipientSecretKey = ed25519.utils.toMontgomerySecret(recipient.secretKey);
    let recipientPublicKey: Uint8Array | undefined;
    let sharedSecret: Uint8Array | undefined;
    let key: Uint8Array | undefined;
    try {
        recipientPublicKey = identityDhPublicKey(recipient);
        sharedSecret = x25519.getSharedSecret(recipientSecretKey, box.ephemeralPublicKey);
        key = deriveBoxKey(sharedSecret, box.ephemeralPublicKey, recipientPublicKey);
        return gcm(key, box.nonce, associatedData).decrypt(box.ciphertext);
    } finally {
        zeroBytes(recipientSecretKey);
        if (recipientPublicKey !== undefined) {
            zeroBytes(recipientPublicKey);
        }
        if (sharedSecret !== undefined) {
            zeroBytes(sharedSecret);
        }
        if (key !== undefined) {
            zeroBytes(key);
        }
    }
}
