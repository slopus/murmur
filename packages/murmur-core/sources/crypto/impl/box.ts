import { gcm } from "@noble/ciphers/aes";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { concatBytes, utf8Encode, zeroBytes } from "../../utils/index.js";
import type { IdentityKeyPair, IdentityPublicKeys, SealedBox } from "../types.js";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const INFO = utf8Encode("murmur sealed box v1");

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

/** Encrypt bytes to an X25519 identity key. */
export function sealBox(
    recipient: Pick<IdentityPublicKeys, "encryptionKey">,
    plaintext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(),
): SealedBox {
    if (recipient.encryptionKey.length !== 32) {
        throw new Error("Recipient encryption key must be 32 bytes");
    }

    const ephemeralSecretKey = randomBytes(32);
    const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey);
    const sharedSecret = x25519.getSharedSecret(ephemeralSecretKey, recipient.encryptionKey);
    const key = deriveBoxKey(sharedSecret, ephemeralPublicKey, recipient.encryptionKey);
    const nonce = randomBytes(NONCE_LENGTH);

    try {
        return {
            ephemeralPublicKey,
            nonce,
            ciphertext: gcm(key, nonce, associatedData).encrypt(plaintext),
        };
    } finally {
        zeroBytes(ephemeralSecretKey);
        zeroBytes(sharedSecret);
        zeroBytes(key);
    }
}

/** Decrypt a sealed box addressed to an identity. */
export function openBox(
    recipient: Pick<IdentityKeyPair, "encryptionKey" | "encryptionSecretKey">,
    box: SealedBox,
    associatedData: Uint8Array = new Uint8Array(),
): Uint8Array {
    if (
        recipient.encryptionKey.length !== 32 ||
        recipient.encryptionSecretKey.length !== 32 ||
        box.ephemeralPublicKey.length !== 32 ||
        box.nonce.length !== NONCE_LENGTH
    ) {
        throw new Error("Invalid sealed box key or nonce length");
    }

    const sharedSecret = x25519.getSharedSecret(
        recipient.encryptionSecretKey,
        box.ephemeralPublicKey,
    );
    const key = deriveBoxKey(sharedSecret, box.ephemeralPublicKey, recipient.encryptionKey);

    try {
        return gcm(key, box.nonce, associatedData).decrypt(box.ciphertext);
    } finally {
        zeroBytes(sharedSecret);
        zeroBytes(key);
    }
}
