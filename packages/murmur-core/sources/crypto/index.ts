import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";
import { zeroBytes } from "../utils/index.js";
import {
    identityDhPublicKey,
    importIdentityKeyPair,
    validateIdentityKeyPair,
} from "./impl/identityKeys.js";
import type { IdentityKeyPair, IdentityPublicKey } from "./types.js";

export type { IdentityKeyPair, IdentityPublicKey, SealedBox, StoredIdentityRoot } from "./types.js";
export { openBox, sealBox } from "./impl/box.js";
export { decodeIdentityRoot, encodeIdentityRoot } from "./impl/rootCodec.js";
export {
    identityDhPublicKey,
    importIdentityKeyPair,
    validateIdentityKeyPair,
} from "./impl/identityKeys.js";

const KEY_LENGTH = 32;

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error("Random byte length must be a non-negative safe integer");
    }
    return nobleRandomBytes(length);
}

/**
 * Generate one Murmur root secret and its single Ed25519 public identity key.
 *
 * Murmur intentionally converts this same root to X25519 for key agreement.
 * This avoids publishing two linkable identity keys, but it accepts the
 * composition risk documented in the friends master plan. It does not treat
 * Ed25519 and X25519 encodings as interchangeable raw bytes.
 */
export function generateIdentityKeyPair(): IdentityKeyPair {
    const secretKey = randomBytes(KEY_LENGTH);
    try {
        return importIdentityKeyPair(secretKey);
    } finally {
        zeroBytes(secretKey);
    }
}

/** Derive the pairwise X25519 secret from one root secret and one identity key. */
export function deriveSharedSecret(self: IdentityKeyPair, peer: IdentityPublicKey): Uint8Array {
    validateIdentityKeyPair(self);
    const secret = ed25519.utils.toMontgomerySecret(self.secretKey);
    const publicKey = identityDhPublicKey(peer);
    try {
        return x25519.getSharedSecret(secret, publicKey);
    } finally {
        zeroBytes(secret);
        zeroBytes(publicKey);
    }
}

/** Sign bytes using the Ed25519 capability derived directly from the root. */
export function signBytes(identity: IdentityKeyPair, message: Uint8Array): Uint8Array {
    validateIdentityKeyPair(identity);
    return ed25519.sign(message, identity.secretKey);
}

/** Verify an Ed25519 signature against the single public identity key. */
export function verifyBytes(
    identity: IdentityPublicKey,
    message: Uint8Array,
    signature: Uint8Array,
): boolean {
    try {
        return (
            identity.publicKey.length === KEY_LENGTH &&
            signature.length === 64 &&
            ed25519.verify(signature, message, identity.publicKey, {
                zip215: false,
            })
        );
    } catch {
        return false;
    }
}

/** Hash bytes with SHA-256. */
export function hashBytes(value: Uint8Array): Uint8Array {
    return sha256(value);
}

/** Zero root identity material in place. */
export function destroyIdentity(identity: IdentityKeyPair): void {
    zeroBytes(identity.secretKey);
}
