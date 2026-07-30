import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";
import { copyBytes, zeroBytes } from "../utils/index.js";
import type { IdentityKeyPair, IdentityPublicKeys } from "./types.js";

export type { IdentityKeyPair, IdentityPublicKeys, SealedBox } from "./types.js";
export { openBox, sealBox } from "./impl/box.js";

const KEY_LENGTH = 32;

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error("Random byte length must be a non-negative safe integer");
    }
    return nobleRandomBytes(length);
}

/** Generate independent Ed25519 and X25519 identity keys. */
export function generateIdentityKeyPair(): IdentityKeyPair {
    const signingSecretKey = randomBytes(KEY_LENGTH);
    const encryptionSecretKey = randomBytes(KEY_LENGTH);

    return {
        signingSecretKey,
        signingKey: ed25519.getPublicKey(signingSecretKey),
        encryptionSecretKey,
        encryptionKey: x25519.getPublicKey(encryptionSecretKey),
    };
}

/** Reconstruct and validate an identity from secret seeds. */
export function importIdentityKeyPair(
    signingSecretKey: Uint8Array,
    encryptionSecretKey: Uint8Array,
): IdentityKeyPair {
    if (signingSecretKey.length !== KEY_LENGTH || encryptionSecretKey.length !== KEY_LENGTH) {
        throw new Error("Identity secret keys must be 32 bytes");
    }
    const signingSecretCopy = copyBytes(signingSecretKey);
    const encryptionSecretCopy = copyBytes(encryptionSecretKey);
    return {
        signingSecretKey: signingSecretCopy,
        signingKey: ed25519.getPublicKey(signingSecretCopy),
        encryptionSecretKey: encryptionSecretCopy,
        encryptionKey: x25519.getPublicKey(encryptionSecretCopy),
    };
}

/** Sign bytes using an identity's Ed25519 secret key. */
export function signBytes(identity: IdentityKeyPair, message: Uint8Array): Uint8Array {
    return ed25519.sign(message, identity.signingSecretKey);
}

/** Verify an Ed25519 signature. */
export function verifyBytes(
    identity: Pick<IdentityPublicKeys, "signingKey">,
    message: Uint8Array,
    signature: Uint8Array,
): boolean {
    try {
        return (
            identity.signingKey.length === 32 &&
            signature.length === 64 &&
            ed25519.verify(signature, message, identity.signingKey, {
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

/** Zero both identity secret keys in place. */
export function destroyIdentity(identity: IdentityKeyPair): void {
    zeroBytes(identity.signingSecretKey);
    zeroBytes(identity.encryptionSecretKey);
}
