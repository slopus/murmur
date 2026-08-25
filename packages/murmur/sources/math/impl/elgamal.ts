import { equalBytes, zeroBytes } from "../../utils/index.js";
import type { ElGamalCiphertext, ElGamalKeyPair } from "../types.js";
import {
    addPoints,
    canonicalizeNonIdentityPoint,
    canonicalizePoint,
    multiplyBase,
    multiplyPoint,
    subtractPoints,
} from "./point.js";
import { decodeScalar, encodeScalar, hashToScalar, randomScalar } from "./scalar.js";

/** Generate a fresh Ristretto255 ElGamal key pair. */
export function generateElGamalKeyPair(): ElGamalKeyPair {
    const secretKey = randomScalar();
    return { secretKey, publicKey: multiplyBase(secretKey) };
}

/** Deterministically derive a non-zero ElGamal key pair from seed material. */
export function deriveElGamalKeyPair(seed: Uint8Array, domain: string): ElGamalKeyPair {
    const secretKey = hashToScalar(
        "murmur.math.elgamal.key.v1",
        [new TextEncoder().encode(domain), seed],
        true,
    );
    return { secretKey, publicKey: multiplyBase(secretKey) };
}

/** Validate that an ElGamal secret key owns its canonical public key. */
export function validateElGamalKeyPair(keyPair: ElGamalKeyPair): void {
    const secretKey = encodeScalar(decodeScalar(keyPair.secretKey, false));
    const publicKey = canonicalizePoint(keyPair.publicKey);
    if (!equalBytes(multiplyBase(secretKey), publicKey)) {
        throw new Error("ElGamal public key does not match its secret key");
    }
}

/**
 * Encrypt one canonical point with correct additive ElGamal.
 *
 * `C1 = rG` and `C2 = M + rPK`, so decryption subtracts `sk*C1` and
 * provably recovers `M`.
 */
export function encryptElGamalPoint(
    publicKey: Uint8Array,
    message: Uint8Array,
    randomness?: Uint8Array,
): ElGamalCiphertext {
    const canonicalPublicKey = canonicalizeNonIdentityPoint(publicKey);
    const canonicalMessage = canonicalizePoint(message);
    const ownedRandomness = randomness === undefined;
    const scalar = randomness?.slice() ?? randomScalar();
    try {
        decodeScalar(scalar, false);
        return {
            ephemeralPublicKey: multiplyBase(scalar),
            encryptedPoint: addPoints(canonicalMessage, multiplyPoint(canonicalPublicKey, scalar)),
        };
    } finally {
        if (ownedRandomness) zeroBytes(scalar);
    }
}

/** Decrypt an ElGamal ciphertext to its exact canonical message point. */
export function decryptElGamalPoint(
    secretKey: Uint8Array,
    ciphertext: ElGamalCiphertext,
): Uint8Array {
    const canonicalSecret = encodeScalar(decodeScalar(secretKey, false));
    const ephemeralPublicKey = canonicalizeNonIdentityPoint(ciphertext.ephemeralPublicKey);
    const encryptedPoint = canonicalizePoint(ciphertext.encryptedPoint);
    try {
        return subtractPoints(encryptedPoint, multiplyPoint(ephemeralPublicKey, canonicalSecret));
    } finally {
        zeroBytes(canonicalSecret);
    }
}

/** Canonically serialize an ElGamal ciphertext. */
export function encodeElGamalCiphertext(ciphertext: ElGamalCiphertext): Uint8Array {
    const encoded = new Uint8Array(68);
    encoded.set([0x4d, 0x45, 0x47, 0x01]);
    encoded.set(canonicalizeNonIdentityPoint(ciphertext.ephemeralPublicKey), 4);
    encoded.set(canonicalizePoint(ciphertext.encryptedPoint), 36);
    return encoded;
}

/** Strictly decode an ElGamal ciphertext. */
export function decodeElGamalCiphertext(value: Uint8Array): ElGamalCiphertext {
    if (
        value.length !== 68 ||
        !equalBytes(value.subarray(0, 4), new Uint8Array([0x4d, 0x45, 0x47, 0x01]))
    ) {
        throw new Error("Invalid ElGamal ciphertext encoding");
    }
    return {
        ephemeralPublicKey: canonicalizeNonIdentityPoint(value.subarray(4, 36)),
        encryptedPoint: canonicalizePoint(value.subarray(36, 68)),
    };
}

/** Zero an ElGamal secret key in place. */
export function destroyElGamalKeyPair(keyPair: ElGamalKeyPair): void {
    zeroBytes(keyPair.secretKey);
}
