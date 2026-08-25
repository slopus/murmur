import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import {
    decodeElGamalCiphertext,
    decryptElGamalPoint,
    encodeElGamalCiphertext,
    encryptElGamalPoint,
    hashToScalar,
    canonicalizeNonIdentityPoint,
    multiplyPoint,
} from "../../math/index.js";
import { concatBytes, equalBytes, utf8Encode, zeroBytes } from "../../utils/index.js";
import type {
    EncryptedUid,
    PrivateGroupParameters,
    PrivateGroupPublicParameters,
} from "../types.js";
import { accountIdentifierScalar } from "./parameters.js";

/** Derive the secret deterministic encryption witness for one group/account pair. */
export function deterministicUidRandomness(
    accountIdentifier: Uint8Array,
    parameters: PrivateGroupParameters,
): Uint8Array {
    const digest = hmac(
        sha256,
        parameters.encryptionParams.deterministicNonceKey,
        concatBytes(
            utf8Encode("Murmur deterministic encrypted UID v1"),
            parameters.opaqueGroupId,
            accountIdentifier,
        ),
    );
    try {
        return hashToScalar(
            "murmur.private-groups.uid-randomness.v1",
            [parameters.opaqueGroupId, digest],
            true,
        );
    } finally {
        zeroBytes(digest);
    }
}

/** Construct the deterministic encrypted member entry for one account and group. */
export function createEncryptedUid(
    accountIdentifier: Uint8Array,
    parameters: PrivateGroupParameters,
): EncryptedUid {
    if (parameters.opaqueGroupId.length !== 32) {
        throw new Error("Opaque group identifier must be 32 bytes");
    }
    const identifier = accountIdentifierScalar(accountIdentifier);
    const randomness = deterministicUidRandomness(accountIdentifier, parameters);
    try {
        const message = multiplyPoint(parameters.encryptionParams.messageGenerator, identifier);
        return encryptElGamalPoint(
            parameters.encryptionParams.keyPair.publicKey,
            message,
            randomness,
        );
    } finally {
        zeroBytes(identifier);
        zeroBytes(randomness);
    }
}

/** Decrypt an encrypted UID to its group-specific identifier point. */
export function decryptEncryptedUid(
    encryptedUid: EncryptedUid,
    parameters: PrivateGroupParameters,
): Uint8Array {
    return decryptElGamalPoint(parameters.encryptionParams.keyPair.secretKey, encryptedUid);
}

/** Check whether an encrypted UID is the canonical entry for this account and group. */
export function isEncryptedUidForAccount(
    encryptedUid: EncryptedUid,
    accountIdentifier: Uint8Array,
    parameters: PrivateGroupParameters,
): boolean {
    try {
        return equalBytes(
            encodeEncryptedUid(encryptedUid),
            encodeEncryptedUid(createEncryptedUid(accountIdentifier, parameters)),
        );
    } catch {
        return false;
    }
}

/** Check exact duplicate encrypted entries in constant time. */
export function equalEncryptedUids(left: EncryptedUid, right: EncryptedUid): boolean {
    try {
        return equalBytes(encodeEncryptedUid(left), encodeEncryptedUid(right));
    } catch {
        return false;
    }
}

/** Canonically serialize an encrypted UID. */
export function encodeEncryptedUid(encryptedUid: EncryptedUid): Uint8Array {
    return encodeElGamalCiphertext(encryptedUid);
}

/** Strictly decode an encrypted UID. */
export function decodeEncryptedUid(value: Uint8Array): EncryptedUid {
    return decodeElGamalCiphertext(value);
}

/** Validate the canonical public subset used by a UID verifier. */
export function validatePrivateGroupPublicParameters(
    parameters: PrivateGroupPublicParameters,
): void {
    if (parameters.opaqueGroupId.length !== 32) {
        throw new Error("Opaque group identifier must be 32 bytes");
    }
    canonicalizeNonIdentityPoint(parameters.publicProofParams.encryptionPublicKey);
    canonicalizeNonIdentityPoint(parameters.publicProofParams.messageGenerator);
}
