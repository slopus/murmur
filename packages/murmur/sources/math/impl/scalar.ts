import { sha512 } from "@noble/hashes/sha2";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";
import { concatBytes } from "../../utils/index.js";
import { encodeUint32 } from "./codec.js";
import { encodeTranscript } from "./transcript.js";

/** Order of the prime Ristretto255 group. */
export const RISTRETTO_ORDER = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

/** Decode a strict canonical 32-byte little-endian scalar. */
export function decodeScalar(value: Uint8Array, allowZero = true): bigint {
    if (value.length !== 32) {
        throw new Error("Ristretto scalar must be 32 bytes");
    }
    let scalar = 0n;
    for (let index = value.length - 1; index >= 0; index -= 1) {
        scalar = (scalar << 8n) | BigInt(value[index] ?? 0);
    }
    if (scalar >= RISTRETTO_ORDER || (!allowZero && scalar === 0n)) {
        throw new Error("Non-canonical Ristretto scalar");
    }
    return scalar;
}

/** Encode a canonical 32-byte little-endian scalar. */
export function encodeScalar(value: bigint): Uint8Array {
    if (value < 0n || value >= RISTRETTO_ORDER) {
        throw new Error("Ristretto scalar is out of range");
    }
    const encoded = new Uint8Array(32);
    let remaining = value;
    for (let index = 0; index < encoded.length; index += 1) {
        encoded[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return encoded;
}

/** Reduce a wide little-endian byte string modulo the group order. */
export function reduceScalar(value: Uint8Array): Uint8Array {
    let scalar = 0n;
    for (let index = value.length - 1; index >= 0; index -= 1) {
        scalar = ((scalar << 8n) | BigInt(value[index] ?? 0)) % RISTRETTO_ORDER;
    }
    return encodeScalar(scalar);
}

/** Hash named byte strings to a canonical scalar with strict domain separation. */
export function hashToScalar(
    domain: string,
    parts: readonly Uint8Array[],
    nonzero = false,
): Uint8Array {
    for (let counter = 0; counter <= 0xffff_ffff; counter += 1) {
        const fields = parts.map((part, index) => ({ label: `part-${index}`, value: part }));
        const digest = sha512(
            encodeTranscript(domain, [
                ...fields,
                { label: "counter", value: encodeUint32(counter) },
            ]),
        );
        const scalar = reduceScalar(digest);
        if (!nonzero || decodeScalar(scalar) !== 0n) {
            return scalar;
        }
    }
    throw new Error("Unable to derive a non-zero scalar");
}

/** Generate an unbiased non-zero Ristretto255 scalar. */
export function randomScalar(): Uint8Array {
    for (;;) {
        const candidate = nobleRandomBytes(32);
        candidate[31] = (candidate[31] ?? 0) & 0x1f;
        try {
            decodeScalar(candidate, false);
            return candidate;
        } catch {
            // Rejection sampling is expected for values at or above the order.
        }
    }
}

/** Add canonical scalars modulo the group order. */
export function addScalars(...values: readonly Uint8Array[]): Uint8Array {
    let result = 0n;
    for (const value of values) {
        result = (result + decodeScalar(value)) % RISTRETTO_ORDER;
    }
    return encodeScalar(result);
}

/** Multiply canonical scalars modulo the group order. */
export function multiplyScalars(...values: readonly Uint8Array[]): Uint8Array {
    let result = 1n;
    for (const value of values) {
        result = (result * decodeScalar(value)) % RISTRETTO_ORDER;
    }
    return encodeScalar(result);
}

/** Negate a canonical scalar modulo the group order. */
export function negateScalar(value: Uint8Array): Uint8Array {
    const scalar = decodeScalar(value);
    return encodeScalar(scalar === 0n ? 0n : RISTRETTO_ORDER - scalar);
}

/** Join scalar byte strings for deterministic test and protocol inputs. */
export function encodeScalarVector(values: readonly Uint8Array[]): Uint8Array {
    return concatBytes(encodeUint32(values.length), ...values);
}
