import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { concatBytes, equalBytes } from "../../utils/index.js";
import { encodeUint32 } from "./codec.js";
import { decodeScalar } from "./scalar.js";
import { encodeTranscript } from "./transcript.js";

type NobleRistrettoPoint = InstanceType<typeof ristretto255.Point>;

const HASH_TO_POINT_DST = "murmur_R255_XMD:SHA-512_R255MAP_RO_v1";
const REVERSIBLE_PAYLOAD_LENGTH = 16;

function decodePointObject(value: Uint8Array): NobleRistrettoPoint {
    if (value.length !== 32) {
        throw new Error("Ristretto point must be 32 bytes");
    }
    const point = ristretto255.Point.fromBytes(value);
    if (!equalBytes(point.toBytes(), value)) {
        throw new Error("Non-canonical Ristretto point");
    }
    return point;
}

/** Strictly validate and copy a canonical RFC 9496 Ristretto255 point. */
export function canonicalizePoint(value: Uint8Array): Uint8Array {
    return decodePointObject(value).toBytes();
}

/** Strictly validate a canonical point and reject the group identity. */
export function canonicalizeNonIdentityPoint(value: Uint8Array): Uint8Array {
    const point = canonicalizePoint(value);
    if (equalBytes(point, identityPoint())) {
        throw new Error("Ristretto point must not be the identity");
    }
    return point;
}

/** Return the canonical Ristretto identity point. */
export function identityPoint(): Uint8Array {
    return ristretto255.Point.ZERO.toBytes();
}

/** Return the canonical Ristretto base point. */
export function basePoint(): Uint8Array {
    return ristretto255.Point.BASE.toBytes();
}

/** Hash named bytes to a Ristretto point using the RFC 9380 public API. */
export function hashToPoint(domain: string, parts: readonly Uint8Array[]): Uint8Array {
    const fields = parts.map((part, index) => ({ label: `part-${index}`, value: part }));
    const input = encodeTranscript(domain, fields);
    const affine = ristretto255_hasher.hashToCurve(input, { DST: HASH_TO_POINT_DST }).toAffine();
    return ristretto255.Point.fromAffine(affine).toBytes();
}

/** Add canonical Ristretto points. */
export function addPoints(...values: readonly Uint8Array[]): Uint8Array {
    let result = ristretto255.Point.ZERO;
    for (const value of values) {
        result = result.add(decodePointObject(value));
    }
    return result.toBytes();
}

/** Subtract one canonical Ristretto point from another. */
export function subtractPoints(left: Uint8Array, right: Uint8Array): Uint8Array {
    return decodePointObject(left).subtract(decodePointObject(right)).toBytes();
}

/** Multiply a canonical Ristretto point by a canonical scalar. */
export function multiplyPoint(point: Uint8Array, scalar: Uint8Array): Uint8Array {
    const decodedScalar = decodeScalar(scalar);
    if (decodedScalar === 0n) {
        decodePointObject(point);
        return identityPoint();
    }
    return decodePointObject(point).multiply(decodedScalar).toBytes();
}

/** Multiply the canonical base point by a canonical scalar. */
export function multiplyBase(scalar: Uint8Array): Uint8Array {
    const decodedScalar = decodeScalar(scalar);
    return decodedScalar === 0n
        ? identityPoint()
        : ristretto255.Point.BASE.multiply(decodedScalar).toBytes();
}

/** Compare canonical point encodings without returning early. */
export function equalPoints(left: Uint8Array, right: Uint8Array): boolean {
    try {
        return equalBytes(canonicalizePoint(left), canonicalizePoint(right));
    } catch {
        return false;
    }
}

/**
 * Reversibly encode exactly 16 bytes in a canonical Ristretto representation.
 *
 * The payload occupies bytes 1-16 of the encoding. Remaining bytes are a
 * deterministic SHA-512 search suffix; decoding re-runs the search and rejects
 * arbitrary Ristretto points which were not emitted by this function.
 */
export function encodeBytesToPoint(value: Uint8Array): Uint8Array {
    if (value.length !== REVERSIBLE_PAYLOAD_LENGTH) {
        throw new Error("Reversible Ristretto payload must be exactly 16 bytes");
    }
    for (let counter = 0; counter <= 0xffff_ffff; counter += 1) {
        const digest = sha512(
            encodeTranscript("murmur.math.reversible-point.v1", [
                { label: "payload", value },
                { label: "counter", value: encodeUint32(counter) },
            ]),
        );
        const candidate = new Uint8Array(32);
        candidate[0] = 0;
        candidate.set(value, 1);
        candidate.set(digest.subarray(0, 15), 17);
        candidate[31] = (candidate[31] ?? 0) & 0x7f;
        try {
            return canonicalizePoint(candidate);
        } catch {
            // Approximately one in a few candidate encodings is a valid point.
        }
    }
    throw new Error("Unable to encode bytes as a Ristretto point");
}

/** Decode a point emitted by `encodeBytesToPoint`. */
export function decodePointToBytes(point: Uint8Array): Uint8Array {
    const canonical = canonicalizePoint(point);
    const payload = canonical.slice(1, 17);
    const expected = encodeBytesToPoint(payload);
    if (!equalBytes(expected, canonical)) {
        throw new Error("Ristretto point is not a reversible Murmur encoding");
    }
    return payload;
}

/** Canonically concatenate points after strict validation. */
export function encodePointVector(points: readonly Uint8Array[]): Uint8Array {
    return concatBytes(encodeUint32(points.length), ...points.map(canonicalizePoint));
}
