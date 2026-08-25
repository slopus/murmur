import { concatBytes, equalBytes, zeroBytes } from "../../utils/index.js";
import type { AlgebraicMac, AlgebraicMacParameters, AlgebraicMacSecretKey } from "../types.js";
import {
    addPoints,
    canonicalizePoint,
    hashToPoint,
    multiplyPoint,
    subtractPoints,
} from "./point.js";
import { decodeScalar, encodeScalar, randomScalar } from "./scalar.js";

function canonicalKey(key: AlgebraicMacSecretKey): AlgebraicMacSecretKey {
    return {
        w: encodeScalar(decodeScalar(key.w, false)),
        x0: encodeScalar(decodeScalar(key.x0, false)),
        x1: encodeScalar(decodeScalar(key.x1, false)),
        identifier: encodeScalar(decodeScalar(key.identifier, false)),
        expiry: encodeScalar(decodeScalar(key.expiry, false)),
    };
}

/** Issue a CPZ-style algebraic MAC over identifier and expiry group elements. */
export function issueAlgebraicMac(
    parameters: AlgebraicMacParameters,
    key: AlgebraicMacSecretKey,
    identifierPoint: Uint8Array,
    expiryPoint: Uint8Array,
    tInput?: Uint8Array,
): AlgebraicMac {
    const canonical = canonicalKey(key);
    const t = tInput?.slice() ?? randomScalar();
    try {
        decodeScalar(t, false);
        const u = hashToPoint("murmur.math.algebraic-mac.u.v1", [t]);
        const v = addPoints(
            multiplyPoint(canonicalizePoint(parameters.wGenerator), canonical.w),
            multiplyPoint(u, canonical.x0),
            multiplyPoint(multiplyPoint(u, t), canonical.x1),
            multiplyPoint(canonicalizePoint(identifierPoint), canonical.identifier),
            multiplyPoint(canonicalizePoint(expiryPoint), canonical.expiry),
        );
        return { t: t.slice(), u, v };
    } finally {
        for (const scalar of Object.values(canonical)) zeroBytes(scalar);
        if (tInput === undefined) zeroBytes(t);
    }
}

/** Verify an algebraic MAC with constant-time canonical point comparison. */
export function verifyAlgebraicMac(
    parameters: AlgebraicMacParameters,
    key: AlgebraicMacSecretKey,
    identifierPoint: Uint8Array,
    expiryPoint: Uint8Array,
    mac: AlgebraicMac,
): boolean {
    try {
        const expected = issueAlgebraicMac(parameters, key, identifierPoint, expiryPoint, mac.t);
        return (
            equalBytes(expected.u, canonicalizePoint(mac.u)) &&
            equalBytes(expected.v, canonicalizePoint(mac.v))
        );
    } catch {
        return false;
    }
}

/** Remove a linear blind from an issued algebraic-MAC tag. */
export function unblindAlgebraicMac(
    mac: AlgebraicMac,
    blinding: Uint8Array,
    unblindingKey: Uint8Array,
): AlgebraicMac {
    decodeScalar(blinding, false);
    return {
        t: encodeScalar(decodeScalar(mac.t, false)),
        u: canonicalizePoint(mac.u),
        v: subtractPoints(canonicalizePoint(mac.v), multiplyPoint(unblindingKey, blinding)),
    };
}

/** Canonically serialize an algebraic MAC. */
export function encodeAlgebraicMac(mac: AlgebraicMac): Uint8Array {
    return concatBytes(
        new Uint8Array([0x4d, 0x41, 0x4d, 0x01]),
        encodeScalar(decodeScalar(mac.t, false)),
        canonicalizePoint(mac.u),
        canonicalizePoint(mac.v),
    );
}

/** Strictly decode an algebraic MAC. */
export function decodeAlgebraicMac(value: Uint8Array): AlgebraicMac {
    if (
        value.length !== 100 ||
        !equalBytes(value.subarray(0, 4), new Uint8Array([0x4d, 0x41, 0x4d, 0x01]))
    ) {
        throw new Error("Invalid algebraic MAC encoding");
    }
    return {
        t: encodeScalar(decodeScalar(value.subarray(4, 36), false)),
        u: canonicalizePoint(value.subarray(36, 68)),
        v: canonicalizePoint(value.subarray(68, 100)),
    };
}

/** Zero all algebraic-MAC secret scalars in place. */
export function destroyAlgebraicMacKey(key: AlgebraicMacSecretKey): void {
    zeroBytes(key.w);
    zeroBytes(key.x0);
    zeroBytes(key.x1);
    zeroBytes(key.identifier);
    zeroBytes(key.expiry);
}
