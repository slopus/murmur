import { describe, expect, it } from "vitest";
import {
    addPoints,
    basePoint,
    canonicalizePoint,
    decodeAlgebraicMac,
    decodeElGamalCiphertext,
    decodePointToBytes,
    decodeScalar,
    decryptElGamalPoint,
    encodeAlgebraicMac,
    encodeBytesToPoint,
    encodeElGamalCiphertext,
    encodeScalar,
    encryptElGamalPoint,
    hashToPoint,
    hashToScalar,
    issueAlgebraicMac,
    multiplyBase,
    multiplyPoint,
    verifyAlgebraicMac,
    RISTRETTO_ORDER,
    type AlgebraicMacSecretKey,
} from "../index.js";
import { equalBytes, utf8Encode } from "../../utils/index.js";

function scalar(label: string): Uint8Array {
    return hashToScalar("murmur.math.test.scalar", [utf8Encode(label)], true);
}

describe("private-group mathematics", () => {
    it("strictly validates canonical scalars and Ristretto points", () => {
        expect(decodeScalar(encodeScalar(RISTRETTO_ORDER - 1n))).toBe(RISTRETTO_ORDER - 1n);
        expect(() => decodeScalar(encodeLittleEndianUnchecked(RISTRETTO_ORDER))).toThrow(
            "Non-canonical",
        );
        expect(() => canonicalizePoint(new Uint8Array(32).fill(0xff))).toThrow();
        expect(canonicalizePoint(basePoint())).toEqual(basePoint());
        expect(basePoint()).toEqual(
            decodeHex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"),
        );
    });

    it("reversibly encodes the required 16-byte payload without private curve fields", () => {
        const payload = Uint8Array.from({ length: 16 }, (_, index) => index * 13);
        const point = encodeBytesToPoint(payload);
        expect(decodePointToBytes(point)).toEqual(payload);
        expect(() =>
            decodePointToBytes(hashToPoint("murmur.math.test.point", [payload])),
        ).toThrow();
    });

    it("uses correct ElGamal equations and decryption round-trips the message point", () => {
        const secretKey = scalar("elgamal-key");
        const publicKey = multiplyBase(secretKey);
        const message = hashToPoint("murmur.math.test.message", [utf8Encode("message")]);
        const randomness = scalar("elgamal-randomness");
        const ciphertext = encryptElGamalPoint(publicKey, message, randomness);

        expect(ciphertext.ephemeralPublicKey).toEqual(multiplyBase(randomness));
        expect(ciphertext.encryptedPoint).toEqual(
            addPoints(message, multiplyPoint(publicKey, randomness)),
        );
        expect(decryptElGamalPoint(secretKey, ciphertext)).toEqual(message);
        expect(equalBytes(decryptElGamalPoint(scalar("wrong-key"), ciphertext), message)).toBe(
            false,
        );
        expect(decodeElGamalCiphertext(encodeElGamalCiphertext(ciphertext))).toEqual(ciphertext);

        const brokenFormula = {
            ephemeralPublicKey: ciphertext.ephemeralPublicKey,
            encryptedPoint: addPoints(publicKey, message),
        };
        expect(equalBytes(decryptElGamalPoint(secretKey, brokenFormula), message)).toBe(false);
    });

    it("issues, serializes, and verifies a keyed algebraic MAC", () => {
        const key: AlgebraicMacSecretKey = {
            w: scalar("mac-w"),
            x0: scalar("mac-x0"),
            x1: scalar("mac-x1"),
            identifier: scalar("mac-identifier"),
            expiry: scalar("mac-expiry"),
        };
        const parameters = {
            wGenerator: hashToPoint("murmur.math.test.generator", [utf8Encode("w")]),
        };
        const identifier = hashToPoint("murmur.math.test.attribute", [utf8Encode("id")]);
        const expiry = hashToPoint("murmur.math.test.attribute", [utf8Encode("expiry")]);
        const mac = issueAlgebraicMac(parameters, key, identifier, expiry, scalar("mac-t"));

        expect(verifyAlgebraicMac(parameters, key, identifier, expiry, mac)).toBe(true);
        expect(decodeAlgebraicMac(encodeAlgebraicMac(mac))).toEqual(mac);
        expect(
            verifyAlgebraicMac(parameters, key, identifier, expiry, {
                ...mac,
                v: addPoints(mac.v, basePoint()),
            }),
        ).toBe(false);
    });
});

function encodeLittleEndianUnchecked(value: bigint): Uint8Array {
    const result = new Uint8Array(32);
    let remaining = value;
    for (let index = 0; index < result.length; index += 1) {
        result[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return result;
}

function decodeHex(value: string): Uint8Array {
    if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
        throw new Error("Invalid test vector hex");
    }
    return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
        Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
    );
}
