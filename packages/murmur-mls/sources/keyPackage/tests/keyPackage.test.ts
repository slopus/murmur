import { generateIdentityKeyPair } from "@murmur/core";
import { describe, expect, it } from "vitest";
import {
    createMlsKeyPackage,
    decodeMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
} from "../index.js";

describe("RFC 9420 KeyPackage profile", () => {
    it("round trips and verifies nested signatures", () => {
        const bundle = createMlsKeyPackage(generateIdentityKeyPair(), 100, 60);
        const encoded = encodeMlsKeyPackage(bundle.keyPackage);
        const decoded = decodeMlsKeyPackage(encoded);

        expect(decoded).toEqual(bundle.keyPackage);
        expect(verifyMlsKeyPackage(decoded, 120)).toBe(true);
        expect(mlsKeyPackageReference(decoded)).toHaveLength(32);
    });

    it("rejects tampering and expiration", () => {
        const bundle = createMlsKeyPackage(generateIdentityKeyPair(), 100, 60);

        expect(
            verifyMlsKeyPackage(
                {
                    ...bundle.keyPackage,
                    initKey: bundle.keyPackage.leafNode.encryptionKey,
                },
                120,
            ),
        ).toBe(false);
        expect(verifyMlsKeyPackage(bundle.keyPackage, 161)).toBe(false);
    });

    it("rejects credential substitution and low-order HPKE keys", () => {
        const bundle = createMlsKeyPackage(generateIdentityKeyPair(), 100, 60);

        expect(
            verifyMlsKeyPackage(
                {
                    ...bundle.keyPackage,
                    leafNode: {
                        ...bundle.keyPackage.leafNode,
                        credential: { identity: new Uint8Array(32) },
                    },
                },
                120,
            ),
        ).toBe(false);
        expect(
            verifyMlsKeyPackage(
                {
                    ...bundle.keyPackage,
                    initKey: new Uint8Array(32),
                },
                120,
            ),
        ).toBe(false);
    });

    it("performs lifetime addition exactly as bigint", () => {
        const bundle = createMlsKeyPackage(
            generateIdentityKeyPair(),
            Number.MAX_SAFE_INTEGER,
            Number.MAX_SAFE_INTEGER,
        );

        expect(bundle.keyPackage.leafNode.notAfter).toBe(BigInt(Number.MAX_SAFE_INTEGER) * 2n);
    });

    it("zeros one-use HPKE secret keys", () => {
        const bundle = createMlsKeyPackage(generateIdentityKeyPair());

        destroyMlsKeyPackageBundle(bundle);

        expect(bundle.initKeyPair.secretKey.every((byte) => byte === 0)).toBe(true);
        expect(bundle.leafKeyPair.secretKey.every((byte) => byte === 0)).toBe(true);
    });
});
