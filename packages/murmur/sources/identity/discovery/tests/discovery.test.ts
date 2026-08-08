import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../../crypto/index.js";
import { createMlsKeyPackage } from "../../../mls/keyPackage/index.js";
import { utf8Decode, utf8Encode } from "../../../utils/index.js";
import {
    DISCOVERY_INVITATION_TTL_MILLISECONDS,
    createDiscoveryBundle,
    parseDiscoveryBundle,
    serializeDiscoveryBundle,
    verifyDiscoveryBundle,
} from "../index.js";

const NOW = 1_700_000_000_000;

describe("discovery bundle", () => {
    test("defaults to the fixed five-minute signed invitation lifetime", () => {
        const identity = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        const bundle = createDiscoveryBundle(identity, [keyPackage.keyPackage], {
            createdAt: NOW,
        });
        expect(bundle.expiresAt - bundle.createdAt).toBe(DISCOVERY_INVITATION_TTL_MILLISECONDS);
    });

    test("roundtrips current identity-bound KeyPackages", () => {
        const identity = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        const bundle = createDiscoveryBundle(identity, [keyPackage.keyPackage], {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const encoded = serializeDiscoveryBundle(bundle);
        const decoded = parseDiscoveryBundle(encoded, { now: NOW + 1 });
        expect(verifyDiscoveryBundle(decoded, { now: NOW + 1 })).toBe(true);
        expect(decoded.identityKey).toEqual(identity.publicKey);
        expect(decoded.keyPackages).toHaveLength(1);
    });

    test("rejects tampering, expiry, duplicates, and unknown fields", () => {
        const identity = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        expect(() =>
            createDiscoveryBundle(identity, [keyPackage.keyPackage, keyPackage.keyPackage], {
                createdAt: NOW,
                expiresAt: NOW + 60_000,
            }),
        ).toThrow("Duplicate");

        const valid = createDiscoveryBundle(identity, [keyPackage.keyPackage], {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const encoded = serializeDiscoveryBundle(valid);
        expect(() => parseDiscoveryBundle(encoded, { now: NOW + 60_000 })).toThrow();
        const json = JSON.parse(utf8Decode(encoded)) as Record<string, unknown>;
        expect(() =>
            parseDiscoveryBundle(utf8Encode(JSON.stringify({ ...json, extra: true })), {
                now: NOW,
            }),
        ).toThrow();
        const signature = String(json.signature);
        json.signature = `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
        expect(() =>
            parseDiscoveryBundle(utf8Encode(JSON.stringify(json)), { now: NOW }),
        ).toThrow();
    });

    test("allows bounded device clock skew", () => {
        const identity = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        const bundle = createDiscoveryBundle(identity, [keyPackage.keyPackage], {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const encoded = serializeDiscoveryBundle(bundle);
        expect(() =>
            parseDiscoveryBundle(encoded, {
                now: NOW - 30_000,
                maximumFutureSkewMilliseconds: 30_000,
            }),
        ).not.toThrow();
        expect(() =>
            parseDiscoveryBundle(encoded, {
                now: NOW - 30_001,
                maximumFutureSkewMilliseconds: 30_000,
            }),
        ).toThrow("not current");
    });

    test("rejects package-count amplification before package decoding", () => {
        const identity = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        const bundle = createDiscoveryBundle(identity, [keyPackage.keyPackage], {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const json = JSON.parse(utf8Decode(serializeDiscoveryBundle(bundle))) as {
            keyPackages: string[];
            signature: string;
        };
        json.keyPackages = Array.from({ length: 1_000 }, () => json.keyPackages[0]!);
        expect(() => parseDiscoveryBundle(utf8Encode(JSON.stringify(json)), { now: NOW })).toThrow(
            "count or size",
        );

        json.keyPackages = ["not-base64url"];
        expect(() => parseDiscoveryBundle(utf8Encode(JSON.stringify(json)), { now: NOW })).toThrow(
            "authentication",
        );
    });
});
