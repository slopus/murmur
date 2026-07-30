import { randomBytes, utf8Decode, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import {
    canonicalizeHpkePublicKey,
    deriveHpkeKeyPair,
    hpkeOpenBase,
    hpkeSealBase,
    mlsDeriveSecret,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../index.js";
import { ed25519 } from "@noble/curves/ed25519";

describe("RFC 9180 HPKE base mode", () => {
    it("round trips and binds info plus associated data", () => {
        const recipient = deriveHpkeKeyPair(randomBytes(32));
        const info = utf8Encode("group context");
        const aad = utf8Encode("header");
        const encrypted = hpkeSealBase(recipient.publicKey, info, aad, utf8Encode("path secret"));

        expect(utf8Decode(hpkeOpenBase(recipient, info, aad, encrypted))).toBe("path secret");
        expect(() => hpkeOpenBase(recipient, utf8Encode("wrong"), aad, encrypted)).toThrow();
    });

    it("canonicalizes equivalent RFC 7748 u-coordinate encodings", () => {
        const nine = new Uint8Array(32);
        nine[0] = 9;
        let nonCanonicalValue = (1n << 255n) - 19n + 9n;
        const nonCanonical = new Uint8Array(32);
        for (let index = 0; index < nonCanonical.length; index += 1) {
            nonCanonical[index] = Number(nonCanonicalValue & 0xffn);
            nonCanonicalValue >>= 8n;
        }

        expect(canonicalizeHpkePublicKey(nonCanonical)).toEqual(canonicalizeHpkePublicKey(nine));
    });
});

describe("RFC 9420 labels", () => {
    it("domain-separates derived secrets", () => {
        const secret = randomBytes(32);

        expect(mlsDeriveSecret(secret, "encryption")).not.toEqual(
            mlsDeriveSecret(secret, "exporter"),
        );
    });

    it("domain-separates Ed25519 signatures", () => {
        const secretKey = randomBytes(32);
        const publicKey = ed25519.getPublicKey(secretKey);
        const content = utf8Encode("commit");
        const signature = mlsSignWithLabel(secretKey, "FramedContentTBS", content);

        expect(mlsVerifyWithLabel(publicKey, "FramedContentTBS", content, signature)).toBe(true);
        expect(mlsVerifyWithLabel(publicKey, "KeyPackageTBS", content, signature)).toBe(false);
    });
});
