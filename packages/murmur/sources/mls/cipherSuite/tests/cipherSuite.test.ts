import { randomBytes, utf8Decode, utf8Encode } from "../../internal.js";
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
    it("opens the official X25519/HKDF-SHA256/AES-128-GCM vector", () => {
        const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
        const plaintext = hpkeOpenBase(
            {
                secretKey: fromHex(
                    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
                ),
                publicKey: fromHex(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                ),
            },
            fromHex("4f6465206f6e2061204772656369616e2055726e"),
            fromHex("436f756e742d30"),
            {
                encapsulatedKey: fromHex(
                    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
                ),
                ciphertext: fromHex(
                    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
                ),
            },
        );

        expect(Buffer.from(plaintext).toString("hex")).toBe(
            "4265617574792069732074727574682c20747275746820626561757479",
        );
    });

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
