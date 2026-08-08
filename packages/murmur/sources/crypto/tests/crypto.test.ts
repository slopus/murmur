import { describe, expect, it } from "vitest";
import {
    deriveSharedSecret,
    decodeIdentityRoot,
    destroyIdentity,
    encodeIdentityRoot,
    generateIdentityKeyPair,
    identityDhPublicKey,
    importIdentityKeyPair,
    openBox,
    sealBox,
    signBytes,
    validateIdentityPublicKey,
    verifyBytes,
} from "../index.js";
import { equalBytes, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";

describe("one-key identity crypto", () => {
    it("exposes one public key and one root secret", () => {
        const identity = generateIdentityKeyPair();
        const restored = importIdentityKeyPair(identity.secretKey);

        expect(Object.keys(identity).sort()).toEqual(["publicKey", "secretKey"]);
        expect(identity.publicKey).toHaveLength(32);
        expect(identity.secretKey).toHaveLength(32);
        expect(restored.publicKey).toEqual(identity.publicKey);
    });

    it("round trips only the clean one-root storage format", () => {
        const identity = generateIdentityKeyPair();
        const encoded = encodeIdentityRoot(identity);
        const stored: unknown = JSON.parse(utf8Decode(encoded));
        const restored = decodeIdentityRoot(encoded);

        expect(stored).toEqual({
            version: 1,
            secretKey: expect.any(String),
        });
        expect(restored.secretKey).toEqual(identity.secretKey);
        expect(restored.publicKey).toEqual(identity.publicKey);
        expect(() =>
            decodeIdentityRoot(
                utf8Encode(
                    JSON.stringify({
                        version: 1,
                        signingSecretKey: "old",
                        encryptionSecretKey: "old",
                    }),
                ),
            ),
        ).toThrow("stored identity root");
    });

    it("converts the same identity root into symmetric X25519 agreement", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceSecret = deriveSharedSecret(alice, bob);
        const bobSecret = deriveSharedSecret(bob, alice);

        try {
            expect(equalBytes(aliceSecret, bobSecret)).toBe(true);
            expect(identityDhPublicKey(alice)).toHaveLength(32);
            expect(identityDhPublicKey(alice)).not.toEqual(alice.publicKey);
        } finally {
            zeroBytes(aliceSecret);
            zeroBytes(bobSecret);
        }
    });

    it("uses the root for signatures and recipient-confidential sealed boxes", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const message = utf8Encode("identity proof");
        const signature = signBytes(alice, message);
        const aad = utf8Encode("friend request");
        const box = sealBox(bob, utf8Encode("secret"), aad);

        expect(verifyBytes(alice, message, signature)).toBe(true);
        expect(verifyBytes(bob, message, signature)).toBe(false);
        expect(utf8Decode(openBox(bob, box, aad))).toBe("secret");
        expect(() => openBox(eve, box, aad)).toThrow();
    });

    it("rejects a public key which does not match the supplied root", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();

        expect(() =>
            signBytes(
                { secretKey: alice.secretKey, publicKey: bob.publicKey },
                utf8Encode("mismatch"),
            ),
        ).toThrow("does not match");
    });

    it("zeros the single root secret", () => {
        const identity = generateIdentityKeyPair();

        destroyIdentity(identity);

        expect(identity.secretKey.every((byte) => byte === 0)).toBe(true);
    });

    it("rejects ZIP-215 small-order identity forgeries", () => {
        const identityPoint = new Uint8Array(32);
        identityPoint[0] = 1;
        const forgedSignature = new Uint8Array(64);
        forgedSignature[0] = 1;

        expect(
            verifyBytes({ publicKey: identityPoint }, utf8Encode("any content"), forgedSignature),
        ).toBe(false);
    });

    it("rejects all-zero and compressed identity Ed25519 points", () => {
        const allZero = new Uint8Array(32);
        const compressedIdentity = new Uint8Array(32);
        compressedIdentity[0] = 1;

        for (const publicKey of [allZero, compressedIdentity]) {
            expect(() => validateIdentityPublicKey({ publicKey })).toThrow(
                "Invalid Ed25519 identity point",
            );
            expect(() => identityDhPublicKey({ publicKey })).toThrow(
                "Invalid Ed25519 identity point",
            );
        }
    });
});
