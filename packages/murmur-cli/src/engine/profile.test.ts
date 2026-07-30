/**
 * Tests for profile encryption and management.
 */

import { describe, it, expect } from "vitest";
import {
    generateProfileKeyPair,
    encryptProfile,
    decryptProfile,
    signProfileKey,
    verifyProfileKeySignature,
    createProfileForRegistration,
    type Profile,
} from "./profile.js";
import { generateSigningKeyPair } from "../encryption/crypto/signing.js";
import { encodeBase64, decodeBase64 } from "../encryption/crypto/utils.js";

describe("Profile encryption", () => {
    it("should encrypt and decrypt profile", () => {
        const profile: Profile = {
            firstName: "Alice",
            lastName: "Smith",
        };

        const keyPair = generateProfileKeyPair();
        const encrypted = encryptProfile(profile, keyPair.privateKey);
        const decrypted = decryptProfile(encrypted, keyPair.privateKey);

        expect(decrypted).toEqual(profile);
    });

    it("should encrypt profile without lastName", () => {
        const profile: Profile = {
            firstName: "Bob",
        };

        const keyPair = generateProfileKeyPair();
        const encrypted = encryptProfile(profile, keyPair.privateKey);
        const decrypted = decryptProfile(encrypted, keyPair.privateKey);

        expect(decrypted.firstName).toBe("Bob");
        expect(decrypted.lastName).toBeUndefined();
    });

    it("should produce different ciphertext for same profile", () => {
        const profile: Profile = { firstName: "Test" };
        const keyPair = generateProfileKeyPair();

        const encrypted1 = encryptProfile(profile, keyPair.privateKey);
        const encrypted2 = encryptProfile(profile, keyPair.privateKey);

        // Due to random nonce, ciphertexts should differ
        expect(encrypted1).not.toBe(encrypted2);

        // But both should decrypt to same value
        expect(decryptProfile(encrypted1, keyPair.privateKey)).toEqual(profile);
        expect(decryptProfile(encrypted2, keyPair.privateKey)).toEqual(profile);
    });

    it("should fail to decrypt with wrong key", () => {
        const profile: Profile = { firstName: "Secret" };
        const keyPair1 = generateProfileKeyPair();
        const keyPair2 = generateProfileKeyPair();

        const encrypted = encryptProfile(profile, keyPair1.privateKey);

        expect(() => decryptProfile(encrypted, keyPair2.privateKey)).toThrow();
    });
});

describe("Profile key signing", () => {
    it("should sign and verify profile key", () => {
        const profileKeyPair = generateProfileKeyPair();
        const identityKeyPair = generateSigningKeyPair();

        const signature = signProfileKey(profileKeyPair.publicKey, identityKeyPair.privateKey);

        expect(
            verifyProfileKeySignature(
                profileKeyPair.publicKey,
                signature,
                identityKeyPair.publicKey,
            ),
        ).toBe(true);
    });

    it("should reject signature from wrong identity", () => {
        const profileKeyPair = generateProfileKeyPair();
        const identityKeyPair1 = generateSigningKeyPair();
        const identityKeyPair2 = generateSigningKeyPair();

        const signature = signProfileKey(profileKeyPair.publicKey, identityKeyPair1.privateKey);

        expect(
            verifyProfileKeySignature(
                profileKeyPair.publicKey,
                signature,
                identityKeyPair2.publicKey,
            ),
        ).toBe(false);
    });

    it("should reject signature for wrong profile key", () => {
        const profileKeyPair1 = generateProfileKeyPair();
        const profileKeyPair2 = generateProfileKeyPair();
        const identityKeyPair = generateSigningKeyPair();

        const signature = signProfileKey(profileKeyPair1.publicKey, identityKeyPair.privateKey);

        expect(
            verifyProfileKeySignature(
                profileKeyPair2.publicKey,
                signature,
                identityKeyPair.publicKey,
            ),
        ).toBe(false);
    });
});

describe("createProfileForRegistration", () => {
    it("should create complete profile data", () => {
        const identityKeyPair = generateSigningKeyPair();
        const profile: Profile = {
            firstName: "Charlie",
            lastName: "Brown",
        };

        const result = createProfileForRegistration(profile, identityKeyPair.privateKey);

        // Should have all required fields
        expect(result.profileKeyPair).toBeDefined();
        expect(result.profilePublicKey).toBeDefined();
        expect(result.profileSecretKey).toBeDefined();
        expect(result.profileKeySignature).toBeDefined();
        expect(result.encryptedProfile).toBeDefined();

        // Public key should be base64 encoded
        expect(() => decodeBase64(result.profilePublicKey)).not.toThrow();
        expect(() => decodeBase64(result.profileSecretKey, "base64url")).not.toThrow();

        // Should be able to decrypt profile
        const decrypted = decryptProfile(result.encryptedProfile, result.profileKeyPair.privateKey);
        expect(decrypted).toEqual(profile);

        // Signature should be valid
        expect(
            verifyProfileKeySignature(
                result.profileKeyPair.publicKey,
                result.profileKeySignature,
                identityKeyPair.publicKey,
            ),
        ).toBe(true);
    });
});
