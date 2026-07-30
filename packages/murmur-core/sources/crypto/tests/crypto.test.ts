import { describe, expect, it } from "vitest";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    openBox,
    sealBox,
    signBytes,
    verifyBytes,
} from "../index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";

describe("identity crypto", () => {
    it("signs and verifies bytes", () => {
        const identity = generateIdentityKeyPair();
        const message = utf8Encode("hello");

        expect(verifyBytes(identity, message, signBytes(identity, message))).toBe(true);
        expect(verifyBytes(identity, utf8Encode("changed"), signBytes(identity, message))).toBe(
            false,
        );
    });

    it("seals bytes to one identity", () => {
        const recipient = generateIdentityKeyPair();
        const other = generateIdentityKeyPair();
        const aad = utf8Encode("profile");
        const box = sealBox(recipient, utf8Encode("secret"), aad);

        expect(utf8Decode(openBox(recipient, box, aad))).toBe("secret");
        expect(() => openBox(other, box, aad)).toThrow();
    });

    it("zeros identity secrets", () => {
        const identity = generateIdentityKeyPair();

        destroyIdentity(identity);

        expect(identity.signingSecretKey.every((byte) => byte === 0)).toBe(true);
        expect(identity.encryptionSecretKey.every((byte) => byte === 0)).toBe(true);
    });
});
