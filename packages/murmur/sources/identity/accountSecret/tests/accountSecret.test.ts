import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, zeroBytes } from "../../../utils/index.js";
import {
    createAccountSecret,
    rewrapAccountSecret,
    unlockAccountSecret,
    type CreatedAccountSecret,
} from "../index.js";

const PASSWORD = "correct horse battery staple";

describe("account secret", () => {
    let identity: IdentityKeyPair;
    let created: CreatedAccountSecret;

    beforeAll(async () => {
        identity = generateIdentityKeyPair();
        created = await createAccountSecret(identity, PASSWORD);
    });

    afterAll(() => {
        destroyIdentity(identity);
    });

    it("round trips one identity root through a canonical opaque blob", async () => {
        const blobBytes = decodeBase64Url(created.blob);
        const restored = await unlockAccountSecret(created.blob, created.generatedSecret, PASSWORD);
        try {
            expect(created.generatedSecret).toMatch(/^murmur-as1-[A-Za-z0-9_-]{43}$/);
            expect(created.blob).toMatch(/^[A-Za-z0-9_-]+$/);
            expect(encodeBase64Url(blobBytes)).toBe(created.blob);
            expect(restored.secretKey).toEqual(identity.secretKey);
            expect(restored.publicKey).toEqual(identity.publicKey);
        } finally {
            zeroBytes(blobBytes);
            destroyIdentity(restored);
        }
    });

    it("rejects a wrong password", async () => {
        await expect(
            unlockAccountSecret(created.blob, created.generatedSecret, "wrong password"),
        ).rejects.toThrow("Unable to unlock account secret");
    });

    it("rejects a wrong generated secret", async () => {
        const final = created.generatedSecret.at(-1);
        const wrongGeneratedSecret = `${created.generatedSecret.slice(0, -1)}${final === "A" ? "E" : "A"}`;

        await expect(
            unlockAccountSecret(created.blob, wrongGeneratedSecret, PASSWORD),
        ).rejects.toThrow("Unable to unlock account secret");
    });

    it("rejects a tampered encrypted blob", async () => {
        const bytes = decodeBase64Url(created.blob);
        bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
        const tampered = encodeBase64Url(bytes);
        zeroBytes(bytes);

        await expect(
            unlockAccountSecret(tampered, created.generatedSecret, PASSWORD),
        ).rejects.toThrow("Unable to unlock account secret");
    });

    it("rejects an unsupported blob version before derivation", async () => {
        const bytes = decodeBase64Url(created.blob);
        bytes[4] = 2;
        const unsupported = encodeBase64Url(bytes);
        zeroBytes(bytes);

        await expect(
            unlockAccountSecret(unsupported, created.generatedSecret, PASSWORD),
        ).rejects.toThrow("Unsupported account secret blob version");
    });

    it("rewraps the complete payload under a changed password", async () => {
        const newPassword = "a changed password with spaces";
        const rewrapped = await rewrapAccountSecret(
            created.blob,
            created.generatedSecret,
            PASSWORD,
            newPassword,
        );
        expect(rewrapped).not.toBe(created.blob);
        await expect(
            unlockAccountSecret(rewrapped, created.generatedSecret, PASSWORD),
        ).rejects.toThrow("Unable to unlock account secret");

        const restored = await unlockAccountSecret(rewrapped, created.generatedSecret, newPassword);
        try {
            expect(restored.secretKey).toEqual(identity.secretKey);
            expect(restored.publicKey).toEqual(identity.publicKey);
        } finally {
            destroyIdentity(restored);
        }
    });
});
