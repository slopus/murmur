import { describe, it, expect, beforeAll } from "vitest";
import {
    generateToken,
    verifyAccessToken,
    verifyRefreshToken,
    refreshAccessToken,
    initializeJWT,
} from "./jwt";

describe("JWT utilities with refresh tokens", () => {
    beforeAll(async () => {
        // Initialize JWT before running tests
        await initializeJWT();
    });

    describe("generateToken", () => {
        it("should generate access and refresh token pair", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            expect(tokens).toBeDefined();
            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(typeof tokens.accessToken).toBe("string");
            expect(typeof tokens.refreshToken).toBe("string");
            expect(tokens.accessToken).not.toBe(tokens.refreshToken);
        });
    });

    describe("verifyAccessToken", () => {
        it("should verify a valid access token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const payload = await verifyAccessToken(tokens.accessToken);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);
            expect(payload?.user).toBe(userId);
        });

        it("should reject invalid access token", async () => {
            const payload = await verifyAccessToken("invalid-token");
            expect(payload).toBeNull();
        });

        it("should reject tampered access token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const tamperedToken = tokens.accessToken.slice(0, -5) + "XXXXX";
            const payload = await verifyAccessToken(tamperedToken);
            expect(payload).toBeNull();
        });

        it("should reject refresh token when expecting access token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const payload = await verifyAccessToken(tokens.refreshToken);
            expect(payload).toBeNull();
        });
    });

    describe("verifyRefreshToken", () => {
        it("should verify a valid refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const payload = await verifyRefreshToken(tokens.refreshToken);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);
            expect(payload?.user).toBe(userId);
        });

        it("should reject invalid refresh token", async () => {
            const payload = await verifyRefreshToken("invalid-token");
            expect(payload).toBeNull();
        });

        it("should reject tampered refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const tamperedToken = tokens.refreshToken.slice(0, -5) + "XXXXX";
            const payload = await verifyRefreshToken(tamperedToken);
            expect(payload).toBeNull();
        });

        it("should reject access token when expecting refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const payload = await verifyRefreshToken(tokens.accessToken);
            expect(payload).toBeNull();
        });
    });

    describe("refreshAccessToken", () => {
        it("should generate new access token from valid refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const newAccessToken = await refreshAccessToken(tokens.refreshToken);
            expect(newAccessToken).toBeDefined();
            expect(typeof newAccessToken).toBe("string");

            // New access token should be valid
            const payload = await verifyAccessToken(newAccessToken!);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);

            // New access token should be different from original
            expect(newAccessToken).not.toBe(tokens.accessToken);
        });

        it("should reject invalid refresh token", async () => {
            const newAccessToken = await refreshAccessToken("invalid-token");
            expect(newAccessToken).toBeNull();
        });

        it("should reject access token when expecting refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const newAccessToken = await refreshAccessToken(tokens.accessToken);
            expect(newAccessToken).toBeNull();
        });

        it("should allow multiple refreshes with same refresh token", async () => {
            const userId = "test-user-id";
            const tokens = await generateToken(userId);

            const newAccessToken1 = await refreshAccessToken(tokens.refreshToken);
            const newAccessToken2 = await refreshAccessToken(tokens.refreshToken);

            expect(newAccessToken1).toBeDefined();
            expect(newAccessToken2).toBeDefined();

            // Both should be valid
            const payload1 = await verifyAccessToken(newAccessToken1!);
            const payload2 = await verifyAccessToken(newAccessToken2!);

            expect(payload1?.userId).toBe(userId);
            expect(payload2?.userId).toBe(userId);
        });
    });

    describe("token isolation", () => {
        it("should not accept tokens from different users", async () => {
            const user1 = "user-1";
            const user2 = "user-2";

            const tokens1 = await generateToken(user1);
            const tokens2 = await generateToken(user2);

            const payload1 = await verifyAccessToken(tokens1.accessToken);
            const payload2 = await verifyAccessToken(tokens2.accessToken);

            expect(payload1?.userId).toBe(user1);
            expect(payload2?.userId).toBe(user2);
            expect(payload1?.userId).not.toBe(payload2?.userId);
        });
    });
});
