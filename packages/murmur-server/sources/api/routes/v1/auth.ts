import { z } from "zod";
import type { Fastify } from "@/types";
import { db } from "@/db";
import {
    isValidPublicKey,
    normalizePublicKey,
    publicKeyToExternal,
    verifySignature,
} from "@/utils/crypto";
import { generateToken, refreshAccessToken } from "@/utils/jwt";
import { rateLimitConfigs } from "@/api/rateLimit";
import { registrationsTotal, loginsTotal, tokenRefreshesTotal } from "@/metrics/prometheus";
import { validateProfileData } from "@/api/validation";

const RegisterSchema = z.object({
    identityPublicKey: z.string(),
    profilePublicKey: z.string(),
    profileKeySignature: z.string(),
    encryptedProfile: z.string(), // Base64-encoded encrypted profile blob
    timestamp: z.number(),
    signature: z.string(), // Signature of the entire request by identity key
});

const LoginSchema = z.object({
    identityPublicKey: z.string(),
    timestamp: z.number(),
    signature: z.string(), // Signature of timestamp by identity key
});

const RefreshSchema = z.object({
    refreshToken: z.string(),
});

/**
 * Authentication routes (no auth required)
 */
export async function authRoutes(app: Fastify) {
    // Register a new user
    app.post(
        "/v1/auth/register",
        {
            schema: {
                body: RegisterSchema,
            },
            config: {
                rateLimit: rateLimitConfigs.auth,
            },
        },
        async (request, reply) => {
            const {
                identityPublicKey,
                profilePublicKey,
                profileKeySignature,
                encryptedProfile,
                timestamp,
                signature,
            } = request.body;

            let normalizedIdentityPublicKey: string;
            let normalizedProfilePublicKey: string;
            try {
                // Validate public keys format
                if (!isValidPublicKey(identityPublicKey)) {
                    registrationsTotal.inc({ status: "invalid_key" });
                    return reply.status(400).send({ error: "Invalid identity public key format" });
                }

                if (!isValidPublicKey(profilePublicKey)) {
                    registrationsTotal.inc({ status: "invalid_key" });
                    return reply.status(400).send({ error: "Invalid profile public key format" });
                }

                normalizedIdentityPublicKey = normalizePublicKey(identityPublicKey);
                normalizedProfilePublicKey = normalizePublicKey(profilePublicKey);

                // Validate size limits
                validateProfileData({ profilePublicKey, profileKeySignature, encryptedProfile });
            } catch (error: any) {
                registrationsTotal.inc({ status: "validation_failed" });
                return reply.status(400).send({ error: error.message });
            }

            // Verify timestamp is recent (within 5 minutes)
            const now = Date.now();
            if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
                registrationsTotal.inc({ status: "timestamp_expired" });
                return reply.status(400).send({ error: "Request timestamp too old" });
            }

            // Verify signature of the entire request
            const message = JSON.stringify({
                identityPublicKey,
                profilePublicKey,
                profileKeySignature,
                encryptedProfile,
                timestamp,
            });

            if (!verifySignature(message, signature, identityPublicKey)) {
                registrationsTotal.inc({ status: "invalid_signature" });
                return reply.status(400).send({ error: "Invalid request signature" });
            }

            // Parse base64 to binary
            const profilePublicKeyBuffer = Buffer.from(normalizedProfilePublicKey, "base64");
            const profileKeySignatureBuffer = Buffer.from(profileKeySignature, "base64");
            const encryptedProfileBuffer = Buffer.from(encryptedProfile, "base64");

            // Verify profile key signature (profile key bytes signed by identity key)
            if (!verifySignature(profilePublicKeyBuffer, profileKeySignature, identityPublicKey)) {
                registrationsTotal.inc({ status: "invalid_profile_signature" });
                return reply.status(400).send({ error: "Invalid profile key signature" });
            }

            // Check if user already exists (idempotent registration)
            let user = await db.user.findUnique({
                where: { id: normalizedIdentityPublicKey },
            });

            if (user) {
                // User exists - verify the profile matches (idempotent)
                if (
                    user.profilePublicKey === normalizedProfilePublicKey &&
                    Buffer.compare(user.profileKeySignature, profileKeySignatureBuffer) === 0 &&
                    Buffer.compare(user.encryptedProfile, encryptedProfileBuffer) === 0
                ) {
                    // Same profile - return success with tokens (idempotent)
                    registrationsTotal.inc({ status: "idempotent" });
                    const tokens = await generateToken(normalizedIdentityPublicKey);
                    return reply.send({
                        success: true,
                        accessToken: tokens.accessToken,
                        refreshToken: tokens.refreshToken,
                        user: {
                            id: publicKeyToExternal(user.id),
                            createdAt: user.createdAt.getTime(),
                        },
                    });
                } else {
                    // Different profile - this is an update, not a registration
                    registrationsTotal.inc({ status: "conflict" });
                    return reply.status(400).send({
                        error: "User exists with different profile. Use /v1/profile/update to update profile.",
                    });
                }
            }

            // Create new user
            user = await db.user.create({
                data: {
                    id: normalizedIdentityPublicKey,
                    profilePublicKey: normalizedProfilePublicKey,
                    profileKeySignature: profileKeySignatureBuffer,
                    encryptedProfile: encryptedProfileBuffer,
                    profileUpdatedAt: new Date(),
                },
            });

            // Generate token pair (access + refresh)
            const tokens = await generateToken(normalizedIdentityPublicKey);

            registrationsTotal.inc({ status: "success" });
            return reply.send({
                success: true,
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                user: {
                    id: publicKeyToExternal(user.id),
                    createdAt: user.createdAt.getTime(),
                },
            });
        },
    );

    // Login (get JWT)
    app.post(
        "/v1/auth/login",
        {
            schema: {
                body: LoginSchema,
            },
            config: {
                rateLimit: rateLimitConfigs.auth,
            },
        },
        async (request, reply) => {
            const { identityPublicKey, timestamp, signature } = request.body;

            let normalizedIdentityPublicKey: string;
            // Validate public key format
            if (!isValidPublicKey(identityPublicKey)) {
                loginsTotal.inc({ status: "invalid_key" });
                return reply.status(400).send({ error: "Invalid identity public key format" });
            }
            try {
                normalizedIdentityPublicKey = normalizePublicKey(identityPublicKey);
            } catch (error: any) {
                loginsTotal.inc({ status: "invalid_key" });
                return reply.status(400).send({ error: "Invalid identity public key format" });
            }

            // Verify timestamp is recent (within 5 minutes)
            const now = Date.now();
            if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
                loginsTotal.inc({ status: "timestamp_expired" });
                return reply.status(400).send({ error: "Request timestamp too old" });
            }

            // Verify signature
            const message = `${identityPublicKey}:${timestamp}`;
            if (!verifySignature(message, signature, identityPublicKey)) {
                loginsTotal.inc({ status: "invalid_signature" });
                return reply.status(400).send({ error: "Invalid signature" });
            }

            // Check if user exists
            const user = await db.user.findUnique({
                where: { id: normalizedIdentityPublicKey },
            });

            if (!user) {
                loginsTotal.inc({ status: "user_not_found" });
                return reply.status(404).send({ error: "User not found" });
            }

            // Generate token pair (access + refresh)
            const tokens = await generateToken(normalizedIdentityPublicKey);

            loginsTotal.inc({ status: "success" });
            return reply.send({
                success: true,
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                user: {
                    id: publicKeyToExternal(user.id),
                    createdAt: user.createdAt.getTime(),
                },
            });
        },
    );

    // Refresh access token using refresh token
    app.post(
        "/v1/auth/refresh",
        {
            schema: {
                body: RefreshSchema,
            },
            config: {
                rateLimit: rateLimitConfigs.auth,
            },
        },
        async (request, reply) => {
            const { refreshToken } = request.body;

            // Attempt to refresh the access token
            const newAccessToken = await refreshAccessToken(refreshToken);

            if (!newAccessToken) {
                tokenRefreshesTotal.inc({ status: "invalid_token" });
                return reply.status(401).send({ error: "Invalid or expired refresh token" });
            }

            tokenRefreshesTotal.inc({ status: "success" });
            return reply.send({
                success: true,
                accessToken: newAccessToken,
            });
        },
    );
}
