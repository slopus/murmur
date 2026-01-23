import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { isValidPublicKey, verifySignature } from '@/utils/crypto';
import { generateToken, refreshAccessToken } from '@/utils/jwt';

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
    app.post('/v1/auth/register', {
        schema: {
            body: RegisterSchema,
        },
    }, async (request, reply) => {
        const {
            identityPublicKey,
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            timestamp,
            signature,
        } = request.body;

        // Validate public keys format
        if (!isValidPublicKey(identityPublicKey)) {
            return reply.status(400).send({ error: 'Invalid identity public key format' });
        }

        if (!isValidPublicKey(profilePublicKey)) {
            return reply.status(400).send({ error: 'Invalid profile public key format' });
        }

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            return reply.status(400).send({ error: 'Request timestamp too old' });
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
            return reply.status(400).send({ error: 'Invalid request signature' });
        }

        // Verify profile key signature (profile key signed by identity key)
        if (!verifySignature(profilePublicKey, profileKeySignature, identityPublicKey)) {
            return reply.status(400).send({ error: 'Invalid profile key signature' });
        }

        // Parse base64 to binary
        const profileKeySignatureBuffer = Buffer.from(profileKeySignature, 'base64');
        const encryptedProfileBuffer = Buffer.from(encryptedProfile, 'base64');

        // Check if user already exists (idempotent registration)
        let user = await db.user.findUnique({
            where: { id: identityPublicKey },
        });

        if (user) {
            // User exists - verify the profile matches (idempotent)
            if (
                user.profilePublicKey === profilePublicKey &&
                Buffer.compare(user.profileKeySignature, profileKeySignatureBuffer) === 0 &&
                Buffer.compare(user.encryptedProfile, encryptedProfileBuffer) === 0
            ) {
                // Same profile - return success with tokens (idempotent)
                const tokens = await generateToken(identityPublicKey);
                return reply.send({
                    success: true,
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken,
                    user: {
                        id: user.id,
                        createdAt: user.createdAt.getTime(),
                    },
                });
            } else {
                // Different profile - this is an update, not a registration
                return reply.status(400).send({ error: 'User exists with different profile. Use /v1/profile/update to update profile.' });
            }
        }

        // Create new user
        user = await db.user.create({
            data: {
                id: identityPublicKey,
                profilePublicKey,
                profileKeySignature: profileKeySignatureBuffer,
                encryptedProfile: encryptedProfileBuffer,
                profileUpdatedAt: new Date(),
            },
        });

        // Generate token pair (access + refresh)
        const tokens = await generateToken(identityPublicKey);

        return reply.send({
            success: true,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id,
                createdAt: user.createdAt.getTime(),
            },
        });
    });

    // Login (get JWT)
    app.post('/v1/auth/login', {
        schema: {
            body: LoginSchema,
        },
    }, async (request, reply) => {
        const { identityPublicKey, timestamp, signature } = request.body;

        // Validate public key format
        if (!isValidPublicKey(identityPublicKey)) {
            return reply.status(400).send({ error: 'Invalid identity public key format' });
        }

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            return reply.status(400).send({ error: 'Request timestamp too old' });
        }

        // Verify signature
        const message = `${identityPublicKey}:${timestamp}`;
        if (!verifySignature(message, signature, identityPublicKey)) {
            return reply.status(400).send({ error: 'Invalid signature' });
        }

        // Check if user exists
        const user = await db.user.findUnique({
            where: { id: identityPublicKey },
        });

        if (!user) {
            return reply.status(404).send({ error: 'User not found' });
        }

        // Generate token pair (access + refresh)
        const tokens = await generateToken(identityPublicKey);

        return reply.send({
            success: true,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id,
                createdAt: user.createdAt.getTime(),
            },
        });
    });

    // Refresh access token using refresh token
    app.post('/v1/auth/refresh', {
        schema: {
            body: RefreshSchema,
        },
    }, async (request, reply) => {
        const { refreshToken } = request.body;

        // Attempt to refresh the access token
        const newAccessToken = await refreshAccessToken(refreshToken);

        if (!newAccessToken) {
            return reply.status(401).send({ error: 'Invalid or expired refresh token' });
        }

        return reply.send({
            success: true,
            accessToken: newAccessToken,
        });
    });
}
