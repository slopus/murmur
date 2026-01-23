import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { isValidPublicKey, verifySignature } from '@/utils/crypto';
import { generateToken } from '@/utils/jwt';

const RegisterSchema = z.object({
    identityPublicKey: z.string(),
    profilePublicKey: z.string(),
    profileKeySignature: z.string(),
    encryptedProfile: z.any(),
    timestamp: z.number(),
    signature: z.string(), // Signature of the entire request by identity key
});

const LoginSchema = z.object({
    identityPublicKey: z.string(),
    timestamp: z.number(),
    signature: z.string(), // Signature of timestamp by identity key
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

        // Check if user already exists
        const existingUser = await db.user.findUnique({
            where: { id: identityPublicKey },
        });

        if (existingUser) {
            return reply.status(409).send({ error: 'User already registered' });
        }

        // Create user
        const user = await db.user.create({
            data: {
                id: identityPublicKey,
                profilePublicKey,
                profileKeySignature,
                encryptedProfile,
                profileUpdatedAt: new Date(),
            },
        });

        // Generate JWT (privacy-kit handles refresh tokens automatically)
        const token = await generateToken(identityPublicKey);

        return reply.send({
            success: true,
            token,
            user: {
                id: user.id,
                createdAt: user.createdAt,
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

        // Generate JWT (privacy-kit handles refresh tokens automatically)
        const token = await generateToken(identityPublicKey);

        return reply.send({
            success: true,
            token,
            user: {
                id: user.id,
                createdAt: user.createdAt,
            },
        });
    });
}
