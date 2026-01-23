import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { isValidPublicKey, verifySignature } from '@/utils/crypto';
import { events } from '@/events';
import { rateLimitConfigs } from '@/api/rateLimit';
import { profileUpdatesTotal } from '@/metrics/prometheus';
import { validateProfileData } from '@/api/validation';

const UpdateProfileSchema = z.object({
    profilePublicKey: z.string(),
    profileKeySignature: z.string(),
    encryptedProfile: z.string(), // Base64-encoded encrypted profile blob
    timestamp: z.number(),
    signature: z.string(),
});

/**
 * Profile routes (authenticated)
 */
export async function profileRoutes(app: Fastify) {
    // Get own profile
    app.get('/v1/profile/me', {
        config: {
            rateLimit: rateLimitConfigs.profile,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);

        const user = await db.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                createdAt: true,
                profilePublicKey: true,
                profileKeySignature: true,
                encryptedProfile: true,
                profileUpdatedAt: true,
            },
        });

        if (!user) {
            return reply.status(404).send({ error: 'User not found' });
        }

        return reply.send({
            id: user.id,
            profilePublicKey: user.profilePublicKey,
            profileKeySignature: Buffer.from(user.profileKeySignature).toString('base64'),
            encryptedProfile: Buffer.from(user.encryptedProfile).toString('base64'),
            profileUpdatedAt: user.profileUpdatedAt.getTime(),
            createdAt: user.createdAt.getTime(),
        });
    });

    // Get another user's profile (requires profile public key)
    app.get('/v1/profile/:identityPublicKey', {
        schema: {
            params: z.object({
                identityPublicKey: z.string(),
            }),
        },
        config: {
            rateLimit: rateLimitConfigs.profile,
        },
    }, async (request, reply) => {
        const { identityPublicKey } = request.params;

        const user = await db.user.findUnique({
            where: { id: identityPublicKey },
            select: {
                id: true,
                profilePublicKey: true,
                profileKeySignature: true,
                encryptedProfile: true,
                profileUpdatedAt: true,
            },
        });

        if (!user) {
            return reply.status(404).send({ error: 'User not found' });
        }

        return reply.send({
            id: user.id,
            profilePublicKey: user.profilePublicKey,
            profileKeySignature: Buffer.from(user.profileKeySignature).toString('base64'),
            encryptedProfile: Buffer.from(user.encryptedProfile).toString('base64'),
            profileUpdatedAt: user.profileUpdatedAt.getTime(),
        });
    });

    // Update own profile
    app.post('/v1/profile/update', {
        schema: {
            body: UpdateProfileSchema,
        },
        config: {
            rateLimit: rateLimitConfigs.profile,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const {
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            timestamp,
            signature,
        } = request.body;

        // Validate size limits
        try {
            validateProfileData({ profilePublicKey, profileKeySignature, encryptedProfile });
        } catch (error: any) {
            profileUpdatesTotal.inc({ status: 'size_limit_exceeded' });
            return reply.status(400).send({ error: error.message });
        }

        // Validate profile public key format
        if (!isValidPublicKey(profilePublicKey)) {
            profileUpdatesTotal.inc({ status: 'invalid_key' });
            return reply.status(400).send({ error: 'Invalid profile public key format' });
        }

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            profileUpdatesTotal.inc({ status: 'timestamp_expired' });
            return reply.status(400).send({ error: 'Request timestamp too old' });
        }

        // Verify signature of the entire request
        const message = JSON.stringify({
            profilePublicKey,
            profileKeySignature,
            encryptedProfile,
            timestamp,
        });

        if (!verifySignature(message, signature, userId)) {
            profileUpdatesTotal.inc({ status: 'invalid_signature' });
            return reply.status(400).send({ error: 'Invalid request signature' });
        }

        // Parse base64 to binary
        const profilePublicKeyBuffer = Buffer.from(profilePublicKey, 'base64');
        const profileKeySignatureBuffer = Buffer.from(profileKeySignature, 'base64');
        const encryptedProfileBuffer = Buffer.from(encryptedProfile, 'base64');

        // Verify profile key signature (profile key bytes signed by identity key)
        if (!verifySignature(profilePublicKeyBuffer, profileKeySignature, userId)) {
            profileUpdatesTotal.inc({ status: 'invalid_profile_signature' });
            return reply.status(400).send({ error: 'Invalid profile key signature' });
        }

        // Update user profile
        const user = await db.user.update({
            where: { id: userId },
            data: {
                profilePublicKey,
                profileKeySignature: profileKeySignatureBuffer,
                encryptedProfile: encryptedProfileBuffer,
                profileUpdatedAt: new Date(),
            },
        });

        profileUpdatesTotal.inc({ status: 'success' });

        // Publish profile update event
        await events.publishUser(userId, {
            type: 'profile:updated',
            userId,
        });

        return reply.send({
            success: true,
            profile: {
                profilePublicKey: user.profilePublicKey,
                profileUpdatedAt: user.profileUpdatedAt.getTime(),
            },
        });
    });
}
