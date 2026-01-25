import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { isValidPublicKey, normalizePublicKey, publicKeyToExternal, verifySignature } from '@/utils/crypto';
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

const DeleteAccountSchema = z.object({
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
            id: publicKeyToExternal(user.id),
            profilePublicKey: publicKeyToExternal(user.profilePublicKey),
            profileKeySignature: Buffer.from(user.profileKeySignature).toString('base64'),
            encryptedProfile: Buffer.from(user.encryptedProfile).toString('base64'),
            profileUpdatedAt: user.profileUpdatedAt.getTime(),
            createdAt: user.createdAt.getTime(),
        });
    });

    // Delete own account
    app.post('/v1/account/delete', {
        schema: {
            body: DeleteAccountSchema,
        },
        config: {
            rateLimit: rateLimitConfigs.profile,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { timestamp, signature } = request.body;

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            return reply.status(400).send({ error: 'Request timestamp too old' });
        }

        // Verify signature of the request
        const message = JSON.stringify({
            timestamp,
        });

        if (!verifySignature(message, signature, userId)) {
            return reply.status(400).send({ error: 'Invalid request signature' });
        }

        try {
            await db.user.delete({
                where: { id: userId },
            });
        } catch (error: any) {
            return reply.status(404).send({ error: 'User not found' });
        }

        return reply.send({ success: true });
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

        let normalizedProfilePublicKey: string;
        // Validate profile public key format
        if (!isValidPublicKey(profilePublicKey)) {
            profileUpdatesTotal.inc({ status: 'invalid_key' });
            return reply.status(400).send({ error: 'Invalid profile public key format' });
        }
        try {
            normalizedProfilePublicKey = normalizePublicKey(profilePublicKey);
        } catch (error: any) {
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
        const profilePublicKeyBuffer = Buffer.from(normalizedProfilePublicKey, 'base64');
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
                profilePublicKey: normalizedProfilePublicKey,
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
                profilePublicKey: publicKeyToExternal(user.profilePublicKey),
                profileUpdatedAt: user.profileUpdatedAt.getTime(),
            },
        });
    });
}

/**
 * Public profile routes (no authentication)
 */
export async function publicProfileRoutes(app: Fastify) {
    // Get another user's profile by profile public key
    app.get('/v1/profile/:profilePublicKey', {
        schema: {
            params: z.object({
                profilePublicKey: z.string(),
            }),
        },
        config: {
            rateLimit: rateLimitConfigs.profile,
        },
    }, async (request, reply) => {
        const { profilePublicKey } = request.params;
        let normalizedProfilePublicKey: string;
        try {
            normalizedProfilePublicKey = normalizePublicKey(profilePublicKey);
        } catch (error: any) {
            return reply.status(400).send({ error: 'Invalid profile public key format' });
        }

        const user = await db.user.findUnique({
            where: { profilePublicKey: normalizedProfilePublicKey },
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
            id: publicKeyToExternal(user.id),
            profilePublicKey: publicKeyToExternal(user.profilePublicKey),
            profileKeySignature: Buffer.from(user.profileKeySignature).toString('base64'),
            encryptedProfile: Buffer.from(user.encryptedProfile).toString('base64'),
            profileUpdatedAt: user.profileUpdatedAt.getTime(),
        });
    });
}
