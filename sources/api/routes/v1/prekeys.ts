import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { normalizePublicKey, publicKeyToExternal, verifySignature } from '@/utils/crypto';
import { rateLimitConfigs } from '@/api/rateLimit';
import { preKeysUploadedTotal, preKeysAllocatedTotal } from '@/metrics/prometheus';
import { validatePreKeyData } from '@/api/validation';

const UploadPreKeysSchema = z.object({
    preKeys: z.array(z.object({
        publicKey: z.string(), // Base64 NaCl public key
        signature: z.string(), // Base64 signature by identity key
        oneTime: z.boolean(), // true = one-time prekey, false = signed prekey
    })).min(1).max(100), // Upload 1-100 prekeys at once
    timestamp: z.number(),
    signature: z.string(), // Signature of entire request
});

/**
 * PreKey routes (authenticated)
 *
 * Signal-style prekey management for session establishment:
 * - Signed PreKey: Medium-term key signed by identity, replaced periodically (oneTime = false)
 * - One-Time PreKeys: Ephemeral keys allocated once per session (oneTime = true)
 * - PreKeys are permanently assigned to users who claim them
 */
export async function preKeyRoutes(app: Fastify) {
    // Upload prekeys (signed or one-time)
    app.post('/v1/prekeys/upload', {
        schema: {
            body: UploadPreKeysSchema,
        },
        config: {
            rateLimit: rateLimitConfigs.preKey,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { preKeys, timestamp, signature } = request.body;
        let normalizedPreKeys: Array<{ publicKey: string; signature: string; oneTime: boolean }> = [];

        // Validate size limits for each prekey
        try {
            for (const preKey of preKeys) {
                validatePreKeyData(preKey);
            }
        } catch (error: any) {
            preKeysUploadedTotal.inc({ status: 'size_limit_exceeded' });
            return reply.status(400).send({ error: error.message });
        }

        try {
            normalizedPreKeys = preKeys.map(preKey => ({
                ...preKey,
                publicKey: normalizePublicKey(preKey.publicKey),
            }));
        } catch (error: any) {
            preKeysUploadedTotal.inc({ status: 'invalid_key' });
            return reply.status(400).send({ error: 'Invalid prekey public key format' });
        }

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            preKeysUploadedTotal.inc({ status: 'timestamp_expired' });
            return reply.status(400).send({ error: 'Request timestamp too old' });
        }

        // Verify signature of the entire request
        const message = JSON.stringify({
            preKeys,
            timestamp,
        });

        if (!verifySignature(message, signature, userId)) {
            preKeysUploadedTotal.inc({ status: 'invalid_signature' });
            return reply.status(400).send({ error: 'Invalid request signature' });
        }

        // Verify each prekey signature
        for (const preKey of normalizedPreKeys) {
            // Decode public key to bytes for signature verification
            const preKeyPublicKeyBuffer = Buffer.from(preKey.publicKey, 'base64');
            if (!verifySignature(preKeyPublicKeyBuffer, preKey.signature, userId)) {
                preKeysUploadedTotal.inc({ status: 'invalid_prekey_signature' });
                return reply.status(400).send({
                    error: `Invalid signature for prekey ${preKey.publicKey.substring(0, 8)}...`
                });
            }
        }

        // Insert all prekeys
        const created = await db.preKey.createMany({
            data: normalizedPreKeys.map(pk => ({
                ownerId: userId,
                publicKey: pk.publicKey,
                signature: Buffer.from(pk.signature, 'base64'),
                oneTime: pk.oneTime,
            })),
        });

        preKeysUploadedTotal.inc({ status: 'success' }, created.count);

        return reply.send({
            success: true,
            uploaded: created.count,
        });
    });

    // Get prekey bundle for a user (for initiating encrypted session)
    app.get('/v1/prekeys/:identityPublicKey', {
        schema: {
            params: z.object({
                identityPublicKey: z.string(),
            }),
        },
        config: {
            rateLimit: rateLimitConfigs.preKey,
        },
    }, async (request, reply) => {
        const requesterId = getAuthUserId(request);
        const { identityPublicKey } = request.params;
        let normalizedIdentityPublicKey: string;
        try {
            normalizedIdentityPublicKey = normalizePublicKey(identityPublicKey);
        } catch (error: any) {
            return reply.status(400).send({ error: 'Invalid identity public key format' });
        }

        // Get user's signed prekey (not allocated yet, or already allocated to requester)
        const signedPreKey = await db.preKey.findFirst({
            where: {
                ownerId: normalizedIdentityPublicKey,
                oneTime: false,
                OR: [
                    { allocatedTo: null }, // Not yet allocated
                    { allocatedTo: requesterId }, // Already allocated to requester
                ],
            },
            orderBy: { createdAt: 'desc' }, // Use newest signed prekey
        });

        if (!signedPreKey) {
            return reply.status(404).send({ error: 'User has not uploaded signed prekeys' });
        }

        // Allocate signed prekey to requester if not already allocated
        if (signedPreKey.allocatedTo !== requesterId) {
            await db.preKey.update({
                where: { id: signedPreKey.id },
                data: {
                    allocatedTo: requesterId,
                    allocatedAt: new Date(),
                },
            });
            preKeysAllocatedTotal.inc({ type: 'signed' });
        }

        // Get one-time prekey (not yet allocated)
        const oneTimePreKey = await db.preKey.findFirst({
            where: {
                ownerId: normalizedIdentityPublicKey,
                oneTime: true,
                allocatedTo: null, // Only unallocated one-time prekeys
            },
            orderBy: { createdAt: 'asc' }, // Use oldest first (FIFO)
        });

        // Allocate one-time prekey to requester if found
        if (oneTimePreKey) {
            await db.preKey.update({
                where: { id: oneTimePreKey.id },
                data: {
                    allocatedTo: requesterId,
                    allocatedAt: new Date(),
                },
            });
            preKeysAllocatedTotal.inc({ type: 'onetime' });
        }

        return reply.send({
            identityKey: publicKeyToExternal(normalizedIdentityPublicKey),
            signedPreKey: {
                publicKey: publicKeyToExternal(signedPreKey.publicKey),
                signature: Buffer.from(signedPreKey.signature).toString('base64'),
                createdAt: signedPreKey.createdAt.getTime(),
            },
            oneTimePreKey: oneTimePreKey ? {
                publicKey: publicKeyToExternal(oneTimePreKey.publicKey),
                signature: Buffer.from(oneTimePreKey.signature).toString('base64'),
            } : null,
        });
    });

    // Get count of remaining unallocated one-time prekeys
    app.get('/v1/prekeys/onetime/count', {
        config: {
            rateLimit: rateLimitConfigs.preKey,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);

        const count = await db.preKey.count({
            where: {
                ownerId: userId,
                oneTime: true,
                allocatedTo: null, // Only unallocated
            },
        });

        return reply.send({
            count,
        });
    });
}
