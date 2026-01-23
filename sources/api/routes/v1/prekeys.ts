import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { verifySignature } from '@/utils/crypto';

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
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { preKeys, timestamp, signature } = request.body;

        // Verify timestamp is recent (within 5 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
            return reply.status(400).send({ error: 'Request timestamp too old' });
        }

        // Verify signature of the entire request
        const message = JSON.stringify({
            preKeys,
            timestamp,
        });

        if (!verifySignature(message, signature, userId)) {
            return reply.status(400).send({ error: 'Invalid request signature' });
        }

        // Verify each prekey signature
        for (const preKey of preKeys) {
            if (!verifySignature(preKey.publicKey, preKey.signature, userId)) {
                return reply.status(400).send({
                    error: `Invalid signature for prekey ${preKey.publicKey.substring(0, 8)}...`
                });
            }
        }

        // Insert all prekeys
        const created = await db.preKey.createMany({
            data: preKeys.map(pk => ({
                ownerId: userId,
                publicKey: pk.publicKey,
                signature: Buffer.from(pk.signature, 'base64'),
                oneTime: pk.oneTime,
            })),
        });

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
    }, async (request, reply) => {
        const requesterId = getAuthUserId(request);
        const { identityPublicKey } = request.params;

        // Get user's signed prekey (not allocated yet, or already allocated to requester)
        const signedPreKey = await db.preKey.findFirst({
            where: {
                ownerId: identityPublicKey,
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
        }

        // Get one-time prekey (not yet allocated)
        const oneTimePreKey = await db.preKey.findFirst({
            where: {
                ownerId: identityPublicKey,
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
        }

        return reply.send({
            identityKey: identityPublicKey,
            signedPreKey: {
                publicKey: signedPreKey.publicKey,
                signature: Buffer.from(signedPreKey.signature).toString('base64'),
                createdAt: signedPreKey.createdAt.getTime(),
            },
            oneTimePreKey: oneTimePreKey ? {
                publicKey: oneTimePreKey.publicKey,
                signature: Buffer.from(oneTimePreKey.signature).toString('base64'),
            } : null,
        });
    });

    // Get count of remaining unallocated one-time prekeys
    app.get('/v1/prekeys/onetime/count', async (request, reply) => {
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
