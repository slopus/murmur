import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { verifySignature } from '@/utils/crypto';
import { events } from '@/events';
import { sseManager, SSEConnection } from '@/api/sse';

const SendMessageSchema = z.object({
    recipientId: z.string(),
    blob: z.any(), // Encrypted message blob
    signature: z.string(), // Signature of blob by sender's identity key
});

/**
 * Message routes (authenticated)
 */
export async function messageRoutes(app: Fastify) {
    // Send a message
    app.post('/v1/messages/send', {
        schema: {
            body: SendMessageSchema,
        },
    }, async (request, reply) => {
        const senderId = getAuthUserId(request);
        const { recipientId, blob, signature } = request.body;

        // Check if recipient exists
        const recipient = await db.user.findUnique({
            where: { id: recipientId },
        });

        if (!recipient) {
            return reply.status(404).send({ error: 'Recipient not found' });
        }

        // Verify signature (blob signed by sender's identity key)
        const blobString = JSON.stringify(blob);
        if (!verifySignature(blobString, signature, senderId)) {
            return reply.status(400).send({ error: 'Invalid message signature' });
        }

        // Calculate expiration (30 days from now)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        // Create message
        const message = await db.message.create({
            data: {
                senderId,
                recipientId,
                blob,
                signature,
                expiresAt,
            },
        });

        // Publish message event to notify recipient
        await events.publishUser(recipientId, {
            type: 'message:new',
            messageId: message.id,
        });

        // Notify via SSE if recipient is connected
        sseManager.sendToUser(recipientId, 'message', {
            messageId: message.id,
            senderId,
            createdAt: message.createdAt,
        });

        return reply.send({
            success: true,
            message: {
                id: message.id,
                createdAt: message.createdAt,
                expiresAt: message.expiresAt,
            },
        });
    });

    // Get pending messages
    app.get('/v1/messages/inbox', {
        schema: {
            querystring: z.object({
                limit: z.string().optional().transform(val => val ? parseInt(val) : 50),
                offset: z.string().optional().transform(val => val ? parseInt(val) : 0),
            }),
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { limit, offset } = request.query;

        const messages = await db.message.findMany({
            where: {
                recipientId: userId,
                expiresAt: {
                    gt: new Date(), // Only non-expired messages
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
            take: limit,
            skip: offset,
            select: {
                id: true,
                senderId: true,
                blob: true,
                signature: true,
                createdAt: true,
                expiresAt: true,
                deliveredAt: true,
            },
        });

        // Mark undelivered messages as delivered
        const undeliveredIds = messages
            .filter(m => !m.deliveredAt)
            .map(m => m.id);

        if (undeliveredIds.length > 0) {
            await db.message.updateMany({
                where: {
                    id: { in: undeliveredIds },
                },
                data: {
                    deliveredAt: new Date(),
                },
            });
        }

        return reply.send({
            messages,
            total: messages.length,
            limit,
            offset,
        });
    });

    // Get a specific message
    app.get('/v1/messages/:messageId', {
        schema: {
            params: z.object({
                messageId: z.string(),
            }),
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { messageId } = request.params;

        const message = await db.message.findUnique({
            where: { id: messageId },
        });

        if (!message) {
            return reply.status(404).send({ error: 'Message not found' });
        }

        // Ensure user is the recipient
        if (message.recipientId !== userId) {
            return reply.status(403).send({ error: 'Not authorized to view this message' });
        }

        // Mark as delivered if not already
        if (!message.deliveredAt) {
            await db.message.update({
                where: { id: messageId },
                data: { deliveredAt: new Date() },
            });
        }

        return reply.send({ message });
    });

    // Delete a message (recipient only)
    app.delete('/v1/messages/:messageId', {
        schema: {
            params: z.object({
                messageId: z.string(),
            }),
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { messageId } = request.params;

        const message = await db.message.findUnique({
            where: { id: messageId },
        });

        if (!message) {
            return reply.status(404).send({ error: 'Message not found' });
        }

        // Ensure user is the recipient
        if (message.recipientId !== userId) {
            return reply.status(403).send({ error: 'Not authorized to delete this message' });
        }

        await db.message.delete({
            where: { id: messageId },
        });

        return reply.send({ success: true });
    });

    // SSE stream for new messages
    app.get('/v1/messages/stream', async (request, reply) => {
        const userId = getAuthUserId(request);

        const connection = new SSEConnection(reply);
        sseManager.addConnection(userId, connection);

        // Send initial connected event
        connection.send('connected', { userId, timestamp: Date.now() });

        // Send heartbeat every 30 seconds
        const heartbeatInterval = setInterval(() => {
            if (connection.isOpen()) {
                connection.heartbeat();
            } else {
                clearInterval(heartbeatInterval);
            }
        }, 30000);

        // Clean up on disconnect
        request.raw.on('close', () => {
            clearInterval(heartbeatInterval);
            connection.close();
        });
    });
}
