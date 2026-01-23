import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { verifySignature } from '@/utils/crypto';
import { events } from '@/events';
import { sseManager, SSEConnection } from '@/api/sse';

// Dynamic import for cuid2
async function validateCuid(id: string): Promise<boolean> {
    const { isCuid } = await import('@paralleldrive/cuid2');
    return isCuid(id);
}

const SendMessageSchema = z.object({
    messageId: z.string(), // cuid2 provided by sender
    recipientId: z.string(),
    blob: z.any(), // Encrypted message blob
    signature: z.string(), // Signature of (blob + messageId) by sender's identity key
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
        const { messageId, recipientId, blob, signature } = request.body;

        // Validate message ID is a valid cuid2
        const isValidCuid = await validateCuid(messageId);
        if (!isValidCuid) {
            return reply.status(400).send({ error: 'Invalid message ID format (must be cuid2)' });
        }

        // Check if message ID already exists (repeat protection)
        const existingMessage = await db.message.findUnique({
            where: { id: messageId },
        });

        if (existingMessage) {
            return reply.status(409).send({ error: 'Message ID already exists (duplicate message)' });
        }

        // Check if recipient exists
        const recipient = await db.user.findUnique({
            where: { id: recipientId },
        });

        if (!recipient) {
            return reply.status(404).send({ error: 'Recipient not found' });
        }

        // Verify signature (blob + messageId signed by sender's identity key)
        const messageToSign = JSON.stringify({ blob, messageId });
        if (!verifySignature(messageToSign, signature, senderId)) {
            return reply.status(400).send({ error: 'Invalid message signature' });
        }

        // Calculate expiration (30 days from now)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        // Create message with provided ID
        const message = await db.message.create({
            data: {
                id: messageId,
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

    // Acknowledge a message (mark as delivered and delete from Redis Stream)
    app.post('/v1/messages/:messageId/ack', {
        schema: {
            params: z.object({
                messageId: z.string(),
            }),
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { messageId } = request.params;

        // Verify the message exists and user is the recipient
        const message = await db.message.findUnique({
            where: { id: messageId },
        });

        if (!message) {
            return reply.status(404).send({ error: 'Message not found' });
        }

        if (message.recipientId !== userId) {
            return reply.status(403).send({ error: 'Not authorized to acknowledge this message' });
        }

        // Mark as delivered in database if not already
        if (!message.deliveredAt) {
            await db.message.update({
                where: { id: messageId },
                data: { deliveredAt: new Date() },
            });
        }

        // Acknowledge in Redis Stream (this removes it from the stream)
        await events.acknowledgeMessage(messageId);

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
