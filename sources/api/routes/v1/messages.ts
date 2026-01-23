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
    blob: z.string(), // Base64-encoded encrypted message blob
    signature: z.string(), // Signature of (blob + messageId) by sender's identity key
});

const AckMessagesSchema = z.object({
    messageIds: z.array(z.string()).min(1).max(100),
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

        // Parse base64 to binary
        const blobBuffer = Buffer.from(blob, 'base64');
        const signatureBuffer = Buffer.from(signature, 'base64');

        // Verify signature (blob + messageId concatenated, signed by sender's identity key)
        const messageToSign = blob + messageId;
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
                blob: blobBuffer,
                signature: signatureBuffer,
                expiresAt,
            },
        });

        // Publish message event to notify recipient
        await events.publishUser(recipientId, {
            type: 'message:new',
            messageId: message.id,
        });

        // Notify via SSE if recipient is connected (send full message)
        sseManager.sendToUser(recipientId, 'message', {
            id: message.id,
            senderId,
            blob: blobBuffer.toString('base64'),
            signature: signatureBuffer.toString('base64'),
            createdAt: message.createdAt.getTime(),
            expiresAt: message.expiresAt.getTime(),
        });

        return reply.send({
            success: true,
            message: {
                id: message.id,
                createdAt: message.createdAt.getTime(),
                expiresAt: message.expiresAt.getTime(),
            },
        });
    });

    // Get pending messages with cursor-based pagination
    app.get('/v1/messages/inbox', {
        schema: {
            querystring: z.object({
                limit: z.string().optional().transform(val => {
                    const parsed = val ? parseInt(val) : 50;
                    return Math.min(parsed, 100); // Cap at 100
                }),
                cursor: z.string().optional(),
            }),
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { limit, cursor } = request.query;

        // Decode cursor (base64-encoded timestamp)
        let cursorDate: Date | undefined;
        if (cursor) {
            try {
                const decodedTimestamp = parseInt(Buffer.from(cursor, 'base64').toString('utf-8'));
                cursorDate = new Date(decodedTimestamp);
            } catch (error) {
                return reply.status(400).send({ error: 'Invalid cursor' });
            }
        }

        // Fetch messages (oldest first)
        const messages = await db.message.findMany({
            where: {
                recipientId: userId,
                expiresAt: {
                    gt: new Date(), // Only non-expired messages
                },
                ...(cursorDate ? {
                    createdAt: {
                        gt: cursorDate, // Messages after cursor
                    },
                } : {}),
            },
            orderBy: {
                createdAt: 'asc', // Oldest first
            },
            take: limit + 1, // Fetch one extra to check if there are more
            select: {
                id: true,
                senderId: true,
                blob: true,
                signature: true,
                createdAt: true,
                expiresAt: true,
            },
        });

        // Check if there are more messages
        const hasMore = messages.length > limit;
        const returnMessages = hasMore ? messages.slice(0, limit) : messages;

        // Generate next cursor from last message
        let nextCursor: string | null = null;
        if (hasMore && returnMessages.length > 0) {
            const lastMessage = returnMessages[returnMessages.length - 1];
            nextCursor = Buffer.from(lastMessage.createdAt.getTime().toString()).toString('base64');
        }

        // Convert to Unix timestamps and encode binary to base64
        const formattedMessages = returnMessages.map(m => ({
            id: m.id,
            senderId: m.senderId,
            blob: m.blob.toString('base64'),
            signature: m.signature.toString('base64'),
            createdAt: m.createdAt.getTime(),
            expiresAt: m.expiresAt.getTime(),
        }));

        return reply.send({
            messages: formattedMessages,
            nextCursor,
            hasMore,
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

    // Acknowledge (delete) messages in batch
    app.post('/v1/messages/ack', {
        schema: {
            body: AckMessagesSchema,
        },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { messageIds } = request.body;

        const failed: Array<{ messageId: string; error: string }> = [];
        let acknowledged = 0;

        // Process each message
        for (const messageId of messageIds) {
            try {
                const message = await db.message.findUnique({
                    where: { id: messageId },
                });

                if (!message) {
                    failed.push({ messageId, error: 'Message not found' });
                    continue;
                }

                if (message.recipientId !== userId) {
                    failed.push({ messageId, error: 'Not authorized' });
                    continue;
                }

                // Delete the message
                await db.message.delete({
                    where: { id: messageId },
                });

                acknowledged++;
            } catch (error) {
                failed.push({ messageId, error: 'Failed to acknowledge' });
            }
        }

        // Return 207 Multi-Status if there are failures, otherwise 200
        const statusCode = failed.length > 0 ? 207 : 200;

        return reply.status(statusCode).send({
            success: true,
            acknowledged,
            failed,
        });
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
