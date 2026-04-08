import { z } from 'zod';
import type { Fastify } from '@/types';
import { db } from '@/db';
import { getAuthUserId } from '@/api/auth';
import { normalizePublicKey, publicKeyToExternal, verifySignature } from '@/utils/crypto';
import { events } from '@/events';
import { rateLimitConfigs } from '@/api/rateLimit';
import { validateFeedItemData, validateFeedKeyData, validateFeedMetadata } from '@/api/validation';

async function validateCuid(id: string): Promise<boolean> {
    const { isCuid } = await import('@paralleldrive/cuid2');
    return isCuid(id);
}

const CreateFeedSchema = z.object({
    feedId: z.string(),
    metadata: z.string(),
});

const UpdateFeedSchema = z.object({
    metadata: z.string(),
});

const FeedMemberSchema = z.object({
    memberId: z.string(),
    encryptedKey: z.string(),
});

const AddMembersSchema = z.object({
    epoch: z.number().int().min(0),
    members: z.array(FeedMemberSchema).min(1).max(200),
});

const RemoveMembersSchema = z.object({
    memberIds: z.array(z.string()).min(1).max(200),
});

const RotateKeysSchema = z.object({
    epoch: z.number().int().min(0),
    members: z.array(FeedMemberSchema).min(1).max(200),
});

const PostFeedItemSchema = z.object({
    itemId: z.string(),
    epoch: z.number().int().min(0),
    blob: z.string(),
    signature: z.string(),
});

const FeedParamsSchema = z.object({
    feedId: z.string(),
});

const FeedItemParamsSchema = z.object({
    feedId: z.string(),
    itemId: z.string(),
});

const FeedListQuerySchema = z.object({
    limit: z.string().optional().transform(value => {
        const parsed = value ? Number.parseInt(value, 10) : 50;
        return Math.min(Number.isFinite(parsed) ? parsed : 50, 100);
    }),
    cursor: z.string().optional(),
});

function encodeCursor(date: Date): string {
    return Buffer.from(date.getTime().toString(), 'utf-8').toString('base64');
}

function decodeCursor(cursor?: string): Date | undefined {
    if (!cursor) {
        return undefined;
    }
    const raw = Buffer.from(cursor, 'base64').toString('utf-8');
    const timestamp = Number.parseInt(raw, 10);
    if (!Number.isFinite(timestamp)) {
        throw new Error('Invalid cursor');
    }
    return new Date(timestamp);
}

async function ensureFeedOwner(feedId: string, ownerId: string) {
    const feed = await db.feed.findUnique({
        where: { id: feedId },
        select: {
            id: true,
            ownerId: true,
            currentEpoch: true,
        },
    });

    if (!feed) {
        return { ok: false as const, status: 404 as const, error: 'Feed not found' };
    }
    if (feed.ownerId !== ownerId) {
        return { ok: false as const, status: 403 as const, error: 'Not authorized for this feed' };
    }

    return { ok: true as const, feed };
}

async function canReadFeed(feedId: string, userId: string) {
    const feed = await db.feed.findUnique({
        where: { id: feedId },
        select: {
            id: true,
            ownerId: true,
            currentEpoch: true,
            members: {
                where: { memberId: userId },
                take: 1,
                select: { id: true },
            },
        },
    });

    if (!feed) {
        return { ok: false as const, status: 404 as const, error: 'Feed not found' };
    }
    if (feed.ownerId !== userId && feed.members.length === 0) {
        return { ok: false as const, status: 403 as const, error: 'Not authorized for this feed' };
    }

    return { ok: true as const, feed };
}

function makeSignedPayload(blob: Buffer, itemId: string): Uint8Array {
    const itemIdBytes = new TextEncoder().encode(itemId);
    const message = new Uint8Array(blob.length + itemIdBytes.length);
    message.set(blob, 0);
    message.set(itemIdBytes, blob.length);
    return message;
}

export async function feedRoutes(app: Fastify) {
    app.post('/v1/feeds/create', {
        schema: { body: CreateFeedSchema },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId, metadata } = request.body;

        validateFeedMetadata(metadata);
        if (!await validateCuid(feedId)) {
            return reply.status(400).send({ error: 'Invalid feed ID format (must be cuid2)' });
        }

        const existing = await db.feed.findUnique({ where: { id: feedId }, select: { id: true } });
        if (existing) {
            return reply.status(409).send({ error: 'Feed ID already exists' });
        }

        const feed = await db.feed.create({
            data: {
                id: feedId,
                ownerId,
                metadata: Buffer.from(metadata, 'base64'),
                currentEpoch: 0,
            },
        });

        return reply.send({
            feedId: feed.id,
            createdAt: feed.createdAt.getTime(),
        });
    });

    app.post('/v1/feeds/:feedId/update', {
        schema: {
            params: FeedParamsSchema,
            body: UpdateFeedSchema,
        },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId } = request.params;
        const { metadata } = request.body;

        validateFeedMetadata(metadata);

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }

        const feed = await db.feed.update({
            where: { id: feedId },
            data: { metadata: Buffer.from(metadata, 'base64') },
        });

        return reply.send({
            feedId: feed.id,
            updatedAt: feed.updatedAt.getTime(),
        });
    });

    app.delete('/v1/feeds/:feedId', {
        schema: { params: FeedParamsSchema },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId } = request.params;

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }

        await db.feed.delete({ where: { id: feedId } });
        return reply.send({ success: true });
    });

    app.get('/v1/feeds/owned', {
        config: { rateLimit: rateLimitConfigs.feedRead },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const feeds = await db.feed.findMany({
            where: { ownerId },
            orderBy: { updatedAt: 'desc' },
            select: {
                id: true,
                metadata: true,
                currentEpoch: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        return reply.send({
            feeds: feeds.map(feed => ({
                feedId: feed.id,
                metadata: Buffer.from(feed.metadata).toString('base64'),
                epoch: feed.currentEpoch,
                createdAt: feed.createdAt.getTime(),
                updatedAt: feed.updatedAt.getTime(),
            })),
        });
    });

    app.get('/v1/feeds/following', {
        config: { rateLimit: rateLimitConfigs.feedRead },
    }, async (request, reply) => {
        const memberId = getAuthUserId(request);
        const memberships = await db.feedMember.findMany({
            where: { memberId },
            distinct: ['feedId'],
            select: {
                feedId: true,
                feed: {
                    select: {
                        ownerId: true,
                        currentEpoch: true,
                    },
                },
            },
        });

        return reply.send({
            feeds: memberships.map(entry => ({
                feedId: entry.feedId,
                ownerId: publicKeyToExternal(entry.feed.ownerId),
                epoch: entry.feed.currentEpoch,
            })),
        });
    });

    app.get('/v1/feeds/keys', {
        config: { rateLimit: rateLimitConfigs.feedRead },
    }, async (request, reply) => {
        const memberId = getAuthUserId(request);
        const rows = await db.feedMember.findMany({
            where: { memberId },
            orderBy: [
                { feedId: 'asc' },
                { epoch: 'asc' },
            ],
            select: {
                feedId: true,
                epoch: true,
                encryptedKey: true,
            },
        });

        return reply.send({
            keys: rows.map(row => ({
                feedId: row.feedId,
                epoch: row.epoch,
                encryptedKey: Buffer.from(row.encryptedKey).toString('base64'),
            })),
        });
    });

    app.post('/v1/feeds/:feedId/members/add', {
        schema: {
            params: FeedParamsSchema,
            body: AddMembersSchema,
        },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId } = request.params;
        const { epoch, members } = request.body;

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }
        const ownedFeed = ownership.feed;
        if (epoch !== ownedFeed.currentEpoch) {
            return reply.status(400).send({ error: `Epoch mismatch. Current epoch is ${ownedFeed.currentEpoch}` });
        }

        const normalizedMembers: Array<{ memberId: string; encryptedKey: string }> = [];
        try {
            for (const member of members) {
                validateFeedKeyData(member.encryptedKey);
                normalizedMembers.push({
                    memberId: normalizePublicKey(member.memberId),
                    encryptedKey: member.encryptedKey,
                });
            }
        } catch (error: any) {
            return reply.status(400).send({ error: error.message ?? 'Invalid member payload' });
        }

        const uniqueIds = Array.from(new Set(normalizedMembers.map(member => member.memberId)));
        const existingUsers = await db.user.findMany({
            where: { id: { in: uniqueIds } },
            select: { id: true },
        });
        if (existingUsers.length !== uniqueIds.length) {
            return reply.status(404).send({ error: 'One or more feed members were not found' });
        }

        const created = await db.feedMember.createMany({
            data: normalizedMembers.map(member => ({
                feedId,
                memberId: member.memberId,
                epoch,
                encryptedKey: Buffer.from(member.encryptedKey, 'base64'),
            })),
            skipDuplicates: true,
        });

        return reply.send({ added: created.count });
    });

    app.post('/v1/feeds/:feedId/members/remove', {
        schema: {
            params: FeedParamsSchema,
            body: RemoveMembersSchema,
        },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId } = request.params;
        const { memberIds } = request.body;

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }

        let normalizedMemberIds: string[] = [];
        try {
            normalizedMemberIds = memberIds.map(memberId => normalizePublicKey(memberId));
        } catch {
            return reply.status(400).send({ error: 'Invalid member public key format' });
        }

        const result = await db.feedMember.deleteMany({
            where: {
                feedId,
                memberId: { in: normalizedMemberIds },
            },
        });

        return reply.send({ removed: result.count });
    });

    app.post('/v1/feeds/:feedId/keys/rotate', {
        schema: {
            params: FeedParamsSchema,
            body: RotateKeysSchema,
        },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId } = request.params;
        const { epoch, members } = request.body;

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }
        const ownedFeed = ownership.feed;
        if (epoch !== ownedFeed.currentEpoch + 1) {
            return reply.status(400).send({ error: `Epoch must advance to ${ownedFeed.currentEpoch + 1}` });
        }

        const normalizedMembers: Array<{ memberId: string; encryptedKey: string }> = [];
        try {
            for (const member of members) {
                validateFeedKeyData(member.encryptedKey);
                normalizedMembers.push({
                    memberId: normalizePublicKey(member.memberId),
                    encryptedKey: member.encryptedKey,
                });
            }
        } catch (error: any) {
            return reply.status(400).send({ error: error.message ?? 'Invalid member payload' });
        }

        const existingMembers = await db.feedMember.findMany({
            where: { feedId },
            distinct: ['memberId'],
            select: { memberId: true },
        });
        const existingSet = new Set(existingMembers.map(member => member.memberId));
        const providedSet = new Set(normalizedMembers.map(member => member.memberId));

        if (existingSet.size !== providedSet.size || [...existingSet].some(memberId => !providedSet.has(memberId))) {
            return reply.status(400).send({ error: 'Rotation members must match the current feed membership' });
        }

        await db.$transaction([
            db.feed.update({
                where: { id: feedId },
                data: { currentEpoch: epoch },
            }),
            db.feedMember.createMany({
                data: normalizedMembers.map(member => ({
                    feedId,
                    memberId: member.memberId,
                    epoch,
                    encryptedKey: Buffer.from(member.encryptedKey, 'base64'),
                })),
                skipDuplicates: false,
            }),
        ]);

        return reply.send({ epoch });
    });

    app.post('/v1/feeds/:feedId/items/post', {
        schema: {
            params: FeedParamsSchema,
            body: PostFeedItemSchema,
        },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const authorId = getAuthUserId(request);
        const { feedId } = request.params;
        const { itemId, epoch, blob, signature } = request.body;

        validateFeedItemData({ itemId, blob, signature });
        if (!await validateCuid(itemId)) {
            return reply.status(400).send({ error: 'Invalid item ID format (must be cuid2)' });
        }

        const ownership = await ensureFeedOwner(feedId, authorId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }
        const ownedFeed = ownership.feed;
        if (epoch !== ownedFeed.currentEpoch) {
            return reply.status(400).send({ error: `Epoch mismatch. Current epoch is ${ownedFeed.currentEpoch}` });
        }

        const existing = await db.feedItem.findUnique({ where: { id: itemId }, select: { id: true } });
        if (existing) {
            return reply.status(409).send({ error: 'Feed item ID already exists' });
        }

        const blobBuffer = Buffer.from(blob, 'base64');
        const signedPayload = makeSignedPayload(blobBuffer, itemId);
        if (!verifySignature(signedPayload, signature, authorId)) {
            return reply.status(400).send({ error: 'Invalid feed item signature' });
        }

        const item = await db.feedItem.create({
            data: {
                id: itemId,
                feedId,
                authorId,
                epoch,
                blob: blobBuffer,
                signature: Buffer.from(signature, 'base64'),
            },
        });

        const recipients = await db.feedMember.findMany({
            where: { feedId },
            distinct: ['memberId'],
            select: { memberId: true },
        });
        const notified = new Set<string>([authorId]);
        for (const recipient of recipients) {
            notified.add(recipient.memberId);
        }
        await Promise.all([...notified].map(userId => events.publishUser(userId, {
            type: 'feed:new_item',
            feedId,
            itemId,
        })));

        return reply.send({
            itemId: item.id,
            createdAt: item.createdAt.getTime(),
        });
    });

    app.delete('/v1/feeds/:feedId/items/:itemId', {
        schema: { params: FeedItemParamsSchema },
        config: { rateLimit: rateLimitConfigs.feedWrite },
    }, async (request, reply) => {
        const ownerId = getAuthUserId(request);
        const { feedId, itemId } = request.params;

        const ownership = await ensureFeedOwner(feedId, ownerId);
        if (!ownership.ok) {
            return reply.status(ownership.status).send({ error: ownership.error });
        }

        const result = await db.feedItem.deleteMany({
            where: {
                id: itemId,
                feedId,
            },
        });
        if (result.count === 0) {
            return reply.status(404).send({ error: 'Feed item not found' });
        }

        return reply.send({ success: true });
    });

    app.get('/v1/feeds/timeline', {
        schema: { querystring: FeedListQuerySchema },
        config: { rateLimit: rateLimitConfigs.feedRead },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        let cursorDate: Date | undefined;
        try {
            cursorDate = decodeCursor(request.query.cursor);
        } catch (error: any) {
            return reply.status(400).send({ error: error.message ?? 'Invalid cursor' });
        }

        const items = await db.feedItem.findMany({
            where: {
                ...(cursorDate ? { createdAt: { lt: cursorDate } } : {}),
                feed: {
                    OR: [
                        { ownerId: userId },
                        { members: { some: { memberId: userId } } },
                    ],
                },
            },
            orderBy: [
                { createdAt: 'desc' },
                { id: 'desc' },
            ],
            take: request.query.limit + 1,
            select: {
                id: true,
                feedId: true,
                authorId: true,
                epoch: true,
                blob: true,
                signature: true,
                createdAt: true,
            },
        });

        const hasMore = items.length > request.query.limit;
        const page = hasMore ? items.slice(0, request.query.limit) : items;
        const nextCursor = hasMore && page.length > 0 ? encodeCursor(page[page.length - 1].createdAt) : null;

        return reply.send({
            items: page.map(item => ({
                feedId: item.feedId,
                itemId: item.id,
                authorId: publicKeyToExternal(item.authorId),
                epoch: item.epoch,
                blob: Buffer.from(item.blob).toString('base64'),
                signature: Buffer.from(item.signature).toString('base64'),
                createdAt: item.createdAt.getTime(),
            })),
            nextCursor,
            hasMore,
        });
    });

    app.get('/v1/feeds/:feedId/items', {
        schema: {
            params: FeedParamsSchema,
            querystring: FeedListQuerySchema,
        },
        config: { rateLimit: rateLimitConfigs.feedRead },
    }, async (request, reply) => {
        const userId = getAuthUserId(request);
        const { feedId } = request.params;

        const readable = await canReadFeed(feedId, userId);
        if (!readable.ok) {
            return reply.status(readable.status).send({ error: readable.error });
        }

        let cursorDate: Date | undefined;
        try {
            cursorDate = decodeCursor(request.query.cursor);
        } catch (error: any) {
            return reply.status(400).send({ error: error.message ?? 'Invalid cursor' });
        }

        const items = await db.feedItem.findMany({
            where: {
                feedId,
                ...(cursorDate ? { createdAt: { lt: cursorDate } } : {}),
            },
            orderBy: [
                { createdAt: 'desc' },
                { id: 'desc' },
            ],
            take: request.query.limit + 1,
            select: {
                id: true,
                feedId: true,
                authorId: true,
                epoch: true,
                blob: true,
                signature: true,
                createdAt: true,
            },
        });

        const hasMore = items.length > request.query.limit;
        const page = hasMore ? items.slice(0, request.query.limit) : items;
        const nextCursor = hasMore && page.length > 0 ? encodeCursor(page[page.length - 1].createdAt) : null;

        return reply.send({
            items: page.map(item => ({
                feedId: item.feedId,
                itemId: item.id,
                authorId: publicKeyToExternal(item.authorId),
                epoch: item.epoch,
                blob: Buffer.from(item.blob).toString('base64'),
                signature: Buffer.from(item.signature).toString('base64'),
                createdAt: item.createdAt.getTime(),
            })),
            nextCursor,
            hasMore,
        });
    });
}
