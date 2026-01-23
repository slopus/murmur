import { z } from 'zod';

/**
 * Event types for the Murmur server
 * Now using Redis Streams with message IDs instead of sequence numbers
 */

// Message events (identified by cuid2 message ID)
export const MessageEventSchema = z.object({
    type: z.literal('message:new'),
    messageId: z.string(), // cuid2 provided by sender
});

export type MessageEvent = z.infer<typeof MessageEventSchema>;

// User events (profile updates, etc.)
export const UserEventSchema = z.discriminatedUnion('type', [
    MessageEventSchema,
    z.object({
        type: z.literal('profile:updated'),
        userId: z.string(),
    }),
]);

export type UserEvent = z.infer<typeof UserEventSchema>;

// Global events
export const GlobalEventSchema = z.discriminatedUnion('type', [
    z.object({
        type: z.literal('system:health'),
        status: z.string(),
    }),
]);

export type GlobalEvent = z.infer<typeof GlobalEventSchema>;

/**
 * Event envelopes for Redis Streams transport
 * No sequence numbers - messages are identified by their cuid2 message ID
 */

export const MessageEnvelopeSchema = z.object({
    type: z.literal('message'),
    timestamp: z.number(),
    channel: z.string(), // e.g., "user:userId" for future sharding
    event: UserEventSchema,
});

export type MessageEnvelope = z.infer<typeof MessageEnvelopeSchema>;

export const GlobalEnvelopeSchema = z.object({
    type: z.literal('global'),
    timestamp: z.number(),
    channel: z.string(), // e.g., "global" or "system"
    event: GlobalEventSchema,
});

export type GlobalEnvelope = z.infer<typeof GlobalEnvelopeSchema>;

export const EventEnvelopeSchema = z.union([
    MessageEnvelopeSchema,
    GlobalEnvelopeSchema,
]);

export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

/**
 * Type guards
 */

export function isMessageEnvelope(envelope: EventEnvelope): envelope is MessageEnvelope {
    return envelope.type === 'message';
}

export function isGlobalEnvelope(envelope: EventEnvelope): envelope is GlobalEnvelope {
    return envelope.type === 'global';
}
