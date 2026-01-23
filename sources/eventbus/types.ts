import { z } from 'zod';

/**
 * Event types for the Murmur server
 */

// User-scoped events (with sequence numbers)
export const UserEventSchema = z.discriminatedUnion('type', [
    z.object({
        type: z.literal('message:new'),
        messageId: z.string(),
    }),
    z.object({
        type: z.literal('profile:updated'),
    }),
]);

export type UserEvent = z.infer<typeof UserEventSchema>;

// Global events (no sequence numbers)
export const GlobalEventSchema = z.discriminatedUnion('type', [
    z.object({
        type: z.literal('system:health'),
        status: z.string(),
    }),
]);

export type GlobalEvent = z.infer<typeof GlobalEventSchema>;

/**
 * Event envelopes for transport
 */

export const UserEnvelopeSchema = z.object({
    type: z.literal('user'),
    timestamp: z.number(),
    userId: z.string(),
    seqno: z.number(),
    event: UserEventSchema,
});

export type UserEnvelope = z.infer<typeof UserEnvelopeSchema>;

export const GlobalEnvelopeSchema = z.object({
    type: z.literal('global'),
    timestamp: z.number(),
    event: GlobalEventSchema,
});

export type GlobalEnvelope = z.infer<typeof GlobalEnvelopeSchema>;

export const EventEnvelopeSchema = z.union([
    UserEnvelopeSchema,
    GlobalEnvelopeSchema,
]);

export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

/**
 * Type guards
 */

export function isUserEnvelope(envelope: EventEnvelope): envelope is UserEnvelope {
    return envelope.type === 'user';
}

export function isGlobalEnvelope(envelope: EventEnvelope): envelope is GlobalEnvelope {
    return envelope.type === 'global';
}
