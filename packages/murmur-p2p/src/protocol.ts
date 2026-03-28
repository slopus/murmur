import { z } from 'zod'
import type { DaemonInfo, DiscoveredPeer, StoredMessage } from './types.js'
import { MURMUR_P2P_PROTOCOL } from './utils.js'

const relayNodeSchema = z.object({
    host: z.string().min(1),
    port: z.number().int().positive(),
})

const discoveredPeerSchema = z.object({
    peerId: z.string().min(1),
    relayNodes: z.array(relayNodeSchema),
})

const storedMessageSchema = z.object({
    id: z.string().min(1),
    direction: z.union([z.literal('inbound'), z.literal('outbound')]),
    from: z.string().min(1),
    to: z.string().min(1),
    body: z.string(),
    sentAt: z.string().min(1),
    receivedAt: z.string().min(1),
})

const daemonInfoSchema = z.object({
    peerId: z.string().min(1),
    name: z.string().min(1),
    dataDir: z.string().min(1),
    controlSocketPath: z.string().min(1),
    topic: z.string().min(1),
    bootstrap: z.array(z.string()),
    transportPolicy: z.union([
        z.literal('any'),
        z.literal('direct-only'),
        z.literal('private-only'),
        z.literal('public-only'),
    ]),
})

/**
 * Request sent over the local control socket.
 */
export const controlRequestSchema = z.discriminatedUnion('type', [
    z.object({
        type: z.literal('get_info'),
    }),
    z.object({
        type: z.literal('list_messages'),
    }),
    z.object({
        type: z.literal('list_peers'),
    }),
    z.object({
        type: z.literal('send_message'),
        to: z.string().min(1),
        body: z.string(),
    }),
])

/**
 * Response returned from the local control socket.
 */
export const controlResponseSchema = z.union([
    z.object({
        status: z.literal('ok'),
        type: z.literal('get_info'),
        info: daemonInfoSchema,
    }),
    z.object({
        status: z.literal('ok'),
        type: z.literal('list_messages'),
        messages: z.array(storedMessageSchema),
    }),
    z.object({
        status: z.literal('ok'),
        type: z.literal('list_peers'),
        peers: z.array(discoveredPeerSchema),
    }),
    z.object({
        status: z.literal('ok'),
        type: z.literal('send_message'),
        id: z.string().min(1),
    }),
    z.object({
        status: z.literal('error'),
        message: z.string().min(1),
    }),
])

/**
 * Message transported over the encrypted peer stream.
 */
export const peerEnvelopeSchema = z.discriminatedUnion('type', [
    z.object({
        protocol: z.literal(MURMUR_P2P_PROTOCOL),
        type: z.literal('message'),
        id: z.string().min(1),
        from: z.string().min(1),
        to: z.string().min(1),
        body: z.string(),
        sentAt: z.string().min(1),
    }),
    z.object({
        protocol: z.literal(MURMUR_P2P_PROTOCOL),
        type: z.literal('ack'),
        id: z.string().min(1),
    }),
])

export type ControlRequest = z.infer<typeof controlRequestSchema>
export type ControlResponse = z.infer<typeof controlResponseSchema>
export type PeerEnvelope = z.infer<typeof peerEnvelopeSchema>

/**
 * Serialize a JSON line frame.
 */
export function encodeFrame(value: object): string {
    return `${JSON.stringify(value)}\n`
}

/**
 * Type helper for the daemon info control response.
 */
export function infoResponse(info: DaemonInfo): ControlResponse {
    return {
        status: 'ok',
        type: 'get_info',
        info,
    }
}

/**
 * Type helper for the peer discovery control response.
 */
export function peersResponse(peers: DiscoveredPeer[]): ControlResponse {
    return {
        status: 'ok',
        type: 'list_peers',
        peers,
    }
}

/**
 * Type helper for the message listing control response.
 */
export function messagesResponse(messages: StoredMessage[]): ControlResponse {
    return {
        status: 'ok',
        type: 'list_messages',
        messages,
    }
}
