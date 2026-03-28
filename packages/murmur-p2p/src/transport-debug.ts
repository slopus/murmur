import type { DhtSocket } from 'hyperdht'
import type { DiscoveredPeer, RelayNode } from './types.js'

interface RawStreamJson {
    connected?: boolean
    remoteHost?: string
    remotePort?: number
    remoteFamily?: number
    rtt?: number
    cwnd?: number
    inflight?: number
    socket?: {
        address?: {
            host?: string
            family?: number
            port?: number
        }
    } | null
}

interface SecretStreamJson {
    connected?: boolean
    remotePublicKey?: string | null
    rawStream?: RawStreamJson | null
}

export interface TransportSnapshot {
    remotePublicKeyHex: string | null
    remoteHost: string | null
    remotePort: number | null
    remoteFamily: number | null
    localHost: string | null
    localPort: number | null
    localFamily: number | null
    connected: boolean
    rtt: number | null
    cwnd: number | null
    inflight: number | null
}

export type TransportMode = 'direct' | 'relay-assisted' | 'unknown'

/**
 * Safely snapshot low-level HyperDHT socket metadata for logging.
 */
export function snapshotTransport(socket: DhtSocket): TransportSnapshot {
    const json = socket.toJSON() as SecretStreamJson
    const raw = json.rawStream ?? null
    const localAddress = raw?.socket?.address ?? null

    return {
        remotePublicKeyHex: json.remotePublicKey ?? null,
        remoteHost: raw?.remoteHost ?? null,
        remotePort: raw?.remotePort ?? null,
        remoteFamily: raw?.remoteFamily ?? null,
        localHost: localAddress?.host ?? null,
        localPort: localAddress?.port ?? null,
        localFamily: localAddress?.family ?? null,
        connected: Boolean(json.connected && raw?.connected),
        rtt: typeof raw?.rtt === 'number' ? raw.rtt : null,
        cwnd: typeof raw?.cwnd === 'number' ? raw.cwnd : null,
        inflight: typeof raw?.inflight === 'number' ? raw.inflight : null,
    }
}

/**
 * Infer whether the final endpoint looks direct or relay-assisted.
 */
export function inferTransportMode(
    snapshot: TransportSnapshot,
    peer: DiscoveredPeer | undefined,
    ownRelayNodes: RelayNode[]
): TransportMode {
    if (!snapshot.remoteHost || !snapshot.remotePort) {
        return 'unknown'
    }

    if (matchesRelay(snapshot.remoteHost, snapshot.remotePort, peer?.relayNodes ?? [])) {
        return 'relay-assisted'
    }

    if (matchesRelay(snapshot.remoteHost, snapshot.remotePort, ownRelayNodes)) {
        return 'relay-assisted'
    }

    return 'direct'
}

/**
 * Render a compact one-line transport debug message.
 */
export function formatTransportSnapshot(
    label: string,
    snapshot: TransportSnapshot,
    mode: TransportMode,
    note?: string
): string {
    const remote =
        snapshot.remoteHost && snapshot.remotePort
            ? `${snapshot.remoteHost}:${snapshot.remotePort}`
            : 'unknown'
    const local =
        snapshot.localHost && snapshot.localPort
            ? `${snapshot.localHost}:${snapshot.localPort}`
            : 'unknown'
    const rtt = snapshot.rtt !== null ? `${snapshot.rtt}ms` : 'n/a'
    const suffix = note ? ` note=${note}` : ''

    return `${label} mode=${mode} remote=${remote} local=${local} rtt=${rtt} connected=${snapshot.connected}${suffix}`
}

function matchesRelay(host: string, port: number, relays: RelayNode[]): boolean {
    return relays.some((relay) => relay.host === host && relay.port === port)
}
