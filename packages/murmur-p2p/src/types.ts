/**
 * Persistent identity for a Murmur P2P daemon.
 */
export interface MurmurP2pIdentity {
    seedHex: string
    peerId: string
    name: string
    createdAt: string
}

/**
 * A peer discovered via the application DHT topic.
 */
export interface DiscoveredPeer {
    peerId: string
    relayNodes: RelayNode[]
}

/**
 * Relay node coordinates published by HyperDHT.
 */
export interface RelayNode {
    host: string
    port: number
}

/**
 * Stored message entry.
 */
export interface StoredMessage {
    id: string
    direction: 'inbound' | 'outbound'
    from: string
    to: string
    body: string
    sentAt: string
    receivedAt: string
}

/**
 * Runtime daemon information exposed through the control socket.
 */
export interface DaemonInfo {
    peerId: string
    name: string
    dataDir: string
    controlSocketPath: string
    topic: string
    bootstrap: string[]
    transportPolicy: TransportPolicy
}

/**
 * Bootstrap peer accepted by HyperDHT.
 */
export type BootstrapNode = string | RelayNode

/**
 * Enforced transport routing policy.
 */
export type TransportPolicy = 'any' | 'direct-only' | 'private-only' | 'public-only'

/**
 * Options used to configure the daemon.
 */
export interface MurmurP2pDaemonOptions {
    dataDir: string
    controlSocketPath: string
    bootstrap: BootstrapNode[]
    name?: string
    log?: (message: string) => void
    presenceRefreshMs?: number
    transportDebug?: boolean
    transportPolicy?: TransportPolicy
}
