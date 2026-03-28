import { createHash, randomBytes } from 'node:crypto'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { BootstrapNode } from './types.js'

/**
 * Protocol identifier used on the wire and control plane.
 */
export const MURMUR_P2P_PROTOCOL = 'murmur-p2p/1'

/**
 * Shared DHT topic used to announce live peers.
 */
export const MURMUR_P2P_TOPIC = 'murmur-p2p/v1/global'

/**
 * Default data directory for the daemon.
 */
export function defaultDataDir(): string {
    return join(homedir(), '.murmur-p2p')
}

/**
 * Default Unix socket used by CLI commands to speak to the daemon.
 */
export function defaultControlSocketPath(dataDir: string): string {
    return join(dataDir, 'control.sock')
}

/**
 * Derive the fixed 32-byte DHT topic for peer discovery.
 */
export function deriveTopicBuffer(): Buffer {
    return createHash('sha256').update(MURMUR_P2P_TOPIC).digest()
}

/**
 * Convert bytes into a stable lowercase hex string.
 */
export function toHex(value: Uint8Array): string {
    return Buffer.from(value).toString('hex')
}

/**
 * Convert a hex string into a buffer.
 */
export function fromHex(value: string): Buffer {
    if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
        throw new Error(`Invalid hex value: ${value}`)
    }
    return Buffer.from(value, 'hex')
}

/**
 * Create a random seed for persistent peer identity.
 */
export function createSeed(): Buffer {
    return randomBytes(32)
}

/**
 * Format log messages with a timestamp prefix.
 */
export function formatLogLine(message: string): string {
    return `[${new Date().toISOString()}] ${message}`
}

/**
 * Normalize bootstrap config into strings for logging and control responses.
 */
export function formatBootstrapNodes(bootstrap: BootstrapNode[]): string[] {
    return bootstrap.map((entry) =>
        typeof entry === 'string' ? entry : `${entry.host}:${entry.port}`
    )
}
