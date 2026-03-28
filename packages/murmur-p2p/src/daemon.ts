import DHT, { type DhtServer, type DhtSocket } from 'hyperdht'
import { randomUUID } from 'node:crypto'
import { createInterface } from 'node:readline'
import { once } from 'node:events'
import type { Server } from 'node:net'
import { StateStore } from './store.js'
import { keyPairFromIdentity } from './identity.js'
import { messagesResponse, peersResponse, infoResponse, type ControlRequest, type ControlResponse, peerEnvelopeSchema, encodeFrame } from './protocol.js'
import { sendControlRequest, startControlServer, stopControlServer } from './control.js'
import type {
    BootstrapNode,
    DaemonInfo,
    DiscoveredPeer,
    MurmurP2pDaemonOptions,
    MurmurP2pIdentity,
    RelayNode,
    StoredMessage,
} from './types.js'
import {
    MURMUR_P2P_PROTOCOL,
    MURMUR_P2P_TOPIC,
    defaultControlSocketPath,
    defaultDataDir,
    deriveTopicBuffer,
    formatBootstrapNodes,
    formatLogLine,
    toHex,
} from './utils.js'

const DEFAULT_PRESENCE_REFRESH_MS = 60_000
const ACK_TIMEOUT_MS = 15_000

/**
 * Standalone daemon that owns identity, local control socket, and DHT presence.
 */
export class MurmurP2pDaemon {
    private readonly dataDir: string
    private readonly controlSocketPath: string
    private readonly bootstrap: BootstrapNode[]
    private readonly log: (message: string) => void
    private readonly desiredName: string
    private readonly presenceRefreshMs: number
    private readonly store: StateStore
    private readonly topic = deriveTopicBuffer()

    private identity: MurmurP2pIdentity | null = null
    private dht: DHT | null = null
    private server: DhtServer | null = null
    private controlServer: Server | null = null
    private presenceTimer: NodeJS.Timeout | null = null
    private refreshingPresence = false

    constructor(options: Partial<MurmurP2pDaemonOptions> = {}) {
        this.dataDir = options.dataDir ?? defaultDataDir()
        this.controlSocketPath = options.controlSocketPath ?? defaultControlSocketPath(this.dataDir)
        this.bootstrap = options.bootstrap ?? []
        this.desiredName = options.name?.trim() || 'murmur-p2p'
        this.presenceRefreshMs = options.presenceRefreshMs ?? DEFAULT_PRESENCE_REFRESH_MS
        this.log = options.log ?? ((message) => console.log(formatLogLine(message)))
        this.store = new StateStore(this.dataDir)
    }

    /**
     * Start the daemon and begin announcing to the DHT.
     */
    async start(): Promise<void> {
        await this.store.ensureReady()
        this.identity = await this.store.loadOrCreateIdentity(this.desiredName)

        const keyPair = keyPairFromIdentity(this.identity)

        this.dht = new DHT({
            bootstrap: this.bootstrap.length > 0 ? this.bootstrap : undefined,
        })

        this.server = this.dht.createServer({}, (socket: DhtSocket) => {
            void this.handlePeerConnection(socket)
        })

        await this.server.listen(keyPair)
        await this.tryRefreshPresence()

        this.presenceTimer = setInterval(() => {
            void this.tryRefreshPresence()
        }, this.presenceRefreshMs)

        this.controlServer = await startControlServer(this.controlSocketPath, async (request) => {
            return await this.handleControlRequest(request)
        })

        this.log(`peer id ${this.identity.peerId}`)
        this.log(`control socket ${this.controlSocketPath}`)
        this.log(`announced topic ${MURMUR_P2P_TOPIC}`)
    }

    /**
     * Stop the daemon, unannounce the server, and close sockets.
     */
    async stop(): Promise<void> {
        if (this.presenceTimer) {
            clearInterval(this.presenceTimer)
            this.presenceTimer = null
        }

        if (this.controlServer) {
            await stopControlServer(this.controlServer, this.controlSocketPath)
            this.controlServer = null
        }

        if (this.server) {
            await this.server.close()
            this.server = null
        }

        if (this.dht) {
            await this.dht.destroy()
            this.dht = null
        }
    }

    /**
     * Expose daemon info for CLI status commands.
     */
    async getInfo(): Promise<DaemonInfo> {
        const identity = this.requireIdentity()
        return {
            peerId: identity.peerId,
            name: identity.name,
            dataDir: this.dataDir,
            controlSocketPath: this.controlSocketPath,
            topic: MURMUR_P2P_TOPIC,
            bootstrap: formatBootstrapNodes(this.bootstrap),
        }
    }

    /**
     * Resolve peers that are currently announcing on the shared topic.
     */
    async listPeers(): Promise<DiscoveredPeer[]> {
        const dht = this.requireDht()
        const identity = this.requireIdentity()
        const lookup = dht.lookup(this.topic)
        const peers = new Map<string, DiscoveredPeer>()

        for await (const result of lookup) {
            for (const peer of result.peers) {
                const peerId = toHex(peer.publicKey)
                if (peerId === identity.peerId) {
                    continue
                }

                peers.set(peerId, {
                    peerId,
                    relayNodes: (peer.nodes ?? []).map((node) => ({
                        host: node.host,
                        port: node.port,
                    })),
                })
            }
        }

        return [...peers.values()].sort((left, right) => left.peerId.localeCompare(right.peerId))
    }

    /**
     * Send a message to a remote peer by public key.
     */
    async sendMessage(to: string, body: string): Promise<string> {
        const dht = this.requireDht()
        const identity = this.requireIdentity()
        const peers = await this.listPeers()
        const targetPeer = peers.find((peer) => peer.peerId === to)
        const socket = dht.connect(to, targetPeer ? { nodes: targetPeer.relayNodes } : undefined)

        await waitForSocketOpen(socket)

        const id = randomUUID()
        const sentAt = new Date().toISOString()
        const envelope = {
            protocol: MURMUR_P2P_PROTOCOL,
            type: 'message' as const,
            id,
            from: identity.peerId,
            to,
            body,
            sentAt,
        }

        await awaitAck(socket, id, envelope)

        const message: StoredMessage = {
            id,
            direction: 'outbound',
            from: identity.peerId,
            to,
            body,
            sentAt,
            receivedAt: new Date().toISOString(),
        }

        await this.store.appendMessage(message)
        this.log(`sent ${id} to ${to}`)

        return id
    }

    /**
     * Read persisted messages from local storage.
     */
    async listMessages(): Promise<StoredMessage[]> {
        return await this.store.listMessages()
    }

    private async refreshPresence(): Promise<void> {
        if (this.refreshingPresence) {
            return
        }

        const dht = this.requireDht()
        const server = this.requireServer()
        const keyPair = keyPairFromIdentity(this.requireIdentity())

        this.refreshingPresence = true
        try {
            const stream = dht.announce(this.topic, keyPair, server.relayAddresses)
            await stream.finished()
        } finally {
            this.refreshingPresence = false
        }
    }

    private async tryRefreshPresence(): Promise<void> {
        try {
            await this.refreshPresence()
        } catch (error) {
            this.log(
                `presence announce failed: ${
                    error instanceof Error ? error.message : 'Unknown error'
                }`
            )
        }
    }

    private async handleControlRequest(request: ControlRequest): Promise<ControlResponse> {
        switch (request.type) {
            case 'get_info':
                return infoResponse(await this.getInfo())
            case 'list_messages':
                return messagesResponse(await this.listMessages())
            case 'list_peers':
                return peersResponse(await this.listPeers())
            case 'send_message':
                return {
                    status: 'ok',
                    type: 'send_message',
                    id: await this.sendMessage(request.to, request.body),
                }
        }
    }

    private async handlePeerConnection(socket: DhtSocket): Promise<void> {
        const lines = createInterface({ input: socket })

        socket.once('error', (error) => {
            this.log(`peer stream error: ${error.message}`)
        })

        lines.on('line', async (line) => {
            try {
                const envelope = peerEnvelopeSchema.parse(JSON.parse(line))
                if (envelope.type !== 'message') {
                    return
                }

                const receivedAt = new Date().toISOString()
                const message: StoredMessage = {
                    id: envelope.id,
                    direction: 'inbound',
                    from: envelope.from,
                    to: envelope.to,
                    body: envelope.body,
                    sentAt: envelope.sentAt,
                    receivedAt,
                }

                await this.store.appendMessage(message)
                this.log(`received ${envelope.id} from ${envelope.from}`)

                socket.write(
                    encodeFrame({
                        protocol: MURMUR_P2P_PROTOCOL,
                        type: 'ack',
                        id: envelope.id,
                    })
                )
                socket.end()
            } catch (error) {
                this.log(
                    `invalid peer frame from ${toHex(socket.remotePublicKey)}: ${
                        error instanceof Error ? error.message : 'Unknown error'
                    }`
                )
                socket.destroy(error instanceof Error ? error : undefined)
            }
        })

        await once(lines, 'close')
    }

    private requireIdentity(): MurmurP2pIdentity {
        if (!this.identity) {
            throw new Error('Daemon identity is not ready')
        }
        return this.identity
    }

    private requireDht(): DHT {
        if (!this.dht) {
            throw new Error('Daemon DHT is not running')
        }
        return this.dht
    }

    private requireServer(): DhtServer {
        if (!this.server) {
            throw new Error('Daemon server is not running')
        }
        return this.server
    }
}

/**
 * Convenience helper used by CLI commands to fetch status from the daemon.
 */
export async function getDaemonInfo(socketPath: string): Promise<DaemonInfo> {
    const response = await sendControlRequest(socketPath, { type: 'get_info' })
    if (response.status !== 'ok' || response.type !== 'get_info') {
        throw new Error(response.status === 'error' ? response.message : 'Unexpected control response')
    }
    return response.info
}

async function waitForSocketOpen(socket: DhtSocket): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        socket.once('open', resolve)
        socket.once('error', reject)
    })
}

async function awaitAck(
    socket: DhtSocket,
    expectedId: string,
    envelope: {
        protocol: string
        type: 'message'
        id: string
        from: string
        to: string
        body: string
        sentAt: string
    }
): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        const lines = createInterface({ input: socket })
        const timeout = setTimeout(() => {
            lines.close()
            socket.destroy(new Error(`Timed out waiting for ack from ${envelope.to}`))
            reject(new Error(`Timed out waiting for ack from ${envelope.to}`))
        }, ACK_TIMEOUT_MS)

        const fail = (error: Error): void => {
            clearTimeout(timeout)
            lines.close()
            reject(error)
        }

        socket.once('error', (error) => {
            fail(error)
        })

        lines.on('line', (line) => {
            try {
                const parsed = peerEnvelopeSchema.parse(JSON.parse(line))
                if (parsed.type === 'ack' && parsed.id === expectedId) {
                    clearTimeout(timeout)
                    lines.close()
                    socket.end()
                    resolve()
                }
            } catch (error) {
                fail(error instanceof Error ? error : new Error('Invalid ack frame'))
            }
        })

        socket.write(encodeFrame(envelope))
    })
}
