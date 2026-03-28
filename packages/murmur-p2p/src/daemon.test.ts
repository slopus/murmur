import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { afterEach, describe, expect, it } from 'vitest'
import { sendControlRequest } from './control.js'
import { MurmurP2pDaemon } from './daemon.js'

const require = createRequire(import.meta.url)
const createTestnet = require('hyperdht/testnet.js') as (
    size?: number,
    options?: object
) => Promise<{
    bootstrap: Array<{ host: string; port: number }>
    destroy(): Promise<void>
}>

const tempPaths: string[] = []

afterEach(async () => {
    await Promise.all(tempPaths.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe('MurmurP2pDaemon', () => {
    it('persists its peer identity across restarts', async () => {
        const testnet = await createTestnet(5)
        const dataDir = await mkdtemp(join(tmpdir(), 'murmur-p2p-identity-'))
        tempPaths.push(dataDir)

        try {
            const daemon = new MurmurP2pDaemon({
                dataDir,
                controlSocketPath: join(dataDir, 'control.sock'),
                bootstrap: testnet.bootstrap,
                name: 'alice',
                presenceRefreshMs: 500,
                log: () => {},
            })

            await daemon.start()
            const firstInfo = await daemon.getInfo()
            await daemon.stop()

            const restarted = new MurmurP2pDaemon({
                dataDir,
                controlSocketPath: join(dataDir, 'control.sock'),
                bootstrap: testnet.bootstrap,
                name: 'alice',
                presenceRefreshMs: 500,
                log: () => {},
            })

            await restarted.start()
            const secondInfo = await restarted.getInfo()
            await restarted.stop()

            expect(secondInfo.peerId).toBe(firstInfo.peerId)
        } finally {
            await testnet.destroy()
        }
    }, 15000)

    it('announces peers and delivers a message over HyperDHT', async () => {
        const testnet = await createTestnet(8)
        let alice: MurmurP2pDaemon | null = null
        let bob: MurmurP2pDaemon | null = null

        try {
            const aliceDir = await mkdtemp(join(tmpdir(), 'murmur-p2p-alice-'))
            const bobDir = await mkdtemp(join(tmpdir(), 'murmur-p2p-bob-'))
            tempPaths.push(aliceDir, bobDir)

            alice = new MurmurP2pDaemon({
                dataDir: aliceDir,
                controlSocketPath: join(aliceDir, 'control.sock'),
                bootstrap: testnet.bootstrap,
                name: 'alice',
                presenceRefreshMs: 500,
                log: () => {},
            })
            bob = new MurmurP2pDaemon({
                dataDir: bobDir,
                controlSocketPath: join(bobDir, 'control.sock'),
                bootstrap: testnet.bootstrap,
                name: 'bob',
                presenceRefreshMs: 500,
                log: () => {},
            })

            await alice.start()
            await bob.start()

            const aliceInfo = await alice.getInfo()
            const bobInfo = await bob.getInfo()

            const peersResponse = await waitFor(async () => {
                const response = await sendControlRequest(aliceInfo.controlSocketPath, {
                    type: 'list_peers',
                })
                if (response.status !== 'ok' || response.type !== 'list_peers') {
                    throw new Error(
                        response.status === 'error'
                            ? response.message
                            : 'Unexpected list_peers response'
                    )
                }
                if (!response.peers.some((peer) => peer.peerId === bobInfo.peerId)) {
                    throw new Error('Bob is not visible in lookup results yet')
                }
                return response
            })

            expect(peersResponse.peers.map((peer) => peer.peerId)).toContain(bobInfo.peerId)

            const sendResponse = await sendControlRequest(aliceInfo.controlSocketPath, {
                type: 'send_message',
                to: bobInfo.peerId,
                body: 'hello from alice',
            })
            if (sendResponse.status !== 'ok' || sendResponse.type !== 'send_message') {
                throw new Error('Failed to send message')
            }

            const messagesResponse = await sendControlRequest(bobInfo.controlSocketPath, {
                type: 'list_messages',
            })
            if (messagesResponse.status !== 'ok' || messagesResponse.type !== 'list_messages') {
                throw new Error('Failed to fetch messages')
            }

            expect(messagesResponse.messages).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        from: aliceInfo.peerId,
                        to: bobInfo.peerId,
                        body: 'hello from alice',
                        direction: 'inbound',
                    }),
                ])
            )

        } finally {
            if (alice) {
                await alice.stop()
            }
            if (bob) {
                await bob.stop()
            }
            await testnet.destroy()
        }
    }, 15000)
})

async function waitFor<T>(callback: () => Promise<T>, timeoutMs = 5_000): Promise<T> {
    const startedAt = Date.now()
    let lastError: Error | null = null

    while (Date.now() - startedAt < timeoutMs) {
        try {
            return await callback()
        } catch (error) {
            lastError = error instanceof Error ? error : new Error('Unknown waitFor error')
            await new Promise((resolve) => setTimeout(resolve, 200))
        }
    }

    throw lastError ?? new Error('Timed out waiting for condition')
}
