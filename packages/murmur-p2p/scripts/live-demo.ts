import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MurmurP2pDaemon } from '../src/daemon.js'
import { sendControlRequest } from '../src/control.js'

async function main(): Promise<void> {
    const aliceDir = await mkdtemp(join(tmpdir(), 'murmur-p2p-live-alice-'))
    const bobDir = await mkdtemp(join(tmpdir(), 'murmur-p2p-live-bob-'))

    const alice = new MurmurP2pDaemon({
        dataDir: aliceDir,
        controlSocketPath: join(aliceDir, 'control.sock'),
        name: 'alice-live',
    })
    const bob = new MurmurP2pDaemon({
        dataDir: bobDir,
        controlSocketPath: join(bobDir, 'control.sock'),
        name: 'bob-live',
    })

    try {
        await alice.start()
        await bob.start()

        const aliceInfo = await alice.getInfo()
        const bobInfo = await bob.getInfo()

        console.log(`alice peer id: ${aliceInfo.peerId}`)
        console.log(`bob peer id: ${bobInfo.peerId}`)
        console.log('waiting for public DHT discovery...')

        await waitFor(async () => {
            const response = await sendControlRequest(aliceInfo.controlSocketPath, {
                type: 'list_peers',
            })
            if (response.status !== 'ok' || response.type !== 'list_peers') {
                throw new Error(
                    response.status === 'error'
                        ? response.message
                        : 'Unexpected response from list_peers'
                )
            }

            if (!response.peers.some((peer) => peer.peerId === bobInfo.peerId)) {
                throw new Error('Bob has not shown up in Alice peer discovery yet')
            }
        }, 30_000)

        const sendResponse = await sendControlRequest(aliceInfo.controlSocketPath, {
            type: 'send_message',
            to: bobInfo.peerId,
            body: 'hello over the public HyperDHT',
        })

        if (sendResponse.status !== 'ok' || sendResponse.type !== 'send_message') {
            throw new Error(
                sendResponse.status === 'error'
                    ? sendResponse.message
                    : 'Unexpected response from send_message'
            )
        }

        const inbox = await waitFor(async () => {
            const response = await sendControlRequest(bobInfo.controlSocketPath, {
                type: 'list_messages',
            })
            if (response.status !== 'ok' || response.type !== 'list_messages') {
                throw new Error(
                    response.status === 'error'
                        ? response.message
                        : 'Unexpected response from list_messages'
                )
            }

            const hit = response.messages.find((message) => message.id === sendResponse.id)
            if (!hit) {
                throw new Error('Bob has not received the message yet')
            }

            return hit
        }, 30_000)

        console.log(`delivered message ${inbox.id}`)
        console.log(`${inbox.from} -> ${inbox.to}: ${inbox.body}`)
    } finally {
        await alice.stop()
        await bob.stop()
        await rm(aliceDir, { recursive: true, force: true })
        await rm(bobDir, { recursive: true, force: true })
    }
}

async function waitFor<T>(
    callback: () => Promise<T>,
    timeoutMs: number,
    intervalMs = 1_000
): Promise<T> {
    const startedAt = Date.now()
    let lastError: Error | null = null

    while (Date.now() - startedAt < timeoutMs) {
        try {
            return await callback()
        } catch (error) {
            lastError = error instanceof Error ? error : new Error('Unknown waitFor error')
            await new Promise((resolve) => setTimeout(resolve, intervalMs))
        }
    }

    throw lastError ?? new Error('Timed out waiting for live demo condition')
}

main().catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
})
