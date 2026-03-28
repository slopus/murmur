#!/usr/bin/env node

import { once } from 'node:events'
import process from 'node:process'
import { MurmurP2pDaemon } from './daemon.js'
import { sendControlRequest } from './control.js'
import type { TransportPolicy } from './types.js'
import { defaultControlSocketPath, defaultDataDir } from './utils.js'

interface ParsedArgs {
    command: string | null
    positionals: string[]
    options: Record<string, string | boolean>
}

function parseArgs(argv: string[]): ParsedArgs {
    const options: Record<string, string | boolean> = {}
    const positionals: string[] = []
    let command: string | null = null

    for (let index = 0; index < argv.length; index += 1) {
        const value = argv[index]
        if (value.startsWith('--')) {
            const key = value.slice(2)
            const next = argv[index + 1]
            if (next && !next.startsWith('--')) {
                options[key] = next
                index += 1
            } else {
                options[key] = true
            }
            continue
        }

        if (!command) {
            command = value
            continue
        }

        positionals.push(value)
    }

    return { command, positionals, options }
}

function readStringOption(options: Record<string, string | boolean>, key: string): string | undefined {
    const value = options[key]
    return typeof value === 'string' && value.trim().length > 0 ? value : undefined
}

function help(): string {
    return [
        'murmur-p2p',
        '',
        'Commands:',
        '  server [--data-dir PATH] [--socket PATH] [--name NAME] [--bootstrap host:port,host:port] [--transport-policy any|direct-only|private-only|public-only]',
        '  whoami [--data-dir PATH] [--socket PATH]',
        '  peers [--data-dir PATH] [--socket PATH]',
        '  messages [--data-dir PATH] [--socket PATH]',
        '  send --to PEER_ID --message TEXT [--data-dir PATH] [--socket PATH]',
        '',
        'The daemon owns a persistent HyperDHT identity and exposes a Unix control socket.',
    ].join('\n')
}

function resolveDataDir(options: Record<string, string | boolean>): string {
    return readStringOption(options, 'data-dir') ?? defaultDataDir()
}

function resolveSocketPath(options: Record<string, string | boolean>, dataDir: string): string {
    return readStringOption(options, 'socket') ?? defaultControlSocketPath(dataDir)
}

function parseBootstrap(options: Record<string, string | boolean>): string[] {
    const raw = readStringOption(options, 'bootstrap')
    if (!raw) {
        return []
    }
    return raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0)
}

function responseError(): Error {
    return new Error('Unexpected response from daemon')
}

function readBooleanOption(options: Record<string, string | boolean>, key: string): boolean {
    return options[key] === true || options[key] === 'true'
}

function readTransportPolicyOption(options: Record<string, string | boolean>): TransportPolicy {
    const value = readStringOption(options, 'transport-policy') ?? 'any'
    if (
        value === 'any' ||
        value === 'direct-only' ||
        value === 'private-only' ||
        value === 'public-only'
    ) {
        return value
    }

    throw new Error(`Invalid --transport-policy value: ${value}`)
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2))
    const dataDir = resolveDataDir(args.options)
    const socketPath = resolveSocketPath(args.options, dataDir)

    if (!args.command || args.command === '--help' || args.command === 'help') {
        console.log(help())
        return
    }

    if (args.command === 'server') {
        const daemon = new MurmurP2pDaemon({
            dataDir,
            controlSocketPath: socketPath,
            bootstrap: parseBootstrap(args.options),
            name: readStringOption(args.options, 'name'),
            transportDebug: readBooleanOption(args.options, 'transport-debug'),
            transportPolicy: readTransportPolicyOption(args.options),
        })

        await daemon.start()

        const info = await daemon.getInfo()
        console.log(`peer id: ${info.peerId}`)
        console.log(`control socket: ${info.controlSocketPath}`)
        console.log(`topic: ${info.topic}`)

        const shutdown = async (): Promise<void> => {
            await daemon.stop()
            process.exit(0)
        }

        process.once('SIGINT', () => {
            void shutdown()
        })
        process.once('SIGTERM', () => {
            void shutdown()
        })

        await new Promise<void>(() => {})
        return
    }

    if (args.command === 'whoami') {
        const response = await sendControlRequest(socketPath, { type: 'get_info' })
        if (response.status !== 'ok' || response.type !== 'get_info') {
            throw response.status === 'error' ? new Error(response.message) : responseError()
        }

        console.log(`peer id: ${response.info.peerId}`)
        console.log(`name: ${response.info.name}`)
        console.log(`socket: ${response.info.controlSocketPath}`)
        console.log(`topic: ${response.info.topic}`)
        console.log(`transport policy: ${response.info.transportPolicy}`)
        return
    }

    if (args.command === 'peers') {
        const response = await sendControlRequest(socketPath, { type: 'list_peers' })
        if (response.status !== 'ok' || response.type !== 'list_peers') {
            throw response.status === 'error' ? new Error(response.message) : responseError()
        }

        for (const peer of response.peers) {
            console.log(peer.peerId)
        }
        return
    }

    if (args.command === 'messages') {
        const response = await sendControlRequest(socketPath, { type: 'list_messages' })
        if (response.status !== 'ok' || response.type !== 'list_messages') {
            throw response.status === 'error' ? new Error(response.message) : responseError()
        }

        for (const message of response.messages) {
            console.log(
                `${message.receivedAt} ${message.direction} ${message.from} -> ${message.to}: ${message.body}`
            )
        }
        return
    }

    if (args.command === 'send') {
        const to = readStringOption(args.options, 'to')
        const body = readStringOption(args.options, 'message')

        if (!to || !body) {
            throw new Error('send requires --to and --message')
        }

        const response = await sendControlRequest(socketPath, {
            type: 'send_message',
            to,
            body,
        })

        if (response.status !== 'ok' || response.type !== 'send_message') {
            throw response.status === 'error' ? new Error(response.message) : responseError()
        }

        console.log(`sent message ${response.id}`)
        return
    }

    throw new Error(`Unknown command: ${args.command}`)
}

main().catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
})
