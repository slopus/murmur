import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { rm } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import type { ControlRequest, ControlResponse } from './protocol.js'
import { controlRequestSchema, controlResponseSchema, encodeFrame } from './protocol.js'

/**
 * Send a single request over the daemon control socket.
 */
export async function sendControlRequest(
    socketPath: string,
    request: ControlRequest
): Promise<ControlResponse> {
    return await new Promise<ControlResponse>((resolve, reject) => {
        const socket = createConnection(socketPath)
        const lines = createInterface({ input: socket })

        const cleanup = (): void => {
            lines.close()
            socket.removeAllListeners()
        }

        socket.once('connect', () => {
            socket.write(encodeFrame(request))
        })

        socket.once('error', (error) => {
            cleanup()
            reject(error)
        })

        lines.once('line', (line) => {
            try {
                const parsed = controlResponseSchema.parse(JSON.parse(line))
                cleanup()
                socket.end()
                resolve(parsed)
            } catch (error) {
                cleanup()
                socket.destroy()
                reject(error)
            }
        })

        lines.once('close', () => {
            cleanup()
        })
    })
}

/**
 * Start the local Unix control server.
 */
export async function startControlServer(
    socketPath: string,
    handler: (request: ControlRequest) => Promise<ControlResponse>
): Promise<Server> {
    await rm(socketPath, { force: true })

    const server = createServer((socket) => {
        void handleSocket(socket, handler)
    })

    await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(socketPath, () => {
            server.removeListener('error', reject)
            resolve()
        })
    })

    return server
}

/**
 * Close the local Unix control server and clean up the socket file.
 */
export async function stopControlServer(server: Server, socketPath: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        server.close((error) => {
            if (error) {
                reject(error)
                return
            }
            resolve()
        })
    })
    await rm(socketPath, { force: true })
}

async function handleSocket(
    socket: Socket,
    handler: (request: ControlRequest) => Promise<ControlResponse>
): Promise<void> {
    const lines = createInterface({ input: socket })

    lines.once('line', async (line) => {
        let response: ControlResponse

        try {
            const request = controlRequestSchema.parse(JSON.parse(line))
            response = await handler(request)
        } catch (error) {
            response = {
                status: 'error',
                message: error instanceof Error ? error.message : 'Unknown control error',
            }
        }

        socket.end(encodeFrame(response))
    })

    lines.once('close', () => {
        socket.end()
    })
}
