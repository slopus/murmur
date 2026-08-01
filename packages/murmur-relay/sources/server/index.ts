import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { RelayFetchHandler, RelayRequestContext } from "../http/index.js";

/** Node listener address for the standalone relay host. */
export interface NodeRelayServerOptions {
    readonly host: string;
    readonly port: number;
}

interface StreamingRequestInit extends RequestInit {
    readonly duplex: "half";
}

interface RequestContext {
    readonly request: Request;
    readonly cleanup: () => void;
}

function requestHeaders(message: IncomingMessage): Headers {
    const headers = new Headers();
    for (const [name, value] of Object.entries(message.headers)) {
        if (typeof value === "string") {
            headers.set(name, value);
        } else if (value !== undefined) {
            for (const item of value) {
                headers.append(name, item);
            }
        }
    }
    return headers;
}

function fetchRequest(message: IncomingMessage, signal: AbortSignal): Request {
    const host = message.headers.host ?? "localhost";
    const path = message.url ?? "/";
    const url = `http://${host}${path}`;
    const method = message.method ?? "GET";
    if (method === "GET" || method === "HEAD") {
        return new Request(url, {
            method,
            headers: requestHeaders(message),
            signal,
        });
    }
    const initialization: StreamingRequestInit = {
        method,
        headers: requestHeaders(message),
        body: Readable.toWeb(message),
        duplex: "half",
        signal,
    };
    return new Request(url, initialization);
}

function requestContext(message: IncomingMessage, response: ServerResponse): RequestContext {
    const controller = new AbortController();
    const abort = (): void => {
        if (!controller.signal.aborted) {
            controller.abort(new Error("Relay HTTP client disconnected"));
        }
    };
    const onRequestClose = (): void => {
        if (message.aborted || !message.complete || message.socket.destroyed) {
            abort();
        }
    };
    const onResponseClose = (): void => {
        if (!response.writableFinished) {
            abort();
        }
    };
    message.once("aborted", abort);
    message.once("close", onRequestClose);
    message.socket.once("close", abort);
    response.once("close", onResponseClose);
    const cleanup = (): void => {
        message.off("aborted", abort);
        message.off("close", onRequestClose);
        message.socket.off("close", abort);
        response.off("close", onResponseClose);
    };
    try {
        return {
            request: fetchRequest(message, controller.signal),
            cleanup,
        };
    } catch (error) {
        cleanup();
        throw error;
    }
}

async function endResponse(outgoing: ServerResponse, body?: Uint8Array | string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        const cleanup = (): void => {
            outgoing.off("error", onError);
            outgoing.off("finish", onFinish);
            outgoing.off("close", onClose);
        };
        const onError = (error: Error): void => {
            cleanup();
            reject(error);
        };
        const onFinish = (): void => {
            cleanup();
            resolve();
        };
        const onClose = (): void => {
            cleanup();
            if (outgoing.writableFinished) {
                resolve();
            } else {
                reject(new Error("Relay HTTP client disconnected"));
            }
        };
        outgoing.once("error", onError);
        outgoing.once("finish", onFinish);
        outgoing.once("close", onClose);
        outgoing.end(body);
    });
}

async function writeResponse(response: Response, outgoing: ServerResponse): Promise<void> {
    outgoing.statusCode = response.status;
    outgoing.statusMessage = response.statusText;
    for (const [name, value] of response.headers) {
        outgoing.setHeader(name, value);
    }
    if (response.body === null) {
        await endResponse(outgoing);
        return;
    }
    await pipeline(Readable.fromWeb(response.body as ReadableStream<Uint8Array>), outgoing);
}

/** Create an unbound Node HTTP server around a relay Fetch handler. */
export function createNodeRelayServer(handler: RelayFetchHandler): Server {
    return createServer((request, response) => {
        let context: RequestContext;
        try {
            context = requestContext(request, response);
        } catch {
            response.statusCode = 500;
            response.setHeader("content-type", "application/json; charset=utf-8");
            response.end('{"error":"internal"}');
            return;
        }
        const remoteAddress = request.socket.remoteAddress;
        const requestMetadata: RelayRequestContext =
            remoteAddress === undefined ? {} : { remoteAddress };
        void Promise.resolve()
            .then(() => handler(context.request, requestMetadata))
            .then((result) => writeResponse(result, response))
            .catch(async () => {
                if (response.destroyed) {
                    return;
                }
                if (!response.headersSent) {
                    response.statusCode = 500;
                    response.setHeader("content-type", "application/json; charset=utf-8");
                }
                await endResponse(response, '{"error":"internal"}').catch(() => undefined);
            })
            .finally(context.cleanup);
    });
}

/** Bind a Node relay server and resolve only after it is accepting connections. */
export async function listenNodeRelayServer(
    server: Server,
    options: NodeRelayServerOptions,
): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        const onError = (error: Error): void => {
            server.off("listening", onListening);
            reject(error);
        };
        const onListening = (): void => {
            server.off("error", onError);
            resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(options.port, options.host);
    });
}

/** Stop accepting requests and resolve after active responses finish. */
export async function closeNodeRelayServer(server: Server): Promise<void> {
    if (!server.listening) {
        return;
    }
    await new Promise<void>((resolve, reject) => {
        server.close((error) => {
            if (error === undefined) {
                resolve();
            } else {
                reject(error);
            }
        });
    });
}
