import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";

type FetchHandler = (request: Request) => Promise<Response>;

/** Browser-origin policy for the Node relay server. */
export interface NodeRelayServerOptions {
    /**
     * Origins allowed to use the HTTP API. The default `["*"]` is safe for
     * Murmur's signed, credential-free protocol.
     */
    readonly allowedOrigins?: readonly string[];
}

function abortError(signal: AbortSignal): Error {
    return signal.reason instanceof Error ? signal.reason : new Error("HTTP client disconnected");
}

function validateAllowedOrigins(origins: readonly string[]): readonly string[] {
    const unique = [...new Set(origins)];
    for (const origin of unique) {
        if (origin.length === 0 || origin.includes("\r") || origin.includes("\n")) {
            throw new Error("CORS origins must be non-empty single-line values");
        }
    }
    if (unique.includes("*") && unique.length > 1) {
        throw new Error("Wildcard CORS origin cannot be combined with explicit origins");
    }
    return unique;
}

function corsOrigin(
    request: IncomingMessage,
    allowedOrigins: readonly string[],
): string | undefined {
    const origin = request.headers.origin;
    if (origin === undefined) {
        return allowedOrigins.includes("*") ? "*" : undefined;
    }
    if (allowedOrigins.includes("*")) {
        return "*";
    }
    return allowedOrigins.includes(origin) ? origin : undefined;
}

function setCorsHeaders(output: ServerResponse, origin: string): void {
    output.setHeader("access-control-allow-origin", origin);
    output.setHeader("access-control-allow-methods", "GET, POST, PUT, OPTIONS");
    output.setHeader("access-control-allow-headers", "content-type");
    output.setHeader("access-control-max-age", "86400");
    if (origin !== "*") {
        const existing = output.getHeader("vary");
        output.setHeader("vary", existing === undefined ? "Origin" : `${String(existing)}, Origin`);
    }
}

function requestHeaders(request: IncomingMessage): Headers {
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) {
        if (Array.isArray(value)) {
            for (const item of value) {
                headers.append(name, item);
            }
        } else if (value !== undefined) {
            headers.set(name, value);
        }
    }
    return headers;
}

function fetchRequest(request: IncomingMessage, signal: AbortSignal): Request {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", "http://murmur-relay.local");
    const init: RequestInit & { duplex?: "half" } = {
        method,
        headers: requestHeaders(request),
        signal,
    };
    if (method !== "GET" && method !== "HEAD") {
        init.body = Readable.toWeb(request) as ReadableStream<Uint8Array>;
        init.duplex = "half";
    }
    return new Request(url, init);
}

async function waitForDrain(output: ServerResponse, signal: AbortSignal): Promise<void> {
    if (signal.aborted) {
        throw abortError(signal);
    }
    if (output.destroyed) {
        throw new Error("HTTP response closed during backpressure");
    }

    await new Promise<void>((resolve, reject) => {
        let settled = false;
        const cleanup = (): void => {
            output.removeListener("drain", onDrain);
            output.removeListener("close", onClose);
            output.removeListener("error", onError);
            signal.removeEventListener("abort", onAbort);
        };
        const settle = (operation: () => void): void => {
            if (settled) {
                return;
            }
            settled = true;
            cleanup();
            operation();
        };
        const onDrain = (): void => settle(resolve);
        const onClose = (): void =>
            settle(() => reject(new Error("HTTP response closed during backpressure")));
        const onError = (error: Error): void => settle(() => reject(error));
        const onAbort = (): void => settle(() => reject(abortError(signal)));

        output.once("drain", onDrain);
        output.once("close", onClose);
        output.once("error", onError);
        signal.addEventListener("abort", onAbort, { once: true });
        if (signal.aborted) {
            onAbort();
        } else if (output.destroyed) {
            onClose();
        }
    });
}

async function writeResponse(
    response: Response,
    output: ServerResponse,
    signal: AbortSignal,
    allowedOrigin: string | undefined,
): Promise<void> {
    output.statusCode = response.status;
    for (const [name, value] of response.headers) {
        output.setHeader(name, value);
    }
    if (allowedOrigin !== undefined) {
        setCorsHeaders(output, allowedOrigin);
    }
    if (response.body === null) {
        output.end();
        return;
    }
    const reader = response.body.getReader();
    try {
        for (;;) {
            if (signal.aborted) {
                throw abortError(signal);
            }
            const result = await reader.read();
            if (result.done) {
                break;
            }
            if (!output.write(Buffer.from(result.value))) {
                await waitForDrain(output, signal);
            }
        }
        output.end();
    } catch (error: unknown) {
        await reader.cancel(error).catch(() => undefined);
        throw error;
    }
}

/** Adapt the runtime-neutral relay Fetch handler to a streaming Node HTTP server. */
export function createNodeRelayServer(
    handler: FetchHandler,
    options: NodeRelayServerOptions = {},
): Server {
    const allowedOrigins = validateAllowedOrigins(options.allowedOrigins ?? ["*"]);

    return createServer((request, response) => {
        const controller = new AbortController();
        const abort = (): void => controller.abort(new Error("HTTP client disconnected"));
        request.once("aborted", abort);
        response.once("close", () => {
            if (!response.writableEnded) {
                abort();
            }
        });

        void (async (): Promise<void> => {
            try {
                const origin = corsOrigin(request, allowedOrigins);
                if (request.headers.origin !== undefined && origin === undefined) {
                    response.statusCode = 403;
                    response.end("Origin not allowed");
                    return;
                }
                if (request.method === "OPTIONS") {
                    response.statusCode = 204;
                    if (origin !== undefined) {
                        setCorsHeaders(response, origin);
                    }
                    response.end();
                    return;
                }
                const fetchResponse = await handler(fetchRequest(request, controller.signal));
                await writeResponse(fetchResponse, response, controller.signal, origin);
            } catch {
                if (!response.headersSent) {
                    response.statusCode = controller.signal.aborted ? 408 : 500;
                    response.end(
                        controller.signal.aborted ? "Request cancelled" : "Internal relay error",
                    );
                } else {
                    response.destroy();
                }
            }
        })();
    });
}
