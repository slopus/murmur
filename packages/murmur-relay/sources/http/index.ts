import {
    RelayError,
    parseRelayTopic,
    parseSignedRelayEvent,
    signedRelayEventToJson,
    type ReadProof,
} from "../protocol/index.js";
import type { RelayService } from "../relay/index.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";

/** Metadata supplied by a concrete HTTP host. */
export interface RelayRequestContext {
    readonly remoteAddress?: string;
}

/** Fetch-compatible relay request handler. */
export type RelayFetchHandler = (
    request: Request,
    context?: RelayRequestContext,
) => Promise<Response>;

/** CORS policy for the relay HTTP boundary. */
export interface RelayHttpOptions {
    readonly allowedOrigins?: "*" | readonly string[];
}

function json(
    body: unknown,
    status: number = 200,
    headers?: Readonly<Record<string, string>>,
): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
        },
    });
}

function boundedJson(
    body: unknown,
    maximumBytes: number,
    headers: Readonly<Record<string, string>>,
): Response {
    const encoded = JSON.stringify(body);
    if (new TextEncoder().encode(encoded).length > maximumBytes) {
        throw new RelayError(413, "Response exceeds relay limit", { error: "limit" });
    }
    return new Response(encoded, {
        status: 200,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
        },
    });
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

async function readJson(request: Request, maximumBytes: number): Promise<unknown> {
    const declared = request.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new RelayError(413, "Request body exceeds relay limit", { error: "limit" });
    }
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader !== undefined) {
        try {
            for (;;) {
                const result = await reader.read();
                if (result.done) break;
                size += result.value.length;
                if (size > maximumBytes || chunks.length >= 65_536) {
                    await reader.cancel().catch(() => undefined);
                    throw new RelayError(413, "Request body exceeds relay limit", {
                        error: "limit",
                    });
                }
                chunks.push(result.value);
            }
        } finally {
            reader.releaseLock();
        }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    try {
        return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
    } catch {
        throw new RelayError(400, "Invalid JSON request", { error: "malformed" });
    }
}

function integer(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function proof(value: unknown): ReadProof | undefined {
    if (value === undefined) return undefined;
    const input = object(value, "read proof");
    if (
        typeof input.challengeId !== "string" ||
        typeof input.signature !== "string" ||
        Object.keys(input).some((key) => key !== "challengeId" && key !== "signature")
    ) {
        throw new RelayError(400, "Invalid read proof", { error: "malformed" });
    }
    try {
        return {
            challengeId: input.challengeId,
            signature: decodeBase64Url(input.signature, 64),
        };
    } catch {
        throw new RelayError(400, "Invalid read proof", { error: "malformed" });
    }
}

function corsOrigin(request: Request, options: RelayHttpOptions): string | undefined {
    const origin = request.headers.get("origin");
    if (origin === null) return undefined;
    const allowed = options.allowedOrigins ?? "*";
    if (allowed === "*" || allowed.includes(origin)) return allowed === "*" ? "*" : origin;
    return undefined;
}

/** Create the relay's complete ordered-event HTTP API. */
export function createRelayFetchHandler(
    relay: RelayService,
    options: RelayHttpOptions = {},
): RelayFetchHandler {
    return async (request): Promise<Response> => {
        const origin = corsOrigin(request, options);
        const corsHeaders: Record<string, string> =
            origin === undefined
                ? {}
                : {
                      "access-control-allow-origin": origin,
                      ...(origin === "*" ? {} : { vary: "Origin" }),
                  };
        try {
            const url = new URL(request.url);
            if (request.method === "OPTIONS") {
                return new Response(null, {
                    status: 204,
                    headers: {
                        ...corsHeaders,
                        "access-control-allow-methods": "GET, POST, OPTIONS",
                        "access-control-allow-headers": "content-type",
                    },
                });
            }
            if (request.method === "GET" && url.pathname === "/health") {
                await relay.health();
                return json({ ok: true }, 200, corsHeaders);
            }
            if (request.method === "POST" && url.pathname === "/v1/events") {
                const event = parseSignedRelayEvent(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const outcome = await relay.publish(event);
                return boundedJson(
                    { seq: outcome.seq.toString(), duplicate: outcome.duplicate },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/read-challenges") {
                const body = object(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                    "challenge request",
                );
                const challenge = await relay.issueReadChallenge(parseRelayTopic(body.topic));
                return boundedJson(
                    {
                        id: challenge.id,
                        nonce: encodeBase64Url(challenge.nonce),
                        expiresAt: challenge.expiresAt,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/events/read") {
                const body = object(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                    "event read",
                );
                if (typeof body.since !== "string" || !/^(0|[1-9]\d*)$/.test(body.since)) {
                    throw new RelayError(400, "Invalid event cursor", { error: "malformed" });
                }
                const page = await relay.readEvents(
                    parseRelayTopic(body.topic),
                    BigInt(body.since),
                    integer(body.limit, "event limit"),
                    integer(body.waitMilliseconds, "long-poll duration"),
                    proof(body.proof),
                    request.signal,
                    relay.options.maximumJsonBodyBytes,
                );
                return boundedJson(
                    {
                        events: page.events.map((retained) => ({
                            seq: retained.seq.toString(),
                            event: signedRelayEventToJson(retained.event),
                        })),
                        head: page.head.toString(),
                        exhausted: page.exhausted,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            return json({ error: "not_found" }, 404, corsHeaders);
        } catch (error: unknown) {
            if (error instanceof RelayError) {
                return json(error.body, error.status, corsHeaders);
            }
            return json({ error: "internal" }, 500, corsHeaders);
        }
    };
}
