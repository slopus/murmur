import { RelayError } from "../protocol/index.js";
import type { RelaySessionIssuerOptions } from "./types.js";
import {
    createRelaySessionToken,
    parseSignedRelaySessionRequest,
    verifyRelaySessionRequest,
} from "./impl/sessionCodec.js";

export {
    createRelaySessionToken,
    parseSignedRelaySessionRequest,
    verifyRelaySessionRequest,
    verifyRelaySessionToken,
} from "./impl/sessionCodec.js";
export type {
    CreateRelaySessionTokenOptions,
    RelaySessionAuthorizer,
    RelaySessionClaims,
    RelaySessionIssuerOptions,
    RelaySessionRoute,
    SignedRelaySessionRequest,
    SignedRelaySessionRequestJson,
    VerifyRelaySessionTokenOptions,
} from "./types.js";

const DEFAULT_TICKET_TTL_MILLISECONDS = 5 * 60 * 1_000;
const DEFAULT_AUTHENTICATION_SKEW_MILLISECONDS = 30_000;
const DEFAULT_MAXIMUM_REQUEST_BYTES = 16 * 1024;

async function readJson(request: Request, maximumBytes: number): Promise<unknown> {
    const declared = request.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new RelayError(413, "Relay-session request exceeds limit", { error: "limit" });
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
                if (size > maximumBytes || chunks.length >= 1_024) {
                    await reader.cancel().catch(() => undefined);
                    throw new RelayError(413, "Relay-session request exceeds limit", {
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
        throw new RelayError(400, "Invalid relay-session JSON", { error: "malformed" });
    }
}

function json(body: unknown, status: number): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

/** Build the main-server endpoint that authenticates and routes one device. */
export function createRelaySessionFetchHandler(
    options: RelaySessionIssuerOptions,
): (request: Request) => Promise<Response> {
    const secret = options.tokenSecret.slice();
    const now = options.now ?? Date.now;
    const ttl = options.ticketTtlMilliseconds ?? DEFAULT_TICKET_TTL_MILLISECONDS;
    const skew =
        options.maximumAuthenticationSkewMilliseconds ?? DEFAULT_AUTHENTICATION_SKEW_MILLISECONDS;
    const maximumBytes = options.maximumRequestBytes ?? DEFAULT_MAXIMUM_REQUEST_BYTES;
    if (secret.length < 32) {
        throw new Error("Relay-session token secret must contain at least 32 bytes");
    }
    if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > 15 * 60 * 1_000) {
        throw new Error("Relay-session ticket TTL must be between 1 and 15 minutes");
    }
    if (!Number.isSafeInteger(skew) || skew < 0 || skew > 5 * 60 * 1_000) {
        throw new Error("Relay-session authentication skew must be at most 5 minutes");
    }
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
        throw new Error("Maximum relay-session request bytes must be positive");
    }

    return async (request): Promise<Response> => {
        try {
            if (request.method !== "POST") {
                return json({ error: "not_found" }, 404);
            }
            const proof = parseSignedRelaySessionRequest(await readJson(request, maximumBytes));
            const issuedAt = now();
            if (Math.abs(proof.createdAt - issuedAt) > skew || !verifyRelaySessionRequest(proof)) {
                throw new RelayError(401, "Invalid relay-session proof", {
                    error: "unauthorized",
                });
            }
            const route = await options.authorize(request, proof);
            if (route === undefined) {
                throw new RelayError(403, "Device is not authorized for this account", {
                    error: "forbidden",
                });
            }
            const expiresAt = issuedAt + ttl;
            const token = createRelaySessionToken(secret, {
                ...route,
                device: proof.device,
                issuedAt,
                expiresAt,
            });
            return json(
                {
                    version: 1,
                    protocol: "murmur-websocket-v1",
                    endpoint: route.endpoint,
                    token,
                    expiresAt,
                },
                200,
            );
        } catch (error: unknown) {
            if (error instanceof RelayError) return json(error.body, error.status);
            return json({ error: "internal" }, 500);
        }
    };
}
