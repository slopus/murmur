import {
    RelayError,
    parseOwnedInvitationUpload,
    parseSignedInvitationRevocation,
    parseSignedDelivery,
    parseSignedQueueAck,
    parseSignedQueueRead,
    signedDeliveryToJson,
} from "../protocol/index.js";
import type { QueueEventSubscription, RelayService } from "../relay/index.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { DuplicateJsonKeyError, parseStrictJson } from "../utils/strictJson.js";

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
    readonly maximumRequestsPerMinutePerAddress?: number;
    readonly maximumTrackedAddresses?: number;
    readonly requireRemoteAddress?: boolean;
    readonly remoteAddressHeader?: string;
    readonly defaultAdmissionPrincipal?: string;
}

interface AddressWindow {
    count: number;
    startedAt: number;
}

const textEncoder = new TextEncoder();
const MINUTE_MILLISECONDS = 60_000;

/** Strictly parse the standalone relay's CORS origin environment value. */
export function parseRelayAllowedOrigins(value: string | undefined): "*" | readonly string[] {
    if (value === undefined || value === "*") return "*";
    const origins = value.split(",").map((origin) => origin.trim());
    if (origins.length === 0 || origins.some((origin) => origin.length === 0)) {
        throw new Error("MURMUR_RELAY_ORIGINS must be * or a comma-separated origin list");
    }
    const seen = new Set<string>();
    for (const origin of origins) {
        if (origin === "*" || seen.has(origin)) {
            throw new Error("MURMUR_RELAY_ORIGINS contains an invalid or duplicate origin");
        }
        let parsed: URL;
        try {
            parsed = new URL(origin);
        } catch {
            throw new Error("MURMUR_RELAY_ORIGINS contains an invalid origin");
        }
        if (
            (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
            parsed.origin !== origin
        ) {
            throw new Error("MURMUR_RELAY_ORIGINS contains an invalid origin");
        }
        seen.add(origin);
    }
    return origins;
}

function json(body: unknown, status: number, headers: Readonly<Record<string, string>>): Response {
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
    overflowBody: unknown = { error: "limit" },
): Response {
    const encoded = JSON.stringify(body);
    if (textEncoder.encode(encoded).length > maximumBytes) {
        return json(overflowBody, 413, headers);
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

function queueEventResponse(
    subscription: QueueEventSubscription,
    signal: AbortSignal,
    headers: Readonly<Record<string, string>>,
): Response {
    const iterator = subscription.events[Symbol.asyncIterator]();
    let initialized = false;
    const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
            if (!initialized) {
                initialized = true;
                controller.enqueue(textEncoder.encode("retry: 1000\n\n"));
                return;
            }
            try {
                const next = await iterator.next();
                if (next.done) {
                    subscription.close();
                    controller.close();
                    return;
                }
                if (next.value === null) {
                    controller.enqueue(textEncoder.encode(": keepalive\n\n"));
                    return;
                }
                if ("type" in next.value) {
                    const data = JSON.stringify({
                        generation: encodeBase64Url(next.value.generation),
                        head: next.value.head,
                        headSequence: next.value.headSequence,
                        acknowledgedThrough: next.value.acknowledgedThrough,
                        acknowledgedSequence: next.value.acknowledgedSequence,
                    });
                    controller.enqueue(textEncoder.encode(`event: continuity\ndata: ${data}\n\n`));
                    return;
                }
                const data = JSON.stringify({
                    eventId: next.value.eventId,
                    sequence: next.value.sequence,
                    delivery: signedDeliveryToJson(next.value.delivery),
                });
                controller.enqueue(
                    textEncoder.encode(
                        `id: ${next.value.eventId}\nevent: delivery\ndata: ${data}\n\n`,
                    ),
                );
            } catch (error: unknown) {
                subscription.close();
                if (signal.aborted) {
                    controller.close();
                } else {
                    controller.error(error);
                }
            }
        },
        async cancel() {
            subscription.close();
            await iterator.return?.();
        },
    });
    return new Response(body, {
        status: 200,
        headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-store",
            connection: "keep-alive",
            "x-accel-buffering": "no",
            ...headers,
        },
    });
}

async function readBytes(request: Request, maximumBytes: number): Promise<Uint8Array> {
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
    return bytes;
}

async function readJson(request: Request, maximumBytes: number): Promise<unknown> {
    try {
        return parseStrictJson(
            new TextDecoder("utf-8", { fatal: true }).decode(
                await readBytes(request, maximumBytes),
            ),
        );
    } catch (error: unknown) {
        if (error instanceof RelayError) throw error;
        if (error instanceof DuplicateJsonKeyError) {
            throw new RelayError(400, error.message, { error: "duplicate_json_key" });
        }
        throw new RelayError(400, "Invalid JSON request", { error: "malformed" });
    }
}

function corsOrigin(request: Request, options: RelayHttpOptions): string | undefined {
    const origin = request.headers.get("origin");
    if (origin === null) return undefined;
    const allowed = options.allowedOrigins ?? "*";
    if (allowed === "*" || allowed.includes(origin)) return allowed === "*" ? "*" : origin;
    return undefined;
}

/** Create the relay's complete identity-queue HTTP API. */
export function createRelayFetchHandler(
    relay: RelayService,
    options: RelayHttpOptions = {},
): RelayFetchHandler {
    const maximumRequestsPerMinutePerAddress = options.maximumRequestsPerMinutePerAddress ?? 600;
    const maximumTrackedAddresses = options.maximumTrackedAddresses ?? 10_000;
    const requireRemoteAddress = options.requireRemoteAddress ?? true;
    const remoteAddressHeader = options.remoteAddressHeader?.toLowerCase();
    const defaultAdmissionPrincipal = options.defaultAdmissionPrincipal;
    if (
        !Number.isSafeInteger(maximumRequestsPerMinutePerAddress) ||
        maximumRequestsPerMinutePerAddress < 1 ||
        !Number.isSafeInteger(maximumTrackedAddresses) ||
        maximumTrackedAddresses < 1
    ) {
        throw new Error("HTTP rate limits must be positive safe integers");
    }
    if (
        remoteAddressHeader !== undefined &&
        !/^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(remoteAddressHeader)
    ) {
        throw new Error("Remote address header must be a valid HTTP field name");
    }
    if (
        defaultAdmissionPrincipal !== undefined &&
        (defaultAdmissionPrincipal.length < 1 || defaultAdmissionPrincipal.length > 255)
    ) {
        throw new Error("Default admission principal must contain 1 through 255 characters");
    }
    if (!requireRemoteAddress && defaultAdmissionPrincipal === undefined) {
        throw new Error(
            "Disabling remote-address admission requires one explicit default admission principal",
        );
    }
    const addressWindows = new Map<string, AddressWindow>();

    return async (request, context): Promise<Response> => {
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
            const remoteAddress =
                remoteAddressHeader === undefined
                    ? context?.remoteAddress
                    : (request.headers.get(remoteAddressHeader) ?? undefined);
            const admissionPrincipal = remoteAddress ?? defaultAdmissionPrincipal;
            if (
                remoteAddress !== undefined &&
                (remoteAddress.length < 1 || remoteAddress.length > 255)
            ) {
                throw new RelayError(400, "Invalid remote address admission value", {
                    error: "malformed",
                });
            }
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
            if (
                request.method !== "OPTIONS" &&
                requireRemoteAddress &&
                remoteAddress === undefined
            ) {
                throw new RelayError(503, "Remote address admission context is required", {
                    error: "admission_context_required",
                });
            }
            if (request.method !== "OPTIONS" && admissionPrincipal !== undefined) {
                const now = Date.now();
                let window = addressWindows.get(admissionPrincipal);
                if (window !== undefined && now - window.startedAt >= MINUTE_MILLISECONDS) {
                    addressWindows.delete(admissionPrincipal);
                    window = undefined;
                }
                if (window === undefined) {
                    if (addressWindows.size >= maximumTrackedAddresses) {
                        for (const [address, candidate] of addressWindows) {
                            if (now - candidate.startedAt >= MINUTE_MILLISECONDS) {
                                addressWindows.delete(address);
                            }
                        }
                    }
                    if (addressWindows.size >= maximumTrackedAddresses) {
                        throw new RelayError(503, "Relay request limiter is full", {
                            error: "overloaded",
                        });
                    }
                    window = { count: 0, startedAt: now };
                    addressWindows.set(admissionPrincipal, window);
                }
                window.count += 1;
                if (window.count > maximumRequestsPerMinutePerAddress) {
                    throw new RelayError(429, "Too many requests from address", {
                        error: "rate_limited",
                    });
                }
            }
            if (request.method === "GET" && url.pathname === "/health") {
                await relay.health();
                return json({ ok: true }, 200, corsHeaders);
            }
            if (request.method === "POST" && url.pathname === "/v1/invitations") {
                if (admissionPrincipal === undefined) {
                    throw new RelayError(503, "Admission principal is required", {
                        error: "admission_context_required",
                    });
                }
                const outcome = await relay.storeInvitation(
                    await readBytes(request, relay.options.maximumInvitationBytes),
                    admissionPrincipal,
                );
                return boundedJson(
                    {
                        digest: encodeBase64Url(outcome.digest),
                        expiresAt: outcome.expiresAt,
                        duplicate: outcome.duplicate,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/invitations/owned") {
                if (admissionPrincipal === undefined) {
                    throw new RelayError(503, "Admission principal is required", {
                        error: "admission_context_required",
                    });
                }
                const upload = parseOwnedInvitationUpload(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const outcome = await relay.storeOwnedInvitation(
                    upload.bundle,
                    upload.authorization,
                    admissionPrincipal,
                );
                return boundedJson(
                    {
                        digest: encodeBase64Url(outcome.digest),
                        expiresAt: outcome.expiresAt,
                        duplicate: outcome.duplicate,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/invitations/revoke") {
                const revocation = parseSignedInvitationRevocation(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const outcome = await relay.revokeInvitations(revocation);
                return boundedJson(
                    { revoked: outcome.revoked },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "GET" && url.pathname.startsWith("/v1/invitations/")) {
                const encodedDigest = url.pathname.slice("/v1/invitations/".length);
                let digest: Uint8Array;
                try {
                    digest = decodeBase64Url(encodedDigest, 32);
                } catch {
                    throw new RelayError(400, "Invalid invitation digest", {
                        error: "malformed",
                    });
                }
                const invitation = await relay.readInvitation(digest);
                return new Response(invitation.bundle, {
                    status: 200,
                    headers: {
                        "content-type": "application/vnd.slopus.murmur-discovery+json",
                        "cache-control": "no-store",
                        "x-murmur-invitation-expires-at": String(invitation.expiresAt),
                        ...corsHeaders,
                    },
                });
            }
            if (request.method === "POST" && url.pathname === "/v1/deliveries") {
                const delivery = parseSignedDelivery(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                if (admissionPrincipal === undefined) {
                    throw new RelayError(503, "Admission principal is required", {
                        error: "admission_context_required",
                    });
                }
                const outcome = await relay.publish(delivery, admissionPrincipal);
                return boundedJson(
                    {
                        eventId: outcome.eventId,
                        duplicate: outcome.duplicate,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/queue/read") {
                const read = parseSignedQueueRead(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const page = await relay.readQueue(
                    read,
                    request.signal,
                    relay.options.maximumJsonBodyBytes,
                );
                return boundedJson(
                    {
                        deliveries: page.deliveries.map((queued) => ({
                            eventId: queued.eventId,
                            sequence: queued.sequence,
                            delivery: signedDeliveryToJson(queued.delivery),
                        })),
                        head: page.head,
                        headSequence: page.headSequence,
                        acknowledgedThrough: page.acknowledgedThrough,
                        acknowledgedSequence: page.acknowledgedSequence,
                        generation: encodeBase64Url(page.generation),
                        exhausted: page.exhausted,
                    },
                    relay.options.maximumJsonBodyBytes,
                    corsHeaders,
                    {
                        error: "delivery_too_large",
                        eventId: page.deliveries[0]?.eventId ?? null,
                        sequence: page.deliveries[0]?.sequence ?? null,
                        head: page.head,
                        headSequence: page.headSequence,
                        acknowledgedThrough: page.acknowledgedThrough,
                        acknowledgedSequence: page.acknowledgedSequence,
                        generation: encodeBase64Url(page.generation),
                    },
                );
            }
            if (request.method === "POST" && url.pathname === "/v1/queue/events") {
                const read = parseSignedQueueRead(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const subscription = await relay.openQueueEventStream(read, request.signal);
                return queueEventResponse(subscription, request.signal, corsHeaders);
            }
            if (request.method === "POST" && url.pathname === "/v1/queue/ack") {
                const acknowledgement = parseSignedQueueAck(
                    await readJson(request, relay.options.maximumJsonBodyBytes),
                );
                const outcome = await relay.acknowledge(acknowledgement);
                return boundedJson(
                    {
                        removed: outcome.removed,
                        sequence: outcome.sequence,
                        generation: encodeBase64Url(outcome.generation),
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
