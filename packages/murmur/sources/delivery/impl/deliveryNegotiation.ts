import type { Context } from "@steve.kite/stdlib";

import type { IdentityKeyPair } from "../../crypto/index.js";
import {
    randomBytes,
    signBytes,
    validateIdentityPublicKey,
    verifyBytes,
} from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Encode,
} from "../../utils/index.js";
import type {
    DeliveryFetch,
    HttpRelaySessionProviderOptions,
    RelaySessionProvider,
    RelaySessionTicket,
    SignedRelaySessionRequest,
} from "../types.js";

const SESSION_DOMAIN = "murmur.relay.session.v1";
const DEFAULT_MAXIMUM_RESPONSE_BYTES = 16 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MILLISECONDS = 15_000;
const MAXIMUM_TOKEN_CHARACTERS = 8 * 1024;
const MAXIMUM_ENDPOINT_CHARACTERS = 2 * 1024;
const SUBPROTOCOL_TOKEN = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;

/** JSON representation of one device-signed relay-session request. */
export interface SignedRelaySessionRequestJson {
    readonly version: 1;
    readonly device: string;
    readonly createdAt: number;
    readonly nonce: string;
    readonly signature: string;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function separated(value: Parameters<typeof canonicalJsonBytes>[0]): Uint8Array {
    const prefix = utf8Encode(`${SESSION_DOMAIN}\0`);
    const body = canonicalJsonBytes(value);
    const bytes = new Uint8Array(prefix.length + body.length);
    bytes.set(prefix);
    bytes.set(body, prefix.length);
    return bytes;
}

/** Convert a signed relay-session request to its strict JSON representation. */
export function signedRelaySessionRequestToJson(
    request: SignedRelaySessionRequest,
): SignedRelaySessionRequestJson {
    return {
        version: 1,
        device: encodeBase64Url(request.device),
        createdAt: request.createdAt,
        nonce: encodeBase64Url(request.nonce),
        signature: encodeBase64Url(request.signature),
    };
}

function signingBytes(request: SignedRelaySessionRequest): Uint8Array {
    const { signature: _signature, ...unsigned } = signedRelaySessionRequestToJson(request);
    return separated(unsigned);
}

function validateRequest(request: SignedRelaySessionRequest): void {
    validateIdentityPublicKey({ publicKey: request.device });
    if (
        request.version !== 1 ||
        !Number.isSafeInteger(request.createdAt) ||
        request.createdAt < 0 ||
        request.nonce.length !== 24 ||
        request.signature.length !== 64
    ) {
        throw new Error("Invalid relay-session request");
    }
}

/** Create a fresh device-signed proof for an application relay-session issuer. */
export function createSignedRelaySessionRequest(
    identity: IdentityKeyPair,
    createdAt: number = Date.now(),
    nonce: Uint8Array = randomBytes(24),
): SignedRelaySessionRequest {
    const request: SignedRelaySessionRequest = {
        version: 1,
        device: identity.publicKey.slice(),
        createdAt,
        nonce: nonce.slice(),
        signature: new Uint8Array(64),
    };
    validateRequest(request);
    return { ...request, signature: signBytes(identity, signingBytes(request)) };
}

/** Strictly decode one device-signed relay-session request. */
export function parseSignedRelaySessionRequest(value: unknown): SignedRelaySessionRequest {
    const input = object(value, "relay-session request");
    exact(input, ["version", "device", "createdAt", "nonce", "signature"], "relay-session request");
    if (
        input.version !== 1 ||
        typeof input.device !== "string" ||
        typeof input.createdAt !== "number" ||
        typeof input.nonce !== "string" ||
        typeof input.signature !== "string"
    ) {
        throw new Error("Invalid relay-session request");
    }
    const request: SignedRelaySessionRequest = {
        version: 1,
        device: decodeBase64Url(input.device),
        createdAt: input.createdAt,
        nonce: decodeBase64Url(input.nonce),
        signature: decodeBase64Url(input.signature),
    };
    if (
        encodeBase64Url(request.device) !== input.device ||
        encodeBase64Url(request.nonce) !== input.nonce ||
        encodeBase64Url(request.signature) !== input.signature
    ) {
        throw new Error("Invalid relay-session request");
    }
    validateRequest(request);
    return request;
}

/** Verify the proof-of-possession signature on a relay-session request. */
export function verifySignedRelaySessionRequest(request: SignedRelaySessionRequest): boolean {
    try {
        validateRequest(request);
        return verifyBytes({ publicKey: request.device }, signingBytes(request), request.signature);
    } catch {
        return false;
    }
}

/** Strictly validate a negotiated WebSocket relay ticket. */
export function parseRelaySessionTicket(value: unknown): RelaySessionTicket {
    const input = object(value, "relay-session ticket");
    exact(input, ["version", "protocol", "endpoint", "token", "expiresAt"], "relay-session ticket");
    if (
        input.version !== 1 ||
        input.protocol !== "murmur-websocket-v1" ||
        typeof input.endpoint !== "string" ||
        input.endpoint.length < 1 ||
        input.endpoint.length > MAXIMUM_ENDPOINT_CHARACTERS ||
        typeof input.token !== "string" ||
        input.token.length < 1 ||
        input.token.length > MAXIMUM_TOKEN_CHARACTERS ||
        !SUBPROTOCOL_TOKEN.test(input.token) ||
        typeof input.expiresAt !== "number" ||
        !Number.isSafeInteger(input.expiresAt) ||
        input.expiresAt < 0
    ) {
        throw new Error("Invalid relay-session ticket");
    }
    const endpoint = new URL(input.endpoint);
    if (endpoint.protocol !== "wss:" && endpoint.protocol !== "ws:") {
        throw new Error("Relay-session endpoint must use WebSocket");
    }
    if (endpoint.username !== "" || endpoint.password !== "" || endpoint.hash !== "") {
        throw new Error("Invalid relay-session endpoint");
    }
    return {
        version: 1,
        protocol: "murmur-websocket-v1",
        endpoint: endpoint.toString(),
        token: input.token,
        expiresAt: input.expiresAt,
    };
}

async function boundedResponseJson(response: Response, maximumBytes: number): Promise<unknown> {
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new Error("Relay-session response exceeds client limit");
    }
    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("Relay-session response has no body");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        for (;;) {
            const result = await reader.read();
            if (result.done) break;
            size += result.value.length;
            if (size > maximumBytes || chunks.length >= 1_024) {
                await reader.cancel().catch(() => undefined);
                throw new Error("Relay-session response exceeds client limit");
            }
            chunks.push(result.value);
        }
    } finally {
        reader.releaseLock();
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
        throw new Error("Invalid relay-session response JSON");
    }
}

/** Fetch-backed application authentication boundary for negotiated relay sessions. */
export class HttpRelaySessionProvider implements RelaySessionProvider {
    readonly #url: URL;
    readonly #fetch: DeliveryFetch;
    readonly #maximumResponseBytes: number;
    readonly #requestTimeoutMilliseconds: number;

    constructor(url: string | URL, options: HttpRelaySessionProviderOptions = {}) {
        this.#url = new URL(url);
        if (this.#url.protocol !== "https:" && this.#url.protocol !== "http:") {
            throw new Error("Relay-session issuer URL must use HTTP or HTTPS");
        }
        this.#fetch = options.fetch ?? ((_ctx, input, init) => globalThis.fetch(input, init));
        this.#maximumResponseBytes = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
        this.#requestTimeoutMilliseconds =
            options.requestTimeoutMilliseconds ?? DEFAULT_REQUEST_TIMEOUT_MILLISECONDS;
        if (!Number.isSafeInteger(this.#maximumResponseBytes) || this.#maximumResponseBytes < 1) {
            throw new Error("Maximum relay-session response bytes must be positive");
        }
        if (
            !Number.isSafeInteger(this.#requestTimeoutMilliseconds) ||
            this.#requestTimeoutMilliseconds < 1 ||
            this.#requestTimeoutMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Relay-session request timeout must be between 1ms and 5 minutes");
        }
    }

    /** Ask the application server to authenticate and route one device. */
    async issue(
        ctx: Context,
        request: SignedRelaySessionRequest,
        signal?: AbortSignal,
    ): Promise<RelaySessionTicket> {
        validateRequest(request);
        const controller = new AbortController();
        const forwardAbort = (): void => controller.abort(signal?.reason);
        if (signal?.aborted === true) {
            forwardAbort();
        } else {
            signal?.addEventListener("abort", forwardAbort, { once: true });
        }
        const timeout = setTimeout(
            () => controller.abort(new Error("Relay-session request timed out")),
            this.#requestTimeoutMilliseconds,
        );
        try {
            const response = await this.#fetch(ctx, this.#url, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(signedRelaySessionRequestToJson(request)),
                signal: controller.signal,
            });
            const value = await boundedResponseJson(response, this.#maximumResponseBytes);
            if (!response.ok) {
                const failure = object(value, "relay-session failure");
                throw new Error(
                    `Relay-session request failed (${response.status} ${typeof failure.error === "string" ? failure.error : "unknown"})`,
                );
            }
            return parseRelaySessionTicket(value);
        } finally {
            clearTimeout(timeout);
            signal?.removeEventListener("abort", forwardAbort);
        }
    }
}
