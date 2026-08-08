import { sha256 } from "@noble/hashes/sha2";
import { decodeBase64Url, encodeBase64Url, equalBytes, utf8Decode } from "../../../utils/index.js";
import type {
    DiscoveryFetch,
    DiscoveryTransport,
    DiscoveryUploadOutcome,
    HttpDiscoveryTransportOptions,
} from "../types.js";

const DEFAULT_MAXIMUM_RESPONSE_BYTES = 64 * 1024;

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid discovery relay response");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid discovery relay response");
    }
}

async function boundedResponseBytes(response: Response, maximumBytes: number): Promise<Uint8Array> {
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new Error("Discovery relay response exceeds client limit");
    }
    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("Discovery relay response has no body");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        for (;;) {
            const result = await reader.read();
            if (result.done) break;
            size += result.value.length;
            if (size > maximumBytes || chunks.length >= 65_536) {
                await reader.cancel().catch(() => undefined);
                throw new Error("Discovery relay response exceeds client limit");
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
    return bytes;
}

/** Error returned by the relay's ephemeral discovery-cache boundary. */
export class DiscoveryTransportError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string) {
        super(`Discovery relay request failed (${status} ${code})`);
        this.name = "DiscoveryTransportError";
        this.status = status;
        this.code = code;
    }
}

/** Fetch-backed content-addressed discovery-cache transport. */
export class HttpDiscoveryTransport implements DiscoveryTransport {
    readonly #baseUrl: URL;
    readonly #fetch: DiscoveryFetch;
    readonly #maximumResponseBytes: number;
    readonly #requestTimeoutMilliseconds: number;

    constructor(baseUrl: string | URL, options: HttpDiscoveryTransportOptions = {}) {
        this.#baseUrl = new URL(baseUrl);
        if (this.#baseUrl.protocol !== "https:" && this.#baseUrl.protocol !== "http:") {
            throw new Error("Discovery relay URL must use HTTP or HTTPS");
        }
        this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
        this.#maximumResponseBytes = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
        this.#requestTimeoutMilliseconds = options.requestTimeoutMilliseconds ?? 45_000;
        if (!Number.isSafeInteger(this.#maximumResponseBytes) || this.#maximumResponseBytes < 1) {
            throw new Error("Maximum discovery response bytes must be a positive safe integer");
        }
        if (
            !Number.isSafeInteger(this.#requestTimeoutMilliseconds) ||
            this.#requestTimeoutMilliseconds < 1 ||
            this.#requestTimeoutMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Discovery request timeout must be between 1ms and 5 minutes");
        }
    }

    async upload(bundle: Uint8Array, signal?: AbortSignal): Promise<DiscoveryUploadOutcome> {
        if (!(bundle instanceof Uint8Array) || bundle.length < 1) {
            throw new Error("Invalid discovery bundle bytes");
        }
        const { response, bytes } = await this.#requestBytes(
            "/v1/invitations",
            {
                method: "POST",
                headers: {
                    "content-type": "application/vnd.slopus.murmur-discovery+json",
                },
                body: bundle.slice(),
            },
            signal,
        );
        const value = this.#responseJson(response, bytes);
        if (!response.ok) this.#throwResponse(response.status, value);
        const outcome = object(value);
        exact(outcome, ["digest", "expiresAt", "duplicate"]);
        if (
            typeof outcome.digest !== "string" ||
            typeof outcome.expiresAt !== "number" ||
            !Number.isSafeInteger(outcome.expiresAt) ||
            typeof outcome.duplicate !== "boolean"
        ) {
            throw new Error("Invalid discovery relay response");
        }
        const digest = decodeBase64Url(outcome.digest);
        if (digest.length !== 32) throw new Error("Invalid discovery relay response");
        if (!equalBytes(digest, sha256(bundle))) {
            throw new Error("Discovery relay returned the wrong bundle digest");
        }
        return {
            digest,
            expiresAt: outcome.expiresAt,
            duplicate: outcome.duplicate,
        };
    }

    async download(digest: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
        if (!(digest instanceof Uint8Array) || digest.length !== 32) {
            throw new Error("Invalid invitation digest");
        }
        const { response, bytes } = await this.#requestBytes(
            `/v1/invitations/${encodeBase64Url(digest)}`,
            { method: "GET" },
            signal,
        );
        if (!response.ok) {
            this.#throwResponse(response.status, this.#responseJson(response, bytes));
        }
        if (!equalBytes(sha256(bytes), digest)) {
            throw new Error("Downloaded invitation digest does not match");
        }
        return bytes;
    }

    async #requestBytes(
        path: string,
        init: RequestInit,
        signal?: AbortSignal,
    ): Promise<{ readonly response: Response; readonly bytes: Uint8Array }> {
        const controller = new AbortController();
        const forwardAbort = (): void => controller.abort(signal?.reason);
        if (signal?.aborted === true) {
            forwardAbort();
        } else {
            signal?.addEventListener("abort", forwardAbort, { once: true });
        }
        const timeout = setTimeout(() => {
            controller.abort(new Error("Discovery relay request timed out"));
        }, this.#requestTimeoutMilliseconds);
        try {
            const response = await this.#fetch(new URL(path, this.#baseUrl), {
                ...init,
                signal: controller.signal,
            });
            return {
                response,
                bytes: await boundedResponseBytes(response, this.#maximumResponseBytes),
            };
        } finally {
            clearTimeout(timeout);
            signal?.removeEventListener("abort", forwardAbort);
        }
    }

    #responseJson(response: Response, bytes: Uint8Array): unknown {
        try {
            return JSON.parse(utf8Decode(bytes)) as unknown;
        } catch {
            if (response.ok) throw new Error("Invalid discovery relay response JSON");
            return { error: "unknown" };
        }
    }

    #throwResponse(status: number, value: unknown): never {
        const failure = object(value);
        throw new DiscoveryTransportError(
            status,
            typeof failure.error === "string" ? failure.error : "unknown",
        );
    }
}
