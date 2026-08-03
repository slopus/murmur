import { hashBytes } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode } from "../../utils/index.js";
import type {
    EventPage,
    ListPage,
    PublishOutcome,
    RelayBlob,
    RelayFetch,
    RelayTransport,
    SignedRelayEvent,
    TopicState,
} from "../types.js";
import { MAX_RELAY_BLOB_BYTES, RelayBlobIntegrityError } from "../types.js";
import {
    decodeEventPageWire,
    decodeListPageWire,
    decodePublishOutcomeWire,
    decodeTopicStateWire,
    encodeSignedRelayEventWire,
} from "./wireCodec.js";

function requestBody(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer as ArrayBuffer;
}

const MAXIMUM_RESPONSE_CHUNKS = 65_536;

async function readBoundedResponse(response: Response, maximumBytes: number): Promise<Uint8Array> {
    const declaredLength = response.headers.get("content-length");
    if (
        declaredLength !== null &&
        (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes)
    ) {
        throw new Error("Relay response is too large");
    }
    if (response.body === null) {
        return new Uint8Array();
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        for (;;) {
            const result = await reader.read();
            if (result.done) {
                break;
            }
            total += result.value.length;
            if (total > maximumBytes) {
                await reader.cancel("Relay response is too large").catch(() => undefined);
                throw new Error("Relay response is too large");
            }
            chunks.push(result.value);
            if (chunks.length > MAXIMUM_RESPONSE_CHUNKS) {
                await reader.cancel("Relay response has too many chunks").catch(() => undefined);
                throw new Error("Relay response has too many chunks");
            }
        }
    } finally {
        reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    return bytes;
}

const MAXIMUM_PAGE_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES = 1_024;
const MAXIMUM_BLOB_LINK_RESPONSE_BYTES = 16 * 1024;

interface BlobLink {
    readonly url: string;
    readonly method: "PUT" | "GET";
    readonly expiresAt: number;
    readonly headers?: Readonly<Record<string, string>>;
}

function blobMaximumBytes(expectedBytes: number | undefined): number {
    if (
        expectedBytes !== undefined &&
        (!Number.isSafeInteger(expectedBytes) ||
            expectedBytes < 0 ||
            expectedBytes > MAX_RELAY_BLOB_BYTES)
    ) {
        throw new Error(`Expected relay blob bytes must be from 0 through ${MAX_RELAY_BLOB_BYTES}`);
    }
    return expectedBytes ?? MAX_RELAY_BLOB_BYTES;
}

async function readBlobResponse(
    response: Response,
    id: string,
    expectedBytes: number | undefined,
): Promise<Uint8Array> {
    const maximumBytes = blobMaximumBytes(expectedBytes);
    let bytes: Uint8Array;
    try {
        bytes = await readBoundedResponse(response, maximumBytes);
    } catch (error) {
        if (error instanceof Error && error.message.startsWith("Relay response")) {
            throw new RelayBlobIntegrityError(`Relay blob ${id} violates response bounds`);
        }
        throw error;
    }
    if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
        throw new RelayBlobIntegrityError(`Relay blob ${id} does not match its expected size`);
    }
    return bytes;
}

function blobLink(bytes: Uint8Array, expectedMethod: "PUT" | "GET"): BlobLink {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("Relay returned an invalid blob link");
    }
    const value = parsed as Record<string, unknown>;
    const allowed = new Set(["url", "method", "expiresAt", "headers"]);
    if (
        typeof value.url !== "string" ||
        value.url.length === 0 ||
        value.method !== expectedMethod ||
        typeof value.expiresAt !== "number" ||
        !Number.isSafeInteger(value.expiresAt) ||
        value.expiresAt < 0 ||
        Object.keys(value).some((key) => !allowed.has(key))
    ) {
        throw new Error("Relay returned an invalid blob link");
    }
    let headers: Readonly<Record<string, string>> | undefined;
    if (Object.hasOwn(value, "headers")) {
        if (
            typeof value.headers !== "object" ||
            value.headers === null ||
            Array.isArray(value.headers)
        ) {
            throw new Error("Relay returned invalid blob link headers");
        }
        const headerRecord = value.headers as Record<string, unknown>;
        if (Object.values(headerRecord).some((header) => typeof header !== "string")) {
            throw new Error("Relay returned invalid blob link headers");
        }
        headers = Object.fromEntries(
            Object.entries(headerRecord).map(([name, header]) => [name, String(header)]),
        );
    }
    return {
        url: value.url,
        method: expectedMethod,
        expiresAt: value.expiresAt,
        ...(headers === undefined ? {} : { headers }),
    };
}

function query(
    path: string,
    values: Readonly<Record<string, string | number | undefined>>,
): string {
    const parameters = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
        if (value !== undefined) {
            parameters.set(key, String(value));
        }
    }
    const encoded = parameters.toString();
    return encoded.length === 0 ? path : `${path}?${encoded}`;
}

function isLocalHostname(value: string): boolean {
    const hostname = value.toLowerCase().replace(/^\[|\]$/g, "");
    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname === "::" ||
        hostname === "::1" ||
        /^(?:fc|fd|fe[89ab])/i.test(hostname)
    ) {
        return true;
    }
    const octets = hostname.split(".").map(Number);
    if (
        octets.length !== 4 ||
        octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
    ) {
        return false;
    }
    const [first = -1, second = -1] = octets;
    return (
        first === 0 ||
        first === 10 ||
        first === 127 ||
        (first === 100 && second >= 64 && second <= 127) ||
        (first === 169 && second === 254) ||
        (first === 172 && second >= 16 && second <= 31) ||
        (first === 192 && second === 168) ||
        first >= 224
    );
}

/** Browser-safe HTTP transport for the fixed topic-state relay protocol. */
export class HttpRelayTransport implements RelayTransport {
    readonly #baseUrl: string;
    readonly #fetch: RelayFetch;

    constructor(
        readonly id: string,
        baseUrl: string,
        fetchImplementation: RelayFetch = globalThis.fetch,
    ) {
        this.#baseUrl = baseUrl.replace(/\/+$/, "");
        this.#fetch = fetchImplementation;
    }

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        const response = await this.#fetch(
            `${this.#baseUrl}/v1/topics/${encodeURIComponent(event.topic)}/events`,
            {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: requestBody(encodeSignedRelayEventWire(event)),
            },
        );
        await this.#requireOk(response);
        return decodePublishOutcomeWire(
            await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES),
        );
    }

    async readState(topic: string, limit?: number): Promise<TopicState | undefined> {
        const response = await this.#get(query(this.#topicPath(topic, "state"), { limit }));
        return response === undefined
            ? undefined
            : decodeTopicStateWire(
                  await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES),
              );
    }

    async readList(topic: string, cursor?: string, limit?: number): Promise<ListPage | undefined> {
        const response = await this.#get(query(this.#topicPath(topic, "list"), { cursor, limit }));
        return response === undefined
            ? undefined
            : decodeListPageWire(await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES));
    }

    async readEvents(
        topic: string,
        since: bigint,
        limit?: number,
        wait?: number,
        signal?: AbortSignal,
    ): Promise<EventPage | undefined> {
        const response = await this.#get(
            query(this.#topicPath(topic, "events"), {
                since: since.toString(),
                limit,
                wait,
            }),
            signal,
        );
        return response === undefined
            ? undefined
            : decodeEventPageWire(await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES));
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        const link = await this.#blobLink(blob.id, "upload-link", "PUT");
        const response = await this.#fetch(this.#blobLinkUrl(link.url), {
            method: link.method,
            ...(link.headers === undefined ? {} : { headers: link.headers }),
            body: requestBody(blob.bytes),
        });
        await this.#requireOk(response);
    }

    async getBlob(id: string, expectedBytes?: number): Promise<RelayBlob | undefined> {
        let decodedId: Uint8Array;
        try {
            decodedId = decodeBase64Url(id);
        } catch {
            throw new Error("Invalid relay blob identifier");
        }
        if (
            decodedId.length !== 32 ||
            encodeBase64Url(decodedId) !== id ||
            !/^[A-Za-z0-9_-]{43}$/.test(id)
        ) {
            throw new Error("Invalid relay blob identifier");
        }
        const link = await this.#blobLink(id, "download-link", "GET", true);
        if (link === undefined) {
            return undefined;
        }
        const response = await this.#fetch(this.#blobLinkUrl(link.url), {
            method: link.method,
            ...(link.headers === undefined ? {} : { headers: link.headers }),
        });
        if (response.status === 404) {
            return undefined;
        }
        await this.#requireOk(response);
        const blob = {
            id,
            bytes: await readBlobResponse(response, id, expectedBytes),
        };
        if (encodeBase64Url(hashBytes(blob.bytes)) !== id) {
            throw new RelayBlobIntegrityError("Relay blob failed content-address validation");
        }
        return blob;
    }

    #topicPath(topic: string, resource: "events" | "list" | "state"): string {
        return `/v1/topics/${encodeURIComponent(topic)}/${resource}`;
    }

    async #blobLink(
        id: string,
        resource: "upload-link" | "download-link",
        method: "PUT" | "GET",
        allowMissing: true,
    ): Promise<BlobLink | undefined>;
    async #blobLink(
        id: string,
        resource: "upload-link" | "download-link",
        method: "PUT" | "GET",
        allowMissing?: false,
    ): Promise<BlobLink>;
    async #blobLink(
        id: string,
        resource: "upload-link" | "download-link",
        method: "PUT" | "GET",
        allowMissing: boolean = false,
    ): Promise<BlobLink | undefined> {
        const response = await this.#fetch(
            `${this.#baseUrl}/v1/blobs/${encodeURIComponent(id)}/${resource}`,
            { method: "POST" },
        );
        if (allowMissing && response.status === 404) {
            return undefined;
        }
        await this.#requireOk(response);
        return blobLink(
            await readBoundedResponse(response, MAXIMUM_BLOB_LINK_RESPONSE_BYTES),
            method,
        );
    }

    #blobLinkUrl(value: string): string {
        const base = new URL(`${this.#baseUrl}/`);
        const resolved = new URL(value, base);
        if (
            resolved.username.length > 0 ||
            resolved.password.length > 0 ||
            (resolved.origin !== base.origin &&
                (resolved.protocol !== "https:" || isLocalHostname(resolved.hostname)))
        ) {
            throw new Error("Relay returned an unsafe blob link");
        }
        return resolved.toString();
    }

    async #get(path: string, signal?: AbortSignal): Promise<Response | undefined> {
        const response = await this.#fetch(`${this.#baseUrl}${path}`, {
            method: "GET",
            ...(signal === undefined ? {} : { signal }),
        });
        if (response.status === 404) {
            return undefined;
        }
        await this.#requireOk(response);
        return response;
    }

    async #requireOk(response: Response): Promise<void> {
        if (response.ok) {
            return;
        }
        const details = utf8Decode(
            await readBoundedResponse(response, MAXIMUM_ERROR_RESPONSE_BYTES),
        );
        throw new Error(
            `Relay ${this.id} returned HTTP ${response.status}${details.length === 0 ? "" : `: ${details}`}`,
        );
    }
}
