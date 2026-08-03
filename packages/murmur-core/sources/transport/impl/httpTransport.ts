import { hashBytes } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode } from "../../utils/index.js";
import type {
    EventPage,
    ListPage,
    PublishOutcome,
    RelayBlob,
    RelayFetch,
    RelayStreamHandlers,
    RelayTransport,
    SignedRelayEvent,
    TopicState,
} from "../types.js";
import {
    MAX_RELAY_BLOB_BYTES,
    MAX_RELAY_EPHEMERAL_FRAME_BYTES,
    RelayBlobIntegrityError,
} from "../types.js";
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
const MAXIMUM_EPHEMERAL_RESPONSE_BYTES = 1_024;

/**
 * Hard cap on the bytes buffered for a single SSE event.
 *
 * Comfortably above one base64url-encoded {@link MAX_RELAY_EPHEMERAL_FRAME_BYTES}
 * frame (~174 KiB) so a legitimate `frame` event fits, while any line or event
 * that grows past it fails the stream instead of buffering without bound.
 */
const MAXIMUM_STREAM_EVENT_BYTES = 256 * 1024;

const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const COLON = 0x3a;

/** Read one non-negative safe-integer field from a small JSON relay body. */
function readCountField(text: string, field: string): number {
    const parsed = JSON.parse(text) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error(`Relay returned an invalid ${field} response`);
    }
    const value = (parsed as Record<string, unknown>)[field];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Relay returned an invalid ${field} response`);
    }
    return value;
}

/**
 * Incremental parser for the relay's `text/event-stream` framing.
 *
 * Bytes arrive in arbitrary chunks that may split a line or a UTF-8 sequence.
 * Lines are separated on the `\n` byte (a byte that never appears inside a
 * multi-byte UTF-8 sequence), tolerating a trailing `\r`. The pending line, the
 * retained event name, and the accumulated event data are bounded together by
 * {@link MAXIMUM_STREAM_EVENT_BYTES}: every line is measured before it is
 * decoded or retained, so exceeding the bound throws and fails the stream
 * instead of decoding or buffering without bound.
 */
class EventStreamParser {
    readonly #handlers: RelayStreamHandlers;
    #line: Uint8Array = new Uint8Array(0);
    #eventName = "";
    #eventNameBytes = 0;
    #data: string[] = [];
    #dataBytes = 0;

    constructor(handlers: RelayStreamHandlers) {
        this.#handlers = handlers;
    }

    /** Feed one received chunk, dispatching every complete event it contains. */
    push(chunk: Uint8Array): void {
        let start = 0;
        for (let index = 0; index < chunk.length; index += 1) {
            if (chunk[index] === LINE_FEED) {
                this.#handleLine(this.#takeLine(chunk.subarray(start, index)));
                start = index + 1;
            }
        }
        if (start < chunk.length) {
            this.#appendPending(chunk.subarray(start));
        }
    }

    #takeLine(tail: Uint8Array): Uint8Array {
        const pending = this.#line;
        this.#line = new Uint8Array(0);
        let line: Uint8Array;
        if (pending.length === 0) {
            line = tail;
        } else {
            line = new Uint8Array(pending.length + tail.length);
            line.set(pending, 0);
            line.set(tail, pending.length);
        }
        if (line.length > 0 && line[line.length - 1] === CARRIAGE_RETURN) {
            return line.subarray(0, line.length - 1);
        }
        return line;
    }

    #appendPending(tail: Uint8Array): void {
        const combined = new Uint8Array(this.#line.length + tail.length);
        combined.set(this.#line, 0);
        combined.set(tail, this.#line.length);
        this.#line = combined;
        this.#enforceBound(this.#line.length);
    }

    #enforceBound(pendingLineBytes: number): void {
        if (
            pendingLineBytes + this.#eventNameBytes + this.#dataBytes >
            MAXIMUM_STREAM_EVENT_BYTES
        ) {
            throw new Error("Relay stream event exceeded its maximum size");
        }
    }

    #handleLine(line: Uint8Array): void {
        // Measure before decoding: a whole oversized line can arrive in one chunk.
        this.#enforceBound(line.length);
        if (line.length === 0) {
            this.#dispatch();
            return;
        }
        if (line[0] === COLON) {
            return;
        }
        const separator = line.indexOf(COLON);
        const field = utf8Decode(separator === -1 ? line : line.subarray(0, separator));
        let value = separator === -1 ? "" : utf8Decode(line.subarray(separator + 1));
        if (value.startsWith(" ")) {
            value = value.slice(1);
        }
        if (field === "event") {
            // The name replaces any earlier one, so its bytes replace them too.
            this.#eventName = value;
            this.#eventNameBytes = line.length;
        } else if (field === "data") {
            this.#data.push(value);
            this.#dataBytes += line.length;
        }
    }

    #dispatch(): void {
        const name = this.#eventName;
        const data = this.#data.join("\n");
        this.#eventName = "";
        this.#eventNameBytes = 0;
        this.#data = [];
        this.#dataBytes = 0;
        if (name.length === 0 && data.length === 0) {
            return;
        }
        switch (name) {
            case "ready":
                this.#handlers.onReady?.();
                return;
            case "frame":
                this.#handlers.onFrame?.(decodeBase64Url(data));
                return;
            case "wake":
                this.#handlers.onWake?.();
                return;
            case "drop":
                this.#handlers.onDrop?.(readCountField(data, "frames"));
                return;
            default:
                return;
        }
    }
}

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

    async publishEphemeral(
        topic: string,
        frame: Uint8Array,
        signal?: AbortSignal,
    ): Promise<number> {
        if (!(frame instanceof Uint8Array) || frame.length > MAX_RELAY_EPHEMERAL_FRAME_BYTES) {
            throw new Error(`Ephemeral frame exceeds ${MAX_RELAY_EPHEMERAL_FRAME_BYTES} bytes`);
        }
        const response = await this.#fetch(
            `${this.#baseUrl}${this.#topicPath(topic, "ephemeral")}`,
            {
                method: "POST",
                headers: { "content-type": "application/octet-stream" },
                body: requestBody(frame),
                ...(signal === undefined ? {} : { signal }),
            },
        );
        await this.#requireOk(response);
        return readCountField(
            utf8Decode(await readBoundedResponse(response, MAXIMUM_EPHEMERAL_RESPONSE_BYTES)),
            "delivered",
        );
    }

    async openStream(
        topic: string,
        handlers: RelayStreamHandlers,
        signal: AbortSignal,
    ): Promise<void> {
        if (signal.aborted) {
            return;
        }
        const response = await this.#fetch(`${this.#baseUrl}${this.#topicPath(topic, "stream")}`, {
            method: "GET",
            headers: { accept: "text/event-stream" },
            signal,
        });
        await this.#requireOk(response);
        if (response.body === null) {
            return;
        }
        const reader = response.body.getReader();
        const parser = new EventStreamParser(handlers);
        const abort = (): void => {
            reader.cancel("Relay stream aborted").catch(() => undefined);
        };
        signal.addEventListener("abort", abort, { once: true });
        try {
            for (;;) {
                let result: ReadableStreamReadResult<Uint8Array>;
                try {
                    result = await reader.read();
                } catch (error) {
                    if (signal.aborted) {
                        return;
                    }
                    throw error;
                }
                if (result.done) {
                    return;
                }
                parser.push(result.value);
            }
        } catch (error) {
            reader.cancel("Relay stream failed").catch(() => undefined);
            if (signal.aborted) {
                return;
            }
            throw error;
        } finally {
            signal.removeEventListener("abort", abort);
            reader.releaseLock();
        }
    }

    #topicPath(
        topic: string,
        resource: "ephemeral" | "events" | "list" | "state" | "stream",
    ): string {
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
