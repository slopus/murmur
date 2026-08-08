import { utf8Decode } from "../../utils/index.js";
import type {
    DeliveryFetch,
    DeliveryPublishOutcome,
    DeliveryTransport,
    InboxDelivery,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../types.js";
import {
    parseInboxPage,
    signedDeliveryToJson,
    signedInboxAckToJson,
    signedInboxReadToJson,
} from "./deliveryCodec.js";
import { decodeDeliveryEventStream } from "./deliverySse.js";

const DEFAULT_MAXIMUM_RESPONSE_BYTES = 16 * 1024 * 1024;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Error returned by the relay HTTP boundary. */
export class DeliveryTransportError extends Error {
    /** HTTP response status. */
    readonly status: number;
    /** Stable relay error code when one was returned. */
    readonly code: string;

    constructor(status: number, code: string) {
        super(`Delivery relay request failed (${status} ${code})`);
        this.name = "DeliveryTransportError";
        this.status = status;
        this.code = code;
    }
}

/** Terminal metadata for an inbox head too large for the relay response budget. */
export class OversizedInboxDeliveryError extends DeliveryTransportError {
    readonly eventId: string;
    readonly head: string;
    readonly acknowledgedThrough: string | null;

    constructor(eventId: string, head: string, acknowledgedThrough: string | null) {
        super(413, "delivery_too_large");
        this.name = "OversizedInboxDeliveryError";
        this.eventId = eventId;
        this.head = head;
        this.acknowledgedThrough = acknowledgedThrough;
    }
}

/** Relay cursor metadata proving that local queue state was rolled back. */
export class DeliveryCursorTrimmedError extends DeliveryTransportError {
    readonly acknowledgedThrough: string;

    constructor(code: "cursor_trimmed" | "ack_regression", acknowledgedThrough: string) {
        super(409, code);
        this.name = "DeliveryCursorTrimmedError";
        this.acknowledgedThrough = acknowledgedThrough;
    }
}

/** Relay metadata showing an acknowledgement beyond the current inbox head. */
export class DeliveryAcknowledgementFutureError extends DeliveryTransportError {
    readonly head: string;

    constructor(head: string) {
        super(409, "ack_future");
        this.name = "DeliveryAcknowledgementFutureError";
        this.head = head;
    }
}

/** Configuration for the browser-safe relay HTTP transport. */
export interface HttpDeliveryTransportOptions {
    readonly fetch?: DeliveryFetch;
    readonly maximumResponseBytes?: number;
    readonly requestTimeoutMilliseconds?: number;
    readonly streamHeartbeatTimeoutMilliseconds?: number;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid relay response");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid relay response");
    }
}

function uuid(value: unknown): string {
    if (typeof value !== "string" || !UUID_V7.test(value)) {
        throw new Error("Invalid relay event ID");
    }
    return value;
}

async function boundedResponseJson(response: Response, maximumBytes: number): Promise<unknown> {
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new Error("Relay response exceeds client limit");
    }
    const reader = response.body?.getReader();
    if (reader === undefined) {
        throw new Error("Relay response has no body");
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        for (;;) {
            const result = await reader.read();
            if (result.done) break;
            size += result.value.length;
            if (size > maximumBytes || chunks.length >= 65_536) {
                await reader.cancel().catch(() => undefined);
                throw new Error("Relay response exceeds client limit");
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
        return JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid relay response JSON");
    }
}

/** Fetch-backed implementation of the Murmur delivery transport. */
export class HttpDeliveryTransport implements DeliveryTransport {
    readonly #baseUrl: URL;
    readonly #fetch: DeliveryFetch;
    readonly #maximumResponseBytes: number;
    readonly #requestTimeoutMilliseconds: number;
    readonly #streamHeartbeatTimeoutMilliseconds: number;

    constructor(baseUrl: string | URL, options: HttpDeliveryTransportOptions = {}) {
        this.#baseUrl = new URL(baseUrl);
        if (this.#baseUrl.protocol !== "https:" && this.#baseUrl.protocol !== "http:") {
            throw new Error("Delivery relay URL must use HTTP or HTTPS");
        }
        this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
        this.#maximumResponseBytes = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
        this.#requestTimeoutMilliseconds = options.requestTimeoutMilliseconds ?? 45_000;
        this.#streamHeartbeatTimeoutMilliseconds =
            options.streamHeartbeatTimeoutMilliseconds ?? 45_000;
        if (!Number.isSafeInteger(this.#maximumResponseBytes) || this.#maximumResponseBytes < 1) {
            throw new Error("Maximum relay response bytes must be a positive safe integer");
        }
        if (
            !Number.isSafeInteger(this.#requestTimeoutMilliseconds) ||
            this.#requestTimeoutMilliseconds < 1 ||
            this.#requestTimeoutMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Relay request timeout must be between 1ms and 5 minutes");
        }
        if (
            !Number.isSafeInteger(this.#streamHeartbeatTimeoutMilliseconds) ||
            this.#streamHeartbeatTimeoutMilliseconds < 1_000 ||
            this.#streamHeartbeatTimeoutMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Stream heartbeat timeout must be between 1 second and 5 minutes");
        }
    }

    /** Publish one exact sender-signed delivery. */
    async publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        const value = object(
            await this.#post("/v1/deliveries", signedDeliveryToJson(delivery), signal),
        );
        exact(value, ["eventId", "duplicate"]);
        if (typeof value.duplicate !== "boolean") throw new Error("Invalid relay response");
        return { eventId: uuid(value.eventId), duplicate: value.duplicate };
    }

    /** Read one bounded page from an identity inbox. */
    async read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        const page = parseInboxPage(
            await this.#post("/v1/queue/read", signedInboxReadToJson(request), signal),
            request.limit,
        );
        if (page.deliveries.length > request.limit) {
            throw new Error("Relay response exceeds the requested inbox page limit");
        }
        return page;
    }

    /** Acknowledge and trim one durably processed inbox prefix. */
    async acknowledge(
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }> {
        const value = object(
            await this.#post("/v1/queue/ack", signedInboxAckToJson(request), signal),
        );
        exact(value, ["removed"]);
        if (
            typeof value.removed !== "number" ||
            !Number.isSafeInteger(value.removed) ||
            value.removed < 0
        ) {
            throw new Error("Invalid relay response");
        }
        return { removed: value.removed };
    }

    /** Stream exact queued deliveries over one recipient-authenticated SSE response. */
    async *stream(request: SignedInboxRead, signal?: AbortSignal): AsyncGenerator<InboxDelivery> {
        if (request.waitMilliseconds !== 0) {
            throw new Error("Delivery event streams require a zero wait duration");
        }
        const controller = new AbortController();
        const forwardAbort = (): void => controller.abort(signal?.reason);
        if (signal?.aborted === true) {
            forwardAbort();
        } else {
            signal?.addEventListener("abort", forwardAbort, { once: true });
        }
        const timeout = setTimeout(() => {
            controller.abort(new Error("Delivery event stream connection timed out"));
        }, this.#requestTimeoutMilliseconds);
        try {
            const response = await this.#fetch(new URL("/v1/queue/events", this.#baseUrl), {
                method: "POST",
                headers: {
                    accept: "text/event-stream",
                    "content-type": "application/json",
                },
                body: JSON.stringify(signedInboxReadToJson(request)),
                signal: controller.signal,
            });
            if (!response.ok) {
                const value = await boundedResponseJson(response, this.#maximumResponseBytes);
                this.#throwFailure(response, value);
            }
            if (!response.headers.get("content-type")?.startsWith("text/event-stream")) {
                throw new Error("Relay returned an invalid delivery event stream");
            }
            clearTimeout(timeout);
            yield* decodeDeliveryEventStream(
                response,
                controller,
                this.#maximumResponseBytes,
                this.#streamHeartbeatTimeoutMilliseconds,
            );
        } catch (error: unknown) {
            if (signal?.aborted === true) return;
            if (error instanceof DeliveryTransportError) throw error;
            if (
                controller.signal.aborted ||
                error instanceof TypeError ||
                (error instanceof Error &&
                    (error.message === "Delivery event stream heartbeat timed out" ||
                        error.message === "Delivery event stream connection timed out"))
            ) {
                throw new DeliveryTransportError(0, "stream_disconnected");
            }
            throw error;
        } finally {
            clearTimeout(timeout);
            signal?.removeEventListener("abort", forwardAbort);
            controller.abort(new Error("Delivery event stream closed"));
        }
    }

    async #post(path: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
        const controller = new AbortController();
        const forwardAbort = (): void => controller.abort(signal?.reason);
        if (signal?.aborted === true) {
            forwardAbort();
        } else {
            signal?.addEventListener("abort", forwardAbort, { once: true });
        }
        const timeout = setTimeout(() => {
            controller.abort(new Error("Delivery relay request timed out"));
        }, this.#requestTimeoutMilliseconds);
        let response: Response;
        let value: unknown;
        try {
            response = await this.#fetch(new URL(path, this.#baseUrl), {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            value = await boundedResponseJson(response, this.#maximumResponseBytes);
        } finally {
            clearTimeout(timeout);
            signal?.removeEventListener("abort", forwardAbort);
        }
        if (response.ok) return value;
        this.#throwFailure(response, value);
    }

    #throwFailure(response: Response, value: unknown): never {
        const failure = object(value);
        if (
            response.status === 413 &&
            failure.error === "delivery_too_large" &&
            failure.acknowledgedThrough !== undefined
        ) {
            exact(failure, ["error", "eventId", "head", "acknowledgedThrough"]);
            const acknowledgedThrough =
                failure.acknowledgedThrough === null ? null : uuid(failure.acknowledgedThrough);
            throw new OversizedInboxDeliveryError(
                uuid(failure.eventId),
                uuid(failure.head),
                acknowledgedThrough,
            );
        }
        if (
            response.status === 409 &&
            (failure.error === "cursor_trimmed" || failure.error === "ack_regression")
        ) {
            exact(failure, ["error", "acknowledgedThrough"]);
            throw new DeliveryCursorTrimmedError(failure.error, uuid(failure.acknowledgedThrough));
        }
        if (response.status === 409 && failure.error === "ack_future") {
            exact(failure, ["error", "head"]);
            throw new DeliveryAcknowledgementFutureError(uuid(failure.head));
        }
        throw new DeliveryTransportError(
            response.status,
            typeof failure.error === "string" ? failure.error : "unknown",
        );
    }
}
