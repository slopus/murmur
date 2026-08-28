import type { Context } from "@steve.kite/stdlib";

import { decodeBase64Url, encodeBase64Url, utf8Decode } from "../../utils/index.js";
import type {
    DeliveryFetch,
    DeliveryDeviceRoster,
    DeliveryDirectoryClaim,
    DeliveryPublishOutcome,
    DeliveryTransport,
    InboxStreamEvent,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
    DeliveryStreamHooks,
    InboxAcknowledgement,
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
    readonly sequence: number;
    readonly head: string;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;

    constructor(
        eventId: string,
        sequence: number,
        head: string,
        headSequence: number,
        acknowledgedThrough: string | null,
        acknowledgedSequence: number,
        generation: Uint8Array,
    );
    constructor(
        eventId: string,
        sequence: number,
        head: string,
        headSequence: number,
        acknowledgedThrough: string | null,
        acknowledgedSequence: number,
        generation: Uint8Array,
    ) {
        super(413, "delivery_too_large");
        if (
            !Number.isSafeInteger(sequence) ||
            sequence < 1 ||
            !Number.isSafeInteger(headSequence) ||
            headSequence < sequence ||
            !Number.isSafeInteger(acknowledgedSequence) ||
            acknowledgedSequence < 0 ||
            acknowledgedSequence >= sequence ||
            generation.length !== 32
        ) {
            throw new Error("Invalid oversized inbox delivery metadata");
        }
        this.name = "OversizedInboxDeliveryError";
        this.eventId = eventId;
        this.sequence = sequence;
        this.head = head;
        this.headSequence = headSequence;
        this.acknowledgedThrough = acknowledgedThrough;
        this.acknowledgedSequence = acknowledgedSequence;
        this.generation = generation.slice();
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

/** Relay response proving that an account-targeted publication used a stale roster. */
export class DeliveryStaleRosterError extends DeliveryTransportError {
    readonly rosters: readonly DeliveryDeviceRoster[];

    constructor(
        rosters: readonly DeliveryDeviceRoster[],
        code: "stale_roster" | "stale_epoch_coverage" = "stale_roster",
    ) {
        super(409, code);
        this.name = "DeliveryStaleRosterError";
        this.rosters = rosters;
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

function safeInteger(value: unknown): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error("Invalid relay response");
    }
    return value;
}

function roster(value: unknown): DeliveryDeviceRoster {
    const input = object(value);
    exact(input, ["version", "accountKey", "revision", "devices", "admissions"]);
    if (
        input.version !== 1 ||
        typeof input.accountKey !== "string" ||
        !Array.isArray(input.devices) ||
        !Array.isArray(input.admissions) ||
        input.devices.length !== input.admissions.length
    ) {
        throw new Error("Invalid relay response");
    }
    const accountKey = decodeBase64Url(input.accountKey);
    if (accountKey.length !== 32) throw new Error("Invalid relay response");
    return {
        version: 1,
        accountKey,
        revision: safeInteger(input.revision),
        devices: input.devices.map((candidate) => {
            const entry = object(candidate);
            exact(entry, ["deviceKey", "resetGeneration", "lastAccessedAt", "encryptedMetadata"]);
            if (
                typeof entry.deviceKey !== "string" ||
                typeof entry.encryptedMetadata !== "string"
            ) {
                throw new Error("Invalid relay response");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const encryptedMetadata = decodeBase64Url(entry.encryptedMetadata);
            if (deviceKey.length !== 32 || encryptedMetadata.length > 16 * 1024) {
                throw new Error("Invalid relay response");
            }
            return {
                deviceKey,
                resetGeneration: safeInteger(entry.resetGeneration),
                lastAccessedAt: safeInteger(entry.lastAccessedAt),
                encryptedMetadata,
            };
        }),
        admissions: input.admissions.map((candidate) => {
            const entry = object(candidate);
            exact(entry, ["deviceKey", "keyPackage"]);
            if (typeof entry.deviceKey !== "string" || typeof entry.keyPackage !== "string") {
                throw new Error("Invalid relay response");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const keyPackage = decodeBase64Url(entry.keyPackage);
            if (deviceKey.length !== 32 || keyPackage.length < 1) {
                throw new Error("Invalid relay response");
            }
            return { deviceKey, keyPackage };
        }),
    };
}

function directoryClaim(value: unknown): DeliveryDirectoryClaim {
    const input = object(value);
    exact(input, ["version", "accountKey", "rosterRevision", "devices"]);
    if (
        input.version !== 1 ||
        typeof input.accountKey !== "string" ||
        !Array.isArray(input.devices)
    ) {
        throw new Error("Invalid relay response");
    }
    const accountKey = decodeBase64Url(input.accountKey);
    if (accountKey.length !== 32 || input.devices.length > 256) {
        throw new Error("Invalid relay response");
    }
    return {
        version: 1,
        accountKey,
        rosterRevision: safeInteger(input.rosterRevision),
        devices: input.devices.map((candidate) => {
            const entry = object(candidate);
            exact(entry, ["deviceKey", "resetGeneration", "keyPackage", "source"]);
            if (
                typeof entry.deviceKey !== "string" ||
                typeof entry.keyPackage !== "string" ||
                (entry.source !== "one_time" && entry.source !== "last_resort")
            ) {
                throw new Error("Invalid relay response");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const keyPackage = decodeBase64Url(entry.keyPackage);
            if (deviceKey.length !== 32 || keyPackage.length < 1) {
                throw new Error("Invalid relay response");
            }
            return {
                deviceKey,
                resetGeneration: safeInteger(entry.resetGeneration),
                keyPackage,
                source: entry.source,
            };
        }),
    };
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
        this.#fetch = options.fetch ?? ((_ctx, input, init) => globalThis.fetch(input, init));
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
    async publish(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryPublishOutcome> {
        const value = object(
            await this.#post(ctx, "/v1/deliveries", signedDeliveryToJson(delivery), signal),
        );
        exact(value, ["eventId", "duplicate"]);
        if (typeof value.duplicate !== "boolean") throw new Error("Invalid relay response");
        return { eventId: uuid(value.eventId), duplicate: value.duplicate };
    }

    async deleteSession(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<number> {
        const value = object(
            await this.#post(ctx, "/v1/sessions/delete", signedDeliveryToJson(delivery), signal),
        );
        exact(value, ["removed"]);
        if (
            typeof value.removed !== "number" ||
            !Number.isSafeInteger(value.removed) ||
            value.removed < 0
        ) {
            throw new Error("Invalid relay response");
        }
        return value.removed;
    }

    async deleteAccount(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<void> {
        const value = object(
            await this.#post(ctx, "/v1/accounts/delete", signedDeliveryToJson(delivery), signal),
        );
        exact(value, ["deleted"]);
        if (value.deleted !== true) throw new Error("Invalid relay response");
    }

    async readDeviceRoster(
        ctx: Context,
        accountKey: Uint8Array,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster | undefined> {
        if (accountKey.length !== 32) throw new Error("Invalid account identity key");
        const value = object(
            await this.#post(
                ctx,
                "/v1/device-rosters/read",
                { version: 1, accountKey: encodeBase64Url(accountKey) },
                signal,
            ),
        );
        exact(value, ["roster"]);
        return value.roster === null ? undefined : roster(value.roster);
    }

    async mutateDeviceRoster(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster> {
        const value = object(
            await this.#post(
                ctx,
                "/v1/device-rosters/mutate",
                signedDeliveryToJson(delivery),
                signal,
            ),
        );
        exact(value, ["roster"]);
        return roster(value.roster);
    }

    /** Upload one account-signed per-device directory replacement or replenishment. */
    async uploadDirectoryPrekeys(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<void> {
        const value = object(
            await this.#post(ctx, "/v1/directory/upload", signedDeliveryToJson(delivery), signal),
        );
        exact(value, ["uploaded"]);
        if (value.uploaded !== true) throw new Error("Invalid relay response");
    }

    /** Spend one opaque authentication ticket on an exact account identity claim. */
    async claimDirectory(
        ctx: Context,
        accountKey: Uint8Array,
        ticket: Uint8Array,
        signal?: AbortSignal,
    ): Promise<DeliveryDirectoryClaim> {
        if (accountKey.length !== 32 || ticket.length < 1) {
            throw new Error("Invalid directory claim");
        }
        const claim = directoryClaim(
            await this.#post(
                ctx,
                "/v1/directory/claim",
                {
                    version: 1,
                    accountKey: encodeBase64Url(accountKey),
                    ticket: encodeBase64Url(ticket),
                },
                signal,
            ),
        );
        if (!accountKey.every((value, index) => claim.accountKey[index] === value)) {
            throw new Error("Directory response names a different account");
        }
        return claim;
    }

    /** Read one bounded page from an identity inbox. */
    async read(ctx: Context, request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        const page = parseInboxPage(
            await this.#post(ctx, "/v1/queue/read", signedInboxReadToJson(request), signal),
            request.limit,
        );
        if (page.deliveries.length > request.limit) {
            throw new Error("Relay response exceeds the requested inbox page limit");
        }
        return page;
    }

    /** Acknowledge and trim one durably processed inbox prefix. */
    async acknowledge(
        ctx: Context,
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<InboxAcknowledgement> {
        const value = object(
            await this.#post(ctx, "/v1/queue/ack", signedInboxAckToJson(request), signal),
        );
        exact(value, ["removed", "sequence", "generation"]);
        if (
            typeof value.removed !== "number" ||
            !Number.isSafeInteger(value.removed) ||
            value.removed < 0 ||
            typeof value.sequence !== "number" ||
            !Number.isSafeInteger(value.sequence) ||
            value.sequence < 0 ||
            typeof value.generation !== "string"
        ) {
            throw new Error("Invalid relay response");
        }
        return {
            removed: value.removed,
            sequence: value.sequence,
            generation: (() => {
                const generation = decodeBase64Url(value.generation);
                if (generation.length !== 32) throw new Error("Invalid relay response");
                return generation;
            })(),
        };
    }

    /** Stream exact queued deliveries over one recipient-authenticated SSE response. */
    async *stream(
        ctx: Context,
        request: SignedInboxRead,
        signal?: AbortSignal,
        hooks: DeliveryStreamHooks = {},
    ): AsyncGenerator<InboxStreamEvent> {
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
            const response = await this.#fetch(ctx, new URL("/v1/queue/events", this.#baseUrl), {
                method: "POST",
                headers: {
                    accept: "text/event-stream",
                    "content-type": "application/json",
                },
                body: JSON.stringify(signedInboxReadToJson(request)),
                signal: controller.signal,
            });
            if (!response.ok) {
                let value: unknown;
                try {
                    value = await boundedResponseJson(response, this.#maximumResponseBytes);
                } catch {
                    throw new DeliveryTransportError(0, "invalid_response");
                }
                this.#throwFailure(response, value);
            }
            if (!response.headers.get("content-type")?.startsWith("text/event-stream")) {
                throw new DeliveryTransportError(0, "invalid_stream");
            }
            clearTimeout(timeout);
            await hooks.onConnected?.(ctx);
            try {
                yield* decodeDeliveryEventStream(
                    ctx,
                    response,
                    controller,
                    this.#maximumResponseBytes,
                    this.#streamHeartbeatTimeoutMilliseconds,
                    hooks.onDeviceRosterChanged,
                );
            } catch (error: unknown) {
                if (controller.signal.aborted) throw error;
                throw new DeliveryTransportError(0, "invalid_stream");
            }
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

    async #post(ctx: Context, path: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
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
            response = await this.#fetch(ctx, new URL(path, this.#baseUrl), {
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
            exact(failure, [
                "error",
                "eventId",
                "sequence",
                "head",
                "headSequence",
                "acknowledgedThrough",
                "acknowledgedSequence",
                "generation",
            ]);
            const acknowledgedThrough =
                failure.acknowledgedThrough === null ? null : uuid(failure.acknowledgedThrough);
            if (
                typeof failure.sequence !== "number" ||
                typeof failure.headSequence !== "number" ||
                typeof failure.acknowledgedSequence !== "number" ||
                typeof failure.generation !== "string"
            ) {
                throw new Error("Invalid relay response");
            }
            throw new OversizedInboxDeliveryError(
                uuid(failure.eventId),
                failure.sequence,
                uuid(failure.head),
                failure.headSequence,
                acknowledgedThrough,
                failure.acknowledgedSequence,
                decodeBase64Url(failure.generation),
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
        if (
            response.status === 409 &&
            (failure.error === "stale_roster" || failure.error === "stale_epoch_coverage") &&
            Array.isArray(failure.rosters)
        ) {
            exact(failure, ["error", "rosters"]);
            throw new DeliveryStaleRosterError(failure.rosters.map(roster), failure.error);
        }
        throw new DeliveryTransportError(
            response.status,
            typeof failure.error === "string" ? failure.error : "unknown",
        );
    }
}
