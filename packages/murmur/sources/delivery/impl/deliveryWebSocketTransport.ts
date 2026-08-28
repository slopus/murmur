import type { Context } from "@steve.kite/stdlib";

import type { IdentityKeyPair } from "../../crypto/index.js";
import { randomBytes } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, equalBytes, utf8Encode } from "../../utils/index.js";
import type {
    DeliveryPublishOutcome,
    DeliveryDeviceRoster,
    DeliveryDirectoryClaim,
    DeliveryStreamHooks,
    DeliveryTransport,
    DeliveryWebSocket,
    DeliveryWebSocketFactory,
    InboxAcknowledgement,
    InboxPage,
    InboxStreamEvent,
    RelaySessionProvider,
    RelaySessionTicket,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
    WebSocketDeliveryTransportOptions,
} from "../types.js";
import {
    parseInboxDelivery,
    parseInboxContinuity,
    parseInboxPage,
    signedDeliveryToJson,
    signedInboxAckToJson,
    signedInboxReadToJson,
} from "./deliveryCodec.js";
import {
    DeliveryAcknowledgementFutureError,
    DeliveryCursorTrimmedError,
    DeliveryStaleRosterError,
    DeliveryTransportError,
    OversizedInboxDeliveryError,
} from "./deliveryHttpTransport.js";
import { createSignedRelaySessionRequest, parseRelaySessionTicket } from "./deliveryNegotiation.js";

const PROTOCOL = "murmur-websocket-v1";
const TICKET_PROTOCOL_PREFIX = "murmur-ticket.";
const DEFAULT_REQUEST_TIMEOUT_MILLISECONDS = 45_000;
const DEFAULT_STREAM_HEARTBEAT_TIMEOUT_MILLISECONDS = 45_000;
const DEFAULT_MAXIMUM_MESSAGE_BYTES = 16 * 1024 * 1024;
const DEFAULT_TICKET_REFRESH_SKEW_MILLISECONDS = 5_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type WebSocketOperation =
    | "publish"
    | "delete_session"
    | "delete_account"
    | "read_device_roster"
    | "mutate_device_roster"
    | "upload_directory_prekeys"
    | "claim_directory"
    | "read"
    | "acknowledge"
    | "stream";

interface WebSocketResponse {
    readonly status: number;
    readonly body: unknown;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid relay WebSocket message");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid relay WebSocket message");
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
        throw new Error("Invalid relay WebSocket message");
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
        throw new Error("Invalid relay WebSocket message");
    }
    const accountKey = decodeBase64Url(input.accountKey);
    if (accountKey.length !== 32) throw new Error("Invalid relay WebSocket message");
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
                throw new Error("Invalid relay WebSocket message");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const encryptedMetadata = decodeBase64Url(entry.encryptedMetadata);
            if (deviceKey.length !== 32 || encryptedMetadata.length > 16 * 1024) {
                throw new Error("Invalid relay WebSocket message");
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
                throw new Error("Invalid relay WebSocket message");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const keyPackage = decodeBase64Url(entry.keyPackage);
            if (deviceKey.length !== 32 || keyPackage.length < 1) {
                throw new Error("Invalid relay WebSocket message");
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
        throw new Error("Invalid relay WebSocket message");
    }
    const accountKey = decodeBase64Url(input.accountKey);
    if (accountKey.length !== 32 || input.devices.length > 256) {
        throw new Error("Invalid relay WebSocket message");
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
                throw new Error("Invalid relay WebSocket message");
            }
            const deviceKey = decodeBase64Url(entry.deviceKey);
            const keyPackage = decodeBase64Url(entry.keyPackage);
            if (deviceKey.length !== 32 || keyPackage.length < 1) {
                throw new Error("Invalid relay WebSocket message");
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

function defaultWebSocketFactory(
    _ctx: Context,
    url: string,
    protocols: readonly string[],
): DeliveryWebSocket {
    return new WebSocket(url, [...protocols]) as unknown as DeliveryWebSocket;
}

function parseResponse(message: string, requestId: string): WebSocketResponse {
    const input = object(JSON.parse(message) as unknown);
    exact(input, ["version", "id", "type", "status", "body"]);
    if (
        input.version !== 1 ||
        input.id !== requestId ||
        input.type !== "response" ||
        typeof input.status !== "number" ||
        !Number.isSafeInteger(input.status) ||
        input.status < 100 ||
        input.status > 599
    ) {
        throw new Error("Invalid relay WebSocket message");
    }
    return { status: input.status, body: input.body };
}

function throwFailure(status: number, value: unknown): never {
    const failure = object(value);
    if (
        status === 413 &&
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
        if (
            typeof failure.sequence !== "number" ||
            typeof failure.headSequence !== "number" ||
            typeof failure.acknowledgedSequence !== "number" ||
            typeof failure.generation !== "string"
        ) {
            throw new Error("Invalid relay WebSocket message");
        }
        throw new OversizedInboxDeliveryError(
            uuid(failure.eventId),
            failure.sequence,
            uuid(failure.head),
            failure.headSequence,
            failure.acknowledgedThrough === null ? null : uuid(failure.acknowledgedThrough),
            failure.acknowledgedSequence,
            decodeBase64Url(failure.generation),
        );
    }
    if (
        status === 409 &&
        (failure.error === "cursor_trimmed" || failure.error === "ack_regression")
    ) {
        exact(failure, ["error", "acknowledgedThrough"]);
        throw new DeliveryCursorTrimmedError(failure.error, uuid(failure.acknowledgedThrough));
    }
    if (status === 409 && failure.error === "ack_future") {
        exact(failure, ["error", "head"]);
        throw new DeliveryAcknowledgementFutureError(uuid(failure.head));
    }
    if (
        status === 409 &&
        (failure.error === "stale_roster" || failure.error === "stale_epoch_coverage") &&
        Array.isArray(failure.rosters)
    ) {
        exact(failure, ["error", "rosters"]);
        throw new DeliveryStaleRosterError(failure.rosters.map(roster), failure.error);
    }
    throw new DeliveryTransportError(
        status,
        typeof failure.error === "string" ? failure.error : "unknown",
    );
}

function validateDuration(value: number, name: string, minimum: number): void {
    if (!Number.isSafeInteger(value) || value < minimum || value > 5 * 60 * 1_000) {
        throw new Error(`${name} must be between ${minimum}ms and 5 minutes`);
    }
}

function abortError(signal: AbortSignal): unknown {
    return signal.reason ?? new DOMException("The operation was aborted", "AbortError");
}

function isAborted(signal: AbortSignal | undefined): boolean {
    return signal?.aborted === true;
}

/** Ticket-negotiated WebSocket implementation of Murmur delivery operations. */
export class WebSocketDeliveryTransport implements DeliveryTransport {
    readonly #identity: IdentityKeyPair;
    readonly #sessionProvider: RelaySessionProvider;
    readonly #webSocketFactory: DeliveryWebSocketFactory;
    readonly #now: () => number;
    readonly #requestTimeoutMilliseconds: number;
    readonly #streamHeartbeatTimeoutMilliseconds: number;
    readonly #maximumMessageBytes: number;
    readonly #ticketRefreshSkewMilliseconds: number;
    #ticket: RelaySessionTicket | undefined;
    #ticketPromise: Promise<RelaySessionTicket> | undefined;

    constructor(
        identity: IdentityKeyPair,
        sessionProvider: RelaySessionProvider,
        options: WebSocketDeliveryTransportOptions = {},
    ) {
        this.#identity = identity;
        this.#sessionProvider = sessionProvider;
        this.#webSocketFactory = options.webSocketFactory ?? defaultWebSocketFactory;
        this.#now = options.now ?? Date.now;
        this.#requestTimeoutMilliseconds =
            options.requestTimeoutMilliseconds ?? DEFAULT_REQUEST_TIMEOUT_MILLISECONDS;
        this.#streamHeartbeatTimeoutMilliseconds =
            options.streamHeartbeatTimeoutMilliseconds ??
            DEFAULT_STREAM_HEARTBEAT_TIMEOUT_MILLISECONDS;
        this.#maximumMessageBytes = options.maximumMessageBytes ?? DEFAULT_MAXIMUM_MESSAGE_BYTES;
        this.#ticketRefreshSkewMilliseconds =
            options.ticketRefreshSkewMilliseconds ?? DEFAULT_TICKET_REFRESH_SKEW_MILLISECONDS;
        validateDuration(this.#requestTimeoutMilliseconds, "Relay request timeout", 1);
        validateDuration(
            this.#streamHeartbeatTimeoutMilliseconds,
            "Stream heartbeat timeout",
            1_000,
        );
        if (!Number.isSafeInteger(this.#maximumMessageBytes) || this.#maximumMessageBytes < 1) {
            throw new Error("Maximum relay WebSocket message bytes must be positive");
        }
        if (
            !Number.isSafeInteger(this.#ticketRefreshSkewMilliseconds) ||
            this.#ticketRefreshSkewMilliseconds < 0 ||
            this.#ticketRefreshSkewMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Ticket refresh skew must be between zero and 5 minutes");
        }
    }

    /** Publish one exact signed delivery after negotiating its routed endpoint. */
    async publish(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryPublishOutcome> {
        if (!equalBytes(delivery.sender, this.#identity.publicKey)) {
            throw new Error("Delivery sender differs from the negotiated device");
        }
        const response = await this.#request(
            ctx,
            "publish",
            signedDeliveryToJson(delivery),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["eventId", "duplicate"]);
        if (typeof body.duplicate !== "boolean") {
            throw new Error("Invalid relay WebSocket response");
        }
        return { eventId: uuid(body.eventId), duplicate: body.duplicate };
    }

    async deleteSession(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<number> {
        const response = await this.#request(
            ctx,
            "delete_session",
            signedDeliveryToJson(delivery),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["removed"]);
        if (
            typeof body.removed !== "number" ||
            !Number.isSafeInteger(body.removed) ||
            body.removed < 0
        ) {
            throw new Error("Invalid relay WebSocket response");
        }
        return body.removed;
    }

    async deleteAccount(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<void> {
        const response = await this.#request(
            ctx,
            "delete_account",
            signedDeliveryToJson(delivery),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["deleted"]);
        if (body.deleted !== true) throw new Error("Invalid relay WebSocket response");
    }

    async readDeviceRoster(
        ctx: Context,
        accountKey: Uint8Array,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster | undefined> {
        if (accountKey.length !== 32) throw new Error("Invalid account identity key");
        const response = await this.#request(
            ctx,
            "read_device_roster",
            { version: 1, accountKey: encodeBase64Url(accountKey) },
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["roster"]);
        return body.roster === null ? undefined : roster(body.roster);
    }

    async mutateDeviceRoster(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster> {
        const response = await this.#request(
            ctx,
            "mutate_device_roster",
            signedDeliveryToJson(delivery),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["roster"]);
        return roster(body.roster);
    }

    async uploadDirectoryPrekeys(
        ctx: Context,
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<void> {
        const response = await this.#request(
            ctx,
            "upload_directory_prekeys",
            signedDeliveryToJson(delivery),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["uploaded"]);
        if (body.uploaded !== true) throw new Error("Invalid relay WebSocket response");
    }

    async claimDirectory(
        ctx: Context,
        accountKey: Uint8Array,
        ticket: Uint8Array,
        signal?: AbortSignal,
    ): Promise<DeliveryDirectoryClaim> {
        if (accountKey.length !== 32 || ticket.length < 1) {
            throw new Error("Invalid directory claim");
        }
        const response = await this.#request(
            ctx,
            "claim_directory",
            {
                version: 1,
                accountKey: encodeBase64Url(accountKey),
                ticket: encodeBase64Url(ticket),
            },
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        return directoryClaim(response.body);
    }

    /** Read one bounded page from the negotiated device inbox. */
    async read(ctx: Context, request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        this.#assertRecipient(request.recipient);
        const response = await this.#request(ctx, "read", signedInboxReadToJson(request), signal);
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        return parseInboxPage(response.body, request.limit);
    }

    /** Acknowledge and trim one processed prefix of the negotiated device inbox. */
    async acknowledge(
        ctx: Context,
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<InboxAcknowledgement> {
        this.#assertRecipient(request.recipient);
        const response = await this.#request(
            ctx,
            "acknowledge",
            signedInboxAckToJson(request),
            signal,
        );
        if (response.status < 200 || response.status >= 300) {
            throwFailure(response.status, response.body);
        }
        const body = object(response.body);
        exact(body, ["removed", "sequence", "generation"]);
        if (
            typeof body.removed !== "number" ||
            !Number.isSafeInteger(body.removed) ||
            body.removed < 0 ||
            typeof body.sequence !== "number" ||
            !Number.isSafeInteger(body.sequence) ||
            body.sequence < 0 ||
            typeof body.generation !== "string"
        ) {
            throw new Error("Invalid relay WebSocket response");
        }
        return {
            removed: body.removed,
            sequence: body.sequence,
            generation: (() => {
                const generation = decodeBase64Url(body.generation);
                if (generation.length !== 32) throw new Error("Invalid relay WebSocket response");
                return generation;
            })(),
        };
    }

    /** Stream exact queued deliveries over a negotiated WebSocket. */
    async *stream(
        ctx: Context,
        request: SignedInboxRead,
        signal?: AbortSignal,
        hooks: DeliveryStreamHooks = {},
    ): AsyncGenerator<InboxStreamEvent> {
        this.#assertRecipient(request.recipient);
        if (request.waitMilliseconds !== 0) {
            throw new Error("Delivery event streams require a zero wait duration");
        }
        if (isAborted(signal)) return;
        const ticket = await this.#getTicket(ctx, signal);
        if (isAborted(signal)) return;
        const requestId = encodeBase64Url(randomBytes(18));
        const socket = this.#openSocket(ctx, ticket);
        const queued: InboxStreamEvent[] = [];
        let wake: (() => void) | undefined;
        let connected = false;
        let ended = false;
        let failure: unknown;
        let connectionTimeout: ReturnType<typeof setTimeout> | undefined;
        let heartbeatTimeout: ReturnType<typeof setTimeout> | undefined;

        const notify = (): void => {
            const resolve = wake;
            wake = undefined;
            resolve?.();
        };
        const finish = (error?: unknown): void => {
            if (ended) return;
            ended = true;
            failure = error;
            if (connectionTimeout !== undefined) clearTimeout(connectionTimeout);
            if (heartbeatTimeout !== undefined) clearTimeout(heartbeatTimeout);
            notify();
        };
        const resetHeartbeat = (): void => {
            if (heartbeatTimeout !== undefined) clearTimeout(heartbeatTimeout);
            heartbeatTimeout = setTimeout(
                () => finish(new DeliveryTransportError(0, "stream_disconnected")),
                this.#streamHeartbeatTimeoutMilliseconds,
            );
        };
        const onAbort = (): void => {
            finish();
            socket.close(1000, "client abort");
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        connectionTimeout = setTimeout(
            () => finish(new DeliveryTransportError(0, "stream_disconnected")),
            this.#requestTimeoutMilliseconds,
        );
        socket.onopen = () => {
            try {
                socket.send(
                    JSON.stringify({
                        version: 1,
                        id: requestId,
                        operation: "stream",
                        body: signedInboxReadToJson(request),
                    }),
                );
            } catch {
                finish(new DeliveryTransportError(0, "stream_disconnected"));
            }
        };
        socket.onmessage = (event) => {
            try {
                const message = this.#messageText(event.data);
                const input = object(JSON.parse(message) as unknown);
                if (input.type === "response") {
                    const response = parseResponse(message, requestId);
                    if (connected) throw new Error("Duplicate relay stream response");
                    if (response.status < 200 || response.status >= 300) {
                        throwFailure(response.status, response.body);
                    }
                    const body = object(response.body);
                    exact(body, ["connected"]);
                    if (body.connected !== true) {
                        throw new Error("Invalid relay stream response");
                    }
                    connected = true;
                    if (connectionTimeout !== undefined) clearTimeout(connectionTimeout);
                    resetHeartbeat();
                    notify();
                    return;
                }
                exact(input, ["version", "id", "type", "body"]);
                if (input.version !== 1 || input.id !== requestId) {
                    throw new Error("Invalid relay stream message");
                }
                if (input.type === "heartbeat") {
                    if (input.body !== null) throw new Error("Invalid relay stream heartbeat");
                    resetHeartbeat();
                    return;
                }
                if (input.type === "device_roster_changed") {
                    if (!connected) throw new Error("Invalid relay stream message");
                    const body = object(input.body);
                    exact(body, ["accountKey"]);
                    if (typeof body.accountKey !== "string") {
                        throw new Error("Invalid relay stream message");
                    }
                    const accountKey = decodeBase64Url(body.accountKey);
                    if (
                        accountKey.length !== 32 ||
                        encodeBase64Url(accountKey) !== body.accountKey
                    ) {
                        throw new Error("Invalid relay stream message");
                    }
                    hooks.onDeviceRosterChanged?.(ctx, accountKey);
                    resetHeartbeat();
                    return;
                }
                if ((input.type !== "delivery" && input.type !== "continuity") || !connected) {
                    throw new Error("Invalid relay stream message");
                }
                queued.push(
                    input.type === "continuity"
                        ? parseInboxContinuity(input.body)
                        : parseInboxDelivery(input.body),
                );
                resetHeartbeat();
                notify();
            } catch (error: unknown) {
                finish(
                    error instanceof DeliveryTransportError
                        ? error
                        : new DeliveryTransportError(0, "invalid_stream"),
                );
                socket.close(1002, "invalid message");
            }
        };
        socket.onerror = () => finish(new DeliveryTransportError(0, "stream_disconnected"));
        socket.onclose = () => {
            if (signal?.aborted === true) finish();
            else finish(new DeliveryTransportError(0, "stream_disconnected"));
        };

        try {
            while (!connected && !ended) {
                await new Promise<void>((resolve) => {
                    wake = resolve;
                });
            }
            if (failure !== undefined) throw failure;
            if (ended) return;
            await hooks.onConnected?.(ctx);
            for (;;) {
                while (queued.length > 0) yield queued.shift()!;
                if (failure !== undefined) throw failure;
                if (ended) return;
                await new Promise<void>((resolve) => {
                    wake = resolve;
                });
            }
        } finally {
            if (connectionTimeout !== undefined) clearTimeout(connectionTimeout);
            if (heartbeatTimeout !== undefined) clearTimeout(heartbeatTimeout);
            signal?.removeEventListener("abort", onAbort);
            socket.close(1000, "stream closed");
        }
    }

    async #request(
        ctx: Context,
        operation: WebSocketOperation,
        body: unknown,
        signal?: AbortSignal,
    ): Promise<WebSocketResponse> {
        if (signal !== undefined && isAborted(signal)) throw abortError(signal);
        const ticket = await this.#getTicket(ctx, signal);
        if (signal !== undefined && isAborted(signal)) throw abortError(signal);
        const requestId = encodeBase64Url(randomBytes(18));
        const socket = this.#openSocket(ctx, ticket);
        return new Promise<WebSocketResponse>((resolve, reject) => {
            let settled = false;
            const cleanup = (): void => {
                clearTimeout(timeout);
                signal?.removeEventListener("abort", onAbort);
                socket.onopen = null;
                socket.onmessage = null;
                socket.onerror = null;
                socket.onclose = null;
            };
            const succeed = (value: WebSocketResponse): void => {
                if (settled) return;
                settled = true;
                cleanup();
                socket.close(1000, "request complete");
                resolve(value);
            };
            const fail = (error: unknown): void => {
                if (settled) return;
                settled = true;
                cleanup();
                socket.close(1000, "request failed");
                reject(error);
            };
            const onAbort = (): void => fail(signal === undefined ? undefined : abortError(signal));
            const timeout = setTimeout(
                () => fail(new DeliveryTransportError(0, "request_timeout")),
                this.#requestTimeoutMilliseconds,
            );
            signal?.addEventListener("abort", onAbort, { once: true });
            socket.onopen = () => {
                try {
                    socket.send(JSON.stringify({ version: 1, id: requestId, operation, body }));
                } catch {
                    fail(new DeliveryTransportError(0, "stream_disconnected"));
                }
            };
            socket.onmessage = (event) => {
                try {
                    succeed(parseResponse(this.#messageText(event.data), requestId));
                } catch {
                    fail(new DeliveryTransportError(0, "invalid_response"));
                }
            };
            socket.onerror = () => fail(new DeliveryTransportError(0, "stream_disconnected"));
            socket.onclose = () => fail(new DeliveryTransportError(0, "stream_disconnected"));
        });
    }

    async #getTicket(ctx: Context, signal?: AbortSignal): Promise<RelaySessionTicket> {
        const now = this.#now();
        if (
            this.#ticket !== undefined &&
            this.#ticket.expiresAt - this.#ticketRefreshSkewMilliseconds > now
        ) {
            return this.#ticket;
        }
        this.#ticketPromise ??= this.#sessionProvider
            .issue(ctx, createSignedRelaySessionRequest(this.#identity, now))
            .then((value) => {
                const ticket = parseRelaySessionTicket(value);
                if (ticket.expiresAt <= this.#now()) {
                    throw new Error("Relay-session ticket is already expired");
                }
                this.#ticket = ticket;
                return ticket;
            })
            .finally(() => {
                this.#ticketPromise = undefined;
            });
        if (signal === undefined) return this.#ticketPromise;
        if (signal.aborted) throw abortError(signal);
        return new Promise<RelaySessionTicket>((resolve, reject) => {
            const onAbort = (): void => reject(abortError(signal));
            signal.addEventListener("abort", onAbort, { once: true });
            void this.#ticketPromise!.then(
                (ticket) => {
                    signal.removeEventListener("abort", onAbort);
                    resolve(ticket);
                },
                (error: unknown) => {
                    signal.removeEventListener("abort", onAbort);
                    reject(error);
                },
            );
        });
    }

    #openSocket(ctx: Context, ticket: RelaySessionTicket): DeliveryWebSocket {
        return this.#webSocketFactory(ctx, ticket.endpoint, [
            PROTOCOL,
            `${TICKET_PROTOCOL_PREFIX}${ticket.token}`,
        ]);
    }

    #messageText(value: unknown): string {
        if (typeof value !== "string" || utf8Encode(value).length > this.#maximumMessageBytes) {
            throw new Error("Invalid relay WebSocket message");
        }
        return value;
    }

    #assertRecipient(recipient: Uint8Array): void {
        if (!equalBytes(recipient, this.#identity.publicKey)) {
            throw new Error("Inbox recipient differs from the negotiated device");
        }
    }
}
