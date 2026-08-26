import {
    RelayError,
    parseSignedDelivery,
    parseSignedQueueAck,
    parseSignedQueueRead,
    signedDeliveryToJson,
} from "../protocol/index.js";
import type { RelayService } from "../relay/index.js";
import { verifyRelaySessionToken } from "../session/index.js";
import { equalBytes } from "../utils/bytes.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import type {
    RelayWebSocketAuthenticationOptions,
    RelayWebSocketPeer,
    RelayWebSocketSessionOptions,
} from "./types.js";

export type {
    RelayWebSocketAuthenticationOptions,
    RelayWebSocketPeer,
    RelayWebSocketSessionOptions,
} from "./types.js";

const PROTOCOL = "murmur-websocket-v1";
const TICKET_PREFIX = "murmur-ticket.";
const DEFAULT_MAXIMUM_MESSAGE_BYTES = 16 * 1024 * 1024;
const textEncoder = new TextEncoder();

interface RequestFrame {
    readonly id: string;
    readonly operation:
        | "publish"
        | "delete_session"
        | "delete_account"
        | "read"
        | "acknowledge"
        | "stream";
    readonly body: unknown;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, "Invalid WebSocket request", { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new RelayError(400, "Invalid WebSocket request", { error: "malformed" });
    }
}

function frame(value: string, maximumBytes: number): RequestFrame {
    if (textEncoder.encode(value).length > maximumBytes) {
        throw new RelayError(413, "WebSocket message exceeds relay limit", { error: "limit" });
    }
    let decoded: unknown;
    try {
        decoded = JSON.parse(value) as unknown;
    } catch {
        throw new RelayError(400, "Invalid WebSocket JSON", { error: "malformed" });
    }
    const input = object(decoded);
    exact(input, ["version", "id", "operation", "body"]);
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !/^[A-Za-z0-9_-]{24}$/.test(input.id) ||
        (input.operation !== "publish" &&
            input.operation !== "delete_session" &&
            input.operation !== "delete_account" &&
            input.operation !== "read" &&
            input.operation !== "acknowledge" &&
            input.operation !== "stream")
    ) {
        throw new RelayError(400, "Invalid WebSocket request", { error: "malformed" });
    }
    return { id: input.id, operation: input.operation, body: input.body };
}

function response(id: string, status: number, body: unknown): string {
    return JSON.stringify({ version: 1, id, type: "response", status, body });
}

function tokenFromProtocols(header: string | null): string {
    const protocols = (header ?? "")
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
    if (!protocols.includes(PROTOCOL)) {
        throw new RelayError(401, "Missing Murmur WebSocket protocol", {
            error: "unauthorized",
        });
    }
    const tickets = protocols.filter((value) => value.startsWith(TICKET_PREFIX));
    if (
        tickets.length !== 1 ||
        tickets[0]!.length === TICKET_PREFIX.length ||
        tickets[0]!.length > TICKET_PREFIX.length + 8 * 1024
    ) {
        throw new RelayError(401, "Missing relay-session ticket", { error: "unauthorized" });
    }
    return tickets[0]!.slice(TICKET_PREFIX.length);
}

/** Parse the browser-compatible subprotocol header and return its compact token. */
export function relaySessionTokenFromWebSocketProtocols(header: string | null): string {
    return tokenFromProtocols(header);
}

/** One authenticated, single-operation relay WebSocket session. */
export class RelayWebSocketSession {
    readonly #relay: RelayService;
    readonly #claims: RelayWebSocketSessionOptions["claims"];
    readonly #peer: RelayWebSocketPeer;
    readonly #maximumMessageBytes: number;
    readonly #abort = new AbortController();
    #started = false;
    #closed = false;

    constructor(options: RelayWebSocketSessionOptions) {
        this.#relay = options.relay;
        this.#claims = options.claims;
        this.#peer = options.peer;
        this.#maximumMessageBytes = options.maximumMessageBytes ?? DEFAULT_MAXIMUM_MESSAGE_BYTES;
        if (!Number.isSafeInteger(this.#maximumMessageBytes) || this.#maximumMessageBytes < 1) {
            throw new Error("Maximum WebSocket message bytes must be positive");
        }
    }

    /** Process the socket's sole request frame. Stream work continues until close. */
    async receive(message: string): Promise<void> {
        let requestId = "invalid";
        try {
            if (this.#closed || this.#started) {
                throw new RelayError(400, "WebSocket accepts exactly one request", {
                    error: "malformed",
                });
            }
            this.#started = true;
            const request = frame(message, this.#maximumMessageBytes);
            requestId = request.id;
            if (request.operation === "publish") {
                const delivery = parseSignedDelivery(request.body);
                this.#assertDevice(delivery.sender);
                const outcome = await this.#relay.publish(
                    delivery,
                    this.#claims.admissionPrincipal,
                );
                this.#send(response(request.id, 200, outcome));
                return;
            }
            if (request.operation === "delete_session") {
                const delivery = parseSignedDelivery(request.body);
                const removed = await this.#relay.deleteSession(delivery);
                this.#send(response(request.id, 200, { removed }));
                return;
            }
            if (request.operation === "delete_account") {
                const delivery = parseSignedDelivery(request.body);
                await this.#relay.deleteAccount(delivery);
                this.#send(response(request.id, 200, { deleted: true }));
                return;
            }
            if (request.operation === "read") {
                const read = parseSignedQueueRead(request.body);
                this.#assertDevice(read.recipient);
                const page = await this.#relay.readQueue(
                    read,
                    this.#abort.signal,
                    this.#maximumMessageBytes,
                );
                const body = {
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
                };
                const encoded = response(request.id, 200, body);
                if (textEncoder.encode(encoded).length > this.#maximumMessageBytes) {
                    this.#send(
                        response(request.id, 413, {
                            error: "delivery_too_large",
                            eventId: page.deliveries[0]?.eventId ?? null,
                            sequence: page.deliveries[0]?.sequence ?? null,
                            head: page.head,
                            headSequence: page.headSequence,
                            acknowledgedThrough: page.acknowledgedThrough,
                            acknowledgedSequence: page.acknowledgedSequence,
                            generation: encodeBase64Url(page.generation),
                        }),
                    );
                } else {
                    this.#send(encoded);
                }
                return;
            }
            if (request.operation === "acknowledge") {
                const acknowledgement = parseSignedQueueAck(request.body);
                this.#assertDevice(acknowledgement.recipient);
                const outcome = await this.#relay.acknowledge(acknowledgement);
                this.#send(
                    response(request.id, 200, {
                        removed: outcome.removed,
                        sequence: outcome.sequence,
                        generation: encodeBase64Url(outcome.generation),
                    }),
                );
                return;
            }
            const read = parseSignedQueueRead(request.body);
            this.#assertDevice(read.recipient);
            const subscription = await this.#relay.openQueueEventStream(read, this.#abort.signal);
            this.#send(response(request.id, 200, { connected: true }));
            void this.#stream(request.id, subscription).catch(() =>
                this.close(1011, "stream failed"),
            );
        } catch (error: unknown) {
            if (error instanceof RelayError) {
                this.#send(response(requestId, error.status, error.body));
            } else {
                this.#send(response(requestId, 500, { error: "internal" }));
            }
        }
    }

    /** End active long-poll or streaming work after the host observes close. */
    close(code?: number, reason?: string): void {
        if (this.#closed) return;
        this.#closed = true;
        this.#abort.abort(new Error("Relay WebSocket closed"));
        this.#peer.close(code, reason);
    }

    async #stream(
        id: string,
        subscription: Awaited<ReturnType<RelayService["openQueueEventStream"]>>,
    ): Promise<void> {
        try {
            for await (const queued of subscription.events) {
                if (this.#closed) return;
                this.#send(
                    JSON.stringify(
                        queued === null
                            ? { version: 1, id, type: "heartbeat", body: null }
                            : "type" in queued
                              ? {
                                    version: 1,
                                    id,
                                    type: "continuity",
                                    body: {
                                        generation: encodeBase64Url(queued.generation),
                                        head: queued.head,
                                        headSequence: queued.headSequence,
                                        acknowledgedThrough: queued.acknowledgedThrough,
                                        acknowledgedSequence: queued.acknowledgedSequence,
                                    },
                                }
                              : {
                                    version: 1,
                                    id,
                                    type: "delivery",
                                    body: {
                                        eventId: queued.eventId,
                                        sequence: queued.sequence,
                                        delivery: signedDeliveryToJson(queued.delivery),
                                    },
                                },
                    ),
                );
            }
        } finally {
            subscription.close();
        }
    }

    #send(message: string): void {
        if (this.#closed) return;
        if (textEncoder.encode(message).length > this.#maximumMessageBytes) {
            throw new RelayError(413, "WebSocket response exceeds relay limit", {
                error: "limit",
            });
        }
        this.#peer.send(message);
    }

    #assertDevice(identity: Uint8Array): void {
        if (!equalBytes(identity, this.#claims.device)) {
            throw new RelayError(403, "Relay ticket does not authorize this device", {
                error: "forbidden",
            });
        }
    }
}

/** Authenticate a ticket subprotocol and create one host-neutral relay session. */
export function authenticateRelayWebSocket(
    relay: RelayService,
    peer: RelayWebSocketPeer,
    protocolHeader: string | null,
    options: RelayWebSocketAuthenticationOptions,
): RelayWebSocketSession {
    const claims = verifyRelaySessionToken(
        options.tokenSecret,
        tokenFromProtocols(protocolHeader),
        {
            expectedEndpoint: options.endpoint,
            ...(options.now === undefined ? {} : { now: options.now() }),
            ...(options.maximumFutureSkewMilliseconds === undefined
                ? {}
                : {
                      maximumFutureSkewMilliseconds: options.maximumFutureSkewMilliseconds,
                  }),
        },
    );
    return new RelayWebSocketSession({
        relay,
        peer,
        claims,
        ...(options.maximumMessageBytes === undefined
            ? {}
            : { maximumMessageBytes: options.maximumMessageBytes }),
    });
}
