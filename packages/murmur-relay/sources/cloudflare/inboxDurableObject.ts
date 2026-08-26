import { sha256 } from "@noble/hashes/sha2";
import {
    RelayError,
    deliveryFingerprint,
    parseSessionDeletionRequest,
    parseSignedDelivery,
    parseSignedQueueAck,
    parseSignedQueueRead,
    signedDeliveryToJson,
    validateSignedDeliveryShape,
    verifyDeliverySignature,
    verifyQueueAckSignature,
    verifyQueueReadSignature,
    type SignedDelivery,
    type SignedDeliveryJson,
    type SignedQueueAck,
    type SignedQueueRead,
} from "../protocol/index.js";
import { verifyRelaySessionToken } from "../session/index.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { DuplicateJsonKeyError, parseStrictJson } from "../utils/strictJson.js";
import { isUuidV7 } from "../utils/uuidV7.js";
import { relaySessionTokenFromWebSocketProtocols } from "../websocket/index.js";
import { advanceLossGeneration, createGenerationSeed } from "../storage/continuity.js";
import {
    MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS,
    MAXIMUM_DELIVERY_TTL_MILLISECONDS,
    MAXIMUM_MESSAGE_BYTES,
    MAXIMUM_QUEUE_BYTES,
    MAXIMUM_QUEUE_ITEMS,
    STREAM_HEARTBEAT_MILLISECONDS,
    decodeStoredDelivery,
    continuityFrame,
    deliveryFrame,
    encodedDeliveryBytes,
    exact,
    heartbeatFrame,
    object,
    parseTokenSecret,
    requestFrame,
    responseFrame,
    send,
    textEncoder,
    websocketPair,
    websocketResponse,
    type InboxMetadata,
    type StoredDeliveryRecord,
} from "./impl/cloudflareCodec.js";
import type {
    CloudflareServerWebSocket,
    CloudflareWebSocketAttachment,
    DurableObjectStateLike,
    DurableObjectTransactionLike,
    MurmurCloudflareEnvironment,
} from "./types.js";

const META_KEY = "inbox:meta";
const EVENT_PREFIX = "inbox:event:";
const EXPIRY_PREFIX = "inbox:expiry:";
const SENDER_PREFIX = "inbox:sender:";
const PRINCIPAL_PREFIX = "inbox:principal:";
const DELETED_SESSION_PREFIX = "inbox:deleted-session:";
const DELETED_SESSION_EXPIRY_PREFIX = "inbox:deleted-session-expiry:";
const FANOUT_OBJECT_NAME = "global-v1";
const MAXIMUM_SENDER_ITEMS = 1_000;
const MAXIMUM_SENDER_BYTES = 256 * 1024 * 1024;
const MAXIMUM_ADMISSION_REFERENCES = 10_000;
const PRUNE_BATCH = 100;

interface UsageCounter {
    readonly items: number;
    readonly bytes: number;
}

interface InboxExpiryRecord {
    readonly eventKey: string;
}

interface DeletedSessionRecord {
    readonly expiresAt: number;
}

interface DeletedSessionExpiryRecord {
    readonly tombstoneKey: string;
}

interface QueuePageBody {
    readonly deliveries: readonly {
        readonly eventId: string;
        readonly sequence: number;
        readonly delivery: SignedDeliveryJson;
    }[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: string;
    readonly exhausted: boolean;
}

function eventKey(eventId: string): string {
    return `${EVENT_PREFIX}${eventId}`;
}

function expiryKey(expiresAt: number, eventId: string): string {
    return `${EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}:${eventId}`;
}

function deletedSessionKey(ownerAccount: Uint8Array, sessionId: Uint8Array): string {
    return `${DELETED_SESSION_PREFIX}${encodeBase64Url(ownerAccount)}:${encodeBase64Url(sessionId)}`;
}

function deletedSessionExpiryKey(
    expiresAt: number,
    ownerAccount: Uint8Array,
    sessionId: Uint8Array,
): string {
    return `${DELETED_SESSION_EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}:${encodeBase64Url(ownerAccount)}:${encodeBase64Url(sessionId)}`;
}

function emptyMetadata(): InboxMetadata {
    return {
        head: null,
        headSequence: 0,
        nextSequence: 1,
        acknowledgedThrough: null,
        acknowledgedSequence: 0,
        generation: encodeBase64Url(createGenerationSeed()),
        pendingItems: 0,
        pendingBytes: 0,
    };
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

async function requestJson(request: Request): Promise<unknown> {
    const declared = request.headers.get("content-length");
    if (
        declared !== null &&
        (!/^\d+$/.test(declared) || Number(declared) > MAXIMUM_MESSAGE_BYTES)
    ) {
        throw new RelayError(413, "Inbox request exceeds limit", { error: "limit" });
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.length > MAXIMUM_MESSAGE_BYTES) {
        throw new RelayError(413, "Inbox request exceeds limit", { error: "limit" });
    }
    try {
        return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch (error: unknown) {
        if (error instanceof DuplicateJsonKeyError) {
            throw new RelayError(400, error.message, { error: "duplicate_json_key" });
        }
        throw new RelayError(400, "Invalid inbox JSON", { error: "malformed" });
    }
}

function attachment(socket: CloudflareServerWebSocket): CloudflareWebSocketAttachment {
    const value = socket.deserializeAttachment();
    if (value === null) throw new Error("Missing WebSocket attachment");
    return value;
}

function assertDevice(encodedDevice: string, identity: Uint8Array): void {
    let device: Uint8Array;
    try {
        device = decodeBase64Url(encodedDevice, 32);
    } catch {
        throw new RelayError(401, "Invalid socket device", { error: "unauthorized" });
    }
    if (!equalBytes(device, identity)) {
        throw new RelayError(403, "Ticket does not authorize this device", {
            error: "forbidden",
        });
    }
}

/** One device inbox and its hibernating negotiated WebSocket sessions. */
export class MurmurInboxDurableObject {
    readonly #state: DurableObjectStateLike;
    readonly #environment: MurmurCloudflareEnvironment;

    constructor(state: DurableObjectStateLike, environment: MurmurCloudflareEnvironment) {
        this.#state = state;
        this.#environment = environment;
    }

    /** Accept authenticated sockets or idempotent internal fanout insertions. */
    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        if (request.method === "POST" && url.pathname === "/v2/delete") {
            try {
                const input = object(await requestJson(request));
                exact(input, ["recipient", "delivery"]);
                if (typeof input.recipient !== "string") {
                    throw new RelayError(400, "Invalid inbox deletion", {
                        error: "malformed",
                    });
                }
                const recipient = decodeBase64Url(input.recipient, 32);
                const delivery = parseSignedDelivery(input.delivery);
                const sessionId = this.#authorizeDeletion(delivery);
                const removed = await this.#deleteSessionDeliveries(delivery.sender, sessionId);
                return json({ removed, recipient: encodeBase64Url(recipient) }, 200);
            } catch (error: unknown) {
                if (error instanceof RelayError) return json(error.body, error.status);
                return json({ error: "internal" }, 500);
            }
        }
        if (request.method === "POST" && url.pathname === "/v2/insert") {
            try {
                const input = object(await requestJson(request));
                exact(input, ["eventId", "recipient", "delivery", "admissionPrincipal"]);
                if (
                    typeof input.eventId !== "string" ||
                    !isUuidV7(input.eventId) ||
                    typeof input.recipient !== "string" ||
                    typeof input.admissionPrincipal !== "string" ||
                    input.admissionPrincipal.length < 1 ||
                    input.admissionPrincipal.length > 255
                ) {
                    throw new RelayError(400, "Invalid inbox insertion", {
                        error: "malformed",
                    });
                }
                const recipient = decodeBase64Url(input.recipient, 32);
                const delivery = parseSignedDelivery(input.delivery);
                if (!delivery.recipients.some((value) => equalBytes(value, recipient))) {
                    throw new RelayError(400, "Delivery omits target inbox", {
                        error: "malformed",
                    });
                }
                const duplicate = await this.#insert(
                    recipient,
                    input.eventId,
                    delivery,
                    input.admissionPrincipal,
                );
                return json({ duplicate }, 200);
            } catch (error: unknown) {
                if (error instanceof RelayError) return json(error.body, error.status);
                return json({ error: "internal" }, 500);
            }
        }
        if (
            request.method !== "GET" ||
            url.pathname !== "/v2/connect" ||
            request.headers.get("upgrade")?.toLowerCase() !== "websocket"
        ) {
            return json({ error: "not_found" }, 404);
        }
        try {
            const token = relaySessionTokenFromWebSocketProtocols(
                request.headers.get("sec-websocket-protocol"),
            );
            const claims = verifyRelaySessionToken(
                parseTokenSecret(this.#environment.MURMUR_RELAY_TOKEN_SECRET),
                token,
                { expectedEndpoint: this.#environment.MURMUR_RELAY_ENDPOINT },
            );
            const pair = websocketPair();
            pair.server.serializeAttachment({
                device: encodeBase64Url(claims.device),
                admissionPrincipal: claims.admissionPrincipal,
                expiresAt: claims.expiresAt,
            });
            this.#state.acceptWebSocket(pair.server);
            await this.#scheduleAt(claims.expiresAt);
            return websocketResponse(pair.client);
        } catch (error: unknown) {
            if (error instanceof RelayError) return json(error.body, error.status);
            return json({ error: "internal" }, 500);
        }
    }

    /** Process one strict request from a hibernated socket. */
    async webSocketMessage(
        socket: CloudflareServerWebSocket,
        message: string | ArrayBuffer,
    ): Promise<void> {
        let id = "invalid";
        try {
            if (typeof message !== "string") {
                throw new RelayError(400, "Binary WebSocket messages are unsupported", {
                    error: "malformed",
                });
            }
            const frame = requestFrame(message);
            id = frame.id;
            const authorization = attachment(socket);
            if (authorization.started === true) {
                throw new RelayError(400, "WebSocket accepts exactly one request", {
                    error: "malformed",
                });
            }
            socket.serializeAttachment({ ...authorization, started: true });
            if (frame.operation === "publish") {
                const delivery = parseSignedDelivery(frame.body);
                assertDevice(authorization.device, delivery.sender);
                const fanoutId = this.#environment.MURMUR_FANOUT.idFromName(FANOUT_OBJECT_NAME);
                const response = await this.#environment.MURMUR_FANOUT.get(fanoutId).fetch(
                    new Request("https://murmur.internal/v2/publish", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({
                            delivery: signedDeliveryToJson(delivery),
                            admissionPrincipal: authorization.admissionPrincipal,
                        }),
                    }),
                );
                send(socket, responseFrame(frame.id, response.status, await response.json()));
                return;
            }
            if (frame.operation === "delete_session") {
                const delivery = parseSignedDelivery(frame.body);
                const fanoutId = this.#environment.MURMUR_FANOUT.idFromName(FANOUT_OBJECT_NAME);
                const response = await this.#environment.MURMUR_FANOUT.get(fanoutId).fetch(
                    new Request("https://murmur.internal/v2/delete", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({ delivery: signedDeliveryToJson(delivery) }),
                    }),
                );
                send(socket, responseFrame(frame.id, response.status, await response.json()));
                return;
            }
            if (frame.operation === "delete_account") {
                send(
                    socket,
                    responseFrame(frame.id, 501, {
                        error: "account_deletion_unavailable",
                    }),
                );
                return;
            }
            if (frame.operation === "read") {
                const read = parseSignedQueueRead(frame.body);
                this.#authorizeRead(authorization.device, read, false);
                const page = await this.#read(read);
                const encoded = responseFrame(frame.id, 200, page);
                if (textEncoder.encode(encoded).length > MAXIMUM_MESSAGE_BYTES) {
                    send(
                        socket,
                        responseFrame(frame.id, 413, {
                            error: "delivery_too_large",
                            eventId: page.deliveries[0]?.eventId ?? null,
                            sequence: page.deliveries[0]?.sequence ?? null,
                            head: page.head,
                            headSequence: page.headSequence,
                            acknowledgedThrough: page.acknowledgedThrough,
                            acknowledgedSequence: page.acknowledgedSequence,
                            generation: page.generation,
                        }),
                    );
                } else {
                    send(socket, encoded);
                }
                return;
            }
            if (frame.operation === "acknowledge") {
                const acknowledgement = parseSignedQueueAck(frame.body);
                this.#authorizeAck(authorization.device, acknowledgement);
                send(
                    socket,
                    responseFrame(frame.id, 200, await this.#acknowledge(acknowledgement)),
                );
                return;
            }
            const read = parseSignedQueueRead(frame.body);
            this.#authorizeRead(authorization.device, read, true);
            const page = await this.#read(read);
            socket.serializeAttachment({
                ...authorization,
                started: true,
                streamId: frame.id,
                after: read.after,
            });
            send(socket, responseFrame(frame.id, 200, { connected: true }));
            send(
                socket,
                continuityFrame(frame.id, {
                    head: page.head,
                    headSequence: page.headSequence,
                    nextSequence: page.headSequence + 1,
                    acknowledgedThrough: page.acknowledgedThrough,
                    acknowledgedSequence: page.acknowledgedSequence,
                    generation: page.generation,
                    pendingItems: page.deliveries.length,
                    pendingBytes: 0,
                }),
            );
            for (const queued of page.deliveries) {
                send(
                    socket,
                    deliveryFrame(frame.id, queued.eventId, queued.sequence, queued.delivery),
                );
                socket.serializeAttachment({
                    ...attachment(socket),
                    after: queued.eventId,
                });
            }
            await this.#scheduleHeartbeat();
            await this.#scheduleAt(authorization.expiresAt);
        } catch (error: unknown) {
            if (error instanceof RelayError) {
                send(socket, responseFrame(id, error.status, error.body));
            } else {
                send(socket, responseFrame(id, 500, { error: "internal" }));
            }
        }
    }

    /** Release a socket after Cloudflare reports its peer closure. */
    webSocketClose(socket: CloudflareServerWebSocket): void {
        socket.close(1000, "closed");
    }

    /** Close a hibernated socket after Cloudflare reports a transport error. */
    webSocketError(socket: CloudflareServerWebSocket): void {
        socket.close(1011, "socket error");
    }

    /** Send stream heartbeats and enforce the ticket's maximum socket lifetime. */
    async alarm(): Promise<void> {
        const now = Date.now();
        await this.#pruneDeletedSessions(now);
        await this.#pruneExpired(now);
        let active = false;
        for (const socket of this.#state.getWebSockets()) {
            try {
                const value = attachment(socket);
                if (value.expiresAt <= now) {
                    socket.close(1008, "ticket expired");
                    continue;
                }
                await this.#scheduleAt(value.expiresAt);
                if (value.streamId !== undefined) {
                    send(socket, heartbeatFrame(value.streamId));
                    active = true;
                }
            } catch {
                socket.close(1011, "heartbeat failed");
            }
        }
        if (active) await this.#scheduleAt(now + STREAM_HEARTBEAT_MILLISECONDS);
        const expirations = await this.#state.storage.list<InboxExpiryRecord>({
            prefix: EXPIRY_PREFIX,
            limit: 1,
        });
        const key = expirations.keys().next().value as string | undefined;
        if (key !== undefined) {
            const expiresAt = Number(key.slice(EXPIRY_PREFIX.length, EXPIRY_PREFIX.length + 16));
            if (Number.isSafeInteger(expiresAt)) await this.#scheduleAt(expiresAt);
        }
        const tombstones = await this.#state.storage.list<DeletedSessionExpiryRecord>({
            prefix: DELETED_SESSION_EXPIRY_PREFIX,
            limit: 1,
        });
        const tombstoneKey = tombstones.keys().next().value as string | undefined;
        if (tombstoneKey !== undefined) {
            const expiresAt = Number(
                tombstoneKey.slice(
                    DELETED_SESSION_EXPIRY_PREFIX.length,
                    DELETED_SESSION_EXPIRY_PREFIX.length + 16,
                ),
            );
            if (Number.isSafeInteger(expiresAt)) await this.#scheduleAt(expiresAt);
        }
    }

    async #insert(
        recipient: Uint8Array,
        eventId: string,
        delivery: SignedDelivery,
        admissionPrincipal: string,
    ): Promise<boolean> {
        await this.#pruneExpired(Date.now());
        const encodedBytes = encodedDeliveryBytes(delivery);
        const senderCounter = `${SENDER_PREFIX}${encodeBase64Url(delivery.sender)}`;
        const principalCounter = `${PRINCIPAL_PREFIX}${encodeBase64Url(
            sha256(textEncoder.encode(admissionPrincipal)),
        )}`;
        const expires = expiryKey(delivery.expiresAt, eventId);
        const duplicate = await this.#state.storage.transaction(async (transaction) => {
            const key = eventKey(eventId);
            if (delivery.ownerAccount !== null && delivery.sessionId !== null) {
                const tombstoneKey = deletedSessionKey(delivery.ownerAccount, delivery.sessionId);
                const tombstone = await transaction.get<DeletedSessionRecord>(tombstoneKey);
                if (tombstone !== undefined && tombstone.expiresAt > Date.now()) {
                    throw new RelayError(409, "Session was deleted", {
                        error: "session_deleted",
                    });
                }
                if (tombstone !== undefined) await transaction.delete(tombstoneKey);
            }
            const existing = await transaction.get<StoredDeliveryRecord>(key);
            if (existing !== undefined) {
                const stored = decodeStoredDelivery(existing.delivery);
                if (!equalBytes(deliveryFingerprint(stored), deliveryFingerprint(delivery))) {
                    throw new RelayError(409, "Event identifier collision", {
                        error: "id_collision",
                    });
                }
                return true;
            }
            const metadata = await this.#metadataInTransaction(transaction);
            if (metadata.head !== null && eventId <= metadata.head) {
                throw new RelayError(409, "Inbox event order regressed", {
                    error: "event_order",
                });
            }
            const sender = (await transaction.get<UsageCounter>(senderCounter)) ?? {
                items: 0,
                bytes: 0,
            };
            const principal = (await transaction.get<UsageCounter>(principalCounter)) ?? {
                items: 0,
                bytes: 0,
            };
            if (
                metadata.pendingItems + 1 > MAXIMUM_QUEUE_ITEMS ||
                metadata.pendingBytes + encodedBytes > MAXIMUM_QUEUE_BYTES
            ) {
                throw new RelayError(429, "Device inbox is full", { error: "queue_full" });
            }
            if (
                sender.items + 1 > MAXIMUM_SENDER_ITEMS ||
                sender.bytes + encodedBytes > MAXIMUM_SENDER_BYTES
            ) {
                throw new RelayError(429, "Sender quota is full", {
                    error: "sender_queue_full",
                });
            }
            if (principal.items + 1 > MAXIMUM_ADMISSION_REFERENCES) {
                throw new RelayError(429, "Admission quota is full", {
                    error: "admission_queue_full",
                });
            }
            const record: StoredDeliveryRecord = {
                eventId,
                sequence: metadata.nextSequence,
                delivery: signedDeliveryToJson(delivery),
                encodedBytes,
                senderCounter,
                principalCounter,
                expiryKey: expires,
            };
            await transaction.put(key, record);
            await transaction.put<InboxExpiryRecord>(expires, { eventKey: key });
            await transaction.put<InboxMetadata>(META_KEY, {
                ...metadata,
                head: eventId,
                headSequence: metadata.nextSequence,
                nextSequence: metadata.nextSequence + 1,
                pendingItems: metadata.pendingItems + 1,
                pendingBytes: metadata.pendingBytes + encodedBytes,
            });
            await transaction.put<UsageCounter>(senderCounter, {
                items: sender.items + 1,
                bytes: sender.bytes + encodedBytes,
            });
            await transaction.put<UsageCounter>(principalCounter, {
                items: principal.items + 1,
                bytes: principal.bytes + encodedBytes,
            });
            return false;
        });
        const metadata = await this.#state.storage.get<InboxMetadata>(META_KEY);
        if (metadata === undefined) throw new Error("Missing inbox metadata after insertion");
        this.#broadcast(eventId, metadata.headSequence, signedDeliveryToJson(delivery));
        await this.#scheduleAt(delivery.expiresAt);
        return duplicate;
    }

    async #read(read: SignedQueueRead): Promise<QueuePageBody> {
        await this.#pruneExpired(Date.now());
        const metadata = await this.#metadata();
        if (
            metadata.acknowledgedThrough !== null &&
            (read.after === null || read.after < metadata.acknowledgedThrough)
        ) {
            throw new RelayError(409, "Queue cursor was already trimmed", {
                error: "cursor_trimmed",
                acknowledgedThrough: metadata.acknowledgedThrough,
            });
        }
        const entries = await this.#state.storage.list<StoredDeliveryRecord>({
            prefix: EVENT_PREFIX,
            ...(read.after === null ? {} : { startAfter: eventKey(read.after) }),
            limit: read.limit + 1,
        });
        const values = [...entries.values()];
        const selected: StoredDeliveryRecord[] = [];
        let bytes = 256;
        for (const value of values.slice(0, read.limit)) {
            const next = bytes + value.encodedBytes + 128;
            if (selected.length > 0 && next > MAXIMUM_MESSAGE_BYTES) break;
            selected.push(value);
            bytes = next;
        }
        return {
            deliveries: selected.map((value) => ({
                eventId: value.eventId,
                sequence: value.sequence,
                delivery: value.delivery,
            })),
            head: metadata.head,
            headSequence: metadata.headSequence,
            acknowledgedThrough: metadata.acknowledgedThrough,
            acknowledgedSequence: metadata.acknowledgedSequence,
            generation: metadata.generation,
            exhausted: values.length <= selected.length,
        };
    }

    async #acknowledge(acknowledgement: SignedQueueAck): Promise<{
        readonly removed: number;
        readonly sequence: number;
        readonly generation: string;
    }> {
        return this.#state.storage.transaction(async (transaction) => {
            const metadata = await this.#metadataInTransaction(transaction);
            if (metadata.head === null) {
                return { removed: 0, sequence: 0, generation: metadata.generation };
            }
            if (acknowledgement.through > metadata.head) {
                throw new RelayError(409, "Acknowledgement exceeds inbox head", {
                    error: "ack_future",
                    head: metadata.head,
                });
            }
            if (
                metadata.acknowledgedThrough !== null &&
                acknowledgement.through < metadata.acknowledgedThrough
            ) {
                throw new RelayError(409, "Acknowledgement regressed", {
                    error: "ack_regression",
                    acknowledgedThrough: metadata.acknowledgedThrough,
                });
            }
            const entries = await transaction.list<StoredDeliveryRecord>({
                prefix: EVENT_PREFIX,
                end: `${eventKey(acknowledgement.through)}\uffff`,
            });
            await this.#deleteRecords(transaction, [...entries.entries()]);
            const removedBytes = [...entries.values()].reduce(
                (total, value) => total + value.encodedBytes,
                0,
            );
            await transaction.put<InboxMetadata>(META_KEY, {
                ...metadata,
                acknowledgedThrough: acknowledgement.through,
                acknowledgedSequence:
                    acknowledgement.through === metadata.head
                        ? metadata.headSequence
                        : Math.max(
                              metadata.acknowledgedSequence,
                              ...[...entries.values()].map((entry) => entry.sequence),
                          ),
                pendingItems: Math.max(0, metadata.pendingItems - entries.size),
                pendingBytes: Math.max(0, metadata.pendingBytes - removedBytes),
            });
            return {
                removed: entries.size,
                sequence:
                    acknowledgement.through === metadata.head
                        ? metadata.headSequence
                        : Math.max(
                              metadata.acknowledgedSequence,
                              ...[...entries.values()].map((entry) => entry.sequence),
                          ),
                generation: metadata.generation,
            };
        });
    }

    async #deleteSessionDeliveries(
        ownerAccount: Uint8Array,
        sessionId: Uint8Array,
    ): Promise<number> {
        const now = Date.now();
        const expiresAt = now + MAXIMUM_DELIVERY_TTL_MILLISECONDS;
        const tombstoneKey = deletedSessionKey(ownerAccount, sessionId);
        await this.#state.storage.transaction(async (transaction) => {
            await transaction.put<DeletedSessionRecord>(tombstoneKey, { expiresAt });
            await transaction.put<DeletedSessionExpiryRecord>(
                deletedSessionExpiryKey(expiresAt, ownerAccount, sessionId),
                { tombstoneKey },
            );
        });
        await this.#scheduleAt(expiresAt);
        let after: string | undefined;
        let removed = 0;
        for (;;) {
            const page = await this.#state.storage.list<StoredDeliveryRecord>({
                prefix: EVENT_PREFIX,
                ...(after === undefined ? {} : { startAfter: after }),
                limit: PRUNE_BATCH,
            });
            if (page.size === 0) break;
            after = [...page.keys()].at(-1);
            const candidates = [...page.entries()].filter(([, value]) => {
                const delivery = decodeStoredDelivery(value.delivery);
                return (
                    delivery.ownerAccount !== null &&
                    delivery.sessionId !== null &&
                    equalBytes(delivery.ownerAccount, ownerAccount) &&
                    equalBytes(delivery.sessionId, sessionId)
                );
            });
            if (candidates.length > 0) {
                const result = await this.#state.storage.transaction(async (transaction) => {
                    const records: [string, StoredDeliveryRecord][] = [];
                    for (const [key] of candidates) {
                        const current = await transaction.get<StoredDeliveryRecord>(key);
                        if (current === undefined) continue;
                        const delivery = decodeStoredDelivery(current.delivery);
                        if (
                            delivery.ownerAccount !== null &&
                            delivery.sessionId !== null &&
                            equalBytes(delivery.ownerAccount, ownerAccount) &&
                            equalBytes(delivery.sessionId, sessionId)
                        ) {
                            records.push([key, current]);
                        }
                    }
                    if (records.length === 0) return undefined;
                    await this.#deleteRecords(transaction, records);
                    const metadata = await this.#metadataInTransaction(transaction);
                    const removedBytes = records.reduce(
                        (total, [, value]) => total + value.encodedBytes,
                        0,
                    );
                    const updated: InboxMetadata = {
                        ...metadata,
                        generation: encodeBase64Url(
                            advanceLossGeneration(
                                decodeBase64Url(metadata.generation, 32),
                                records.length,
                            ),
                        ),
                        pendingItems: Math.max(0, metadata.pendingItems - records.length),
                        pendingBytes: Math.max(0, metadata.pendingBytes - removedBytes),
                    };
                    await transaction.put<InboxMetadata>(META_KEY, updated);
                    return { count: records.length, metadata: updated };
                });
                if (result !== undefined) {
                    removed += result.count;
                    this.#broadcastContinuity(result.metadata);
                }
            }
            if (page.size < PRUNE_BATCH) break;
        }
        return removed;
    }

    async #pruneDeletedSessions(now: number): Promise<number> {
        const entries = await this.#state.storage.list<DeletedSessionExpiryRecord>({
            prefix: DELETED_SESSION_EXPIRY_PREFIX,
            end: `${DELETED_SESSION_EXPIRY_PREFIX}${(now + 1).toString().padStart(16, "0")}`,
            limit: PRUNE_BATCH,
        });
        if (entries.size === 0) return 0;
        await this.#state.storage.transaction(async (transaction) => {
            for (const [key, value] of entries) {
                await transaction.delete([key, value.tombstoneKey]);
            }
        });
        return entries.size;
    }

    async #pruneExpired(now: number): Promise<number> {
        const expirations = await this.#state.storage.list<InboxExpiryRecord>({
            prefix: EXPIRY_PREFIX,
            end: `${EXPIRY_PREFIX}${(now + 1).toString().padStart(16, "0")}`,
            limit: PRUNE_BATCH,
        });
        if (expirations.size === 0) return 0;
        return this.#state.storage.transaction(async (transaction) => {
            const records: [string, StoredDeliveryRecord][] = [];
            for (const expiration of expirations.values()) {
                const record = await transaction.get<StoredDeliveryRecord>(expiration.eventKey);
                if (record !== undefined) records.push([expiration.eventKey, record]);
            }
            await this.#deleteRecords(transaction, records);
            await transaction.delete([...expirations.keys()]);
            const metadata = await this.#metadataInTransaction(transaction);
            const removedBytes = records.reduce(
                (total, [, value]) => total + value.encodedBytes,
                0,
            );
            await transaction.put<InboxMetadata>(META_KEY, {
                ...metadata,
                generation: encodeBase64Url(
                    advanceLossGeneration(decodeBase64Url(metadata.generation, 32), records.length),
                ),
                pendingItems: Math.max(0, metadata.pendingItems - records.length),
                pendingBytes: Math.max(0, metadata.pendingBytes - removedBytes),
            });
            return records.length;
        });
    }

    async #deleteRecords(
        transaction: DurableObjectTransactionLike,
        records: readonly [string, StoredDeliveryRecord][],
    ): Promise<void> {
        const counters = new Map<string, UsageCounter>();
        for (const [key, value] of records) {
            await transaction.delete([key, value.expiryKey]);
            for (const counterKey of [value.senderCounter, value.principalCounter]) {
                const current = counters.get(counterKey) ??
                    (await transaction.get<UsageCounter>(counterKey)) ?? {
                        items: 0,
                        bytes: 0,
                    };
                counters.set(counterKey, {
                    items: Math.max(0, current.items - 1),
                    bytes: Math.max(0, current.bytes - value.encodedBytes),
                });
            }
        }
        for (const [key, counter] of counters) {
            if (counter.items === 0) await transaction.delete(key);
            else await transaction.put(key, counter);
        }
    }

    #authorizeRead(device: string, read: SignedQueueRead, stream: boolean): void {
        assertDevice(device, read.recipient);
        this.#validateRequestTime(read.createdAt);
        if (!verifyQueueReadSignature(read)) {
            throw new RelayError(401, "Invalid queue-read signature", {
                error: "unauthorized",
            });
        }
        if (
            read.limit < 1 ||
            read.limit > 256 ||
            read.waitMilliseconds < 0 ||
            read.waitMilliseconds > 30_000 ||
            (stream && (read.limit !== 1 || read.waitMilliseconds !== 0))
        ) {
            throw new RelayError(400, "Invalid queue read", { error: "malformed" });
        }
    }

    #authorizeAck(device: string, acknowledgement: SignedQueueAck): void {
        assertDevice(device, acknowledgement.recipient);
        this.#validateRequestTime(acknowledgement.createdAt);
        if (!verifyQueueAckSignature(acknowledgement)) {
            throw new RelayError(401, "Invalid queue acknowledgement", {
                error: "unauthorized",
            });
        }
    }

    #authorizeDeletion(delivery: SignedDelivery): Uint8Array {
        validateSignedDeliveryShape(delivery);
        if (
            delivery.recipients.length !== 0 ||
            delivery.targetAccounts.length !== 0 ||
            delivery.ownerAccount !== null ||
            delivery.sessionId !== null ||
            delivery.ciphertext.length > 1_024 ||
            !verifyDeliverySignature(delivery)
        ) {
            throw new RelayError(401, "Invalid session deletion authorization", {
                error: "unauthorized",
            });
        }
        const now = Date.now();
        if (
            delivery.createdAt > now + MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS ||
            delivery.createdAt < now - MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS ||
            delivery.createdAt >= delivery.expiresAt ||
            delivery.expiresAt <= now ||
            delivery.expiresAt - now > MAXIMUM_DELIVERY_TTL_MILLISECONDS
        ) {
            throw new RelayError(401, "Session deletion violates relay time policy", {
                error: "unauthorized",
            });
        }
        return parseSessionDeletionRequest(delivery.ciphertext);
    }

    #validateRequestTime(createdAt: number): void {
        if (Math.abs(createdAt - Date.now()) > MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS) {
            throw new RelayError(401, "Signed request violates relay time policy", {
                error: "unauthorized",
            });
        }
    }

    #broadcast(eventId: string, sequence: number, delivery: SignedDeliveryJson): void {
        for (const socket of this.#state.getWebSockets()) {
            try {
                const value = attachment(socket);
                if (
                    value.streamId !== undefined &&
                    (value.after === null || value.after === undefined || eventId > value.after)
                ) {
                    send(socket, deliveryFrame(value.streamId, eventId, sequence, delivery));
                    socket.serializeAttachment({ ...value, after: eventId });
                }
            } catch {
                socket.close(1011, "stream delivery failed");
            }
        }
    }

    #broadcastContinuity(metadata: InboxMetadata): void {
        for (const socket of this.#state.getWebSockets()) {
            try {
                const value = attachment(socket);
                if (value.streamId !== undefined) {
                    send(socket, continuityFrame(value.streamId, metadata));
                }
            } catch {
                socket.close(1011, "stream continuity failed");
            }
        }
    }

    async #scheduleHeartbeat(): Promise<void> {
        await this.#scheduleAt(Date.now() + STREAM_HEARTBEAT_MILLISECONDS);
    }

    async #metadata(): Promise<InboxMetadata> {
        return this.#state.storage.transaction((transaction) =>
            this.#metadataInTransaction(transaction),
        );
    }

    async #metadataInTransaction(
        transaction: DurableObjectTransactionLike,
    ): Promise<InboxMetadata> {
        const existing = await transaction.get<unknown>(META_KEY);
        if (existing === undefined) {
            const created = emptyMetadata();
            await transaction.put(META_KEY, created);
            return created;
        }
        const metadata = object(existing);
        exact(metadata, [
            "head",
            "headSequence",
            "nextSequence",
            "acknowledgedThrough",
            "acknowledgedSequence",
            "generation",
            "pendingItems",
            "pendingBytes",
        ]);
        if (
            (metadata.head === null || typeof metadata.head === "string") &&
            Number.isSafeInteger(metadata.headSequence) &&
            (metadata.headSequence as number) >= 0 &&
            Number.isSafeInteger(metadata.nextSequence) &&
            (metadata.nextSequence as number) > (metadata.headSequence as number) &&
            (metadata.acknowledgedThrough === null ||
                typeof metadata.acknowledgedThrough === "string") &&
            Number.isSafeInteger(metadata.acknowledgedSequence) &&
            (metadata.acknowledgedSequence as number) >= 0 &&
            typeof metadata.generation === "string" &&
            Number.isSafeInteger(metadata.pendingItems) &&
            (metadata.pendingItems as number) >= 0 &&
            (metadata.pendingItems as number) <= MAXIMUM_QUEUE_ITEMS &&
            Number.isSafeInteger(metadata.pendingBytes) &&
            (metadata.pendingBytes as number) >= 0 &&
            (metadata.pendingBytes as number) <= MAXIMUM_QUEUE_BYTES
        ) {
            decodeBase64Url(metadata.generation, 32);
            return metadata as unknown as InboxMetadata;
        }
        throw new Error("Invalid inbox metadata");
    }

    async #scheduleAt(scheduled: number): Promise<void> {
        const current = await this.#state.storage.getAlarm();
        if (current === null || scheduled < current) {
            await this.#state.storage.setAlarm(scheduled);
        }
    }
}
