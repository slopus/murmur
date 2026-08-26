import { DurableFanoutCoordinator } from "../fanout/index.js";
import type {
    DurableFanoutStore,
    FanoutRetryScheduler,
    FanoutTarget,
    PendingFanoutManifest,
} from "../fanout/index.js";
import {
    RelayError,
    deliveryFingerprint,
    parseSessionDeletionRequest,
    parseSignedDelivery,
    signedDeliveryToJson,
    validateSignedDeliveryShape,
    verifyDeliverySignature,
    type SignedDelivery,
    type SignedDeliveryJson,
} from "../protocol/index.js";
import type { PublishOutcome } from "../storage/index.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { DuplicateJsonKeyError, parseStrictJson } from "../utils/strictJson.js";
import { nextUuidV7 } from "../utils/uuidV7.js";
import {
    MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS,
    MAXIMUM_CIPHERTEXT_BYTES,
    MAXIMUM_DELIVERY_TTL_MILLISECONDS,
    MAXIMUM_RECIPIENTS,
    object,
    textEncoder,
} from "./impl/cloudflareCodec.js";
import type { DurableObjectStateLike, MurmurCloudflareEnvironment } from "./types.js";

const META_KEY = "fanout:meta";
const PENDING_PREFIX = "fanout:pending:";
const INDEX_PREFIX = "fanout:index:";
const EXPIRY_PREFIX = "fanout:expiry:";
const SESSION_INDEX_PREFIX = "fanout:session:";
const SESSION_TOMBSTONE_PREFIX = "fanout:deleted-session:";
const DELETION_PREFIX = "fanout:deletion:";
const DELETION_EXPIRY_PREFIX = "fanout:deletion-expiry:";
const MAXIMUM_GLOBAL_ITEMS = 100_000;
const MAXIMUM_GLOBAL_BYTES = 8 * 1024 * 1024 * 1024;
const MAXIMUM_GLOBAL_REFERENCES = 1_000_000;
const PRUNE_BATCH = 100;

interface FanoutMetadata {
    readonly lastEventId: string | null;
    readonly retainedItems: number;
    readonly retainedBytes: number;
    readonly retainedReferences: number;
}

interface FanoutIndexRecord {
    readonly eventId: string;
    readonly fingerprint: string;
    readonly expiresAt: number;
    readonly encodedBytes: number;
    readonly references: number;
    readonly sessionIndexKey: string | null;
}

interface FanoutExpiryRecord extends FanoutIndexRecord {
    readonly indexKey: string;
}

interface StoredFanoutManifest {
    readonly eventId: string;
    readonly delivery: SignedDeliveryJson;
    readonly admissionPrincipal: string;
    readonly pendingRecipients: readonly string[];
}

interface SessionIndexRecord {
    readonly recipients: readonly string[];
}

interface SessionTombstoneRecord {
    readonly expiresAt: number;
}

interface SessionDeletionRecord {
    readonly expiresAt: number;
    readonly tombstoneKey: string;
    readonly sessionPrefix: string;
    readonly status: "collecting" | "pending" | "complete";
    readonly pendingRecipients: readonly string[];
    readonly removed: number;
}

interface SessionDeletionExpiryRecord {
    readonly deletionKey: string;
    readonly tombstoneKey: string;
}

function indexKey(delivery: SignedDelivery): string {
    return `${INDEX_PREFIX}${encodeBase64Url(delivery.sender)}:${delivery.id}`;
}

function pendingKey(eventId: string): string {
    return `${PENDING_PREFIX}${eventId}`;
}

function expiryKey(expiresAt: number, eventId: string): string {
    return `${EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}:${eventId}`;
}

function sessionPrefix(ownerAccount: Uint8Array, sessionId: Uint8Array): string {
    return `${SESSION_INDEX_PREFIX}${encodeBase64Url(ownerAccount)}:${encodeBase64Url(sessionId)}:`;
}

function sessionIndexKey(ownerAccount: Uint8Array, sessionId: Uint8Array, eventId: string): string {
    return `${sessionPrefix(ownerAccount, sessionId)}${eventId}`;
}

function sessionTombstoneKey(ownerAccount: Uint8Array, sessionId: Uint8Array): string {
    return `${SESSION_TOMBSTONE_PREFIX}${encodeBase64Url(ownerAccount)}:${encodeBase64Url(sessionId)}`;
}

function deletionKey(delivery: SignedDelivery): string {
    return `${DELETION_PREFIX}${encodeBase64Url(delivery.sender)}:${delivery.id}`;
}

function deletionExpiryKey(expiresAt: number, delivery: SignedDelivery): string {
    return `${DELETION_EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}:${encodeBase64Url(delivery.sender)}:${delivery.id}`;
}

function emptyMetadata(): FanoutMetadata {
    return {
        lastEventId: null,
        retainedItems: 0,
        retainedBytes: 0,
        retainedReferences: 0,
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
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > 16 * 1024 * 1024)) {
        throw new RelayError(413, "Fanout request exceeds limit", { error: "limit" });
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.length > 16 * 1024 * 1024) {
        throw new RelayError(413, "Fanout request exceeds limit", { error: "limit" });
    }
    try {
        return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch (error: unknown) {
        if (error instanceof DuplicateJsonKeyError) {
            throw new RelayError(400, error.message, { error: "duplicate_json_key" });
        }
        throw new RelayError(400, "Invalid fanout JSON", { error: "malformed" });
    }
}

/** Deployment-wide event sequencer and durable retry coordinator. */
export class MurmurFanoutDurableObject implements DurableFanoutStore, FanoutRetryScheduler {
    readonly #state: DurableObjectStateLike;
    readonly #environment: MurmurCloudflareEnvironment;
    readonly #coordinator: DurableFanoutCoordinator;
    readonly #deletionsInFlight = new Set<string>();

    constructor(state: DurableObjectStateLike, environment: MurmurCloudflareEnvironment) {
        this.#state = state;
        this.#environment = environment;
        const target: FanoutTarget = {
            insert: async (recipient, eventId, delivery, admissionPrincipal) => {
                const id = this.#environment.MURMUR_INBOXES.idFromName(encodeBase64Url(recipient));
                const response = await this.#environment.MURMUR_INBOXES.get(id).fetch(
                    new Request("https://murmur.internal/v2/insert", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({
                            eventId,
                            recipient: encodeBase64Url(recipient),
                            delivery: signedDeliveryToJson(delivery),
                            admissionPrincipal,
                        }),
                    }),
                );
                if (!response.ok) {
                    if (response.status === 409) {
                        const body = (await response.json()) as { readonly error?: unknown };
                        if (body.error === "session_deleted") return;
                    }
                    throw new Error(`Inbox insertion failed (${response.status})`);
                }
            },
        };
        this.#coordinator = new DurableFanoutCoordinator(this, target, this);
    }

    /** Internal publication boundary used by authenticated inbox sockets. */
    async fetch(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url);
            if (request.method !== "POST") {
                return json({ error: "not_found" }, 404);
            }
            const input = object(await requestJson(request));
            if (url.pathname === "/v2/delete") {
                const delivery = parseSignedDelivery(input.delivery);
                const removed = await this.#deleteSession(delivery);
                return json({ removed }, 200);
            }
            if (url.pathname !== "/v2/publish") {
                return json({ error: "not_found" }, 404);
            }
            if (
                typeof input.admissionPrincipal !== "string" ||
                input.admissionPrincipal.length < 1 ||
                input.admissionPrincipal.length > 255
            ) {
                throw new RelayError(400, "Invalid admission principal", {
                    error: "malformed",
                });
            }
            const delivery = parseSignedDelivery(input.delivery);
            this.#validateDelivery(delivery);
            const outcome = await this.#coordinator.publish(delivery, input.admissionPrincipal);
            return json(outcome, 200);
        } catch (error: unknown) {
            if (error instanceof RelayError) return json(error.body, error.status);
            return json({ error: "internal" }, 500);
        }
    }

    /** Resume the oldest incomplete manifest after a durable alarm. */
    async alarm(): Promise<void> {
        await this.#pruneDeletionState(Date.now());
        await this.#coordinator.retry();
        await this.#scheduleNextExpiration();
    }

    /** Assign one global UUIDv7 and persist the exact manifest atomically. */
    async reserve(
        delivery: SignedDelivery,
        admissionPrincipal: string,
        now: number,
    ): Promise<PublishOutcome> {
        await this.pruneExpired(now);
        const fingerprint = encodeBase64Url(deliveryFingerprint(delivery));
        const encodedBytes = textEncoder.encode(
            JSON.stringify(signedDeliveryToJson(delivery)),
        ).length;
        return this.#state.storage.transaction(async (transaction) => {
            const key = indexKey(delivery);
            const existing = await transaction.get<FanoutIndexRecord>(key);
            if (existing !== undefined) {
                if (existing.fingerprint !== fingerprint) {
                    throw new RelayError(409, "Delivery identifier collision", {
                        error: "id_collision",
                    });
                }
                return { eventId: existing.eventId, duplicate: true };
            }
            const metadata = (await transaction.get<FanoutMetadata>(META_KEY)) ?? emptyMetadata();
            const eventId = nextUuidV7(now, metadata.lastEventId);
            let linkedSessionIndexKey: string | null = null;
            if (delivery.ownerAccount !== null && delivery.sessionId !== null) {
                const tombstoneKey = sessionTombstoneKey(delivery.ownerAccount, delivery.sessionId);
                const tombstone = await transaction.get<SessionTombstoneRecord>(tombstoneKey);
                if (tombstone !== undefined && tombstone.expiresAt > now) {
                    throw new RelayError(409, "Session was deleted", {
                        error: "session_deleted",
                    });
                }
                if (tombstone !== undefined) await transaction.delete(tombstoneKey);
                linkedSessionIndexKey = sessionIndexKey(
                    delivery.ownerAccount,
                    delivery.sessionId,
                    eventId,
                );
            }
            if (
                metadata.retainedItems + 1 > MAXIMUM_GLOBAL_ITEMS ||
                metadata.retainedBytes + encodedBytes > MAXIMUM_GLOBAL_BYTES ||
                metadata.retainedReferences + delivery.recipients.length > MAXIMUM_GLOBAL_REFERENCES
            ) {
                throw new RelayError(503, "Fanout storage quota exceeded", {
                    error: "relay_full",
                });
            }
            const record: FanoutIndexRecord = {
                eventId,
                fingerprint,
                expiresAt: delivery.expiresAt,
                encodedBytes,
                references: delivery.recipients.length,
                sessionIndexKey: linkedSessionIndexKey,
            };
            const manifest: StoredFanoutManifest = {
                eventId,
                delivery: signedDeliveryToJson(delivery),
                admissionPrincipal,
                pendingRecipients: delivery.recipients.map(encodeBase64Url),
            };
            await transaction.put(key, record);
            await transaction.put<FanoutExpiryRecord>(expiryKey(delivery.expiresAt, eventId), {
                ...record,
                indexKey: key,
            });
            if (linkedSessionIndexKey !== null) {
                await transaction.put<SessionIndexRecord>(linkedSessionIndexKey, {
                    recipients: delivery.recipients.map(encodeBase64Url),
                });
            }
            await transaction.put(pendingKey(eventId), manifest);
            await transaction.put<FanoutMetadata>(META_KEY, {
                lastEventId: eventId,
                retainedItems: metadata.retainedItems + 1,
                retainedBytes: metadata.retainedBytes + encodedBytes,
                retainedReferences: metadata.retainedReferences + delivery.recipients.length,
            });
            return { eventId, duplicate: false };
        });
    }

    /** Read the globally oldest incomplete, unexpired manifest. */
    async oldestPending(now: number): Promise<PendingFanoutManifest | undefined> {
        await this.pruneExpired(now);
        const entries = await this.#state.storage.list<StoredFanoutManifest>({
            prefix: PENDING_PREFIX,
            limit: 1,
        });
        const stored = entries.values().next().value as StoredFanoutManifest | undefined;
        if (stored === undefined) return undefined;
        return {
            eventId: stored.eventId,
            delivery: parseSignedDelivery(stored.delivery),
            admissionPrincipal: stored.admissionPrincipal,
            pendingRecipients: stored.pendingRecipients.map((recipient) => {
                return decodeBase64Url(recipient, 32);
            }),
        };
    }

    /** Durably record one recipient insertion as complete. */
    async markDelivered(
        sender: Uint8Array,
        deliveryId: string,
        recipient: Uint8Array,
    ): Promise<void> {
        await this.#state.storage.transaction(async (transaction) => {
            const index = await transaction.get<FanoutIndexRecord>(
                `${INDEX_PREFIX}${encodeBase64Url(sender)}:${deliveryId}`,
            );
            if (index === undefined) return;
            const key = pendingKey(index.eventId);
            const manifest = await transaction.get<StoredFanoutManifest>(key);
            if (manifest === undefined) return;
            const encodedRecipient = encodeBase64Url(recipient);
            const pendingRecipients = manifest.pendingRecipients.filter(
                (value) => value !== encodedRecipient,
            );
            if (pendingRecipients.length === manifest.pendingRecipients.length) return;
            if (pendingRecipients.length === 0) {
                await transaction.delete(key);
            } else {
                await transaction.put<StoredFanoutManifest>(key, {
                    ...manifest,
                    pendingRecipients,
                });
            }
        });
    }

    /** Remove a bounded prefix of expired idempotency and retry state. */
    async pruneExpired(now: number): Promise<number> {
        const entries = await this.#state.storage.list<FanoutExpiryRecord>({
            prefix: EXPIRY_PREFIX,
            end: `${EXPIRY_PREFIX}${(now + 1).toString().padStart(16, "0")}`,
            limit: PRUNE_BATCH,
        });
        const expired = [...entries.entries()].filter(([, value]) => value.expiresAt <= now);
        if (expired.length === 0) return 0;
        await this.#state.storage.transaction(async (transaction) => {
            const metadata = (await transaction.get<FanoutMetadata>(META_KEY)) ?? emptyMetadata();
            let retainedItems = metadata.retainedItems;
            let retainedBytes = metadata.retainedBytes;
            let retainedReferences = metadata.retainedReferences;
            for (const [key, value] of expired) {
                await transaction.delete([
                    key,
                    value.indexKey,
                    pendingKey(value.eventId),
                    ...(value.sessionIndexKey === null ? [] : [value.sessionIndexKey]),
                ]);
                retainedItems -= 1;
                retainedBytes -= value.encodedBytes;
                retainedReferences -= value.references;
            }
            await transaction.put<FanoutMetadata>(META_KEY, {
                ...metadata,
                retainedItems: Math.max(0, retainedItems),
                retainedBytes: Math.max(0, retainedBytes),
                retainedReferences: Math.max(0, retainedReferences),
            });
        });
        return expired.length;
    }

    /** Set the Durable Object alarm without delaying an earlier wake. */
    async schedule(at: number): Promise<void> {
        const existing = await this.#state.storage.getAlarm();
        if (existing === null || at < existing) await this.#state.storage.setAlarm(at);
    }

    async #scheduleNextExpiration(): Promise<void> {
        const [deliveryEntries, deletionEntries] = await Promise.all([
            this.#state.storage.list<FanoutExpiryRecord>({
                prefix: EXPIRY_PREFIX,
                limit: 1,
            }),
            this.#state.storage.list<SessionDeletionExpiryRecord>({
                prefix: DELETION_EXPIRY_PREFIX,
                limit: 1,
            }),
        ]);
        const delivery = deliveryEntries.values().next().value as FanoutExpiryRecord | undefined;
        const deletionKey = deletionEntries.keys().next().value as string | undefined;
        if (delivery !== undefined) await this.schedule(delivery.expiresAt);
        if (deletionKey !== undefined) {
            const expiresAt = Number(
                deletionKey.slice(
                    DELETION_EXPIRY_PREFIX.length,
                    DELETION_EXPIRY_PREFIX.length + 16,
                ),
            );
            if (Number.isSafeInteger(expiresAt)) await this.schedule(expiresAt);
        }
    }

    async #deleteSession(delivery: SignedDelivery): Promise<number> {
        const now = Date.now();
        const sessionId = this.#validateDeletion(delivery, now);
        await this.#pruneDeletionState(now);
        const key = deletionKey(delivery);
        if (this.#deletionsInFlight.has(key)) {
            throw new RelayError(409, "Session deletion is already in progress", {
                error: "replay",
            });
        }
        this.#deletionsInFlight.add(key);
        try {
            const tombstoneKey = sessionTombstoneKey(delivery.sender, sessionId);
            const linkedSessionPrefix = sessionPrefix(delivery.sender, sessionId);
            let record = await this.#state.storage.transaction(async (transaction) => {
                const existing = await transaction.get<SessionDeletionRecord>(key);
                if (existing !== undefined) {
                    if (existing.sessionPrefix !== linkedSessionPrefix) {
                        throw new RelayError(409, "Deletion identifier collision", {
                            error: "id_collision",
                        });
                    }
                    if (existing.status === "complete") {
                        throw new RelayError(409, "Session deletion was already applied", {
                            error: "replay",
                        });
                    }
                    return existing;
                }
                const tombstone = await transaction.get<SessionTombstoneRecord>(tombstoneKey);
                if (tombstone !== undefined && tombstone.expiresAt > now) {
                    throw new RelayError(409, "Session was already deleted", {
                        error: "session_deleted",
                    });
                }
                const expiresAt = now + MAXIMUM_DELIVERY_TTL_MILLISECONDS;
                const created: SessionDeletionRecord = {
                    expiresAt,
                    tombstoneKey,
                    sessionPrefix: linkedSessionPrefix,
                    status: "collecting",
                    pendingRecipients: [],
                    removed: 0,
                };
                await transaction.put<SessionTombstoneRecord>(tombstoneKey, { expiresAt });
                await transaction.put<SessionDeletionRecord>(key, created);
                await transaction.put<SessionDeletionExpiryRecord>(
                    deletionExpiryKey(expiresAt, delivery),
                    { deletionKey: key, tombstoneKey },
                );
                return created;
            });
            if (record.status === "collecting") {
                const recipients = new Set<string>();
                let after: string | undefined;
                for (;;) {
                    const page = await this.#state.storage.list<SessionIndexRecord>({
                        prefix: record.sessionPrefix,
                        ...(after === undefined ? {} : { startAfter: after }),
                        limit: 1_000,
                    });
                    if (page.size === 0) break;
                    after = [...page.keys()].at(-1);
                    for (const value of page.values()) {
                        for (const recipient of value.recipients) recipients.add(recipient);
                    }
                    if (page.size < 1_000) break;
                }
                record = {
                    ...record,
                    status: "pending",
                    pendingRecipients: [...recipients].sort(),
                };
                await this.#state.storage.put<SessionDeletionRecord>(key, record);
            }
            for (const recipient of record.pendingRecipients) {
                const id = this.#environment.MURMUR_INBOXES.idFromName(recipient);
                const response = await this.#environment.MURMUR_INBOXES.get(id).fetch(
                    new Request("https://murmur.internal/v2/delete", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({
                            recipient,
                            delivery: signedDeliveryToJson(delivery),
                        }),
                    }),
                );
                if (!response.ok) {
                    throw new Error(`Inbox session deletion failed (${response.status})`);
                }
                const body = (await response.json()) as { readonly removed?: unknown };
                const removed =
                    typeof body.removed === "number" && Number.isSafeInteger(body.removed)
                        ? body.removed
                        : 0;
                record = {
                    ...record,
                    pendingRecipients: record.pendingRecipients.filter(
                        (value) => value !== recipient,
                    ),
                    removed: record.removed + removed,
                };
                await this.#state.storage.put<SessionDeletionRecord>(key, record);
            }
            await this.#deletePrefix(record.sessionPrefix);
            record = { ...record, status: "complete", pendingRecipients: [] };
            await this.#state.storage.put<SessionDeletionRecord>(key, record);
            await this.schedule(record.expiresAt);
            return record.removed;
        } finally {
            this.#deletionsInFlight.delete(key);
        }
    }

    async #deletePrefix(prefix: string): Promise<void> {
        for (;;) {
            const page = await this.#state.storage.list({ prefix, limit: 1_000 });
            if (page.size === 0) return;
            await this.#state.storage.delete([...page.keys()]);
            if (page.size < 1_000) return;
        }
    }

    async #pruneDeletionState(now: number): Promise<number> {
        const entries = await this.#state.storage.list<SessionDeletionExpiryRecord>({
            prefix: DELETION_EXPIRY_PREFIX,
            end: `${DELETION_EXPIRY_PREFIX}${(now + 1).toString().padStart(16, "0")}`,
            limit: PRUNE_BATCH,
        });
        if (entries.size === 0) return 0;
        await this.#state.storage.transaction(async (transaction) => {
            for (const [key, value] of entries) {
                await transaction.delete([key, value.deletionKey, value.tombstoneKey]);
            }
        });
        return entries.size;
    }

    #validateDeletion(delivery: SignedDelivery, now: number): Uint8Array {
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

    #validateDelivery(delivery: SignedDelivery): void {
        validateSignedDeliveryShape(delivery);
        if (!verifyDeliverySignature(delivery)) {
            throw new RelayError(401, "Invalid delivery signature", {
                error: "unauthorized",
            });
        }
        const now = Date.now();
        if (
            delivery.recipients.length > MAXIMUM_RECIPIENTS ||
            delivery.ciphertext.length > MAXIMUM_CIPHERTEXT_BYTES
        ) {
            throw new RelayError(413, "Delivery exceeds relay limits", { error: "limit" });
        }
        if (
            delivery.createdAt > now + MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS ||
            delivery.createdAt >= delivery.expiresAt ||
            delivery.expiresAt <= now ||
            delivery.expiresAt - now > MAXIMUM_DELIVERY_TTL_MILLISECONDS
        ) {
            throw new RelayError(401, "Delivery violates relay time policy", {
                error: "unauthorized",
            });
        }
    }
}
