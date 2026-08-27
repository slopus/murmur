import { DurableFanoutCoordinator } from "../fanout/index.js";
import { sha256 } from "@noble/hashes/sha2";
import { LocalDirectoryTicketIssuer } from "../directory/index.js";
import type {
    DurableFanoutStore,
    FanoutRetryScheduler,
    FanoutTarget,
    PendingFanoutManifest,
} from "../fanout/index.js";
import {
    RelayError,
    deviceRosterToJson,
    directoryClaimToJson,
    deliveryFingerprint,
    parseAccountDeletionRequest,
    parseDeviceRosterLookup,
    parseDeviceRosterMutation,
    parseDirectoryClaimRequest,
    parseDirectoryPrekeyUpload,
    parseDirectorySpentNotification,
    parseSessionDeletionRequest,
    parseSignedDelivery,
    signedDeliveryToJson,
    validateSignedDeliveryShape,
    verifyDeliverySignature,
    type DirectoryClaim,
    type SignedDelivery,
    type SignedDeliveryJson,
} from "../protocol/index.js";
import type { RelayStorePublishOutcome } from "../storage/index.js";
import { RelayControlSqlStore, type RelayControlSql } from "../storage/controlSql.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { DuplicateJsonKeyError, parseStrictJson } from "../utils/strictJson.js";
import { nextUuidV7 } from "../utils/uuidV7.js";
import {
    MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS,
    MAXIMUM_CIPHERTEXT_BYTES,
    MAXIMUM_DELIVERY_TTL_MILLISECONDS,
    MAXIMUM_RECIPIENTS,
    deriveCloudflareDirectoryTicketSecret,
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
const DIRECTORY_TICKET_ISSUANCE_LIMIT = 8;
const DIRECTORY_TICKET_ISSUANCE_WINDOW_MILLISECONDS = 60_000;
const DIRECTORY_TICKET_ISSUANCE_PREFIX = "directory-ticket:issuance:";

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
    readonly recipients: readonly string[];
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

interface DirectoryTicketIssuanceRecord {
    readonly issued: number;
    readonly windowStartedAt: number;
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

function controlSql(state: DurableObjectStateLike): RelayControlSql {
    return {
        exec: <Row extends Record<string, unknown>>(
            query: string,
            ...bindings: readonly (Uint8Array | string | number | null)[]
        ) => {
            const cursor = state.storage.sql.exec<Row>(
                query,
                ...bindings.map((binding) =>
                    binding instanceof Uint8Array ? binding.slice().buffer : binding,
                ),
            );
            return {
                toArray: () => cursor.toArray(),
                one: () => cursor.one(),
            };
        },
    };
}

/** Deployment-wide event sequencer and durable retry coordinator. */
export class MurmurFanoutDurableObject implements DurableFanoutStore, FanoutRetryScheduler {
    readonly #state: DurableObjectStateLike;
    readonly #environment: MurmurCloudflareEnvironment;
    readonly #coordinator: DurableFanoutCoordinator;
    readonly #control: RelayControlSqlStore;
    readonly #directoryTickets: LocalDirectoryTicketIssuer;
    readonly #deletionsInFlight = new Set<string>();

    constructor(state: DurableObjectStateLike, environment: MurmurCloudflareEnvironment) {
        this.#state = state;
        this.#environment = environment;
        this.#control = new RelayControlSqlStore(controlSql(state));
        this.#directoryTickets = new LocalDirectoryTicketIssuer({
            issuer: "murmur-cloudflare-directory",
            secretKey: deriveCloudflareDirectoryTicketSecret(environment.MURMUR_RELAY_TOKEN_SECRET),
        });
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
            if (url.pathname === "/v2/delete-account") {
                const delivery = parseSignedDelivery(input.delivery);
                await this.#deleteAccount(delivery);
                return json({ deleted: true }, 200);
            }
            if (url.pathname === "/v2/roster/read") {
                const roster = this.#control.readDeviceRoster(parseDeviceRosterLookup(input));
                return json(
                    { roster: roster === undefined ? null : deviceRosterToJson(roster) },
                    200,
                );
            }
            if (url.pathname === "/v2/roster/mutate") {
                const delivery = parseSignedDelivery(input.delivery);
                const admissionPrincipal = this.#admissionPrincipal(input.admissionPrincipal);
                const roster = await this.#mutateDeviceRoster(delivery, admissionPrincipal);
                return json({ roster: deviceRosterToJson(roster) }, 200);
            }
            if (url.pathname === "/v2/directory/upload") {
                const delivery = parseSignedDelivery(input.delivery);
                this.#uploadDirectoryPrekeys(delivery);
                return json({ uploaded: true }, 200);
            }
            if (url.pathname === "/v2/directory/claim") {
                const request = parseDirectoryClaimRequest(input);
                const claim = await this.#claimDirectory(request.accountKey, request.ticket);
                return json(directoryClaimToJson(claim), 200);
            }
            if (url.pathname === "/v2/directory-ticket/authorize") {
                const admissionPrincipal = this.#admissionPrincipal(input.admissionPrincipal);
                const retryAfterMilliseconds =
                    await this.#authorizeDirectoryTicket(admissionPrincipal);
                return retryAfterMilliseconds === undefined
                    ? json({ authorized: true }, 200)
                    : json({ error: "rate_limited", retryAfterMilliseconds }, 429);
            }
            if (url.pathname !== "/v2/publish") {
                return json({ error: "not_found" }, 404);
            }
            const admissionPrincipal = this.#admissionPrincipal(input.admissionPrincipal);
            const delivery = parseSignedDelivery(input.delivery);
            this.#validateDelivery(delivery);
            const outcome = await this.#coordinator.publish(delivery, admissionPrincipal);
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
        await this.#resumeAccountPurges();
        await this.#scheduleNextExpiration();
    }

    /** Assign one global UUIDv7 and persist the exact manifest atomically. */
    async reserve(
        delivery: SignedDelivery,
        admissionPrincipal: string,
        now: number,
    ): Promise<RelayStorePublishOutcome> {
        await this.pruneExpired(now);
        const fingerprint = encodeBase64Url(deliveryFingerprint(delivery));
        const key = indexKey(delivery);
        const prior = await this.#state.storage.get<FanoutIndexRecord>(key);
        if (prior !== undefined) {
            if (prior.fingerprint !== fingerprint) {
                throw new RelayError(409, "Delivery identifier collision", {
                    error: "id_collision",
                });
            }
            return {
                eventId: prior.eventId,
                duplicate: true,
                recipients: prior.recipients.map((recipient) => decodeBase64Url(recipient, 32)),
            };
        }
        if (delivery.ownerAccount !== null && delivery.sessionId !== null) {
            const tombstone = await this.#state.storage.get<SessionTombstoneRecord>(
                sessionTombstoneKey(delivery.ownerAccount, delivery.sessionId),
            );
            if (tombstone !== undefined && tombstone.expiresAt > now) {
                throw new RelayError(409, "Session was deleted", { error: "session_deleted" });
            }
        }
        const recipients = this.#state.storage.transactionSync(() =>
            delivery.sessionControl === null
                ? this.#control.resolveDirectRecipients(delivery)
                : this.#control.resolveSessionRecipients(delivery, MAXIMUM_RECIPIENTS),
        );
        const encodedRecipients = recipients.map(encodeBase64Url);
        const encodedBytes = textEncoder.encode(
            JSON.stringify(signedDeliveryToJson(delivery)),
        ).length;
        return this.#state.storage.transaction(async (transaction) => {
            const existing = await transaction.get<FanoutIndexRecord>(key);
            if (existing !== undefined) {
                if (existing.fingerprint !== fingerprint) {
                    throw new RelayError(409, "Delivery identifier collision", {
                        error: "id_collision",
                    });
                }
                return {
                    eventId: existing.eventId,
                    duplicate: true,
                    recipients: existing.recipients.map((recipient) =>
                        decodeBase64Url(recipient, 32),
                    ),
                };
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
                metadata.retainedReferences + recipients.length > MAXIMUM_GLOBAL_REFERENCES
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
                references: recipients.length,
                recipients: encodedRecipients,
                sessionIndexKey: linkedSessionIndexKey,
            };
            const manifest: StoredFanoutManifest = {
                eventId,
                delivery: signedDeliveryToJson(delivery),
                admissionPrincipal,
                pendingRecipients: encodedRecipients,
            };
            await transaction.put(key, record);
            await transaction.put<FanoutExpiryRecord>(expiryKey(delivery.expiresAt, eventId), {
                ...record,
                indexKey: key,
            });
            if (linkedSessionIndexKey !== null) {
                await transaction.put<SessionIndexRecord>(linkedSessionIndexKey, {
                    recipients: encodedRecipients,
                });
            }
            await transaction.put(pendingKey(eventId), manifest);
            await transaction.put<FanoutMetadata>(META_KEY, {
                lastEventId: eventId,
                retainedItems: metadata.retainedItems + 1,
                retainedBytes: metadata.retainedBytes + encodedBytes,
                retainedReferences: metadata.retainedReferences + recipients.length,
            });
            return { eventId, duplicate: false, recipients };
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
        if (existing === null || at < existing || existing <= Date.now()) {
            await this.#state.storage.setAlarm(at);
        }
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
            this.#state.storage.transactionSync(() => {
                this.#control.deleteSession(delivery.sender, sessionId);
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

    async #mutateDeviceRoster(
        delivery: SignedDelivery,
        admissionPrincipal: string,
    ): Promise<ReturnType<RelayControlSqlStore["mutateDeviceRoster"]>> {
        this.#validateDelivery(delivery, true);
        this.#validateRecentControlTime(delivery, "Device roster mutation");
        if (!equalBytes(delivery.senderAccount, delivery.sender)) {
            throw new RelayError(401, "Invalid device roster mutation owner", {
                error: "unauthorized",
            });
        }
        const mutation = parseDeviceRosterMutation(delivery.ciphertext);
        const roster = this.#state.storage.transactionSync(() =>
            this.#control.mutateDeviceRoster(delivery, mutation, Date.now()),
        );
        if (delivery.recipients.length > 0) {
            await this.#coordinator.publish(delivery, admissionPrincipal);
        }
        return roster;
    }

    #uploadDirectoryPrekeys(delivery: SignedDelivery): void {
        this.#validateDelivery(delivery, true);
        this.#validateRecentControlTime(delivery, "Directory upload");
        if (!equalBytes(delivery.senderAccount, delivery.sender)) {
            throw new RelayError(401, "Invalid directory upload owner", {
                error: "unauthorized",
            });
        }
        if (delivery.recipients.length !== 0 || delivery.targetAccounts.length !== 0) {
            throw new RelayError(400, "Directory uploads may not target inboxes", {
                error: "malformed",
            });
        }
        const upload = parseDirectoryPrekeyUpload(delivery.ciphertext);
        const now = Date.now();
        for (const entry of upload.oneTimePrekeys) {
            const notification = entry.spentNotification;
            if (
                !equalBytes(notification.sender, upload.deviceKey) ||
                !equalBytes(notification.senderAccount, delivery.sender) ||
                notification.recipients.length !== 1 ||
                !equalBytes(notification.recipients[0]!, upload.deviceKey) ||
                notification.targetAccounts.length !== 0 ||
                notification.ciphertext.length > MAXIMUM_CIPHERTEXT_BYTES ||
                notification.createdAt > now + MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS ||
                notification.expiresAt <= now ||
                notification.expiresAt - now > MAXIMUM_DELIVERY_TTL_MILLISECONDS ||
                notification.expiresAt < entry.expiresAt ||
                !equalBytes(
                    parseDirectorySpentNotification(notification.ciphertext),
                    entry.reference,
                ) ||
                !verifyDeliverySignature(notification)
            ) {
                throw new RelayError(401, "Invalid spent-prekey notification", {
                    error: "unauthorized",
                });
            }
        }
        this.#state.storage.transactionSync(() => {
            this.#control.uploadDirectoryPrekeys(delivery, upload, now);
        });
    }

    async #claimDirectory(accountKey: Uint8Array, ticket: Uint8Array): Promise<DirectoryClaim> {
        const now = Date.now();
        let claims;
        try {
            claims = this.#directoryTickets.verify(ticket, now);
        } catch {
            throw new RelayError(401, "Invalid directory claim ticket", {
                error: "invalid_ticket",
            });
        }
        const result = this.#state.storage.transactionSync(() =>
            this.#control.claimDirectory(accountKey, claims, now),
        );
        for (const notification of result.notifications) {
            await this.#coordinator.publish(notification, `directory-ticket:${claims.issuer}`);
        }
        return result.claim;
    }

    async #authorizeDirectoryTicket(admissionPrincipal: string): Promise<number | undefined> {
        const now = Date.now();
        const key = `${DIRECTORY_TICKET_ISSUANCE_PREFIX}${encodeBase64Url(
            sha256(textEncoder.encode(admissionPrincipal)),
        )}`;
        return this.#state.storage.transaction(async (transaction) => {
            const existing = await transaction.get<DirectoryTicketIssuanceRecord>(key);
            if (
                existing === undefined ||
                existing.windowStartedAt + DIRECTORY_TICKET_ISSUANCE_WINDOW_MILLISECONDS <= now
            ) {
                await transaction.put<DirectoryTicketIssuanceRecord>(key, {
                    issued: 1,
                    windowStartedAt: now,
                });
                return undefined;
            }
            if (existing.issued >= DIRECTORY_TICKET_ISSUANCE_LIMIT) {
                return Math.max(
                    1,
                    existing.windowStartedAt + DIRECTORY_TICKET_ISSUANCE_WINDOW_MILLISECONDS - now,
                );
            }
            await transaction.put<DirectoryTicketIssuanceRecord>(key, {
                ...existing,
                issued: existing.issued + 1,
            });
            return undefined;
        });
    }

    async #deleteAccount(delivery: SignedDelivery): Promise<void> {
        const now = Date.now();
        this.#validateTerminalAccountDeletion(delivery, now);
        this.#state.storage.transactionSync(() => {
            this.#control.deleteAccount(delivery.sender, delivery.id, now);
        });
        await this.schedule(now);
    }

    async #resumeAccountPurges(): Promise<void> {
        const purges = this.#state.storage.transactionSync(() =>
            this.#control.pendingAccountPurges(),
        );
        let failed = false;
        for (const purge of purges) {
            for (const deviceKey of purge.deviceKeys) {
                const recipient = encodeBase64Url(deviceKey);
                try {
                    const id = this.#environment.MURMUR_INBOXES.idFromName(recipient);
                    const response = await this.#environment.MURMUR_INBOXES.get(id).fetch(
                        new Request("https://murmur.internal/v2/purge", {
                            method: "POST",
                            headers: { "content-type": "application/json" },
                            body: JSON.stringify({ recipient }),
                        }),
                    );
                    if (!response.ok) throw new Error(`Inbox purge failed (${response.status})`);
                    this.#state.storage.transactionSync(() => {
                        this.#control.completeAccountPurgeDevice(purge.accountDigest, deviceKey);
                    });
                } catch {
                    failed = true;
                }
            }
        }
        if (failed) await this.schedule(Date.now() + 1_000);
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

    #admissionPrincipal(value: unknown): string {
        if (typeof value !== "string" || value.length < 1 || value.length > 255) {
            throw new RelayError(400, "Invalid admission principal", {
                error: "malformed",
            });
        }
        return value;
    }

    #validateRecentControlTime(delivery: SignedDelivery, name: string): void {
        if (delivery.createdAt < Date.now() - MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS) {
            throw new RelayError(401, `${name} violates relay time policy`, {
                error: "unauthorized",
            });
        }
    }

    #validateTerminalAccountDeletion(delivery: SignedDelivery, now: number): void {
        validateSignedDeliveryShape(delivery);
        if (
            delivery.recipients.length !== 0 ||
            delivery.targetAccounts.length !== 0 ||
            delivery.ownerAccount !== null ||
            delivery.sessionId !== null ||
            !equalBytes(delivery.senderAccount, delivery.sender) ||
            !verifyDeliverySignature(delivery)
        ) {
            throw new RelayError(401, "Invalid account deletion authorization", {
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
            throw new RelayError(401, "Account deletion violates relay time policy", {
                error: "unauthorized",
            });
        }
        parseAccountDeletionRequest(delivery.ciphertext);
    }

    #validateDeletion(delivery: SignedDelivery, now: number): Uint8Array {
        validateSignedDeliveryShape(delivery);
        if (
            delivery.recipients.length !== 0 ||
            delivery.targetAccounts.length !== 0 ||
            delivery.ownerAccount !== null ||
            delivery.sessionId !== null ||
            delivery.ciphertext.length > 1_024 ||
            !equalBytes(delivery.senderAccount, delivery.sender) ||
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

    #validateDelivery(delivery: SignedDelivery, allowRecipientless: boolean = false): void {
        validateSignedDeliveryShape(delivery);
        if (!verifyDeliverySignature(delivery)) {
            throw new RelayError(401, "Invalid delivery signature", {
                error: "unauthorized",
            });
        }
        if (
            !allowRecipientless &&
            delivery.sessionControl === null &&
            delivery.recipients.length < 1
        ) {
            throw new RelayError(400, "Delivery has no recipients", { error: "malformed" });
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
            delivery.createdAt <
                now -
                    MAXIMUM_DELIVERY_TTL_MILLISECONDS -
                    MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS ||
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
