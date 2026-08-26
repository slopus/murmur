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

function indexKey(delivery: SignedDelivery): string {
    return `${INDEX_PREFIX}${encodeBase64Url(delivery.sender)}:${delivery.id}`;
}

function pendingKey(eventId: string): string {
    return `${PENDING_PREFIX}${eventId}`;
}

function expiryKey(expiresAt: number, eventId: string): string {
    return `${EXPIRY_PREFIX}${expiresAt.toString().padStart(16, "0")}:${eventId}`;
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
            if (request.method !== "POST" || url.pathname !== "/v2/publish") {
                return json({ error: "not_found" }, 404);
            }
            const input = object(await requestJson(request));
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
            if (
                metadata.retainedItems + 1 > MAXIMUM_GLOBAL_ITEMS ||
                metadata.retainedBytes + encodedBytes > MAXIMUM_GLOBAL_BYTES ||
                metadata.retainedReferences + delivery.recipients.length > MAXIMUM_GLOBAL_REFERENCES
            ) {
                throw new RelayError(503, "Fanout storage quota exceeded", {
                    error: "relay_full",
                });
            }
            const eventId = nextUuidV7(now, metadata.lastEventId);
            const record: FanoutIndexRecord = {
                eventId,
                fingerprint,
                expiresAt: delivery.expiresAt,
                encodedBytes,
                references: delivery.recipients.length,
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
                await transaction.delete([key, value.indexKey, pendingKey(value.eventId)]);
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
        const entries = await this.#state.storage.list<FanoutExpiryRecord>({
            prefix: EXPIRY_PREFIX,
            limit: 1,
        });
        const record = entries.values().next().value as FanoutExpiryRecord | undefined;
        if (record !== undefined) await this.schedule(record.expiresAt);
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
