import {
    DatabaseSync,
    type SQLInputValue,
    type StatementResultingChanges,
    type StatementSync,
} from "node:sqlite";
import {
    RelayError,
    deliveryFingerprint,
    parseSignedDelivery,
    type SignedDelivery,
} from "../../protocol/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { bigintColumn, copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import { nextUuidV7 } from "../../utils/uuidV7.js";
import {
    encodeStoredDelivery,
    selectQueuePageMetadata,
    type StoredPageCandidate,
} from "../page.js";
import {
    advanceLossGeneration,
    createGenerationSeed,
    initialLossGeneration,
} from "../continuity.js";
import { RELAY_EXPIRATION_BATCH_ITEMS } from "../types.js";
import type {
    AcknowledgeOutcome,
    PageReadConstraints,
    PublishOutcome,
    QueuedDelivery,
    QueueLimits,
    QueuePage,
    RelayStore,
} from "../types.js";

const SQL_VALUE_CHUNK = 5_000;

/** SQLite store construction options for embedding. */
export interface SqliteRelayStoreOptions {
    readonly database?: DatabaseSync;
}

function record(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid SQLite queue row");
    }
    return value as Record<string, unknown>;
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name} in SQLite queue store`);
    }
    return value;
}

function nullableTextColumn(value: unknown, name: string): string | null {
    return value === null ? null : textColumn(value, name);
}

/** Fresh-schema SQLite identity-queue store. */
export class SqliteRelayStore implements RelayStore {
    readonly #database: DatabaseSync;
    #closed = false;

    constructor(path: string, options: SqliteRelayStoreOptions = {}) {
        this.#database = options.database ?? new DatabaseSync(path);
        this.#database.exec("PRAGMA journal_mode = WAL");
        this.#database.exec("PRAGMA foreign_keys = ON");
        this.#database.exec("PRAGMA busy_timeout = 5000");
        this.#initializeSchema();
    }

    async publish(
        delivery: SignedDelivery,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<PublishOutcome> {
        this.#assertOpen();
        if (!(admissionPrincipal instanceof Uint8Array) || admissionPrincipal.length !== 32) {
            throw new Error("Invalid admission principal");
        }
        await this.pruneExpired(now);
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const fingerprint = deliveryFingerprint(delivery);
            const existing = this.#get(
                `SELECT event_id, fingerprint
                 FROM murmur_queue_deliveries
                 WHERE sender = ? AND delivery_id = ?`,
                delivery.sender,
                delivery.id,
            );
            if (existing !== undefined) {
                const storedFingerprint = copyBytes(existing.fingerprint, "delivery fingerprint");
                if (!equalBytes(storedFingerprint, fingerprint)) {
                    throw new RelayError(409, "Delivery identifier collision", {
                        error: "id_collision",
                    });
                }
                this.#database.exec("COMMIT");
                return {
                    eventId: textColumn(existing.event_id, "event ID"),
                    duplicate: true,
                };
            }

            const encoded = encodeStoredDelivery(delivery);
            const global = this.#requiredGet(
                `SELECT last_event_id, generation_seed, pending_items, pending_bytes,
                        pending_references
                 FROM murmur_queue_global WHERE singleton = 1`,
            );
            if (
                bigintColumn(global.pending_items) + 1n > BigInt(limits.maximumGlobalItems) ||
                bigintColumn(global.pending_bytes) + BigInt(encoded.encodedBytes) >
                    BigInt(limits.maximumGlobalBytes) ||
                bigintColumn(global.pending_references) + BigInt(delivery.recipients.length) >
                    BigInt(limits.maximumGlobalReferences)
            ) {
                throw new RelayError(503, "Relay pending-storage quota exceeded", {
                    error: "relay_full",
                });
            }
            const admissionUsage = this.#requiredGet(
                `SELECT COUNT(*) AS reference_count
                 FROM murmur_queue_references
                 WHERE admission_principal = ?`,
                admissionPrincipal,
            );
            if (
                bigintColumn(admissionUsage.reference_count) + BigInt(delivery.recipients.length) >
                BigInt(limits.maximumAdmissionReferences)
            ) {
                throw new RelayError(429, "Admission-principal fanout quota exceeded", {
                    error: "admission_full",
                });
            }
            const senderUsage = this.#requiredGet(
                `SELECT COUNT(*) AS item_count,
                        COALESCE(SUM(encoded_bytes), 0) AS byte_count,
                        (SELECT COUNT(*)
                         FROM murmur_queue_references
                         WHERE sender = ?) AS reference_count
                 FROM murmur_queue_deliveries
                 WHERE sender = ?`,
                delivery.sender,
                delivery.sender,
            );
            if (
                bigintColumn(senderUsage.item_count) + 1n > BigInt(limits.maximumSenderItems) ||
                bigintColumn(senderUsage.byte_count) + BigInt(encoded.encodedBytes) >
                    BigInt(limits.maximumSenderBytes) ||
                bigintColumn(senderUsage.reference_count) + BigInt(delivery.recipients.length) >
                    BigInt(limits.maximumSenderReferences)
            ) {
                throw new RelayError(429, "Sender pending-storage quota exceeded", {
                    error: "sender_full",
                });
            }
            const targetValues = delivery.recipients.map(() => "(?)").join(", ");
            const recipientUsage = this.#all(
                `WITH targets(recipient) AS (VALUES ${targetValues})
                 SELECT targets.recipient,
                        COALESCE(queue.pending_items, 0) AS item_count,
                        COALESCE(queue.pending_bytes, 0) AS byte_count
                 FROM targets
                 LEFT JOIN murmur_queues AS queue
                   ON queue.recipient = targets.recipient`,
                ...delivery.recipients,
            );
            if (recipientUsage.length !== delivery.recipients.length) {
                throw new Error("SQLite recipient usage did not cover every target");
            }
            for (const usage of recipientUsage) {
                if (
                    bigintColumn(usage.item_count) >= BigInt(limits.maximumItems) ||
                    bigintColumn(usage.byte_count) + BigInt(encoded.encodedBytes) >
                        BigInt(limits.maximumBytes)
                ) {
                    throw new RelayError(429, "Recipient queue quota exceeded", {
                        error: "queue_full",
                    });
                }
            }

            const lastEventId =
                global.last_event_id === null
                    ? null
                    : textColumn(global.last_event_id, "last event ID");
            const eventId = nextUuidV7(now, lastEventId);
            this.#run(
                `UPDATE murmur_queue_global
                 SET last_event_id = ?,
                     pending_items = pending_items + 1,
                     pending_bytes = pending_bytes + ?,
                     pending_references = pending_references + ?
                 WHERE singleton = 1`,
                eventId,
                BigInt(encoded.encodedBytes),
                BigInt(delivery.recipients.length),
            );
            this.#run(
                `INSERT INTO murmur_queue_deliveries
                    (sender, delivery_id, event_id, fingerprint, delivery_json,
                     encoded_bytes, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                delivery.sender,
                delivery.id,
                eventId,
                fingerprint,
                encoded.json,
                BigInt(encoded.encodedBytes),
                BigInt(delivery.expiresAt),
            );
            const generationSeed = copyBytes(global.generation_seed, "generation seed");
            const queueValues = delivery.recipients
                .map(() => "(?, ?, 1, 2, NULL, 0, ?, 1, ?)")
                .join(", ");
            const queueParameters = delivery.recipients.flatMap((recipient) => [
                recipient,
                eventId,
                initialLossGeneration(generationSeed, recipient),
                BigInt(encoded.encodedBytes),
            ]);
            this.#run(
                `INSERT INTO murmur_queues
                    (recipient, head, head_sequence, next_sequence,
                     acknowledged_through, acknowledged_sequence, loss_generation,
                     pending_items, pending_bytes)
                 VALUES ${queueValues}
                 ON CONFLICT (recipient) DO UPDATE SET
                    head = excluded.head,
                    head_sequence = murmur_queues.next_sequence,
                    next_sequence = murmur_queues.next_sequence + 1,
                    pending_items = murmur_queues.pending_items + 1,
                    pending_bytes = murmur_queues.pending_bytes + excluded.pending_bytes`,
                ...queueParameters,
            );
            const assigned = this.#all(
                `SELECT recipient, head_sequence FROM murmur_queues
                 WHERE recipient IN (${delivery.recipients.map(() => "?").join(", ")})`,
                ...delivery.recipients,
            );
            const sequenceByRecipient = new Map(
                assigned.map((row) => [
                    encodeBase64Url(copyBytes(row.recipient, "queue recipient")),
                    safeNumberColumn(row.head_sequence),
                ]),
            );
            const referenceValues = delivery.recipients
                .map(() => "(?, ?, ?, ?, ?, ?, ?)")
                .join(", ");
            const referenceParameters = delivery.recipients.flatMap((recipient) => {
                const sequence = sequenceByRecipient.get(encodeBase64Url(recipient));
                if (sequence === undefined) throw new Error("Missing assigned inbox sequence");
                return [
                    recipient,
                    eventId,
                    BigInt(sequence),
                    delivery.sender,
                    delivery.id,
                    BigInt(encoded.encodedBytes),
                    admissionPrincipal,
                ];
            });
            this.#run(
                `INSERT INTO murmur_queue_references
                    (recipient, event_id, sequence, sender, delivery_id, encoded_bytes,
                     admission_principal)
                 VALUES ${referenceValues}`,
                ...referenceParameters,
            );
            this.#database.exec("COMMIT");
            return { eventId, duplicate: false };
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async readQueue(
        recipient: Uint8Array,
        after: string | null,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<QueuePage> {
        this.#assertOpen();
        await this.pruneExpired(now);
        this.#database.exec("BEGIN");
        try {
            const queue = this.#get(
                `SELECT head, head_sequence, acknowledged_through, acknowledged_sequence,
                        loss_generation
                 FROM murmur_queues WHERE recipient = ?`,
                recipient,
            );
            if (queue === undefined) {
                const global = this.#requiredGet(
                    `SELECT generation_seed FROM murmur_queue_global WHERE singleton = 1`,
                );
                this.#database.exec("COMMIT");
                return {
                    deliveries: [],
                    head: after,
                    headSequence: 0,
                    acknowledgedThrough: after,
                    acknowledgedSequence: 0,
                    generation: initialLossGeneration(
                        copyBytes(global.generation_seed, "generation seed"),
                        recipient,
                    ),
                    exhausted: true,
                };
            }
            const head = textColumn(queue.head, "queue head");
            const headSequence = safeNumberColumn(queue.head_sequence);
            const acknowledgedThrough = nullableTextColumn(
                queue.acknowledged_through,
                "acknowledged event ID",
            );
            const acknowledgedSequence = safeNumberColumn(queue.acknowledged_sequence);
            const generation = copyBytes(queue.loss_generation, "loss generation");
            if (acknowledgedThrough !== null && (after === null || after < acknowledgedThrough)) {
                throw new RelayError(409, "Queue cursor was already trimmed", {
                    error: "cursor_trimmed",
                    acknowledgedThrough,
                });
            }
            if (after !== null && after > head) {
                throw new RelayError(400, "Queue cursor exceeds its head", {
                    error: "malformed",
                });
            }

            const metadata = this.#all(
                `SELECT reference.event_id, reference.sequence, delivery.encoded_bytes
                 FROM murmur_queue_references AS reference
                 JOIN murmur_queue_deliveries AS delivery
                   ON delivery.sender = reference.sender
                  AND delivery.delivery_id = reference.delivery_id
                 WHERE reference.recipient = ?
                   AND (? IS NULL OR reference.event_id > ?)
                   AND delivery.expires_at > ?
                 ORDER BY reference.sequence
                 LIMIT ?`,
                recipient,
                after,
                after,
                BigInt(now),
                BigInt(limit + 1),
            );
            const selection = selectQueuePageMetadata(
                metadata.map(
                    (row): StoredPageCandidate => ({
                        eventId: textColumn(row.event_id, "event ID"),
                        sequence: safeNumberColumn(row.sequence),
                        encodedBytes: safeNumberColumn(row.encoded_bytes),
                    }),
                ),
                head,
                headSequence,
                acknowledgedThrough,
                acknowledgedSequence,
                generation,
                after,
                limit,
                constraints,
            );
            const hydrated =
                selection.candidates.length === 0
                    ? []
                    : this.#all(
                          `SELECT reference.event_id, reference.sequence,
                                  delivery.delivery_json
                           FROM murmur_queue_references AS reference
                           JOIN murmur_queue_deliveries AS delivery
                             ON delivery.sender = reference.sender
                            AND delivery.delivery_id = reference.delivery_id
                           WHERE reference.recipient = ?
                             AND reference.event_id IN (${selection.candidates
                                 .map(() => "?")
                                 .join(", ")})
                           ORDER BY reference.sequence`,
                          recipient,
                          ...selection.candidates.map(({ eventId }) => eventId),
                      );
            if (hydrated.length !== selection.candidates.length) {
                throw new Error("SQLite queue hydration did not match selected references");
            }
            const deliveries = hydrated.map((row, index): QueuedDelivery => {
                const eventId = textColumn(row.event_id, "event ID");
                if (eventId !== selection.candidates[index]!.eventId) {
                    throw new Error("SQLite queue hydration order is inconsistent");
                }
                return {
                    eventId,
                    sequence: safeNumberColumn(row.sequence),
                    delivery: parseSignedDelivery(
                        JSON.parse(textColumn(row.delivery_json, "delivery JSON")) as unknown,
                    ),
                };
            });
            this.#database.exec("COMMIT");
            return {
                deliveries,
                head: selection.head,
                headSequence: selection.headSequence,
                acknowledgedThrough: selection.acknowledgedThrough,
                acknowledgedSequence: selection.acknowledgedSequence,
                generation: selection.generation,
                exhausted: selection.exhausted,
            };
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async acknowledge(
        recipient: Uint8Array,
        through: string,
        now: number,
    ): Promise<AcknowledgeOutcome> {
        this.#assertOpen();
        await this.pruneExpired(now);
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const queue = this.#get(
                `SELECT head, head_sequence, acknowledged_through, acknowledged_sequence,
                        loss_generation
                 FROM murmur_queues WHERE recipient = ?`,
                recipient,
            );
            if (queue === undefined) {
                const global = this.#requiredGet(
                    `SELECT generation_seed FROM murmur_queue_global WHERE singleton = 1`,
                );
                this.#database.exec("COMMIT");
                return {
                    removed: 0,
                    generation: initialLossGeneration(
                        copyBytes(global.generation_seed, "generation seed"),
                        recipient,
                    ),
                    sequence: 0,
                };
            }
            const head = textColumn(queue.head, "queue head");
            const headSequence = safeNumberColumn(queue.head_sequence);
            const acknowledgedThrough = nullableTextColumn(
                queue.acknowledged_through,
                "acknowledged event ID",
            );
            if (acknowledgedThrough !== null && through < acknowledgedThrough) {
                throw new RelayError(409, "Acknowledgement regresses queue progress", {
                    error: "ack_regression",
                    acknowledgedThrough,
                });
            }
            if (through > head) {
                throw new RelayError(409, "Acknowledgement exceeds queue head", {
                    error: "ack_future",
                    head,
                });
            }
            const affected = this.#all(
                `SELECT sender, delivery_id, encoded_bytes, sequence
                 FROM murmur_queue_references
                 WHERE recipient = ? AND event_id <= ?`,
                recipient,
                through,
            );
            const removed = safeNumberColumn(
                this.#run(
                    `DELETE FROM murmur_queue_references
                     WHERE recipient = ? AND event_id <= ?`,
                    recipient,
                    through,
                ).changes,
            );
            const removedBytes = affected.reduce(
                (total, row) => total + bigintColumn(row.encoded_bytes),
                0n,
            );
            const previousAcknowledgedSequence = safeNumberColumn(queue.acknowledged_sequence);
            const acknowledgedSequence =
                through === head
                    ? headSequence
                    : affected.reduce(
                          (maximum, row) => Math.max(maximum, safeNumberColumn(row.sequence)),
                          previousAcknowledgedSequence,
                      );
            this.#run(
                `UPDATE murmur_queues
                 SET acknowledged_through = ?,
                     acknowledged_sequence = ?,
                     pending_items = pending_items - ?,
                     pending_bytes = pending_bytes - ?
                 WHERE recipient = ?`,
                through,
                BigInt(acknowledgedSequence),
                BigInt(removed),
                removedBytes,
                recipient,
            );
            let orphanedItems = 0n;
            let orphanedBytes = 0n;
            for (const row of affected) {
                const stored = this.#get(
                    `SELECT encoded_bytes
                     FROM murmur_queue_deliveries
                     WHERE sender = ? AND delivery_id = ?`,
                    copyBytes(row.sender, "delivery sender"),
                    textColumn(row.delivery_id, "delivery ID"),
                );
                const deleted = this.#run(
                    `DELETE FROM murmur_queue_deliveries
                     WHERE sender = ? AND delivery_id = ?
                       AND NOT EXISTS (
                           SELECT 1 FROM murmur_queue_references AS reference
                           WHERE reference.sender = murmur_queue_deliveries.sender
                             AND reference.delivery_id = murmur_queue_deliveries.delivery_id
                       )`,
                    copyBytes(row.sender, "delivery sender"),
                    textColumn(row.delivery_id, "delivery ID"),
                ).changes;
                if (deleted === 1n && stored !== undefined) {
                    orphanedItems += 1n;
                    orphanedBytes += bigintColumn(stored.encoded_bytes);
                }
            }
            this.#run(
                `UPDATE murmur_queue_global
                 SET pending_items = pending_items - ?,
                     pending_bytes = pending_bytes - ?,
                     pending_references = pending_references - ?
                 WHERE singleton = 1`,
                orphanedItems,
                orphanedBytes,
                BigInt(removed),
            );
            this.#database.exec("COMMIT");
            return {
                removed,
                generation: copyBytes(queue.loss_generation, "loss generation"),
                sequence: acknowledgedSequence,
            };
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async pruneExpired(now: number): Promise<number> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const removedDeliveries = this.#pruneExpired(now);
            this.#database.exec("COMMIT");
            return removedDeliveries;
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async declareRestored(): Promise<number> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const queues = this.#all(`SELECT recipient FROM murmur_queues ORDER BY recipient`);
            for (const queue of queues) {
                this.#run(
                    `UPDATE murmur_queues SET loss_generation = ? WHERE recipient = ?`,
                    createGenerationSeed(),
                    copyBytes(queue.recipient, "queue recipient"),
                );
            }
            this.#run(
                `UPDATE murmur_queue_global SET generation_seed = ? WHERE singleton = 1`,
                createGenerationSeed(),
            );
            this.#database.exec("COMMIT");
            return queues.length;
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async health(): Promise<void> {
        this.#assertOpen();
        this.#requiredGet("SELECT 1 AS healthy");
    }

    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            this.#database.close();
        }
    }

    #initializeSchema(): void {
        const marker = this.#get(
            `SELECT name FROM sqlite_master
             WHERE type = 'table' AND name = 'murmur_queue_schema'`,
        );
        if (marker === undefined) {
            const incomplete = this.#get(
                `SELECT name FROM sqlite_master
                 WHERE type = 'table'
                   AND name LIKE 'murmur_queue_%'
                 LIMIT 1`,
            );
            if (incomplete !== undefined) {
                throw new Error("Incomplete SQLite queue schema");
            }
        } else {
            const schema = this.#requiredGet(
                "SELECT version FROM murmur_queue_schema WHERE singleton = 1",
            );
            const version = bigintColumn(schema.version);
            if (version !== 1n) {
                throw new Error("Unsupported SQLite queue schema version");
            }
            const tables = this.#requiredGet(
                `SELECT COUNT(*) AS table_count FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                    'murmur_queue_schema',
                    'murmur_queue_global',
                    'murmur_queues',
                    'murmur_queue_deliveries',
                    'murmur_queue_references'
                 )`,
            );
            if (safeNumberColumn(tables.table_count) !== 5) {
                throw new Error("Incomplete SQLite queue schema");
            }
            return;
        }
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            this.#database.exec(`
            CREATE TABLE murmur_queue_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            ) STRICT;
            INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 1);
            CREATE TABLE murmur_queue_global (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_event_id TEXT CHECK (
                    last_event_id IS NULL OR length(last_event_id) = 36
                ),
                generation_seed BLOB NOT NULL CHECK (length(generation_seed) = 32),
                pending_items INTEGER NOT NULL CHECK (pending_items >= 0),
                pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0),
                pending_references INTEGER NOT NULL CHECK (pending_references >= 0)
            ) STRICT;
            INSERT INTO murmur_queue_global
                (singleton, last_event_id, generation_seed, pending_items, pending_bytes,
                 pending_references)
            VALUES (1, NULL, zeroblob(32), 0, 0, 0);
            CREATE TABLE murmur_queues (
                recipient BLOB PRIMARY KEY CHECK (length(recipient) = 32),
                head TEXT NOT NULL CHECK (length(head) = 36),
                head_sequence INTEGER NOT NULL CHECK (head_sequence >= 1),
                next_sequence INTEGER NOT NULL CHECK (next_sequence = head_sequence + 1),
                acknowledged_through TEXT CHECK (
                    acknowledged_through IS NULL OR (
                        length(acknowledged_through) = 36
                        AND acknowledged_through <= head
                    )
                ),
                acknowledged_sequence INTEGER NOT NULL CHECK (
                    acknowledged_sequence >= 0 AND acknowledged_sequence <= head_sequence
                ),
                loss_generation BLOB NOT NULL CHECK (length(loss_generation) = 32),
                pending_items INTEGER NOT NULL CHECK (pending_items >= 0),
                pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0)
            ) STRICT;
            CREATE TABLE murmur_queue_deliveries (
                sender BLOB NOT NULL CHECK (length(sender) = 32),
                delivery_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36),
                fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
                delivery_json TEXT NOT NULL,
                encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0),
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (sender, delivery_id)
            ) STRICT;
            CREATE INDEX murmur_queue_delivery_expiration
                ON murmur_queue_deliveries(expires_at);
            CREATE TABLE murmur_queue_references (
                recipient BLOB NOT NULL REFERENCES murmur_queues(recipient)
                    ON DELETE CASCADE,
                event_id TEXT NOT NULL CHECK (length(event_id) = 36),
                sequence INTEGER NOT NULL CHECK (sequence >= 1),
                sender BLOB NOT NULL,
                delivery_id TEXT NOT NULL,
                encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0),
                admission_principal BLOB NOT NULL CHECK (length(admission_principal) = 32),
                PRIMARY KEY (recipient, event_id),
                UNIQUE (recipient, sequence),
                FOREIGN KEY (sender, delivery_id)
                    REFERENCES murmur_queue_deliveries(sender, delivery_id)
                    ON DELETE CASCADE
            ) STRICT;
            CREATE INDEX murmur_queue_reference_delivery
                ON murmur_queue_references(sender, delivery_id);
            CREATE INDEX murmur_queue_reference_admission
                ON murmur_queue_references(admission_principal);
            `);
            this.#run(
                `UPDATE murmur_queue_global SET generation_seed = ? WHERE singleton = 1`,
                createGenerationSeed(),
            );
            this.#database.exec("COMMIT");
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    #pruneExpired(now: number): number {
        const usage = this.#requiredGet(
            `SELECT COUNT(*) AS item_count,
                    COALESCE(SUM(encoded_bytes), 0) AS byte_count
             FROM murmur_queue_deliveries
             WHERE event_id IN (
                 SELECT event_id FROM murmur_queue_deliveries
                 WHERE expires_at <= ?
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )`,
            BigInt(now),
        );
        const references = this.#requiredGet(
            `SELECT COUNT(*) AS reference_count
             FROM murmur_queue_references AS reference
             JOIN murmur_queue_deliveries AS delivery
               ON delivery.sender = reference.sender
              AND delivery.delivery_id = reference.delivery_id
             WHERE delivery.event_id IN (
                 SELECT event_id FROM murmur_queue_deliveries
                 WHERE expires_at <= ?
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )`,
            BigInt(now),
        );
        const affected = this.#all(
            `SELECT reference.recipient,
                    COUNT(reference.event_id) AS item_count,
                    COALESCE(SUM(reference.encoded_bytes), 0) AS byte_count,
                    queue.loss_generation
             FROM murmur_queue_references AS reference
             JOIN murmur_queues AS queue ON queue.recipient = reference.recipient
             JOIN murmur_queue_deliveries AS delivery
               ON delivery.sender = reference.sender
              AND delivery.delivery_id = reference.delivery_id
             WHERE delivery.event_id IN (
                 SELECT event_id FROM murmur_queue_deliveries
                 WHERE expires_at <= ?
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             GROUP BY reference.recipient, queue.loss_generation`,
            BigInt(now),
        );
        const removed = safeNumberColumn(
            this.#run(
                `DELETE FROM murmur_queue_deliveries
                 WHERE event_id IN (
                     SELECT event_id FROM murmur_queue_deliveries
                     WHERE expires_at <= ?
                     ORDER BY expires_at, event_id
                     LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
                 )`,
                BigInt(now),
            ).changes,
        );
        for (let offset = 0; offset < affected.length; offset += SQL_VALUE_CHUNK) {
            const chunk = affected.slice(offset, offset + SQL_VALUE_CHUNK);
            const changeValues = chunk.map(() => "(?, ?, ?, ?)").join(", ");
            const changeParameters = chunk.flatMap((row) => [
                copyBytes(row.recipient, "queue recipient"),
                bigintColumn(row.item_count),
                bigintColumn(row.byte_count),
                advanceLossGeneration(
                    copyBytes(row.loss_generation, "loss generation"),
                    safeNumberColumn(row.item_count),
                ),
            ]);
            this.#run(
                `WITH changes(recipient, item_count, byte_count, loss_generation) AS (
                     VALUES ${changeValues}
                 )
                 UPDATE murmur_queues
                 SET pending_items = pending_items - (
                         SELECT item_count FROM changes
                         WHERE changes.recipient = murmur_queues.recipient
                     ),
                     pending_bytes = pending_bytes - (
                         SELECT byte_count FROM changes
                         WHERE changes.recipient = murmur_queues.recipient
                     ),
                     loss_generation = (
                         SELECT loss_generation FROM changes
                         WHERE changes.recipient = murmur_queues.recipient
                     )
                 WHERE recipient IN (SELECT recipient FROM changes)`,
                ...changeParameters,
            );
        }
        this.#run(
            `UPDATE murmur_queue_global
             SET pending_items = pending_items - ?,
                 pending_bytes = pending_bytes - ?,
                 pending_references = pending_references - ?
             WHERE singleton = 1`,
            bigintColumn(usage.item_count),
            bigintColumn(usage.byte_count),
            bigintColumn(references.reference_count),
        );
        return removed;
    }

    #get(
        sql: string,
        ...parameters: readonly SQLInputValue[]
    ): Record<string, unknown> | undefined {
        const row = this.#prepare(sql).get(...parameters);
        return row === undefined ? undefined : record(row);
    }

    #requiredGet(sql: string, ...parameters: readonly SQLInputValue[]): Record<string, unknown> {
        const row = this.#get(sql, ...parameters);
        if (row === undefined) {
            throw new Error("Missing required SQLite queue row");
        }
        return row;
    }

    #all(sql: string, ...parameters: readonly SQLInputValue[]): readonly Record<string, unknown>[] {
        return this.#prepare(sql)
            .all(...parameters)
            .map(record);
    }

    #run(sql: string, ...parameters: readonly SQLInputValue[]): StatementResultingChanges {
        return this.#prepare(sql).run(...parameters);
    }

    #prepare(sql: string): StatementSync {
        const statement = this.#database.prepare(sql);
        statement.setReadBigInts(true);
        return statement;
    }

    #rollback(): void {
        try {
            this.#database.exec("ROLLBACK");
        } catch {
            // Preserve the original transaction error.
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("SQLite queue store is closed");
        }
    }
}
