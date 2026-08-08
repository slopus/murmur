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
import type { PostgresDatabase, PostgresQuery } from "./database.js";
import { createPostgresRelaySchema } from "./migrations.js";

export {
    PgPoolDatabase,
    PGliteDatabase,
    type PGliteDatabaseLike,
    type PGliteQueryLike,
    type PostgresDatabase,
    type PostgresParameter,
    type PostgresQuery,
    type PostgresSession,
} from "./database.js";

/** Shared LISTEN/NOTIFY channel used only to reduce queue long-poll latency. */
export const POSTGRES_WAKE_CHANNEL = "murmur_queue_wake_v1";
const SQL_VALUE_CHUNK = 10_000;

function jsonValue(value: unknown): unknown {
    return typeof value === "string" ? (JSON.parse(value) as unknown) : value;
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name} in Postgres queue store`);
    }
    return value;
}

function nullableTextColumn(value: unknown, name: string): string | null {
    return value === null ? null : textColumn(value, name);
}

/** Fresh-schema Postgres/PGlite identity-queue store. */
export class PostgresRelayStore implements RelayStore {
    readonly #database: PostgresDatabase;
    #closed = false;

    private constructor(database: PostgresDatabase) {
        this.#database = database;
    }

    /** Create the clean schema and store. */
    static async create(database: PostgresDatabase): Promise<PostgresRelayStore> {
        await createPostgresRelaySchema(database);
        return new PostgresRelayStore(database);
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
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            const globalResult = await transaction.query<{
                last_event_id: unknown;
                pending_items: unknown;
                pending_bytes: unknown;
                pending_references: unknown;
            }>(
                `SELECT last_event_id, pending_items, pending_bytes, pending_references
                 FROM murmur_queue_global WHERE singleton = 1`,
            );
            const global = globalResult.rows[0];
            if (global === undefined) throw new Error("Missing global queue state");

            const fingerprint = deliveryFingerprint(delivery);
            const existing = await transaction.query<{
                event_id: unknown;
                fingerprint: unknown;
            }>(
                `SELECT event_id, fingerprint FROM murmur_queue_deliveries
                 WHERE sender = $1 AND delivery_id = $2`,
                [delivery.sender, delivery.id],
            );
            const duplicate = existing.rows[0];
            if (duplicate !== undefined) {
                const storedFingerprint = copyBytes(duplicate.fingerprint, "delivery fingerprint");
                if (!equalBytes(storedFingerprint, fingerprint)) {
                    throw new RelayError(409, "Delivery identifier collision", {
                        error: "id_collision",
                    });
                }
                await this.#notifyRecipients(transaction, delivery.recipients);
                return {
                    eventId: textColumn(duplicate.event_id, "event ID"),
                    duplicate: true,
                };
            }

            const encoded = encodeStoredDelivery(delivery);
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
            const admissionUsage = await transaction.query<{ reference_count: unknown }>(
                `SELECT COUNT(*) AS reference_count
                 FROM murmur_queue_references
                 WHERE admission_principal = $1`,
                [admissionPrincipal],
            );
            const admissionUsageRow = admissionUsage.rows[0];
            if (admissionUsageRow === undefined) {
                throw new Error("Missing admission-principal usage result");
            }
            if (
                bigintColumn(admissionUsageRow.reference_count) +
                    BigInt(delivery.recipients.length) >
                BigInt(limits.maximumAdmissionReferences)
            ) {
                throw new RelayError(429, "Admission-principal fanout quota exceeded", {
                    error: "admission_full",
                });
            }
            const senderUsage = await transaction.query<{
                item_count: unknown;
                byte_count: unknown;
                reference_count: unknown;
            }>(
                `SELECT COUNT(*) AS item_count,
                        COALESCE(SUM(encoded_bytes), 0) AS byte_count,
                        (SELECT COUNT(*)
                         FROM murmur_queue_references
                         WHERE sender = $1) AS reference_count
                 FROM murmur_queue_deliveries
                 WHERE sender = $1`,
                [delivery.sender],
            );
            const senderUsageRow = senderUsage.rows[0];
            if (senderUsageRow === undefined) throw new Error("Missing sender usage result");
            if (
                bigintColumn(senderUsageRow.item_count) + 1n > BigInt(limits.maximumSenderItems) ||
                bigintColumn(senderUsageRow.byte_count) + BigInt(encoded.encodedBytes) >
                    BigInt(limits.maximumSenderBytes) ||
                bigintColumn(senderUsageRow.reference_count) + BigInt(delivery.recipients.length) >
                    BigInt(limits.maximumSenderReferences)
            ) {
                throw new RelayError(429, "Sender pending-storage quota exceeded", {
                    error: "sender_full",
                });
            }
            const lastEventId = nullableTextColumn(global.last_event_id, "last event ID");
            const eventId = nextUuidV7(now, lastEventId);
            const targetValues = delivery.recipients
                .map((_, index) => `($${index + 1}::bytea)`)
                .join(", ");
            const targetParameters = [...delivery.recipients];
            await transaction.query(
                `INSERT INTO murmur_queues
                    (recipient, head, acknowledged_through, pending_items, pending_bytes)
                 SELECT target.recipient, $${targetParameters.length + 1}::uuid, NULL, 0, 0
                 FROM (VALUES ${targetValues}) AS target(recipient)
                 ON CONFLICT DO NOTHING`,
                [...targetParameters, eventId],
            );
            const recipientUsage = await transaction.query<{
                item_count: unknown;
                byte_count: unknown;
            }>(
                `SELECT queue.pending_items AS item_count,
                        queue.pending_bytes AS byte_count
                 FROM murmur_queues AS queue
                 JOIN (VALUES ${targetValues}) AS target(recipient)
                   ON queue.recipient = target.recipient
                 ORDER BY queue.recipient
                 FOR UPDATE OF queue`,
                targetParameters,
            );
            if (recipientUsage.rows.length !== delivery.recipients.length) {
                throw new Error("Postgres recipient usage did not cover every target");
            }
            for (const row of recipientUsage.rows) {
                if (
                    bigintColumn(row.item_count) >= BigInt(limits.maximumItems) ||
                    bigintColumn(row.byte_count) + BigInt(encoded.encodedBytes) >
                        BigInt(limits.maximumBytes)
                ) {
                    throw new RelayError(429, "Recipient queue quota exceeded", {
                        error: "queue_full",
                    });
                }
            }
            await transaction.query(
                `UPDATE murmur_queue_global
                 SET last_event_id = $1,
                     pending_items = pending_items + 1,
                     pending_bytes = pending_bytes + $2,
                     pending_references = pending_references + $3
                 WHERE singleton = 1`,
                [eventId, encoded.encodedBytes, delivery.recipients.length],
            );
            await transaction.query(
                `INSERT INTO murmur_queue_deliveries
                    (sender, delivery_id, event_id, fingerprint, delivery_json,
                     encoded_bytes, expires_at)
                 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
                [
                    delivery.sender,
                    delivery.id,
                    eventId,
                    fingerprint,
                    encoded.json,
                    encoded.encodedBytes,
                    delivery.expiresAt.toString(),
                ],
            );
            await transaction.query(
                `UPDATE murmur_queues AS queue
                 SET head = $${targetParameters.length + 1}::uuid,
                     pending_items = queue.pending_items + 1,
                     pending_bytes = queue.pending_bytes + $${targetParameters.length + 2}
                 FROM (VALUES ${targetValues}) AS target(recipient)
                 WHERE queue.recipient = target.recipient`,
                [...targetParameters, eventId, encoded.encodedBytes],
            );
            await transaction.query(
                `INSERT INTO murmur_queue_references
                    (recipient, event_id, sender, delivery_id, encoded_bytes,
                     admission_principal)
                 SELECT target.recipient, $${targetParameters.length + 1}::uuid,
                        $${targetParameters.length + 2}::bytea,
                        $${targetParameters.length + 3}::text,
                        $${targetParameters.length + 4},
                        $${targetParameters.length + 5}::bytea
                 FROM (VALUES ${targetValues}) AS target(recipient)`,
                [
                    ...targetParameters,
                    eventId,
                    delivery.sender,
                    delivery.id,
                    encoded.encodedBytes,
                    admissionPrincipal,
                ],
            );
            await this.#notifyRecipients(transaction, delivery.recipients);
            return { eventId, duplicate: false };
        });
    }

    async readQueue(
        recipient: Uint8Array,
        after: string | null,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<QueuePage> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const queueResult = await transaction.query<{
                head: unknown;
                acknowledged_through: unknown;
            }>(
                `SELECT head, acknowledged_through
                 FROM murmur_queues WHERE recipient = $1`,
                [recipient],
            );
            const queue = queueResult.rows[0];
            if (queue === undefined) {
                return {
                    deliveries: [],
                    head: after,
                    acknowledgedThrough: after,
                    exhausted: true,
                };
            }
            const head = textColumn(queue.head, "queue head");
            const acknowledgedThrough = nullableTextColumn(
                queue.acknowledged_through,
                "acknowledged event ID",
            );
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
            const metadata = await transaction.query<{
                event_id: unknown;
                encoded_bytes: unknown;
            }>(
                `SELECT reference.event_id, delivery.encoded_bytes
                 FROM murmur_queue_references AS reference
                 JOIN murmur_queue_deliveries AS delivery
                   ON delivery.sender = reference.sender
                  AND delivery.delivery_id = reference.delivery_id
                 WHERE reference.recipient = $1
                   AND ($2::uuid IS NULL OR reference.event_id > $2)
                   AND delivery.expires_at > $3
                 ORDER BY reference.event_id
                 LIMIT $4`,
                [recipient, after, now.toString(), limit + 1],
            );
            const selection = selectQueuePageMetadata(
                metadata.rows.map(
                    (row): StoredPageCandidate => ({
                        eventId: textColumn(row.event_id, "event ID"),
                        encodedBytes: safeNumberColumn(row.encoded_bytes),
                    }),
                ),
                head,
                acknowledgedThrough,
                after,
                limit,
                constraints,
            );
            const hydrated =
                selection.candidates.length === 0
                    ? { rows: [] }
                    : await transaction.query<{
                          event_id: unknown;
                          delivery_json: unknown;
                      }>(
                          `SELECT reference.event_id, delivery.delivery_json
                           FROM murmur_queue_references AS reference
                           JOIN murmur_queue_deliveries AS delivery
                             ON delivery.sender = reference.sender
                            AND delivery.delivery_id = reference.delivery_id
                           WHERE reference.recipient = $1
                             AND reference.event_id IN (${selection.candidates
                                 .map((_, index) => `$${index + 2}`)
                                 .join(", ")})
                           ORDER BY reference.event_id`,
                          [recipient, ...selection.candidates.map(({ eventId }) => eventId)],
                      );
            if (hydrated.rows.length !== selection.candidates.length) {
                throw new Error("Postgres queue hydration did not match selected references");
            }
            const deliveries = hydrated.rows.map((row, index): QueuedDelivery => {
                const eventId = textColumn(row.event_id, "event ID");
                if (eventId !== selection.candidates[index]!.eventId) {
                    throw new Error("Postgres queue hydration order is inconsistent");
                }
                return {
                    eventId,
                    delivery: parseSignedDelivery(jsonValue(row.delivery_json)),
                };
            });
            return {
                deliveries,
                head: selection.head,
                acknowledgedThrough: selection.acknowledgedThrough,
                exhausted: selection.exhausted,
            };
        }, "repeatable read");
    }

    async acknowledge(
        recipient: Uint8Array,
        through: string,
        now: number,
    ): Promise<AcknowledgeOutcome> {
        this.#assertOpen();
        await this.pruneExpired(now);
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            const queueResult = await transaction.query<{
                head: unknown;
                acknowledged_through: unknown;
            }>(
                `SELECT head, acknowledged_through FROM murmur_queues
                 WHERE recipient = $1 FOR UPDATE`,
                [recipient],
            );
            const queue = queueResult.rows[0];
            if (queue === undefined) {
                return { removed: 0 };
            }
            const head = textColumn(queue.head, "queue head");
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
            const removed = await transaction.query<{
                sender: unknown;
                delivery_id: unknown;
                encoded_bytes: unknown;
            }>(
                `DELETE FROM murmur_queue_references
                 WHERE recipient = $1 AND event_id <= $2
                 RETURNING sender, delivery_id, encoded_bytes`,
                [recipient, through],
            );
            const removedBytes = removed.rows.reduce(
                (total, row) => total + bigintColumn(row.encoded_bytes),
                0n,
            );
            if (removed.rows.length > 0) {
                const parameters: (Uint8Array | string)[] = [];
                const values = removed.rows
                    .map((row, index) => {
                        parameters.push(
                            copyBytes(row.sender, "delivery sender"),
                            textColumn(row.delivery_id, "delivery ID"),
                        );
                        return `($${index * 2 + 1}::bytea, $${index * 2 + 2}::text)`;
                    })
                    .join(", ");
                const orphaned = await transaction.query<{ encoded_bytes: unknown }>(
                    `DELETE FROM murmur_queue_deliveries AS delivery
                     USING (VALUES ${values}) AS affected(sender, delivery_id)
                     WHERE delivery.sender = affected.sender
                       AND delivery.delivery_id = affected.delivery_id
                       AND NOT EXISTS (
                           SELECT 1 FROM murmur_queue_references AS reference
                           WHERE reference.sender = delivery.sender
                             AND reference.delivery_id = delivery.delivery_id
                       )
                     RETURNING delivery.encoded_bytes`,
                    parameters,
                );
                const orphanedBytes = orphaned.rows.reduce(
                    (total, row) => total + bigintColumn(row.encoded_bytes),
                    0n,
                );
                await transaction.query(
                    `UPDATE murmur_queue_global
                     SET pending_items = pending_items - $1,
                         pending_bytes = pending_bytes - $2,
                         pending_references = pending_references - $3
                     WHERE singleton = 1`,
                    [orphaned.rows.length, orphanedBytes.toString(), removed.rows.length],
                );
            } else {
                await transaction.query(
                    `UPDATE murmur_queue_global
                     SET pending_references = pending_references - $1
                     WHERE singleton = 1`,
                    [removed.rows.length],
                );
            }
            await transaction.query(
                `UPDATE murmur_queues
                 SET acknowledged_through = $1,
                     pending_items = pending_items - $2,
                     pending_bytes = pending_bytes - $3
                 WHERE recipient = $4`,
                [through, removed.rows.length, removedBytes.toString(), recipient],
            );
            await transaction.query(
                `DELETE FROM murmur_queues AS queue
                 WHERE queue.recipient = $1
                   AND NOT EXISTS (
                       SELECT 1 FROM murmur_queue_references AS reference
                       WHERE reference.recipient = queue.recipient
                   )`,
                [recipient],
            );
            return {
                removed: removed.rows.length,
            };
        });
    }

    async pruneExpired(now: number): Promise<number> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            return this.#pruneExpired(transaction, now);
        });
    }

    async health(): Promise<void> {
        this.#assertOpen();
        await this.#database.query("SELECT 1 AS healthy");
    }

    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            await this.#database.close();
        }
    }

    async #notifyRecipients(
        transaction: PostgresQuery,
        recipients: readonly Uint8Array[],
    ): Promise<void> {
        const payloads = recipients.map(encodeBase64Url);
        const values = payloads.map((_, index) => `($${index + 1}::text)`).join(", ");
        await transaction.query(
            `SELECT pg_notify('${POSTGRES_WAKE_CHANNEL}', payload)
             FROM (VALUES ${values}) AS notification(payload)`,
            payloads,
        );
    }

    async #pruneExpired(transaction: PostgresQuery, now: number): Promise<number> {
        const usage = await transaction.query<{
            item_count: unknown;
            byte_count: unknown;
            reference_count: unknown;
        }>(
            `WITH expired AS (
                 SELECT sender, delivery_id, encoded_bytes
                 FROM murmur_queue_deliveries
                 WHERE expires_at <= $1
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             SELECT
                (SELECT COUNT(*) FROM expired) AS item_count,
                (SELECT COALESCE(SUM(encoded_bytes), 0) FROM expired) AS byte_count,
                (SELECT COUNT(*)
                 FROM murmur_queue_references AS reference
                 JOIN expired
                   ON expired.sender = reference.sender
                  AND expired.delivery_id = reference.delivery_id) AS reference_count`,
            [now.toString()],
        );
        const usageRow = usage.rows[0];
        if (usageRow === undefined) throw new Error("Missing expired usage result");
        const affected = await transaction.query<{
            recipient: unknown;
            item_count: unknown;
            byte_count: unknown;
        }>(
            `WITH expired AS (
                 SELECT sender, delivery_id
                 FROM murmur_queue_deliveries
                 WHERE expires_at <= $1
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             SELECT reference.recipient,
                    COUNT(reference.event_id) AS item_count,
                    COALESCE(SUM(reference.encoded_bytes), 0) AS byte_count
             FROM murmur_queue_references AS reference
             JOIN expired
              ON expired.sender = reference.sender
              AND expired.delivery_id = reference.delivery_id
             GROUP BY reference.recipient`,
            [now.toString()],
        );
        const removed = await transaction.query<{ event_id: unknown }>(
            `WITH expired AS (
                 SELECT sender, delivery_id
                 FROM murmur_queue_deliveries
                 WHERE expires_at <= $1
                 ORDER BY expires_at, event_id
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             DELETE FROM murmur_queue_deliveries AS delivery
             USING expired
             WHERE delivery.sender = expired.sender
               AND delivery.delivery_id = expired.delivery_id
             RETURNING delivery.event_id`,
            [now.toString()],
        );
        for (let offset = 0; offset < affected.rows.length; offset += SQL_VALUE_CHUNK) {
            const chunk = affected.rows.slice(offset, offset + SQL_VALUE_CHUNK);
            const changeParameters: (Uint8Array | string)[] = [];
            const changeValues = chunk
                .map((row, index) => {
                    changeParameters.push(
                        copyBytes(row.recipient, "queue recipient"),
                        bigintColumn(row.item_count).toString(),
                        bigintColumn(row.byte_count).toString(),
                    );
                    return `($${index * 3 + 1}::bytea, $${index * 3 + 2}::bigint, $${index * 3 + 3}::bigint)`;
                })
                .join(", ");
            await transaction.query(
                `UPDATE murmur_queues AS queue
                 SET pending_items = queue.pending_items - change.item_count,
                     pending_bytes = queue.pending_bytes - change.byte_count
                 FROM (VALUES ${changeValues})
                      AS change(recipient, item_count, byte_count)
                 WHERE queue.recipient = change.recipient`,
                changeParameters,
            );
            const parameters = chunk.map((row) => copyBytes(row.recipient, "queue recipient"));
            const values = parameters.map((_, index) => `($${index + 1}::bytea)`).join(", ");
            await transaction.query(
                `DELETE FROM murmur_queues AS queue
                 USING (VALUES ${values}) AS candidate(recipient)
                 WHERE queue.recipient = candidate.recipient
                   AND NOT EXISTS (
                       SELECT 1 FROM murmur_queue_references AS reference
                       WHERE reference.recipient = queue.recipient
                   )`,
                parameters,
            );
        }
        await transaction.query(
            `UPDATE murmur_queue_global
             SET pending_items = pending_items - $1,
                 pending_bytes = pending_bytes - $2,
                 pending_references = pending_references - $3
             WHERE singleton = 1`,
            [
                bigintColumn(usageRow.item_count).toString(),
                bigintColumn(usageRow.byte_count).toString(),
                bigintColumn(usageRow.reference_count).toString(),
            ],
        );
        return removed.rows.length;
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Postgres queue store is closed");
        }
    }
}
