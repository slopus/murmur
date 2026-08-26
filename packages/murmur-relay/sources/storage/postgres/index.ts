import {
    RelayError,
    deviceRosterToJson,
    deliveryFingerprint,
    parseSignedDelivery,
    type SignedDelivery,
    type DeviceRoster,
    type DeviceRosterMutation,
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
import type { PostgresDatabase, PostgresQuery } from "./database.js";
import { createPostgresRelaySchema } from "./schema.js";

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
        return this.#database.transaction((transaction) =>
            this.#publishWithQuery(transaction, delivery, now, limits, admissionPrincipal),
        );
    }

    async #publishWithQuery(
        transaction: PostgresQuery,
        delivery: SignedDelivery,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<PublishOutcome> {
        await transaction.query(
            "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
        );
        const globalResult = await transaction.query<{
            last_event_id: unknown;
            generation_seed: unknown;
            pending_items: unknown;
            pending_bytes: unknown;
            pending_references: unknown;
        }>(
            `SELECT last_event_id, generation_seed, pending_items, pending_bytes,
                        pending_references
                 FROM murmur_queue_global WHERE singleton = 1`,
        );
        const global = globalResult.rows[0];
        if (global === undefined) throw new Error("Missing global queue state");

        const staleRosters: DeviceRoster[] = [];
        const currentRosters: DeviceRoster[] = [];
        for (const target of delivery.targetAccounts) {
            const roster = await this.#readDeviceRosterWithQuery(
                transaction,
                target.accountKey,
                true,
            );
            if (roster === undefined) {
                throw new RelayError(409, "Target account has no registered devices", {
                    error: "roster_missing",
                    accountKey: encodeBase64Url(target.accountKey),
                });
            }
            currentRosters.push(roster);
            if (
                roster.revision !== target.rosterRevision ||
                roster.devices.some(
                    (entry) =>
                        !delivery.recipients.some((recipient) =>
                            equalBytes(recipient, entry.deviceKey),
                        ),
                )
            ) {
                staleRosters.push(roster);
            }
        }
        if (staleRosters.length === 0 && currentRosters.length > 0) {
            const currentDevices = new Set(
                currentRosters.flatMap((roster) =>
                    roster.devices.map((entry) => encodeBase64Url(entry.deviceKey)),
                ),
            );
            if (
                currentDevices.size !== delivery.recipients.length ||
                delivery.recipients.some(
                    (recipient) => !currentDevices.has(encodeBase64Url(recipient)),
                )
            ) {
                staleRosters.push(...currentRosters);
            }
        }
        if (staleRosters.length > 0) {
            throw new RelayError(409, "Delivery does not match current account devices", {
                error: "stale_roster",
                rosters: staleRosters.map(deviceRosterToJson),
            });
        }

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
            bigintColumn(admissionUsageRow.reference_count) + BigInt(delivery.recipients.length) >
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
        const generationSeed = copyBytes(global.generation_seed, "generation seed");
        const queueParameters: (Uint8Array | string)[] = [];
        const queueValues = delivery.recipients
            .map((recipient, index) => {
                queueParameters.push(recipient, initialLossGeneration(generationSeed, recipient));
                return `($${index * 2 + 1}::bytea, $${index * 2 + 2}::bytea)`;
            })
            .join(", ");
        await transaction.query(
            `INSERT INTO murmur_queues
                    (recipient, head, head_sequence, next_sequence, acknowledged_through,
                     acknowledged_sequence, loss_generation, pending_items, pending_bytes)
                 SELECT target.recipient, $${queueParameters.length + 1}::uuid, 1, 2,
                        NULL, 0, target.loss_generation, 0, 0
                 FROM (VALUES ${queueValues}) AS target(recipient, loss_generation)
                 ON CONFLICT DO NOTHING`,
            [...queueParameters, eventId],
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
                     head_sequence = CASE
                         WHEN queue.head = $${targetParameters.length + 1}::uuid
                         THEN queue.head_sequence ELSE queue.next_sequence END,
                     next_sequence = CASE
                         WHEN queue.head = $${targetParameters.length + 1}::uuid
                         THEN queue.next_sequence ELSE queue.next_sequence + 1 END,
                     pending_items = queue.pending_items + 1,
                     pending_bytes = queue.pending_bytes + $${targetParameters.length + 2}
                 FROM (VALUES ${targetValues}) AS target(recipient)
                 WHERE queue.recipient = target.recipient`,
            [...targetParameters, eventId, encoded.encodedBytes],
        );
        await transaction.query(
            `INSERT INTO murmur_queue_references
                    (recipient, event_id, sequence, sender, delivery_id, encoded_bytes,
                     admission_principal)
                 SELECT target.recipient, $${targetParameters.length + 1}::uuid,
                        queue.head_sequence, $${targetParameters.length + 2}::bytea,
                        $${targetParameters.length + 3}::text,
                        $${targetParameters.length + 4},
                        $${targetParameters.length + 5}::bytea
                 FROM (VALUES ${targetValues}) AS target(recipient)
                 JOIN murmur_queues AS queue ON queue.recipient = target.recipient`,
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
        return this.#database.transaction(async (transaction) => {
            const queueResult = await transaction.query<{
                head: unknown;
                head_sequence: unknown;
                acknowledged_through: unknown;
                acknowledged_sequence: unknown;
                loss_generation: unknown;
            }>(
                `SELECT head, head_sequence, acknowledged_through, acknowledged_sequence,
                        loss_generation
                 FROM murmur_queues WHERE recipient = $1`,
                [recipient],
            );
            const queue = queueResult.rows[0];
            if (queue === undefined) {
                const global = await transaction.query<{ generation_seed: unknown }>(
                    `SELECT generation_seed FROM murmur_queue_global WHERE singleton = 1`,
                );
                const seed = global.rows[0];
                if (seed === undefined) throw new Error("Missing generation seed");
                return {
                    deliveries: [],
                    head: after,
                    headSequence: 0,
                    acknowledgedThrough: after,
                    acknowledgedSequence: 0,
                    generation: initialLossGeneration(
                        copyBytes(seed.generation_seed, "generation seed"),
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
            const metadata = await transaction.query<{
                event_id: unknown;
                sequence: unknown;
                encoded_bytes: unknown;
            }>(
                `SELECT reference.event_id, reference.sequence, delivery.encoded_bytes
                 FROM murmur_queue_references AS reference
                 JOIN murmur_queue_deliveries AS delivery
                   ON delivery.sender = reference.sender
                  AND delivery.delivery_id = reference.delivery_id
                 WHERE reference.recipient = $1
                   AND ($2::uuid IS NULL OR reference.event_id > $2)
                   AND delivery.expires_at > $3
                 ORDER BY reference.sequence
                 LIMIT $4`,
                [recipient, after, now.toString(), limit + 1],
            );
            const selection = selectQueuePageMetadata(
                metadata.rows.map(
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
                    ? { rows: [] }
                    : await transaction.query<{
                          event_id: unknown;
                          sequence: unknown;
                          delivery_json: unknown;
                      }>(
                          `SELECT reference.event_id, reference.sequence,
                                  delivery.delivery_json
                           FROM murmur_queue_references AS reference
                           JOIN murmur_queue_deliveries AS delivery
                             ON delivery.sender = reference.sender
                            AND delivery.delivery_id = reference.delivery_id
                           WHERE reference.recipient = $1
                             AND reference.event_id IN (${selection.candidates
                                 .map((_, index) => `$${index + 2}`)
                                 .join(", ")})
                           ORDER BY reference.sequence`,
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
                    sequence: safeNumberColumn(row.sequence),
                    delivery: parseSignedDelivery(jsonValue(row.delivery_json)),
                };
            });
            return {
                deliveries,
                head: selection.head,
                headSequence: selection.headSequence,
                acknowledgedThrough: selection.acknowledgedThrough,
                acknowledgedSequence: selection.acknowledgedSequence,
                generation: selection.generation,
                exhausted: selection.exhausted,
            };
        }, "repeatable read");
    }

    async readDeviceRoster(accountKey: Uint8Array): Promise<DeviceRoster | undefined> {
        this.#assertOpen();
        return this.#database.connection((connection) =>
            this.#readDeviceRosterWithQuery(connection, accountKey, false),
        );
    }

    async mutateDeviceRoster(
        delivery: SignedDelivery,
        mutation: DeviceRosterMutation,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<DeviceRoster> {
        this.#assertOpen();
        await this.pruneExpired(now);
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            const current = await this.#readDeviceRosterWithQuery(
                transaction,
                delivery.sender,
                true,
            );
            const replay = await transaction.query(
                `SELECT 1 AS present FROM murmur_device_roster_nonces
                 WHERE account_key = $1 AND nonce = $2`,
                [delivery.sender, delivery.id],
            );
            if (replay.rows.length > 0) {
                throw new RelayError(409, "Device roster mutation was already used", {
                    error: "replay",
                });
            }
            const devices = new Map(
                (current?.devices ?? []).map((entry) => [encodeBase64Url(entry.deviceKey), entry]),
            );
            const admissions = new Map(
                (current?.admissions ?? []).map((entry) => [
                    encodeBase64Url(entry.deviceKey),
                    entry,
                ]),
            );
            const encodedDevice = encodeBase64Url(mutation.deviceKey);
            const existing = devices.get(encodedDevice);
            if (mutation.type === "register") {
                const expectedGeneration =
                    existing === undefined ? 0 : existing.resetGeneration + 1;
                if (mutation.resetGeneration !== expectedGeneration) {
                    throw new RelayError(409, "Device reset generation is stale", {
                        error: "reset_generation",
                        expectedGeneration,
                    });
                }
                devices.set(encodedDevice, {
                    deviceKey: mutation.deviceKey,
                    resetGeneration: mutation.resetGeneration,
                });
                admissions.set(encodedDevice, {
                    deviceKey: mutation.deviceKey,
                    keyPackage: mutation.keyPackage,
                });
            } else {
                if (
                    existing === undefined ||
                    mutation.resetGeneration !== existing.resetGeneration
                ) {
                    throw new RelayError(409, "Device removal names stale roster state", {
                        error: "reset_generation",
                        expectedGeneration: existing?.resetGeneration ?? null,
                    });
                }
                devices.delete(encodedDevice);
                admissions.delete(encodedDevice);
            }
            const sortedDevices = [...devices.values()].sort((left, right) => {
                for (let index = 0; index < left.deviceKey.length; index += 1) {
                    const difference = left.deviceKey[index]! - right.deviceKey[index]!;
                    if (difference !== 0) return difference;
                }
                return 0;
            });
            if (
                delivery.targetAccounts.length !== 0 ||
                delivery.recipients.length !== sortedDevices.length ||
                sortedDevices.some(
                    (entry, index) => !equalBytes(entry.deviceKey, delivery.recipients[index]!),
                )
            ) {
                throw new RelayError(409, "Roster mutation recipients are stale", {
                    error: "stale_roster",
                    ...(current === undefined ? {} : { rosters: [deviceRosterToJson(current)] }),
                });
            }
            const revision = (current?.revision ?? 0) + 1;
            await transaction.query(
                `INSERT INTO murmur_device_rosters (account_key, revision)
                 VALUES ($1, $2)
                 ON CONFLICT (account_key) DO UPDATE SET revision = excluded.revision`,
                [delivery.sender, revision],
            );
            await transaction.query(
                "DELETE FROM murmur_device_roster_devices WHERE account_key = $1",
                [delivery.sender],
            );
            for (const entry of sortedDevices) {
                const storedAdmission = admissions.get(encodeBase64Url(entry.deviceKey));
                if (storedAdmission === undefined) throw new Error("Missing roster admission");
                await transaction.query(
                    `INSERT INTO murmur_device_roster_devices
                        (account_key, device_key, reset_generation, key_package)
                     VALUES ($1, $2, $3, $4)`,
                    [
                        delivery.sender,
                        entry.deviceKey,
                        entry.resetGeneration,
                        storedAdmission.keyPackage,
                    ],
                );
            }
            await transaction.query(
                `INSERT INTO murmur_device_roster_nonces (account_key, nonce, created_at)
                 VALUES ($1, $2, $3)`,
                [delivery.sender, delivery.id, now],
            );
            const roster: DeviceRoster = {
                version: 1,
                accountKey: delivery.sender.slice(),
                revision,
                devices: sortedDevices.map((entry) => ({
                    deviceKey: entry.deviceKey.slice(),
                    resetGeneration: entry.resetGeneration,
                })),
                admissions: sortedDevices.map((entry) => {
                    const value = admissions.get(encodeBase64Url(entry.deviceKey));
                    if (value === undefined) throw new Error("Missing roster admission");
                    return {
                        deviceKey: entry.deviceKey.slice(),
                        keyPackage: value.keyPackage.slice(),
                    };
                }),
            };
            if (delivery.recipients.length > 0) {
                await this.#publishWithQuery(
                    transaction,
                    delivery,
                    now,
                    limits,
                    admissionPrincipal,
                );
            }
            return roster;
        });
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
                head_sequence: unknown;
                acknowledged_through: unknown;
                acknowledged_sequence: unknown;
                loss_generation: unknown;
            }>(
                `SELECT head, head_sequence, acknowledged_through, acknowledged_sequence,
                        loss_generation FROM murmur_queues
                 WHERE recipient = $1 FOR UPDATE`,
                [recipient],
            );
            const queue = queueResult.rows[0];
            if (queue === undefined) {
                const global = await transaction.query<{ generation_seed: unknown }>(
                    `SELECT generation_seed FROM murmur_queue_global WHERE singleton = 1`,
                );
                const seed = global.rows[0];
                if (seed === undefined) throw new Error("Missing generation seed");
                return {
                    removed: 0,
                    generation: initialLossGeneration(
                        copyBytes(seed.generation_seed, "generation seed"),
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
            const removed = await transaction.query<{
                sender: unknown;
                delivery_id: unknown;
                encoded_bytes: unknown;
                sequence: unknown;
            }>(
                `DELETE FROM murmur_queue_references
                 WHERE recipient = $1 AND event_id <= $2
                 RETURNING sender, delivery_id, encoded_bytes, sequence`,
                [recipient, through],
            );
            const removedBytes = removed.rows.reduce(
                (total, row) => total + bigintColumn(row.encoded_bytes),
                0n,
            );
            const previousAcknowledgedSequence = safeNumberColumn(queue.acknowledged_sequence);
            const acknowledgedSequence =
                through === head
                    ? headSequence
                    : removed.rows.reduce(
                          (maximum, row) => Math.max(maximum, safeNumberColumn(row.sequence)),
                          previousAcknowledgedSequence,
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
                     acknowledged_sequence = $2,
                     pending_items = pending_items - $3,
                     pending_bytes = pending_bytes - $4
                 WHERE recipient = $5`,
                [
                    through,
                    acknowledgedSequence,
                    removed.rows.length,
                    removedBytes.toString(),
                    recipient,
                ],
            );
            return {
                removed: removed.rows.length,
                generation: copyBytes(queue.loss_generation, "loss generation"),
                sequence: acknowledgedSequence,
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

    async declareRestored(): Promise<number> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                `SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE`,
            );
            const queues = await transaction.query<{ recipient: unknown }>(
                `SELECT recipient FROM murmur_queues ORDER BY recipient FOR UPDATE`,
            );
            for (const queue of queues.rows) {
                await transaction.query(
                    `UPDATE murmur_queues SET loss_generation = $1 WHERE recipient = $2`,
                    [createGenerationSeed(), copyBytes(queue.recipient, "queue recipient")],
                );
            }
            await transaction.query(
                `UPDATE murmur_queue_global SET generation_seed = $1 WHERE singleton = 1`,
                [createGenerationSeed()],
            );
            return queues.rows.length;
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

    async #readDeviceRosterWithQuery(
        query: PostgresQuery,
        accountKey: Uint8Array,
        lock: boolean,
    ): Promise<DeviceRoster | undefined> {
        const roster = await query.query<{ revision: unknown }>(
            `SELECT revision FROM murmur_device_rosters WHERE account_key = $1${lock ? " FOR UPDATE" : ""}`,
            [accountKey],
        );
        const row = roster.rows[0];
        if (row === undefined) return undefined;
        const entries = await query.query<{
            device_key: unknown;
            reset_generation: unknown;
            key_package: unknown;
        }>(
            `SELECT device_key, reset_generation, key_package
             FROM murmur_device_roster_devices
             WHERE account_key = $1 ORDER BY device_key`,
            [accountKey],
        );
        return {
            version: 1,
            accountKey: accountKey.slice(),
            revision: safeNumberColumn(row.revision),
            devices: entries.rows.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                resetGeneration: safeNumberColumn(entry.reset_generation),
            })),
            admissions: entries.rows.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                keyPackage: copyBytes(entry.key_package, "roster KeyPackage"),
            })),
        };
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
            loss_generation: unknown;
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
                    COALESCE(SUM(reference.encoded_bytes), 0) AS byte_count,
                    queue.loss_generation
             FROM murmur_queue_references AS reference
             JOIN murmur_queues AS queue ON queue.recipient = reference.recipient
             JOIN expired
              ON expired.sender = reference.sender
              AND expired.delivery_id = reference.delivery_id
             GROUP BY reference.recipient, queue.loss_generation`,
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
                        advanceLossGeneration(
                            copyBytes(row.loss_generation, "loss generation"),
                            safeNumberColumn(row.item_count),
                        ),
                    );
                    return `($${index * 4 + 1}::bytea, $${index * 4 + 2}::bigint, $${index * 4 + 3}::bigint, $${index * 4 + 4}::bytea)`;
                })
                .join(", ");
            await transaction.query(
                `UPDATE murmur_queues AS queue
                 SET pending_items = queue.pending_items - change.item_count,
                     pending_bytes = queue.pending_bytes - change.byte_count,
                     loss_generation = change.loss_generation
                 FROM (VALUES ${changeValues})
                      AS change(recipient, item_count, byte_count, loss_generation)
                 WHERE queue.recipient = change.recipient`,
                changeParameters,
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
