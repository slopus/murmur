import {
    DatabaseSync,
    type SQLInputValue,
    type StatementResultingChanges,
    type StatementSync,
} from "node:sqlite";
import {
    RelayError,
    deviceRosterToJson,
    deliveryFingerprint,
    parseSignedDelivery,
    signedDeliveryToJson,
    type DeviceRoster,
    type DeviceRosterMutation,
    type DirectoryClaim,
    type DirectoryPrekeyUpload,
    type SignedDelivery,
} from "../../protocol/index.js";
import type { DirectoryTicketClaims } from "../../directory/index.js";
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
const MAXIMUM_DIRECTORY_PREKEYS_PER_DEVICE = 256;
const SESSION_DELETION_NONCE_RETENTION_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;

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

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return 0;
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
        transactionOpen: boolean = false,
    ): Promise<PublishOutcome> {
        this.#assertOpen();
        if (!(admissionPrincipal instanceof Uint8Array) || admissionPrincipal.length !== 32) {
            throw new Error("Invalid admission principal");
        }
        if (!transactionOpen) {
            await this.pruneExpired(now);
            this.#database.exec("BEGIN IMMEDIATE");
        }
        try {
            const staleRosters: DeviceRoster[] = [];
            const currentRosters: DeviceRoster[] = [];
            for (const target of delivery.targetAccounts) {
                const roster = this.#readDeviceRoster(target.accountKey);
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
                if (!transactionOpen) this.#database.exec("COMMIT");
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
                     encoded_bytes, expires_at, owner_account, session_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                delivery.sender,
                delivery.id,
                eventId,
                fingerprint,
                encoded.json,
                BigInt(encoded.encodedBytes),
                BigInt(delivery.expiresAt),
                delivery.ownerAccount,
                delivery.sessionId,
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
            if (!transactionOpen) this.#database.exec("COMMIT");
            return { eventId, duplicate: false };
        } catch (error: unknown) {
            if (!transactionOpen) this.#rollback();
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

    async readDeviceRoster(accountKey: Uint8Array): Promise<DeviceRoster | undefined> {
        this.#assertOpen();
        return this.#readDeviceRoster(accountKey);
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
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const replay = this.#get(
                `SELECT 1 AS present FROM murmur_device_roster_nonces
                 WHERE account_key = ? AND nonce = ?`,
                delivery.sender,
                delivery.id,
            );
            if (replay !== undefined) {
                throw new RelayError(409, "Device roster mutation was already used", {
                    error: "replay",
                });
            }
            const current = this.#readDeviceRoster(delivery.sender);
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
            const sortedDevices = [...devices.values()].sort((left, right) =>
                compareBytes(left.deviceKey, right.deviceKey),
            );
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
            this.#run(
                `INSERT INTO murmur_device_rosters (account_key, revision)
                 VALUES (?, ?)
                 ON CONFLICT (account_key) DO UPDATE SET revision = excluded.revision`,
                delivery.sender,
                BigInt(revision),
            );
            if (mutation.type === "remove" || existing !== undefined) {
                this.#run(
                    `DELETE FROM murmur_device_roster_devices
                     WHERE account_key = ? AND device_key = ?`,
                    delivery.sender,
                    mutation.deviceKey,
                );
            }
            for (const entry of sortedDevices) {
                const storedAdmission = admissions.get(encodeBase64Url(entry.deviceKey));
                if (storedAdmission === undefined) throw new Error("Missing roster admission");
                this.#run(
                    `INSERT INTO murmur_device_roster_devices
                        (account_key, device_key, reset_generation, key_package)
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT (account_key, device_key) DO UPDATE SET
                        reset_generation = excluded.reset_generation,
                        key_package = excluded.key_package`,
                    delivery.sender,
                    entry.deviceKey,
                    BigInt(entry.resetGeneration),
                    storedAdmission.keyPackage,
                );
            }
            this.#run(
                `INSERT INTO murmur_device_roster_nonces (account_key, nonce, created_at)
                 VALUES (?, ?, ?)`,
                delivery.sender,
                delivery.id,
                BigInt(now),
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
                await this.publish(delivery, now, limits, admissionPrincipal, true);
            }
            this.#database.exec("COMMIT");
            return roster;
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async uploadDirectoryPrekeys(
        delivery: SignedDelivery,
        upload: DirectoryPrekeyUpload,
        now: number,
    ): Promise<void> {
        this.#assertOpen();
        await this.pruneExpired(now);
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            if (
                this.#get(
                    `SELECT 1 AS present FROM murmur_directory_upload_nonces
                     WHERE account_key = ? AND nonce = ?`,
                    delivery.sender,
                    delivery.id,
                ) !== undefined
            ) {
                throw new RelayError(409, "Directory upload was already used", {
                    error: "replay",
                });
            }
            const roster = this.#readDeviceRoster(delivery.sender);
            const device = roster?.devices.find((entry) =>
                equalBytes(entry.deviceKey, upload.deviceKey),
            );
            if (device === undefined || device.resetGeneration !== upload.resetGeneration) {
                throw new RelayError(409, "Directory upload names stale roster state", {
                    error: "reset_generation",
                    expectedGeneration: device?.resetGeneration ?? null,
                });
            }
            this.#run("DELETE FROM murmur_directory_prekeys WHERE expires_at <= ?", BigInt(now));
            const currentDirectory = this.#get(
                `SELECT last_resort_reference, last_resort_expires_at
                 FROM murmur_directory_devices
                 WHERE account_key = ? AND device_key = ?`,
                delivery.sender,
                upload.deviceKey,
            );
            const currentAdmission = roster?.admissions.find((entry) =>
                equalBytes(entry.deviceKey, upload.deviceKey),
            );
            if (upload.mode === "replenish") {
                if (
                    currentDirectory === undefined ||
                    currentAdmission === undefined ||
                    !equalBytes(
                        copyBytes(currentDirectory.last_resort_reference, "last-resort reference"),
                        upload.lastResort.reference,
                    ) ||
                    safeNumberColumn(currentDirectory.last_resort_expires_at) !==
                        upload.lastResort.expiresAt ||
                    !equalBytes(currentAdmission.keyPackage, upload.lastResort.keyPackage)
                ) {
                    throw new RelayError(409, "Directory last-resort prekey is stale", {
                        error: "last_resort_stale",
                    });
                }
            } else {
                this.#run(
                    `DELETE FROM murmur_directory_prekeys
                     WHERE account_key = ? AND device_key = ?`,
                    delivery.sender,
                    upload.deviceKey,
                );
                const reassertsCurrentLastResort =
                    currentDirectory !== undefined &&
                    currentAdmission !== undefined &&
                    equalBytes(
                        copyBytes(currentDirectory.last_resort_reference, "last-resort reference"),
                        upload.lastResort.reference,
                    ) &&
                    safeNumberColumn(currentDirectory.last_resort_expires_at) ===
                        upload.lastResort.expiresAt &&
                    equalBytes(currentAdmission.keyPackage, upload.lastResort.keyPackage);
                const lastResortPublished =
                    this.#get(
                        `SELECT 1 AS present FROM murmur_directory_prekey_references
                         WHERE account_key = ? AND device_key = ? AND reference = ?`,
                        delivery.sender,
                        upload.deviceKey,
                        upload.lastResort.reference,
                    ) !== undefined;
                if (lastResortPublished && !reassertsCurrentLastResort) {
                    throw new RelayError(409, "Directory prekey reference was already published", {
                        error: "prekey_reuse",
                    });
                }
                if (!lastResortPublished) {
                    this.#run(
                        `INSERT INTO murmur_directory_prekey_references
                            (account_key, device_key, reference, first_seen_at)
                         VALUES (?, ?, ?, ?)`,
                        delivery.sender,
                        upload.deviceKey,
                        upload.lastResort.reference,
                        BigInt(now),
                    );
                }
            }
            if (upload.lastResort.expiresAt <= now) {
                throw new RelayError(409, "Last-resort prekey is expired", {
                    error: "prekey_expired",
                });
            }
            this.#run(
                `INSERT INTO murmur_directory_devices
                    (account_key, device_key, last_resort_reference, last_resort_expires_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (account_key, device_key) DO UPDATE SET
                    last_resort_reference = excluded.last_resort_reference,
                    last_resort_expires_at = excluded.last_resort_expires_at`,
                delivery.sender,
                upload.deviceKey,
                upload.lastResort.reference,
                BigInt(upload.lastResort.expiresAt),
            );
            this.#run(
                `UPDATE murmur_device_roster_devices SET key_package = ?
                 WHERE account_key = ? AND device_key = ?`,
                upload.lastResort.keyPackage,
                delivery.sender,
                upload.deviceKey,
            );
            const newPrekeys: DirectoryPrekeyUpload["oneTimePrekeys"][number][] = [];
            for (const entry of upload.oneTimePrekeys) {
                if (entry.expiresAt <= now) {
                    throw new RelayError(409, "Directory prekey is expired", {
                        error: "prekey_expired",
                    });
                }
                const activePrekey = this.#get(
                    `SELECT key_package, expires_at FROM murmur_directory_prekeys
                     WHERE account_key = ? AND device_key = ? AND reference = ?`,
                    delivery.sender,
                    upload.deviceKey,
                    entry.reference,
                );
                if (activePrekey !== undefined) {
                    if (
                        !equalBytes(
                            copyBytes(activePrekey.key_package, "directory KeyPackage"),
                            entry.keyPackage,
                        ) ||
                        safeNumberColumn(activePrekey.expires_at) !== entry.expiresAt
                    ) {
                        throw new RelayError(
                            409,
                            "Directory prekey reference was already published",
                            { error: "prekey_reuse" },
                        );
                    }
                    continue;
                }
                if (
                    this.#get(
                        `SELECT 1 AS present FROM murmur_directory_prekey_references
                         WHERE account_key = ? AND device_key = ? AND reference = ?`,
                        delivery.sender,
                        upload.deviceKey,
                        entry.reference,
                    ) !== undefined
                ) {
                    throw new RelayError(409, "Directory prekey reference was already published", {
                        error: "prekey_reuse",
                    });
                }
                newPrekeys.push(entry);
            }
            const active = this.#requiredGet(
                `SELECT COUNT(*) AS item_count FROM murmur_directory_prekeys
                 WHERE account_key = ? AND device_key = ?`,
                delivery.sender,
                upload.deviceKey,
            );
            if (
                safeNumberColumn(active.item_count) + newPrekeys.length >
                MAXIMUM_DIRECTORY_PREKEYS_PER_DEVICE
            ) {
                throw new RelayError(413, "Directory prekey pool exceeds relay limit", {
                    error: "limit",
                });
            }
            for (const entry of newPrekeys) {
                this.#run(
                    `INSERT INTO murmur_directory_prekey_references
                        (account_key, device_key, reference, first_seen_at)
                     VALUES (?, ?, ?, ?)`,
                    delivery.sender,
                    upload.deviceKey,
                    entry.reference,
                    BigInt(now),
                );
                this.#run(
                    `INSERT INTO murmur_directory_prekeys
                        (account_key, device_key, reference, key_package, notification_json,
                         expires_at, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    delivery.sender,
                    upload.deviceKey,
                    entry.reference,
                    entry.keyPackage,
                    JSON.stringify(signedDeliveryToJson(entry.spentNotification)),
                    BigInt(entry.expiresAt),
                    BigInt(now),
                );
            }
            this.#run(
                `INSERT INTO murmur_directory_upload_nonces (account_key, nonce, created_at)
                 VALUES (?, ?, ?)`,
                delivery.sender,
                delivery.id,
                BigInt(now),
            );
            this.#database.exec("COMMIT");
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    async claimDirectory(
        accountKey: Uint8Array,
        ticket: DirectoryTicketClaims,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<DirectoryClaim> {
        this.#assertOpen();
        await this.pruneExpired(now);
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const usage = this.#get(
                `SELECT claim_budget, claims_used, expires_at
                 FROM murmur_directory_ticket_uses WHERE issuer = ? AND ticket_id = ?`,
                ticket.issuer,
                ticket.ticketId,
            );
            if (usage === undefined) {
                this.#run(
                    `INSERT INTO murmur_directory_ticket_uses
                        (issuer, ticket_id, claim_budget, claims_used, expires_at)
                     VALUES (?, ?, ?, 1, ?)`,
                    ticket.issuer,
                    ticket.ticketId,
                    BigInt(ticket.claimBudget),
                    BigInt(ticket.expiresAt),
                );
            } else {
                if (
                    safeNumberColumn(usage.claim_budget) !== ticket.claimBudget ||
                    safeNumberColumn(usage.expires_at) !== ticket.expiresAt ||
                    safeNumberColumn(usage.claims_used) >= ticket.claimBudget
                ) {
                    throw new RelayError(429, "Directory ticket claim budget is exhausted", {
                        error: "ticket_exhausted",
                    });
                }
                this.#run(
                    `UPDATE murmur_directory_ticket_uses SET claims_used = claims_used + 1
                     WHERE issuer = ? AND ticket_id = ?`,
                    ticket.issuer,
                    ticket.ticketId,
                );
            }
            this.#run("DELETE FROM murmur_directory_prekeys WHERE expires_at <= ?", BigInt(now));
            const roster = this.#readDeviceRoster(accountKey);
            if (roster === undefined) {
                this.#database.exec("COMMIT");
                return {
                    version: 1,
                    accountKey: accountKey.slice(),
                    rosterRevision: 0,
                    devices: [],
                };
            }
            const claimed: DirectoryClaim["devices"][number][] = [];
            const notifications: SignedDelivery[] = [];
            for (const device of roster.devices) {
                const prekey = this.#get(
                    `SELECT reference, key_package, notification_json
                     FROM murmur_directory_prekeys
                     WHERE account_key = ? AND device_key = ? AND expires_at > ?
                     ORDER BY created_at, reference LIMIT 1`,
                    accountKey,
                    device.deviceKey,
                    BigInt(now),
                );
                if (prekey === undefined) {
                    const admission = roster.admissions.find((entry) =>
                        equalBytes(entry.deviceKey, device.deviceKey),
                    );
                    if (admission === undefined) throw new Error("Missing last-resort KeyPackage");
                    claimed.push({
                        deviceKey: device.deviceKey.slice(),
                        resetGeneration: device.resetGeneration,
                        keyPackage: admission.keyPackage.slice(),
                        source: "last_resort",
                    });
                    continue;
                }
                const reference = copyBytes(prekey.reference, "directory prekey reference");
                this.#run(
                    `DELETE FROM murmur_directory_prekeys
                     WHERE account_key = ? AND device_key = ? AND reference = ?`,
                    accountKey,
                    device.deviceKey,
                    reference,
                );
                claimed.push({
                    deviceKey: device.deviceKey.slice(),
                    resetGeneration: device.resetGeneration,
                    keyPackage: copyBytes(prekey.key_package, "directory KeyPackage"),
                    source: "one_time",
                });
                notifications.push(
                    parseSignedDelivery(
                        JSON.parse(
                            textColumn(prekey.notification_json, "notification JSON"),
                        ) as unknown,
                    ),
                );
            }
            for (const notification of notifications) {
                await this.publish(notification, now, limits, admissionPrincipal, true);
            }
            this.#database.exec("COMMIT");
            return {
                version: 1,
                accountKey: accountKey.slice(),
                rosterRevision: roster.revision,
                devices: claimed,
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

    async deleteSessionDeliveries(
        ownerAccount: Uint8Array,
        sessionId: Uint8Array,
        requestId: string,
        now: number,
    ): Promise<number> {
        this.#assertOpen();
        if (ownerAccount.length !== 32 || sessionId.length !== 32 || requestId.length < 1) {
            throw new Error("Invalid session deletion");
        }
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            this.#run(
                `DELETE FROM murmur_session_deletion_nonces WHERE created_at < ?`,
                BigInt(now - SESSION_DELETION_NONCE_RETENTION_MILLISECONDS),
            );
            if (
                this.#get(
                    `SELECT request_id FROM murmur_session_deletion_nonces
                     WHERE owner_account = ? AND request_id = ?`,
                    ownerAccount,
                    requestId,
                ) !== undefined
            ) {
                throw new RelayError(409, "Session deletion was already applied", {
                    error: "replay",
                });
            }
            this.#run(
                `INSERT INTO murmur_session_deletion_nonces
                    (owner_account, request_id, created_at) VALUES (?, ?, ?)`,
                ownerAccount,
                requestId,
                BigInt(now),
            );
            const removed = this.#deleteOwnedSessionDeliveries(ownerAccount, sessionId);
            this.#database.exec("COMMIT");
            return removed;
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

    #readDeviceRoster(accountKey: Uint8Array): DeviceRoster | undefined {
        const row = this.#get(
            "SELECT revision FROM murmur_device_rosters WHERE account_key = ?",
            accountKey,
        );
        if (row === undefined) return undefined;
        const entries = this.#all(
            `SELECT device_key, reset_generation, key_package
             FROM murmur_device_roster_devices
             WHERE account_key = ? ORDER BY device_key`,
            accountKey,
        );
        return {
            version: 1,
            accountKey: accountKey.slice(),
            revision: safeNumberColumn(row.revision),
            devices: entries.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                resetGeneration: safeNumberColumn(entry.reset_generation),
            })),
            admissions: entries.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                keyPackage: copyBytes(entry.key_package, "roster KeyPackage"),
            })),
        };
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
            if (bigintColumn(schema.version) !== 3n) {
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
                    ,'murmur_device_rosters'
                    ,'murmur_device_roster_devices'
                    ,'murmur_device_roster_nonces'
                    ,'murmur_session_deletion_nonces'
                    ,'murmur_directory_devices'
                    ,'murmur_directory_prekeys'
                    ,'murmur_directory_prekey_references'
                    ,'murmur_directory_upload_nonces'
                    ,'murmur_directory_ticket_uses'
                 )`,
            );
            if (safeNumberColumn(tables.table_count) !== 14) {
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
            INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 3);
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
                owner_account BLOB CHECK (
                    owner_account IS NULL OR length(owner_account) = 32
                ),
                session_id BLOB CHECK (session_id IS NULL OR length(session_id) = 32),
                CHECK ((owner_account IS NULL) = (session_id IS NULL)),
                PRIMARY KEY (sender, delivery_id)
            ) STRICT;
            CREATE INDEX murmur_queue_delivery_expiration
                ON murmur_queue_deliveries(expires_at);
            CREATE INDEX murmur_queue_delivery_session
                ON murmur_queue_deliveries(owner_account, session_id);
            CREATE TABLE murmur_session_deletion_nonces (
                owner_account BLOB NOT NULL CHECK (length(owner_account) = 32),
                request_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_account, request_id)
            ) STRICT;
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
            CREATE TABLE murmur_device_rosters (
                account_key BLOB PRIMARY KEY CHECK (length(account_key) = 32),
                revision INTEGER NOT NULL CHECK (revision >= 1)
            ) STRICT;
            CREATE TABLE murmur_device_roster_devices (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                device_key BLOB NOT NULL CHECK (length(device_key) = 32),
                reset_generation INTEGER NOT NULL CHECK (reset_generation >= 0),
                key_package BLOB NOT NULL CHECK (length(key_package) > 0),
                PRIMARY KEY (account_key, device_key)
            ) STRICT;
            CREATE TABLE murmur_device_roster_nonces (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, nonce)
            ) STRICT;
            `);
            this.#createDirectorySchema();
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

    #createDirectorySchema(): void {
        this.#database.exec(`
        CREATE TABLE murmur_directory_devices (
            account_key BLOB NOT NULL,
            device_key BLOB NOT NULL,
            last_resort_reference BLOB NOT NULL CHECK (length(last_resort_reference) = 32),
            last_resort_expires_at INTEGER NOT NULL,
            PRIMARY KEY (account_key, device_key),
            FOREIGN KEY (account_key, device_key)
                REFERENCES murmur_device_roster_devices(account_key, device_key)
                ON DELETE CASCADE
        ) STRICT;
        CREATE TABLE murmur_directory_prekeys (
            account_key BLOB NOT NULL,
            device_key BLOB NOT NULL,
            reference BLOB NOT NULL CHECK (length(reference) = 32),
            key_package BLOB NOT NULL CHECK (length(key_package) > 0),
            notification_json TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (account_key, device_key, reference),
            FOREIGN KEY (account_key, device_key)
                REFERENCES murmur_directory_devices(account_key, device_key)
                ON DELETE CASCADE
        ) STRICT;
        CREATE INDEX murmur_directory_prekey_claim
            ON murmur_directory_prekeys(account_key, device_key, created_at, reference);
        CREATE TABLE murmur_directory_prekey_references (
            account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                ON DELETE CASCADE,
            device_key BLOB NOT NULL CHECK (length(device_key) = 32),
            reference BLOB NOT NULL CHECK (length(reference) = 32),
            first_seen_at INTEGER NOT NULL,
            PRIMARY KEY (account_key, device_key, reference)
        ) STRICT;
        CREATE TABLE murmur_directory_upload_nonces (
            account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                ON DELETE CASCADE,
            nonce TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (account_key, nonce)
        ) STRICT;
        CREATE TABLE murmur_directory_ticket_uses (
            issuer TEXT NOT NULL,
            ticket_id BLOB NOT NULL CHECK (length(ticket_id) = 32),
            claim_budget INTEGER NOT NULL CHECK (claim_budget >= 1),
            claims_used INTEGER NOT NULL CHECK (
                claims_used >= 1 AND claims_used <= claim_budget
            ),
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (issuer, ticket_id)
        ) STRICT;
        `);
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

    #deleteOwnedSessionDeliveries(ownerAccount: Uint8Array, sessionId: Uint8Array): number {
        const usage = this.#requiredGet(
            `SELECT COUNT(*) AS item_count, COALESCE(SUM(encoded_bytes), 0) AS byte_count
             FROM murmur_queue_deliveries
             WHERE owner_account = ? AND session_id = ?`,
            ownerAccount,
            sessionId,
        );
        const references = this.#requiredGet(
            `SELECT COUNT(*) AS reference_count
             FROM murmur_queue_references AS reference
             JOIN murmur_queue_deliveries AS delivery
               ON delivery.sender = reference.sender
              AND delivery.delivery_id = reference.delivery_id
             WHERE delivery.owner_account = ? AND delivery.session_id = ?`,
            ownerAccount,
            sessionId,
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
             WHERE delivery.owner_account = ? AND delivery.session_id = ?
             GROUP BY reference.recipient, queue.loss_generation`,
            ownerAccount,
            sessionId,
        );
        const removed = safeNumberColumn(
            this.#run(
                `DELETE FROM murmur_queue_deliveries
                 WHERE owner_account = ? AND session_id = ?`,
                ownerAccount,
                sessionId,
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
