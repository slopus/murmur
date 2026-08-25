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
    InvitationLimits,
    PageReadConstraints,
    PublishOutcome,
    QueuedDelivery,
    QueueLimits,
    QueuePage,
    RelayStore,
    RevokeInvitationsOutcome,
    StoredInvitation,
    StoreInvitationOutcome,
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

    async storeInvitation(
        digest: Uint8Array,
        bundle: Uint8Array,
        expiresAt: number,
        now: number,
        limits: InvitationLimits,
        admissionPrincipal: Uint8Array,
        revocationKey?: Uint8Array,
    ): Promise<StoreInvitationOutcome> {
        this.#assertOpen();
        if (
            digest.length !== 32 ||
            bundle.length < 1 ||
            admissionPrincipal.length !== 32 ||
            (revocationKey !== undefined && revocationKey.length !== 32) ||
            !Number.isSafeInteger(expiresAt) ||
            expiresAt <= now
        ) {
            throw new Error("Invalid invitation persistence input");
        }
        await this.pruneExpired(now);
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            const revoked = await transaction.query<{ digest: unknown }>(
                `SELECT digest FROM murmur_invitation_revocations
                 WHERE digest = $1 AND expires_at > $2`,
                [digest, now.toString()],
            );
            if (revoked.rows[0] !== undefined) {
                throw new RelayError(410, "Invitation has been revoked", {
                    error: "invitation_revoked",
                });
            }
            const existing = await transaction.query<{
                bundle: unknown;
                expires_at: unknown;
                revocation_key: unknown;
            }>(
                `SELECT bundle, expires_at, revocation_key
                 FROM murmur_invitations
                 WHERE digest = $1`,
                [digest],
            );
            const duplicate = existing.rows[0];
            if (duplicate !== undefined) {
                if (!equalBytes(copyBytes(duplicate.bundle, "invitation bundle"), bundle)) {
                    throw new Error("Invitation digest collision");
                }
                if (revocationKey !== undefined) {
                    if (duplicate.revocation_key === null) {
                        await this.#assertRevocationKeyCapacity(
                            transaction,
                            revocationKey,
                            now,
                            limits,
                            1,
                        );
                        await transaction.query(
                            `UPDATE murmur_invitations
                             SET revocation_key = $1 WHERE digest = $2`,
                            [revocationKey, digest],
                        );
                    } else if (
                        !equalBytes(
                            copyBytes(duplicate.revocation_key, "invitation revocation key"),
                            revocationKey,
                        )
                    ) {
                        throw new RelayError(409, "Invitation revocation authority conflicts", {
                            error: "invitation_revocation_authority_conflict",
                        });
                    }
                }
                return {
                    expiresAt: safeNumberColumn(duplicate.expires_at),
                    duplicate: true,
                };
            }
            const global = await transaction.query<{
                item_count: unknown;
                byte_count: unknown;
            }>(
                `SELECT
                    (SELECT COUNT(*) FROM murmur_invitations WHERE expires_at > $1) +
                    (SELECT COUNT(*) FROM murmur_invitation_revocations
                     WHERE expires_at > $1) AS item_count,
                    (SELECT COALESCE(SUM(encoded_bytes), 0)
                     FROM murmur_invitations WHERE expires_at > $1) AS byte_count`,
                [now.toString()],
            );
            const globalRow = global.rows[0];
            if (globalRow === undefined) throw new Error("Missing invitation global usage");
            if (
                bigintColumn(globalRow.item_count) + 1n > BigInt(limits.maximumGlobalItems) ||
                bigintColumn(globalRow.byte_count) + BigInt(bundle.length) >
                    BigInt(limits.maximumGlobalBytes)
            ) {
                throw new RelayError(503, "Relay invitation-cache quota exceeded", {
                    error: "invitation_relay_full",
                });
            }
            const principal = await transaction.query<{
                item_count: unknown;
                byte_count: unknown;
            }>(
                `SELECT
                    (SELECT COUNT(*) FROM murmur_invitations
                     WHERE admission_principal = $1 AND expires_at > $2) +
                    (SELECT COUNT(*) FROM murmur_invitation_revocations
                     WHERE admission_principal = $1 AND expires_at > $2) AS item_count,
                    (SELECT COALESCE(SUM(encoded_bytes), 0)
                     FROM murmur_invitations
                     WHERE admission_principal = $1 AND expires_at > $2) AS byte_count`,
                [admissionPrincipal, now.toString()],
            );
            const principalRow = principal.rows[0];
            if (principalRow === undefined) {
                throw new Error("Missing invitation principal usage");
            }
            if (
                bigintColumn(principalRow.item_count) + 1n > BigInt(limits.maximumPrincipalItems) ||
                bigintColumn(principalRow.byte_count) + BigInt(bundle.length) >
                    BigInt(limits.maximumPrincipalBytes)
            ) {
                throw new RelayError(429, "Admission-principal invitation quota exceeded", {
                    error: "invitation_admission_full",
                });
            }
            if (revocationKey !== undefined) {
                await this.#assertRevocationKeyCapacity(transaction, revocationKey, now, limits, 1);
            }
            await transaction.query(
                `INSERT INTO murmur_invitations
                    (digest, bundle, encoded_bytes, expires_at, admission_principal,
                     revocation_key)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [
                    digest,
                    bundle,
                    bundle.length,
                    expiresAt.toString(),
                    admissionPrincipal,
                    revocationKey ?? null,
                ],
            );
            return { expiresAt, duplicate: false };
        });
    }

    async readInvitation(digest: Uint8Array, now: number): Promise<StoredInvitation | undefined> {
        this.#assertOpen();
        if (digest.length !== 32) throw new Error("Invalid invitation digest");
        const result = await this.#database.query<{
            bundle: unknown;
            expires_at: unknown;
        }>(
            `SELECT bundle, expires_at
             FROM murmur_invitations
             WHERE digest = $1 AND expires_at > $2`,
            [digest, now.toString()],
        );
        const row = result.rows[0];
        return row === undefined
            ? undefined
            : {
                  bundle: copyBytes(row.bundle, "invitation bundle"),
                  expiresAt: safeNumberColumn(row.expires_at),
              };
    }

    async revokeInvitations(
        revocationKey: Uint8Array,
        digest: Uint8Array | null,
        now: number,
        maximumItems: number,
    ): Promise<RevokeInvitationsOutcome> {
        this.#assertOpen();
        if (
            revocationKey.length !== 32 ||
            (digest !== null && digest.length !== 32) ||
            !Number.isSafeInteger(now) ||
            !Number.isSafeInteger(maximumItems) ||
            maximumItems < 1
        ) {
            throw new Error("Invalid invitation revocation input");
        }
        await this.pruneExpired(now);
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "SELECT last_event_id FROM murmur_queue_global WHERE singleton = 1 FOR UPDATE",
            );
            if (digest !== null) {
                const active = await transaction.query<{
                    revocation_key: unknown;
                    expires_at: unknown;
                    admission_principal: unknown;
                }>(
                    `SELECT revocation_key, expires_at, admission_principal
                     FROM murmur_invitations
                     WHERE digest = $1 AND expires_at > $2`,
                    [digest, now.toString()],
                );
                const invitation = active.rows[0];
                if (invitation !== undefined) {
                    if (
                        invitation.revocation_key === null ||
                        !equalBytes(
                            copyBytes(invitation.revocation_key, "invitation revocation key"),
                            revocationKey,
                        )
                    ) {
                        throw new RelayError(401, "Invitation revocation is unauthorized", {
                            error: "invitation_revocation_unauthorized",
                        });
                    }
                    await transaction.query(
                        `INSERT INTO murmur_invitation_revocations
                            (digest, revocation_key, expires_at, admission_principal)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (digest) DO NOTHING`,
                        [
                            digest,
                            revocationKey,
                            safeNumberColumn(invitation.expires_at).toString(),
                            copyBytes(invitation.admission_principal, "admission principal"),
                        ],
                    );
                    const removed = await transaction.query<{ digest: unknown }>(
                        `DELETE FROM murmur_invitations WHERE digest = $1 RETURNING digest`,
                        [digest],
                    );
                    return { revoked: removed.rows.length };
                }
                const revoked = await transaction.query<{ revocation_key: unknown }>(
                    `SELECT revocation_key FROM murmur_invitation_revocations
                     WHERE digest = $1 AND expires_at > $2`,
                    [digest, now.toString()],
                );
                const tombstone = revoked.rows[0];
                if (
                    tombstone !== undefined &&
                    !equalBytes(
                        copyBytes(tombstone.revocation_key, "invitation revocation key"),
                        revocationKey,
                    )
                ) {
                    throw new RelayError(401, "Invitation revocation is unauthorized", {
                        error: "invitation_revocation_unauthorized",
                    });
                }
                return { revoked: 0 };
            }
            let revoked = 0;
            while (true) {
                const active = await transaction.query<{
                    digest: unknown;
                    expires_at: unknown;
                    admission_principal: unknown;
                }>(
                    `SELECT digest, expires_at, admission_principal
                     FROM murmur_invitations
                     WHERE revocation_key = $1 AND expires_at > $2
                     ORDER BY expires_at, digest
                     LIMIT $3`,
                    [revocationKey, now.toString(), maximumItems],
                );
                if (active.rows.length === 0) break;
                for (const invitation of active.rows) {
                    const invitationDigest = copyBytes(invitation.digest, "invitation digest");
                    await transaction.query(
                        `INSERT INTO murmur_invitation_revocations
                            (digest, revocation_key, expires_at, admission_principal)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (digest) DO NOTHING`,
                        [
                            invitationDigest,
                            revocationKey,
                            safeNumberColumn(invitation.expires_at).toString(),
                            copyBytes(invitation.admission_principal, "admission principal"),
                        ],
                    );
                    const removed = await transaction.query<{ digest: unknown }>(
                        `DELETE FROM murmur_invitations
                         WHERE digest = $1 AND revocation_key = $2
                         RETURNING digest`,
                        [invitationDigest, revocationKey],
                    );
                    revoked += removed.rows.length;
                }
            }
            return { revoked };
        });
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
            const generationSeed = copyBytes(global.generation_seed, "generation seed");
            const queueParameters: (Uint8Array | string)[] = [];
            const queueValues = delivery.recipients
                .map((recipient, index) => {
                    queueParameters.push(
                        recipient,
                        initialLossGeneration(generationSeed, recipient),
                    );
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

    async #assertRevocationKeyCapacity(
        transaction: PostgresQuery,
        revocationKey: Uint8Array,
        now: number,
        limits: InvitationLimits,
        addedItems: number,
    ): Promise<void> {
        const usage = await transaction.query<{ item_count: unknown }>(
            `SELECT
                (SELECT COUNT(*) FROM murmur_invitations
                 WHERE revocation_key = $1 AND expires_at > $2) +
                (SELECT COUNT(*) FROM murmur_invitation_revocations
                 WHERE revocation_key = $1 AND expires_at > $2) AS item_count`,
            [revocationKey, now.toString()],
        );
        const row = usage.rows[0];
        if (row === undefined) throw new Error("Missing revocation-authority usage");
        if (
            bigintColumn(row.item_count) + BigInt(addedItems) >
            BigInt(limits.maximumRevocationKeyItems)
        ) {
            throw new RelayError(429, "Invitation revocation-authority quota exceeded", {
                error: "invitation_revocation_authority_full",
            });
        }
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
        const removedInvitations = await transaction.query<{ digest: unknown }>(
            `WITH expired AS (
                 SELECT digest
                 FROM murmur_invitations
                 WHERE expires_at <= $1
                 ORDER BY expires_at, digest
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             DELETE FROM murmur_invitations AS invitation
             USING expired
             WHERE invitation.digest = expired.digest
             RETURNING invitation.digest`,
            [now.toString()],
        );
        const removedRevocations = await transaction.query<{ digest: unknown }>(
            `WITH expired AS (
                 SELECT digest
                 FROM murmur_invitation_revocations
                 WHERE expires_at <= $1
                 ORDER BY expires_at, digest
                 LIMIT ${RELAY_EXPIRATION_BATCH_ITEMS}
             )
             DELETE FROM murmur_invitation_revocations AS revocation
             USING expired
             WHERE revocation.digest = expired.digest
             RETURNING revocation.digest`,
            [now.toString()],
        );
        return (
            removed.rows.length + removedInvitations.rows.length + removedRevocations.rows.length
        );
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Postgres queue store is closed");
        }
    }
}
