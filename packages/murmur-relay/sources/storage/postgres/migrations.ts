import { bigintColumn, copyBytes } from "../../utils/bytes.js";
import { createGenerationSeed, initialLossGeneration } from "../continuity.js";
import type { PostgresDatabase } from "./database.js";

const SCHEMA_LOCK = "5570743552625583469";

/** Create or validate the clean identity-queue schema under one session lock. */
export async function createPostgresRelaySchema(database: PostgresDatabase): Promise<void> {
    await database.connection(async (connection) => {
        await connection.query("SELECT pg_advisory_lock($1::bigint)", [SCHEMA_LOCK]);
        try {
            const presence = await connection.query<{
                marker: unknown;
                queue_state: unknown;
                invitations: unknown;
                invitation_revocations: unknown;
                legacy_schema: unknown;
                legacy_topics: unknown;
                legacy_receipts: unknown;
                legacy_events: unknown;
                legacy_challenges: unknown;
                legacy_challenge_state: unknown;
            }>(
                `SELECT
                    to_regclass('murmur_queue_schema') AS marker,
                    to_regclass('murmur_queue_global') AS queue_state,
                    to_regclass('murmur_invitations') AS invitations,
                    to_regclass('murmur_invitation_revocations') AS invitation_revocations,
                    to_regclass('murmur_relay_schema') AS legacy_schema,
                    to_regclass('murmur_relay_topics') AS legacy_topics,
                    to_regclass('murmur_relay_receipts') AS legacy_receipts,
                    to_regclass('murmur_relay_events') AS legacy_events,
                    to_regclass('murmur_relay_read_challenges') AS legacy_challenges,
                    to_regclass('murmur_relay_challenge_state') AS legacy_challenge_state`,
            );
            const row = presence.rows[0];
            if (row === undefined) throw new Error("Missing Postgres schema inspection");
            if (
                row.legacy_schema !== null ||
                row.legacy_topics !== null ||
                row.legacy_receipts !== null ||
                row.legacy_events !== null ||
                row.legacy_challenges !== null ||
                row.legacy_challenge_state !== null
            ) {
                throw new Error(
                    "Legacy Postgres relay schema is not supported; use a clean database",
                );
            }
            if (
                row.marker === null &&
                (row.queue_state !== null ||
                    row.invitations !== null ||
                    row.invitation_revocations !== null)
            ) {
                throw new Error("Incomplete Postgres queue schema");
            }
            if (row.marker !== null) {
                const version = await connection.query<{ version: unknown }>(
                    "SELECT version FROM murmur_queue_schema WHERE singleton = 1",
                );
                const versionRow = version.rows[0];
                if (versionRow === undefined) {
                    throw new Error("Unsupported Postgres queue schema version");
                }
                const schemaVersion = bigintColumn(versionRow.version);
                if (schemaVersion === 3n) {
                    if (row.invitation_revocations !== null) {
                        throw new Error("Incomplete Postgres queue schema");
                    }
                    await connection.transaction(async (transaction) => {
                        await transaction.query(
                            `ALTER TABLE murmur_invitations ADD COLUMN revocation_key bytea
                             CHECK (
                                revocation_key IS NULL OR octet_length(revocation_key) = 32
                             )`,
                        );
                        await transaction.query(
                            `CREATE INDEX murmur_invitation_revocation_key
                             ON murmur_invitations(revocation_key)`,
                        );
                        await transaction.query(
                            `CREATE TABLE murmur_invitation_revocations (
                                digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
                                revocation_key bytea NOT NULL
                                    CHECK (octet_length(revocation_key) = 32),
                                expires_at bigint NOT NULL,
                                admission_principal bytea NOT NULL
                                    CHECK (octet_length(admission_principal) = 32)
                             )`,
                        );
                        await transaction.query(
                            `CREATE INDEX murmur_invitation_revocation_expiration
                             ON murmur_invitation_revocations(expires_at)`,
                        );
                        await transaction.query(
                            `CREATE INDEX murmur_invitation_revocation_authority
                             ON murmur_invitation_revocations(revocation_key)`,
                        );
                        await transaction.query(
                            `CREATE INDEX murmur_invitation_revocation_admission
                             ON murmur_invitation_revocations(admission_principal)`,
                        );
                        await transaction.query(
                            "UPDATE murmur_queue_schema SET version = 4 WHERE singleton = 1",
                        );
                    });
                }
                if (schemaVersion === 3n) {
                    const continuityTables = await connection.query<{ queues: unknown }>(
                        `SELECT to_regclass('murmur_queues') AS queues`,
                    );
                    if (continuityTables.rows[0]?.queues === null) return;
                }
                if (schemaVersion === 3n || schemaVersion === 4n) {
                    await connection.transaction(async (transaction) => {
                        await transaction.query(
                            `ALTER TABLE murmur_queue_global ADD COLUMN generation_seed bytea
                             NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
                             CHECK (octet_length(generation_seed) = 32)`,
                        );
                        await transaction.query(
                            `ALTER TABLE murmur_queues ADD COLUMN head_sequence bigint
                             NOT NULL DEFAULT 0 CHECK (head_sequence >= 0)`,
                        );
                        await transaction.query(
                            `ALTER TABLE murmur_queues ADD COLUMN next_sequence bigint
                             NOT NULL DEFAULT 1 CHECK (next_sequence > head_sequence)`,
                        );
                        await transaction.query(
                            `ALTER TABLE murmur_queues ADD COLUMN acknowledged_sequence bigint
                             NOT NULL DEFAULT 0 CHECK (
                                acknowledged_sequence >= 0 AND
                                acknowledged_sequence <= head_sequence
                             )`,
                        );
                        await transaction.query(
                            `ALTER TABLE murmur_queues ADD COLUMN loss_generation bytea
                             NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
                             CHECK (octet_length(loss_generation) = 32)`,
                        );
                        await transaction.query(
                            `ALTER TABLE murmur_queue_references ADD COLUMN sequence bigint
                             NOT NULL DEFAULT 0 CHECK (sequence >= 0)`,
                        );
                        await transaction.query(
                            `WITH numbered AS (
                                SELECT recipient, event_id,
                                       row_number() OVER (
                                           PARTITION BY recipient ORDER BY event_id
                                       ) AS sequence
                                FROM murmur_queue_references
                             )
                             UPDATE murmur_queue_references AS reference
                             SET sequence = numbered.sequence
                             FROM numbered
                             WHERE reference.recipient = numbered.recipient
                               AND reference.event_id = numbered.event_id`,
                        );
                        await transaction.query(
                            `CREATE UNIQUE INDEX murmur_queue_reference_sequence
                             ON murmur_queue_references(recipient, sequence)`,
                        );
                        await transaction.query(
                            `UPDATE murmur_queues AS queue
                             SET head_sequence = COALESCE(reference.maximum, 0),
                                 next_sequence = COALESCE(reference.maximum + 1, 1)
                             FROM (
                                SELECT recipient, MAX(sequence) AS maximum
                                FROM murmur_queue_references GROUP BY recipient
                             ) AS reference
                             WHERE queue.recipient = reference.recipient`,
                        );
                        const seed = createGenerationSeed();
                        await transaction.query(
                            `UPDATE murmur_queue_global SET generation_seed = $1
                             WHERE singleton = 1`,
                            [seed],
                        );
                        const queues = await transaction.query<{ recipient: unknown }>(
                            `SELECT recipient FROM murmur_queues`,
                        );
                        for (const queue of queues.rows) {
                            const recipient = copyBytes(queue.recipient, "queue recipient");
                            await transaction.query(
                                `UPDATE murmur_queues SET loss_generation = $1
                                 WHERE recipient = $2`,
                                [initialLossGeneration(seed, recipient), recipient],
                            );
                        }
                        await transaction.query(
                            "UPDATE murmur_queue_schema SET version = 5 WHERE singleton = 1",
                        );
                    });
                    return;
                }
                if (schemaVersion !== 5n || row.invitation_revocations === null) {
                    throw new Error("Unsupported Postgres queue schema version");
                }
                return;
            }
            const statements = [
                `CREATE TABLE murmur_queue_schema (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    version bigint NOT NULL
                )`,
                `INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 5)`,
                `CREATE TABLE murmur_queue_global (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    last_event_id uuid,
                    generation_seed bytea NOT NULL CHECK (octet_length(generation_seed) = 32),
                    pending_items bigint NOT NULL CHECK (pending_items >= 0),
                    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0),
                    pending_references bigint NOT NULL CHECK (pending_references >= 0)
                )`,
                `INSERT INTO murmur_queue_global
                    (singleton, last_event_id, generation_seed, pending_items, pending_bytes,
                     pending_references)
                 VALUES (1, NULL, decode(repeat('00', 32), 'hex'), 0, 0, 0)`,
                `CREATE TABLE murmur_queues (
                    recipient bytea PRIMARY KEY CHECK (octet_length(recipient) = 32),
                    head uuid NOT NULL,
                    head_sequence bigint NOT NULL CHECK (head_sequence >= 1),
                    next_sequence bigint NOT NULL CHECK (next_sequence = head_sequence + 1),
                    acknowledged_through uuid CHECK (
                        acknowledged_through IS NULL OR acknowledged_through <= head
                    ),
                    acknowledged_sequence bigint NOT NULL CHECK (
                        acknowledged_sequence >= 0 AND acknowledged_sequence <= head_sequence
                    ),
                    loss_generation bytea NOT NULL CHECK (octet_length(loss_generation) = 32),
                    pending_items bigint NOT NULL CHECK (pending_items >= 0),
                    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0)
                )`,
                `CREATE TABLE murmur_queue_deliveries (
                    sender bytea NOT NULL CHECK (octet_length(sender) = 32),
                    delivery_id text NOT NULL,
                    event_id uuid NOT NULL UNIQUE,
                    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
                    delivery_json jsonb NOT NULL,
                    encoded_bytes bigint NOT NULL CHECK (encoded_bytes > 0),
                    expires_at bigint NOT NULL,
                    PRIMARY KEY (sender, delivery_id)
                )`,
                `CREATE INDEX murmur_queue_delivery_expiration
                    ON murmur_queue_deliveries(expires_at)`,
                `CREATE TABLE murmur_queue_references (
                    recipient bytea NOT NULL REFERENCES murmur_queues(recipient)
                        ON DELETE CASCADE,
                    event_id uuid NOT NULL,
                    sequence bigint NOT NULL CHECK (sequence >= 1),
                    sender bytea NOT NULL,
                    delivery_id text NOT NULL,
                    encoded_bytes bigint NOT NULL CHECK (encoded_bytes > 0),
                    admission_principal bytea NOT NULL
                        CHECK (octet_length(admission_principal) = 32),
                    PRIMARY KEY (recipient, event_id),
                    UNIQUE (recipient, sequence),
                    FOREIGN KEY (sender, delivery_id)
                        REFERENCES murmur_queue_deliveries(sender, delivery_id)
                        ON DELETE CASCADE
                )`,
                `CREATE INDEX murmur_queue_reference_delivery
                    ON murmur_queue_references(sender, delivery_id)`,
                `CREATE INDEX murmur_queue_reference_admission
                    ON murmur_queue_references(admission_principal)`,
                `CREATE TABLE murmur_invitations (
                    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
                    bundle bytea NOT NULL,
                    encoded_bytes bigint NOT NULL CHECK (
                        encoded_bytes > 0 AND octet_length(bundle) = encoded_bytes
                    ),
                    expires_at bigint NOT NULL,
                    admission_principal bytea NOT NULL
                        CHECK (octet_length(admission_principal) = 32),
                    revocation_key bytea
                        CHECK (revocation_key IS NULL OR octet_length(revocation_key) = 32)
                )`,
                `CREATE INDEX murmur_invitation_expiration
                    ON murmur_invitations(expires_at)`,
                `CREATE INDEX murmur_invitation_admission
                    ON murmur_invitations(admission_principal)`,
                `CREATE INDEX murmur_invitation_revocation_key
                    ON murmur_invitations(revocation_key)`,
                `CREATE TABLE murmur_invitation_revocations (
                    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
                    revocation_key bytea NOT NULL
                        CHECK (octet_length(revocation_key) = 32),
                    expires_at bigint NOT NULL,
                    admission_principal bytea NOT NULL
                        CHECK (octet_length(admission_principal) = 32)
                )`,
                `CREATE INDEX murmur_invitation_revocation_expiration
                    ON murmur_invitation_revocations(expires_at)`,
                `CREATE INDEX murmur_invitation_revocation_authority
                    ON murmur_invitation_revocations(revocation_key)`,
                `CREATE INDEX murmur_invitation_revocation_admission
                    ON murmur_invitation_revocations(admission_principal)`,
            ];
            await connection.transaction(async (transaction) => {
                for (const statement of statements) {
                    await transaction.query(statement);
                }
                await transaction.query(
                    `UPDATE murmur_queue_global SET generation_seed = $1 WHERE singleton = 1`,
                    [createGenerationSeed()],
                );
            });
        } finally {
            await connection.query("SELECT pg_advisory_unlock($1::bigint)", [SCHEMA_LOCK]);
        }
    });
}
