import { bigintColumn } from "../../utils/bytes.js";
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
            if (row.marker === null && row.queue_state !== null) {
                throw new Error("Incomplete Postgres queue schema");
            }
            if (row.marker !== null) {
                const version = await connection.query<{ version: unknown }>(
                    "SELECT version FROM murmur_queue_schema WHERE singleton = 1",
                );
                const versionRow = version.rows[0];
                if (versionRow === undefined || bigintColumn(versionRow.version) !== 2n) {
                    throw new Error("Unsupported Postgres queue schema version");
                }
                return;
            }
            const statements = [
                `CREATE TABLE murmur_queue_schema (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    version bigint NOT NULL
                )`,
                `INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 2)`,
                `CREATE TABLE murmur_queue_global (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    last_event_id uuid,
                    pending_items bigint NOT NULL CHECK (pending_items >= 0),
                    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0),
                    pending_references bigint NOT NULL CHECK (pending_references >= 0)
                )`,
                `INSERT INTO murmur_queue_global
                    (singleton, last_event_id, pending_items, pending_bytes, pending_references)
                 VALUES (1, NULL, 0, 0, 0)`,
                `CREATE TABLE murmur_queues (
                    recipient bytea PRIMARY KEY CHECK (octet_length(recipient) = 32),
                    head uuid NOT NULL,
                    acknowledged_through uuid CHECK (
                        acknowledged_through IS NULL OR acknowledged_through <= head
                    ),
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
                    sender bytea NOT NULL,
                    delivery_id text NOT NULL,
                    encoded_bytes bigint NOT NULL CHECK (encoded_bytes > 0),
                    admission_principal bytea NOT NULL
                        CHECK (octet_length(admission_principal) = 32),
                    PRIMARY KEY (recipient, event_id),
                    FOREIGN KEY (sender, delivery_id)
                        REFERENCES murmur_queue_deliveries(sender, delivery_id)
                        ON DELETE CASCADE
                )`,
                `CREATE INDEX murmur_queue_reference_delivery
                    ON murmur_queue_references(sender, delivery_id)`,
                `CREATE INDEX murmur_queue_reference_admission
                    ON murmur_queue_references(admission_principal)`,
            ];
            await connection.transaction(async (transaction) => {
                for (const statement of statements) {
                    await transaction.query(statement);
                }
            });
        } finally {
            await connection.query("SELECT pg_advisory_unlock($1::bigint)", [SCHEMA_LOCK]);
        }
    });
}
