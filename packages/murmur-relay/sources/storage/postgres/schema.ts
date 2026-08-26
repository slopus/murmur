import { bigintColumn } from "../../utils/bytes.js";
import { createGenerationSeed } from "../continuity.js";
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
                queues: unknown;
                deliveries: unknown;
                references: unknown;
                rosters: unknown;
                roster_devices: unknown;
                roster_nonces: unknown;
                directory_devices: unknown;
                directory_prekeys: unknown;
                directory_references: unknown;
                directory_nonces: unknown;
                directory_tickets: unknown;
            }>(
                `SELECT
                    to_regclass('murmur_queue_schema') AS marker,
                    to_regclass('murmur_queue_global') AS queue_state,
                    to_regclass('murmur_queues') AS queues,
                    to_regclass('murmur_queue_deliveries') AS deliveries,
                    to_regclass('murmur_queue_references') AS references,
                    to_regclass('murmur_device_rosters') AS rosters,
                    to_regclass('murmur_device_roster_devices') AS roster_devices,
                    to_regclass('murmur_device_roster_nonces') AS roster_nonces,
                    to_regclass('murmur_directory_devices') AS directory_devices,
                    to_regclass('murmur_directory_prekeys') AS directory_prekeys,
                    to_regclass('murmur_directory_prekey_references') AS directory_references,
                    to_regclass('murmur_directory_upload_nonces') AS directory_nonces,
                    to_regclass('murmur_directory_ticket_uses') AS directory_tickets`,
            );
            const row = presence.rows[0];
            if (row === undefined) throw new Error("Missing Postgres schema inspection");
            if (
                row.marker === null &&
                (row.queue_state !== null ||
                    row.queues !== null ||
                    row.deliveries !== null ||
                    row.references !== null ||
                    row.rosters !== null ||
                    row.roster_devices !== null ||
                    row.roster_nonces !== null ||
                    row.directory_devices !== null ||
                    row.directory_prekeys !== null ||
                    row.directory_references !== null ||
                    row.directory_nonces !== null ||
                    row.directory_tickets !== null)
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
                if (schemaVersion !== 3n) {
                    throw new Error("Unsupported Postgres queue schema version");
                }
                if (
                    row.queue_state === null ||
                    row.queues === null ||
                    row.deliveries === null ||
                    row.references === null ||
                    row.rosters === null ||
                    row.roster_devices === null ||
                    row.roster_nonces === null ||
                    row.directory_devices === null ||
                    row.directory_prekeys === null ||
                    row.directory_references === null ||
                    row.directory_nonces === null ||
                    row.directory_tickets === null
                ) {
                    throw new Error("Incomplete Postgres queue schema");
                }
                return;
            }
            const statements = [
                `CREATE TABLE murmur_queue_schema (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    version bigint NOT NULL
                )`,
                `INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 3)`,
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
                `CREATE TABLE murmur_device_rosters (
                    account_key bytea PRIMARY KEY CHECK (octet_length(account_key) = 32),
                    revision bigint NOT NULL CHECK (revision >= 1)
                )`,
                `CREATE TABLE murmur_device_roster_devices (
                    account_key bytea NOT NULL REFERENCES murmur_device_rosters(account_key)
                        ON DELETE CASCADE,
                    device_key bytea NOT NULL CHECK (octet_length(device_key) = 32),
                    reset_generation bigint NOT NULL CHECK (reset_generation >= 0),
                    key_package bytea NOT NULL CHECK (octet_length(key_package) > 0),
                    PRIMARY KEY (account_key, device_key)
                )`,
                `CREATE TABLE murmur_device_roster_nonces (
                    account_key bytea NOT NULL REFERENCES murmur_device_rosters(account_key)
                        ON DELETE CASCADE,
                    nonce text NOT NULL,
                    created_at bigint NOT NULL,
                    PRIMARY KEY (account_key, nonce)
                )`,
                ...directoryStatements(),
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

function directoryStatements(): readonly string[] {
    return [
        `CREATE TABLE murmur_directory_devices (
            account_key bytea NOT NULL,
            device_key bytea NOT NULL,
            last_resort_reference bytea NOT NULL
                CHECK (octet_length(last_resort_reference) = 32),
            last_resort_expires_at bigint NOT NULL,
            PRIMARY KEY (account_key, device_key),
            FOREIGN KEY (account_key, device_key)
                REFERENCES murmur_device_roster_devices(account_key, device_key)
                ON DELETE CASCADE
        )`,
        `CREATE TABLE murmur_directory_prekeys (
            account_key bytea NOT NULL,
            device_key bytea NOT NULL,
            reference bytea NOT NULL CHECK (octet_length(reference) = 32),
            key_package bytea NOT NULL CHECK (octet_length(key_package) > 0),
            notification_json jsonb NOT NULL,
            expires_at bigint NOT NULL,
            created_at bigint NOT NULL,
            PRIMARY KEY (account_key, device_key, reference),
            FOREIGN KEY (account_key, device_key)
                REFERENCES murmur_directory_devices(account_key, device_key)
                ON DELETE CASCADE
        )`,
        `CREATE INDEX murmur_directory_prekey_claim
            ON murmur_directory_prekeys(account_key, device_key, created_at, reference)`,
        `CREATE TABLE murmur_directory_prekey_references (
            account_key bytea NOT NULL REFERENCES murmur_device_rosters(account_key)
                ON DELETE CASCADE,
            device_key bytea NOT NULL CHECK (octet_length(device_key) = 32),
            reference bytea NOT NULL CHECK (octet_length(reference) = 32),
            first_seen_at bigint NOT NULL,
            PRIMARY KEY (account_key, device_key, reference)
        )`,
        `CREATE TABLE murmur_directory_upload_nonces (
            account_key bytea NOT NULL REFERENCES murmur_device_rosters(account_key)
                ON DELETE CASCADE,
            nonce text NOT NULL,
            created_at bigint NOT NULL,
            PRIMARY KEY (account_key, nonce)
        )`,
        `CREATE TABLE murmur_directory_ticket_uses (
            issuer text NOT NULL,
            ticket_id bytea NOT NULL CHECK (octet_length(ticket_id) = 32),
            claim_budget bigint NOT NULL CHECK (claim_budget >= 1),
            claims_used bigint NOT NULL CHECK (
                claims_used >= 1 AND claims_used <= claim_budget
            ),
            expires_at bigint NOT NULL,
            PRIMARY KEY (issuer, ticket_id)
        )`,
    ];
}
