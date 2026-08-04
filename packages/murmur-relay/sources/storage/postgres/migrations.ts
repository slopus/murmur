import { bigintColumn } from "../../utils/bytes.js";
import type { PostgresDatabase } from "./database.js";

const SCHEMA_LOCK = "5570743552625583469";

/** Create or validate the clean relay schema under one session lock. */
export async function createPostgresRelaySchema(database: PostgresDatabase): Promise<void> {
    await database.connection(async (connection) => {
        await connection.query("SELECT pg_advisory_lock($1::bigint)", [SCHEMA_LOCK]);
        try {
            const presence = await connection.query<{ marker: unknown; topics: unknown }>(
                `SELECT
                    to_regclass('murmur_relay_schema') AS marker,
                    to_regclass('murmur_relay_topics') AS topics`,
            );
            const row = presence.rows[0];
            if (row === undefined) throw new Error("Missing Postgres schema inspection");
            if (row.marker === null && row.topics !== null) {
                throw new Error("Incompatible legacy Postgres relay schema");
            }
            if (row.marker !== null) {
                const version = await connection.query<{ version: unknown }>(
                    "SELECT version FROM murmur_relay_schema WHERE singleton = 1",
                );
                const versionRow = version.rows[0];
                if (versionRow === undefined || bigintColumn(versionRow.version) !== 1n) {
                    throw new Error("Unsupported Postgres relay schema version");
                }
                return;
            }
            const statements = [
                `CREATE TABLE murmur_relay_schema (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    version bigint NOT NULL
                )`,
                `INSERT INTO murmur_relay_schema (singleton, version) VALUES (1, 1)`,
                `CREATE TABLE murmur_relay_topics (
                    id text PRIMARY KEY,
                    head bigint NOT NULL CHECK (head >= 0)
                )`,
                `CREATE TABLE murmur_relay_receipts (
                    topic_id text NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                    id text NOT NULL,
                    seq bigint NOT NULL CHECK (seq > 0),
                    fingerprint bytea NOT NULL,
                    PRIMARY KEY (topic_id, id)
                )`,
                `CREATE TABLE murmur_relay_events (
                    topic_id text NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                    seq bigint NOT NULL CHECK (seq > 0),
                    event_json jsonb NOT NULL,
                    expires_at bigint,
                    collapse_key bytea,
                    PRIMARY KEY (topic_id, seq)
                )`,
                `CREATE INDEX murmur_relay_events_expiration
                    ON murmur_relay_events(expires_at) WHERE expires_at IS NOT NULL`,
                `CREATE INDEX murmur_relay_events_collapse
                    ON murmur_relay_events(topic_id, collapse_key)
                    WHERE collapse_key IS NOT NULL`,
                `CREATE TABLE murmur_relay_read_challenges (
                    id text PRIMARY KEY,
                    topic_id text NOT NULL,
                    nonce bytea NOT NULL,
                    expires_at bigint NOT NULL
                )`,
                `CREATE INDEX murmur_relay_challenge_expiration
                    ON murmur_relay_read_challenges(expires_at)`,
                `CREATE TABLE murmur_relay_challenge_state (
                    singleton bigint PRIMARY KEY CHECK (singleton = 1),
                    outstanding bigint NOT NULL CHECK (outstanding >= 0)
                )`,
                `INSERT INTO murmur_relay_challenge_state (singleton, outstanding)
                    VALUES (1, 0)`,
            ];
            await connection.transaction(async (transaction) => {
                for (const statement of statements) await transaction.query(statement);
            });
        } finally {
            await connection.query("SELECT pg_advisory_unlock($1::bigint)", [SCHEMA_LOCK]);
        }
    });
}
