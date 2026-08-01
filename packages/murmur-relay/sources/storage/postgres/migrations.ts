import { bigintColumn } from "../../utils/bytes.js";
import type { PostgresDatabase, PostgresQuery } from "./database.js";

const MIGRATION_LOCK = "5570743552625583469";
const CURRENT_SCHEMA_VERSION = 2n;

const INITIAL_MIGRATION: readonly string[] = [
    `CREATE TABLE murmur_relay_topics (
        id text PRIMARY KEY,
        seq bigint NOT NULL CHECK (seq >= 0),
        oldest_retained_seq bigint NOT NULL CHECK (oldest_retained_seq >= 1),
        snapshot_version bigint NOT NULL CHECK (snapshot_version >= 0),
        next_position bigint NOT NULL CHECK (next_position >= 0),
        element_count bigint NOT NULL CHECK (element_count >= 0),
        last_activity_at bigint NOT NULL
    )`,
    `CREATE TABLE murmur_relay_snapshots (
        topic text PRIMARY KEY
            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
        version bigint NOT NULL CHECK (version > 0),
        seq bigint NOT NULL CHECK (seq > 0),
        bytes bytea NOT NULL
    )`,
    `CREATE TABLE murmur_relay_list_elements (
        topic text NOT NULL
            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
        id text NOT NULL,
        version bigint NOT NULL CHECK (version > 0),
        position bigint NOT NULL CHECK (position > 0),
        seq bigint NOT NULL CHECK (seq > 0),
        bytes bytea NOT NULL,
        PRIMARY KEY (topic, id),
        UNIQUE (topic, position)
    )`,
    `CREATE TABLE murmur_relay_events (
        topic text NOT NULL
            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
        seq bigint NOT NULL CHECK (seq > 0),
        id text NOT NULL,
        fingerprint bytea NOT NULL,
        event_json jsonb NOT NULL,
        observed_at bigint NOT NULL,
        snapshot_version bigint,
        PRIMARY KEY (topic, seq),
        UNIQUE (topic, id)
    )`,
    `CREATE INDEX murmur_relay_events_retention
        ON murmur_relay_events(observed_at)`,
];

const IDEMPOTENCY_RECEIPT_MIGRATION: readonly string[] = [
    `CREATE TABLE murmur_relay_event_receipts (
        topic text NOT NULL
            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
        id text NOT NULL,
        seq bigint NOT NULL CHECK (seq > 0),
        fingerprint bytea NOT NULL,
        snapshot_version bigint,
        PRIMARY KEY (topic, id)
    )`,
    `INSERT INTO murmur_relay_event_receipts (
        topic, id, seq, fingerprint, snapshot_version
     )
     SELECT topic, id, seq, fingerprint, snapshot_version
     FROM murmur_relay_events`,
];

const MIGRATIONS: readonly {
    readonly version: bigint;
    readonly statements: readonly string[];
}[] = [
    { version: 1n, statements: INITIAL_MIGRATION },
    { version: 2n, statements: IDEMPOTENCY_RECEIPT_MIGRATION },
];

async function currentVersion(query: PostgresQuery): Promise<bigint> {
    const result = await query.query<{ version: unknown }>(
        `SELECT version
         FROM murmur_relay_schema_migrations
         ORDER BY version DESC
         LIMIT 1`,
    );
    const row = result.rows[0];
    return row === undefined ? 0n : bigintColumn(row.version);
}

/** Apply explicit Postgres schema migrations once under a session advisory lock. */
export async function migratePostgresRelay(database: PostgresDatabase): Promise<void> {
    await database.connection(async (connection) => {
        await connection.query("SELECT pg_advisory_lock($1::bigint)", [MIGRATION_LOCK]);
        try {
            await connection.query(`
                CREATE TABLE IF NOT EXISTS murmur_relay_schema_migrations (
                    version bigint PRIMARY KEY,
                    applied_at bigint NOT NULL
                )
            `);
            const version = await currentVersion(connection);
            if (version > CURRENT_SCHEMA_VERSION) {
                throw new Error("Postgres relay schema is newer than this server");
            }
            for (const migration of MIGRATIONS) {
                if (migration.version > version) {
                    await connection.transaction(async (transaction) => {
                        for (const statement of migration.statements) {
                            await transaction.query(statement);
                        }
                        await transaction.query(
                            `INSERT INTO murmur_relay_schema_migrations
                                (version, applied_at)
                             VALUES ($1, $2)`,
                            [migration.version.toString(), Date.now().toString()],
                        );
                    });
                }
            }
        } finally {
            await connection.query("SELECT pg_advisory_unlock($1::bigint)", [MIGRATION_LOCK]);
        }
    });
}
