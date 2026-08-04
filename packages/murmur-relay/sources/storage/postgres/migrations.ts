import type { PostgresDatabase } from "./database.js";

/** Create the clean relay schema. Existing legacy schemas are intentionally unsupported. */
export async function createPostgresRelaySchema(database: PostgresDatabase): Promise<void> {
    await database.connection(async (connection) => {
        const statements = [
            `CREATE TABLE IF NOT EXISTS murmur_relay_topics (
                id text PRIMARY KEY,
                head bigint NOT NULL CHECK (head >= 0)
            )`,
            `CREATE TABLE IF NOT EXISTS murmur_relay_receipts (
                topic_id text NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                id text NOT NULL,
                seq bigint NOT NULL CHECK (seq > 0),
                fingerprint bytea NOT NULL,
                PRIMARY KEY (topic_id, id)
            )`,
            `CREATE TABLE IF NOT EXISTS murmur_relay_events (
                topic_id text NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                seq bigint NOT NULL CHECK (seq > 0),
                event_json jsonb NOT NULL,
                expires_at bigint,
                collapse_key bytea,
                PRIMARY KEY (topic_id, seq)
            )`,
            `CREATE INDEX IF NOT EXISTS murmur_relay_events_expiration
                ON murmur_relay_events(expires_at) WHERE expires_at IS NOT NULL`,
            `CREATE INDEX IF NOT EXISTS murmur_relay_events_collapse
                ON murmur_relay_events(topic_id, collapse_key)
                WHERE collapse_key IS NOT NULL`,
        ];
        for (const statement of statements) {
            await connection.query(statement);
        }
    });
}
