import {
    DatabaseSync,
    type SQLInputValue,
    type StatementResultingChanges,
    type StatementSync,
} from "node:sqlite";
import {
    RelayError,
    parseSignedRelayEvent,
    relayEventFingerprint,
    signedRelayEventToJson,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { bigintColumn, copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import type {
    EventPage,
    PageReadConstraints,
    PublishOutcome,
    PublishReceipt,
    RelayStore,
    RetainedRelayEvent,
} from "../types.js";

/** SQLite store construction options for embedding. */
export interface SqliteRelayStoreOptions {
    readonly database?: DatabaseSync;
}

function record(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid SQLite relay row");
    }
    return value as Record<string, unknown>;
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name} in SQLite relay store`);
    }
    return value;
}

/** Fresh-schema SQLite ordered event store. */
export class SqliteRelayStore implements RelayStore {
    readonly #database: DatabaseSync;
    #closed = false;

    constructor(path: string, options: SqliteRelayStoreOptions = {}) {
        this.#database = options.database ?? new DatabaseSync(path);
        this.#database.exec("PRAGMA journal_mode = WAL");
        this.#database.exec("PRAGMA foreign_keys = ON");
        this.#database.exec(`
            CREATE TABLE IF NOT EXISTS murmur_relay_topics (
                id TEXT PRIMARY KEY,
                head INTEGER NOT NULL CHECK (head >= 0)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_relay_receipts (
                topic_id TEXT NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                id TEXT NOT NULL,
                seq INTEGER NOT NULL CHECK (seq > 0),
                fingerprint BLOB NOT NULL,
                PRIMARY KEY (topic_id, id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_relay_events (
                topic_id TEXT NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                seq INTEGER NOT NULL CHECK (seq > 0),
                event_json TEXT NOT NULL,
                expires_at INTEGER,
                collapse_key BLOB,
                PRIMARY KEY (topic_id, seq)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS murmur_relay_events_expiration
                ON murmur_relay_events(expires_at) WHERE expires_at IS NOT NULL;
            CREATE INDEX IF NOT EXISTS murmur_relay_events_collapse
                ON murmur_relay_events(topic_id, collapse_key)
                WHERE collapse_key IS NOT NULL
        `);
    }

    async readPublishReceipt(topicId: string, id: string): Promise<PublishReceipt | undefined> {
        this.#assertOpen();
        const row = this.#get(
            "SELECT seq, fingerprint FROM murmur_relay_receipts WHERE topic_id = ? AND id = ?",
            topicId,
            id,
        );
        return row === undefined
            ? undefined
            : {
                  seq: bigintColumn(row.seq),
                  fingerprint: copyBytes(row.fingerprint, "event fingerprint"),
              };
    }

    async publish(event: SignedRelayEvent, topicId: string, _now: number): Promise<PublishOutcome> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const fingerprint = relayEventFingerprint(event);
            const duplicate = this.#get(
                "SELECT seq, fingerprint FROM murmur_relay_receipts WHERE topic_id = ? AND id = ?",
                topicId,
                event.id,
            );
            if (duplicate !== undefined) {
                if (!equalBytes(copyBytes(duplicate.fingerprint, "fingerprint"), fingerprint)) {
                    throw new RelayError(409, "Event identifier collision", {
                        error: "id_collision",
                    });
                }
                this.#database.exec("COMMIT");
                return { seq: bigintColumn(duplicate.seq), duplicate: true };
            }
            this.#run(
                "INSERT INTO murmur_relay_topics (id, head) VALUES (?, 0) ON CONFLICT DO NOTHING",
                topicId,
            );
            const topic = this.#requiredGet(
                "SELECT head FROM murmur_relay_topics WHERE id = ?",
                topicId,
            );
            const seq = bigintColumn(topic.head) + 1n;
            this.#run("UPDATE murmur_relay_topics SET head = ? WHERE id = ?", seq, topicId);
            if (event.collapseKey !== undefined) {
                this.#run(
                    "DELETE FROM murmur_relay_events WHERE topic_id = ? AND collapse_key = ?",
                    topicId,
                    event.collapseKey,
                );
            }
            this.#run(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, expires_at, collapse_key)
                 VALUES (?, ?, ?, ?, ?)`,
                topicId,
                seq,
                JSON.stringify(signedRelayEventToJson(event)),
                event.expiresAt === undefined ? null : BigInt(event.expiresAt),
                event.collapseKey ?? null,
            );
            this.#run(
                `INSERT INTO murmur_relay_receipts (topic_id, id, seq, fingerprint)
                 VALUES (?, ?, ?, ?)`,
                topicId,
                event.id,
                seq,
                fingerprint,
            );
            this.#database.exec("COMMIT");
            return { seq, duplicate: false };
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    async readEvents(
        topicId: string,
        since: bigint,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage> {
        this.#assertOpen();
        const topic = this.#get("SELECT head FROM murmur_relay_topics WHERE id = ?", topicId);
        if (topic === undefined) {
            return { events: [], head: 0n, exhausted: true };
        }
        const rows = this.#all(
            `WITH candidates AS (
                SELECT seq, event_json,
                    ROW_NUMBER() OVER (ORDER BY seq) AS row_number,
                    COUNT(*) OVER () AS available_count,
                    SUM(LENGTH(event_json) + 64) OVER (
                        ORDER BY seq ROWS UNBOUNDED PRECEDING
                    ) AS cumulative_bytes
                FROM murmur_relay_events
                WHERE topic_id = ? AND seq > ? AND (expires_at IS NULL OR expires_at > ?)
             )
             SELECT seq, event_json, row_number, available_count FROM candidates
             WHERE row_number = 1 OR cumulative_bytes <= ?
             ORDER BY seq LIMIT ?`,
            topicId,
            since,
            BigInt(now),
            BigInt(constraints.maximumEncodedBytes),
            BigInt(limit),
        );
        return {
            events: rows.map(
                (row): RetainedRelayEvent => ({
                    seq: bigintColumn(row.seq),
                    event: parseSignedRelayEvent(
                        JSON.parse(textColumn(row.event_json, "event JSON")) as unknown,
                    ),
                }),
            ),
            head: bigintColumn(topic.head),
            exhausted:
                rows.length === 0 ||
                bigintColumn(rows.at(-1)!.row_number) ===
                    bigintColumn(rows.at(-1)!.available_count),
        };
    }

    async pruneExpired(now: number): Promise<number> {
        this.#assertOpen();
        return safeNumberColumn(
            this.#run(
                "DELETE FROM murmur_relay_events WHERE expires_at IS NOT NULL AND expires_at <= ?",
                BigInt(now),
            ).changes,
        );
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

    #prepare(sql: string): StatementSync {
        const statement = this.#database.prepare(sql);
        statement.setReadBigInts(true);
        return statement;
    }
    #get(sql: string, ...values: SQLInputValue[]): Record<string, unknown> | undefined {
        const value = this.#prepare(sql).get(...values);
        return value === undefined ? undefined : record(value);
    }
    #requiredGet(sql: string, ...values: SQLInputValue[]): Record<string, unknown> {
        const value = this.#get(sql, ...values);
        if (value === undefined) {
            throw new Error("Missing SQLite relay row");
        }
        return value;
    }
    #all(sql: string, ...values: SQLInputValue[]): Record<string, unknown>[] {
        return this.#prepare(sql)
            .all(...values)
            .map(record);
    }
    #run(sql: string, ...values: SQLInputValue[]): StatementResultingChanges {
        return this.#prepare(sql).run(...values);
    }
    #rollback(): void {
        try {
            this.#database.exec("ROLLBACK");
        } catch {}
    }
    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("SQLite relay store is closed");
        }
    }
}
