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
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { bigintColumn, copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import {
    encodeStoredRelayEvent,
    selectEventPageMetadata,
    type StoredPageCandidate,
} from "../page.js";
import type {
    EventPage,
    PageReadConstraints,
    PublishOutcome,
    PublishReceipt,
    RelayStore,
    RelayStoreInstrumentation,
    RetainedRelayEvent,
    StoredReadChallenge,
} from "../types.js";

/** SQLite store construction options for embedding. */
export interface SqliteRelayStoreOptions {
    readonly database?: DatabaseSync;
    readonly instrumentation?: RelayStoreInstrumentation;
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

/** Bounded retained-candidate query kept visible for query-plan regression tests. */
export const SQLITE_READ_EVENTS_QUERY = `
    SELECT seq, encoded_bytes
    FROM murmur_relay_events
    WHERE topic_id = ? AND seq > ? AND (expires_at IS NULL OR expires_at > ?)
    ORDER BY seq
    LIMIT ?`;

/** Build the exact selected-sequence hydration query for tests and store reads. */
export function sqliteHydrateEventsQuery(count: number): string {
    if (!Number.isSafeInteger(count) || count < 1) {
        throw new Error("SQLite hydration count must be a positive safe integer");
    }
    return `
        SELECT seq, event_json
        FROM murmur_relay_events
        WHERE topic_id = ? AND seq IN (${Array.from({ length: count }, () => "?").join(", ")})
        ORDER BY seq`;
}

/** Fresh-schema SQLite ordered event store. */
export class SqliteRelayStore implements RelayStore {
    readonly #database: DatabaseSync;
    readonly #instrumentation: RelayStoreInstrumentation | undefined;
    #closed = false;

    constructor(path: string, options: SqliteRelayStoreOptions = {}) {
        this.#database = options.database ?? new DatabaseSync(path);
        this.#instrumentation = options.instrumentation;
        this.#database.exec("PRAGMA journal_mode = WAL");
        this.#database.exec("PRAGMA foreign_keys = ON");
        this.#initializeSchema();
    }

    async issueReadChallenge(
        challenge: StoredReadChallenge,
        now: number,
        maximumOutstanding: number,
    ): Promise<boolean> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const deleted = safeNumberColumn(
                this.#run(
                    "DELETE FROM murmur_relay_read_challenges WHERE expires_at <= ?",
                    BigInt(now),
                ).changes,
            );
            if (deleted > 0) {
                this.#run(
                    `UPDATE murmur_relay_challenge_state
                     SET outstanding = MAX(0, outstanding - ?)
                     WHERE singleton = 1`,
                    BigInt(deleted),
                );
            }
            const state = this.#requiredGet(
                "SELECT outstanding FROM murmur_relay_challenge_state WHERE singleton = 1",
            );
            if (bigintColumn(state.outstanding) >= BigInt(maximumOutstanding)) {
                this.#database.exec("COMMIT");
                return false;
            }
            this.#run(
                `INSERT INTO murmur_relay_read_challenges
                    (id, topic_id, nonce, expires_at)
                 VALUES (?, ?, ?, ?)`,
                challenge.id,
                challenge.topicId,
                challenge.nonce,
                BigInt(challenge.expiresAt),
            );
            this.#run(
                `UPDATE murmur_relay_challenge_state
                 SET outstanding = outstanding + 1 WHERE singleton = 1`,
            );
            this.#database.exec("COMMIT");
            return true;
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    async consumeReadChallenge(id: string, now: number): Promise<StoredReadChallenge | undefined> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const row = this.#get(
                `DELETE FROM murmur_relay_read_challenges
                 WHERE id = ?
                 RETURNING id, topic_id, nonce, expires_at`,
                id,
            );
            if (row !== undefined) {
                this.#run(
                    `UPDATE murmur_relay_challenge_state
                     SET outstanding = MAX(0, outstanding - 1)
                     WHERE singleton = 1`,
                );
            }
            this.#database.exec("COMMIT");
            if (row === undefined || bigintColumn(row.expires_at) <= BigInt(now)) return undefined;
            return {
                id: textColumn(row.id, "challenge id"),
                topicId: textColumn(row.topic_id, "challenge topic"),
                nonce: copyBytes(row.nonce, "challenge nonce"),
                expiresAt: safeNumberColumn(row.expires_at),
            };
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    #initializeSchema(): void {
        const marker = this.#get(
            `SELECT name FROM sqlite_master
             WHERE type = 'table' AND name = 'murmur_relay_schema'`,
        );
        if (marker === undefined) {
            const legacy = this.#get(
                `SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name LIKE 'murmur_relay_%' LIMIT 1`,
            );
            if (legacy !== undefined) {
                throw new Error("Incompatible legacy SQLite relay schema");
            }
        } else {
            const schema = this.#requiredGet(
                "SELECT version FROM murmur_relay_schema WHERE singleton = 1",
            );
            if (bigintColumn(schema.version) !== 3n) {
                throw new Error("Unsupported SQLite relay schema version");
            }
            return;
        }
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            this.#database.exec(`
            CREATE TABLE murmur_relay_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            ) STRICT;
            INSERT INTO murmur_relay_schema (singleton, version) VALUES (1, 3);
            CREATE TABLE murmur_relay_topics (
                id TEXT PRIMARY KEY,
                head INTEGER NOT NULL CHECK (head >= 0)
            ) STRICT;
            CREATE TABLE murmur_relay_receipts (
                topic_id TEXT NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                id TEXT NOT NULL,
                seq INTEGER NOT NULL CHECK (seq > 0),
                fingerprint BLOB NOT NULL,
                PRIMARY KEY (topic_id, id)
            ) STRICT;
            CREATE TABLE murmur_relay_events (
                topic_id TEXT NOT NULL REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                seq INTEGER NOT NULL CHECK (seq > 0),
                event_json TEXT NOT NULL,
                encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0),
                expires_at INTEGER,
                author_signing_key BLOB NOT NULL,
                collapse_key BLOB,
                PRIMARY KEY (topic_id, seq)
            ) STRICT;
            CREATE INDEX murmur_relay_events_page
                ON murmur_relay_events(topic_id, seq, encoded_bytes, expires_at);
            CREATE INDEX murmur_relay_events_expiration
                ON murmur_relay_events(expires_at) WHERE expires_at IS NOT NULL;
            CREATE INDEX murmur_relay_events_collapse
                ON murmur_relay_events(topic_id, author_signing_key, collapse_key)
                WHERE collapse_key IS NOT NULL;
            CREATE TABLE murmur_relay_read_challenges (
                id TEXT PRIMARY KEY,
                topic_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                expires_at INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX murmur_relay_challenge_expiration
                ON murmur_relay_read_challenges(expires_at);
            CREATE TABLE murmur_relay_challenge_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                outstanding INTEGER NOT NULL CHECK (outstanding >= 0)
            ) STRICT;
            INSERT INTO murmur_relay_challenge_state (singleton, outstanding)
                VALUES (1, 0);
            `);
            this.#database.exec("COMMIT");
        } catch (error) {
            this.#rollback();
            throw error;
        }
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
                    `DELETE FROM murmur_relay_events
                     WHERE topic_id = ? AND author_signing_key = ? AND collapse_key = ?`,
                    topicId,
                    event.author.signingKey,
                    event.collapseKey,
                );
            }
            const encoded = encodeStoredRelayEvent(event);
            this.#run(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                topicId,
                seq,
                encoded.json,
                BigInt(encoded.encodedBytes),
                event.expiresAt === undefined ? null : BigInt(event.expiresAt),
                event.author.signingKey,
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
        this.#database.exec("BEGIN");
        try {
            const topic = this.#get("SELECT head FROM murmur_relay_topics WHERE id = ?", topicId);
            if (topic === undefined) {
                this.#database.exec("COMMIT");
                return { events: [], head: 0n, exhausted: true };
            }
            const rows = this.#all(
                SQLITE_READ_EVENTS_QUERY,
                topicId,
                since,
                BigInt(now),
                BigInt(limit + 1),
            );
            const selection = selectEventPageMetadata(
                rows.map(
                    (row): StoredPageCandidate => ({
                        seq: bigintColumn(row.seq),
                        encodedBytes: safeNumberColumn(row.encoded_bytes),
                    }),
                ),
                bigintColumn(topic.head),
                limit,
                constraints,
            );
            const hydrated =
                selection.candidates.length === 0
                    ? []
                    : this.#all(
                          sqliteHydrateEventsQuery(selection.candidates.length),
                          topicId,
                          ...selection.candidates.map(({ seq }) => seq),
                      );
            if (hydrated.length !== selection.candidates.length) {
                throw new Error("SQLite relay hydration did not match selected events");
            }
            const events = hydrated.map((row, index): RetainedRelayEvent => {
                const seq = bigintColumn(row.seq);
                if (seq !== selection.candidates[index]!.seq) {
                    throw new Error("SQLite relay hydration order is inconsistent");
                }
                const eventJson = textColumn(row.event_json, "event JSON");
                this.#instrumentation?.eventJsonHydrated(seq);
                return {
                    seq,
                    event: parseSignedRelayEvent(JSON.parse(eventJson) as unknown),
                };
            });
            const page: EventPage = {
                events,
                head: selection.head,
                exhausted: selection.exhausted,
            };
            this.#database.exec("COMMIT");
            return page;
        } catch (error) {
            this.#rollback();
            throw error;
        }
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
