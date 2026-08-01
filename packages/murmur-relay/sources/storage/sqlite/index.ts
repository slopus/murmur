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
import { decodeListCursor, encodeListCursor } from "../../utils/cursor.js";
import { planEventMutations, type ExistingElement } from "../impl/eventPlan.js";
import type {
    EventPage,
    ListElement,
    ListPage,
    PageReadConstraints,
    PruneResult,
    PublishConstraints,
    PublishOutcome,
    PublishReceipt,
    RelayStore,
    RetainedRelayEvent,
    TopicSnapshot,
    TopicState,
} from "../types.js";

/** SQLite store construction options for embedding. */
export interface SqliteRelayStoreOptions {
    /** Open an already-created database, primarily for embedding and tests. */
    readonly database?: DatabaseSync;
}

function record(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name} row in SQLite relay store`);
    }
    return value as Record<string, unknown>;
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name} in SQLite relay store`);
    }
    return value;
}

function nullableBigInt(value: unknown): bigint | undefined {
    return value === null ? undefined : bigintColumn(value);
}

/** Durable SQLite implementation with gapless per-topic sequencing and atomic mutations. */
export class SqliteRelayStore implements RelayStore {
    readonly #database: DatabaseSync;
    #closed = false;

    constructor(path: string, options: SqliteRelayStoreOptions = {}) {
        this.#database = options.database ?? new DatabaseSync(path);
        try {
            this.#database.exec("PRAGMA journal_mode = WAL");
            this.#database.exec("PRAGMA foreign_keys = ON");
            this.#migrate();
        } catch (error) {
            this.#database.close();
            throw error;
        }
    }

    /** Read one committed idempotency receipt without considering event age. */
    async readPublishReceipt(topic: string, id: string): Promise<PublishReceipt | undefined> {
        this.#assertOpen();
        const row = this.#get(
            `SELECT seq, fingerprint, snapshot_version
             FROM murmur_relay_event_receipts
             WHERE topic = ? AND id = ?`,
            topic,
            id,
        );
        return row === undefined ? undefined : this.#receiptFromRow(row);
    }

    /** Atomically allocate a topic sequence and apply one authenticated event. */
    async publish(
        event: SignedRelayEvent,
        now: number,
        constraints: PublishConstraints,
    ): Promise<PublishOutcome> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const fingerprint = relayEventFingerprint(event);
            const duplicateRow = this.#get(
                `SELECT seq, fingerprint, snapshot_version
                 FROM murmur_relay_event_receipts
                 WHERE topic = ? AND id = ?`,
                event.topic,
                event.id,
            );
            if (duplicateRow !== undefined) {
                if (
                    !equalBytes(
                        copyBytes(duplicateRow.fingerprint, "event fingerprint"),
                        fingerprint,
                    )
                ) {
                    throw new RelayError(409, "Event identifier collision", {
                        error: "id_collision",
                    });
                }
                const receipt = this.#receiptFromRow(duplicateRow);
                this.#database.exec("COMMIT");
                if (receipt.snapshotVersion === undefined) {
                    return {
                        seq: receipt.seq,
                        duplicate: true,
                    };
                }
                return {
                    seq: receipt.seq,
                    duplicate: true,
                    snapshotVersion: receipt.snapshotVersion,
                };
            }

            this.#run(
                `INSERT INTO murmur_relay_topics (
                    id, seq, oldest_retained_seq, snapshot_version,
                    next_position, element_count, last_activity_at
                ) VALUES (?, 0, 1, 0, 0, 0, ?)
                ON CONFLICT (id) DO NOTHING`,
                event.topic,
                BigInt(now),
            );
            const topic = this.#requiredGet(
                `SELECT seq, snapshot_version, next_position, element_count
                 FROM murmur_relay_topics
                 WHERE id = ?`,
                "topic",
                event.topic,
            );
            const existingElements = this.#readExistingElements(event);
            const snapshotRow = this.#get(
                "SELECT version FROM murmur_relay_snapshots WHERE topic = ?",
                event.topic,
            );
            const snapshotGeneration = bigintColumn(topic.snapshot_version);
            const plan = planEventMutations(
                event,
                snapshotRow === undefined ? undefined : bigintColumn(snapshotRow.version),
                snapshotGeneration,
                existingElements,
                bigintColumn(topic.element_count),
                bigintColumn(topic.next_position),
                constraints.maximumElementsPerTopic,
            );
            const seq = bigintColumn(topic.seq) + 1n;

            if (event.snapshot !== undefined && plan.snapshotVersion !== undefined) {
                if (event.snapshot.bytes === undefined) {
                    this.#run("DELETE FROM murmur_relay_snapshots WHERE topic = ?", event.topic);
                } else {
                    this.#run(
                        `INSERT INTO murmur_relay_snapshots (topic, version, seq, bytes)
                         VALUES (?, ?, ?, ?)
                         ON CONFLICT (topic) DO UPDATE SET
                            version = excluded.version,
                            seq = excluded.seq,
                            bytes = excluded.bytes`,
                        event.topic,
                        plan.snapshotVersion,
                        seq,
                        event.snapshot.bytes,
                    );
                }
            }

            for (const action of plan.listActions) {
                if (action.op === "append") {
                    this.#run(
                        `INSERT INTO murmur_relay_list_elements
                            (topic, id, version, position, seq, bytes)
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        event.topic,
                        action.id,
                        action.version,
                        action.position,
                        seq,
                        action.bytes,
                    );
                } else if (action.op === "replace") {
                    this.#run(
                        `UPDATE murmur_relay_list_elements
                         SET version = ?, seq = ?, bytes = ?
                         WHERE topic = ? AND id = ?`,
                        action.version,
                        seq,
                        action.bytes,
                        event.topic,
                        action.id,
                    );
                } else {
                    this.#run(
                        "DELETE FROM murmur_relay_list_elements WHERE topic = ? AND id = ?",
                        event.topic,
                        action.id,
                    );
                }
            }

            this.#run(
                `UPDATE murmur_relay_topics
                 SET seq = ?, snapshot_version = ?, next_position = ?,
                     element_count = ?, last_activity_at = ?
                 WHERE id = ?`,
                seq,
                plan.snapshotVersion ?? snapshotGeneration,
                plan.nextPosition,
                plan.elementCount,
                BigInt(now),
                event.topic,
            );
            this.#run(
                `INSERT INTO murmur_relay_event_receipts (
                    topic, id, seq, fingerprint, snapshot_version
                 ) VALUES (?, ?, ?, ?, ?)`,
                event.topic,
                event.id,
                seq,
                fingerprint,
                plan.snapshotVersion ?? null,
            );
            this.#run(
                `INSERT INTO murmur_relay_events (
                    topic, seq, id, fingerprint, event_json, observed_at, snapshot_version
                 ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                event.topic,
                seq,
                event.id,
                fingerprint,
                JSON.stringify(signedRelayEventToJson(event)),
                BigInt(now),
                plan.snapshotVersion ?? null,
            );
            this.#database.exec("COMMIT");
            if (plan.snapshotVersion === undefined) {
                return { seq, duplicate: false };
            }
            return {
                seq,
                duplicate: false,
                snapshotVersion: plan.snapshotVersion,
            };
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Read the topic head, snapshot, and first list page in one SQLite transaction. */
    async readState(
        topic: string,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<TopicState | undefined> {
        this.#assertOpen();
        this.#database.exec("BEGIN");
        try {
            const topicRow = this.#get("SELECT seq FROM murmur_relay_topics WHERE id = ?", topic);
            if (topicRow === undefined) {
                this.#database.exec("COMMIT");
                return undefined;
            }
            const snapshotRow = this.#get(
                `SELECT version, seq, bytes
                 FROM murmur_relay_snapshots
                 WHERE topic = ?`,
                topic,
            );
            const state: TopicState = {
                seq: bigintColumn(topicRow.seq),
                snapshot: snapshotRow === undefined ? null : this.#snapshotFromRow(snapshotRow),
                list: this.#readListPage(topic, 0n, limit, constraints.maximumEncodedBytes),
            };
            this.#database.exec("COMMIT");
            return state;
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Read a subsequent ordered list page after an opaque position cursor. */
    async readList(
        topic: string,
        cursor: string | undefined,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<ListPage | undefined> {
        this.#assertOpen();
        let position = 0n;
        if (cursor !== undefined) {
            try {
                position = decodeListCursor(cursor);
            } catch {
                throw new RelayError(400, "Invalid list cursor", { error: "malformed" });
            }
        }
        this.#database.exec("BEGIN");
        try {
            if (
                this.#get("SELECT 1 AS present FROM murmur_relay_topics WHERE id = ?", topic) ===
                undefined
            ) {
                this.#database.exec("COMMIT");
                return undefined;
            }
            const page = this.#readListPage(
                topic,
                position,
                limit,
                constraints.maximumEncodedBytes,
            );
            this.#database.exec("COMMIT");
            return page;
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Read a retained event page or demand reset when retention created a gap. */
    async readEvents(
        topic: string,
        since: bigint,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage | undefined> {
        this.#assertOpen();
        this.#database.exec("BEGIN");
        try {
            const topicRow = this.#get(
                `SELECT seq, oldest_retained_seq
                 FROM murmur_relay_topics
                 WHERE id = ?`,
                topic,
            );
            if (topicRow === undefined) {
                this.#database.exec("COMMIT");
                return undefined;
            }
            const seq = bigintColumn(topicRow.seq);
            const oldestRetainedSeq = bigintColumn(topicRow.oldest_retained_seq);
            if (since > seq || since < oldestRetainedSeq - 1n) {
                this.#database.exec("COMMIT");
                return { events: [], reset: true, seq };
            }
            const rows = this.#all(
                `WITH candidates AS (
                    SELECT seq, event_json,
                        ROW_NUMBER() OVER (ORDER BY seq) AS row_number,
                        SUM(LENGTH(event_json) + 64) OVER (
                            ORDER BY seq ROWS UNBOUNDED PRECEDING
                        ) AS cumulative_bytes
                    FROM murmur_relay_events
                    WHERE topic = ? AND seq > ?
                 )
                 SELECT seq, event_json
                 FROM candidates
                 WHERE row_number = 1 OR cumulative_bytes <= ?
                 ORDER BY seq
                 LIMIT ?`,
                topic,
                since,
                BigInt(constraints.maximumEncodedBytes),
                BigInt(limit),
            );
            const events = rows.map((row): RetainedRelayEvent => {
                const eventJson = textColumn(row.event_json, "event JSON");
                return {
                    seq: bigintColumn(row.seq),
                    event: parseSignedRelayEvent(JSON.parse(eventJson) as unknown),
                };
            });
            this.#database.exec("COMMIT");
            return { events, reset: false, seq };
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Delete expired event rows and advance every affected topic's reset watermark. */
    async pruneEvents(olderThan: number): Promise<number> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const watermarks = this.#all(
                `SELECT topic, MAX(seq) AS maximum_seq
                 FROM murmur_relay_events
                 WHERE observed_at < ?
                 GROUP BY topic`,
                BigInt(olderThan),
            );
            const deleted = this.#run(
                "DELETE FROM murmur_relay_events WHERE observed_at < ?",
                BigInt(olderThan),
            );
            for (const row of watermarks) {
                const topic = textColumn(row.topic, "topic");
                const oldest = bigintColumn(row.maximum_seq) + 1n;
                this.#run(
                    `UPDATE murmur_relay_topics
                     SET oldest_retained_seq = MAX(oldest_retained_seq, ?)
                     WHERE id = ?`,
                    oldest,
                    topic,
                );
            }
            this.#database.exec("COMMIT");
            return safeNumberColumn(deleted.changes);
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Drop all durable state for topics whose last successful publish is too old. */
    async pruneInactiveTopics(olderThan: number): Promise<PruneResult> {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const result = this.#run(
                "DELETE FROM murmur_relay_topics WHERE last_activity_at < ?",
                BigInt(olderThan),
            );
            this.#database.exec("COMMIT");
            return { topics: safeNumberColumn(result.changes) };
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    /** Confirm the SQLite connection can execute a query. */
    async health(): Promise<void> {
        this.#assertOpen();
        this.#requiredGet("SELECT 1 AS healthy", "health");
    }

    /** Close the owned SQLite connection once. */
    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            this.#database.close();
        }
    }

    #migrate(): void {
        this.#database.exec(`
            CREATE TABLE IF NOT EXISTS murmur_relay_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            ) STRICT
        `);
        const migration = this.#get(
            "SELECT version FROM murmur_relay_schema_migrations ORDER BY version DESC LIMIT 1",
        );
        const version = migration === undefined ? 0n : bigintColumn(migration.version);
        if (version > 2n) {
            throw new Error("SQLite relay schema is newer than this server");
        }
        if (version === 2n) {
            return;
        }
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            if (version < 1n) {
                this.#database.exec(`
                    CREATE TABLE murmur_relay_topics (
                        id TEXT PRIMARY KEY,
                        seq INTEGER NOT NULL CHECK (seq >= 0),
                        oldest_retained_seq INTEGER NOT NULL CHECK (oldest_retained_seq >= 1),
                        snapshot_version INTEGER NOT NULL CHECK (snapshot_version >= 0),
                        next_position INTEGER NOT NULL CHECK (next_position >= 0),
                        element_count INTEGER NOT NULL CHECK (element_count >= 0),
                        last_activity_at INTEGER NOT NULL
                    ) STRICT;

                    CREATE TABLE murmur_relay_snapshots (
                        topic TEXT PRIMARY KEY
                            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                        version INTEGER NOT NULL CHECK (version > 0),
                        seq INTEGER NOT NULL CHECK (seq > 0),
                        bytes BLOB NOT NULL
                    ) STRICT;

                    CREATE TABLE murmur_relay_list_elements (
                        topic TEXT NOT NULL
                            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        version INTEGER NOT NULL CHECK (version > 0),
                        position INTEGER NOT NULL CHECK (position > 0),
                        seq INTEGER NOT NULL CHECK (seq > 0),
                        bytes BLOB NOT NULL,
                        PRIMARY KEY (topic, id),
                        UNIQUE (topic, position)
                    ) STRICT;

                    CREATE TABLE murmur_relay_events (
                        topic TEXT NOT NULL
                            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                        seq INTEGER NOT NULL CHECK (seq > 0),
                        id TEXT NOT NULL,
                        fingerprint BLOB NOT NULL,
                        event_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL,
                        snapshot_version INTEGER,
                        PRIMARY KEY (topic, seq),
                        UNIQUE (topic, id)
                    ) STRICT;

                    CREATE INDEX murmur_relay_events_retention
                        ON murmur_relay_events(observed_at);

                `);
                this.#run(
                    `INSERT INTO murmur_relay_schema_migrations (version, applied_at)
                     VALUES (1, ?)`,
                    BigInt(Date.now()),
                );
            }
            if (version < 2n) {
                this.#database.exec(`
                    CREATE TABLE murmur_relay_event_receipts (
                        topic TEXT NOT NULL
                            REFERENCES murmur_relay_topics(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        seq INTEGER NOT NULL CHECK (seq > 0),
                        fingerprint BLOB NOT NULL,
                        snapshot_version INTEGER,
                        PRIMARY KEY (topic, id)
                    ) STRICT;

                    INSERT INTO murmur_relay_event_receipts (
                        topic, id, seq, fingerprint, snapshot_version
                    )
                    SELECT topic, id, seq, fingerprint, snapshot_version
                    FROM murmur_relay_events;
                `);
                this.#run(
                    `INSERT INTO murmur_relay_schema_migrations (version, applied_at)
                     VALUES (2, ?)`,
                    BigInt(Date.now()),
                );
            }
            this.#database.exec("COMMIT");
        } catch (error) {
            this.#rollback();
            throw error;
        }
    }

    #readExistingElements(event: SignedRelayEvent): Map<string, ExistingElement> {
        const elements = new Map<string, ExistingElement>();
        for (const id of new Set((event.list ?? []).map((operation) => operation.id))) {
            const row = this.#get(
                `SELECT version
                 FROM murmur_relay_list_elements
                 WHERE topic = ? AND id = ?`,
                event.topic,
                id,
            );
            if (row !== undefined) {
                elements.set(id, { version: bigintColumn(row.version) });
            }
        }
        return elements;
    }

    #readListPage(
        topic: string,
        after: bigint,
        limit: number,
        maximumEncodedBytes: number,
    ): ListPage {
        const rows = this.#all(
            `WITH candidates AS (
                SELECT id, version, position, seq, bytes,
                    ROW_NUMBER() OVER (ORDER BY position) AS row_number,
                    COUNT(*) OVER () AS available_count,
                    SUM(
                        ((LENGTH(bytes) * 4 + 2) / 3) + LENGTH(id) + 128
                    ) OVER (
                        ORDER BY position ROWS UNBOUNDED PRECEDING
                    ) AS cumulative_bytes
                FROM murmur_relay_list_elements
                WHERE topic = ? AND position > ?
             )
             SELECT id, version, position, seq, bytes, row_number, available_count
             FROM candidates
             WHERE row_number = 1 OR cumulative_bytes <= ?
             ORDER BY position
             LIMIT ?`,
            topic,
            after,
            BigInt(maximumEncodedBytes),
            BigInt(limit),
        );
        const lastRow = rows.at(-1);
        const hasMore =
            lastRow !== undefined &&
            bigintColumn(lastRow.row_number) < bigintColumn(lastRow.available_count);
        const elements = rows.map((row): ListElement => this.#elementFromRow(row));
        const last = elements.at(-1);
        return {
            elements,
            nextCursor: hasMore && last !== undefined ? encodeListCursor(last.position) : null,
        };
    }

    #snapshotFromRow(row: Record<string, unknown>): TopicSnapshot {
        return {
            version: bigintColumn(row.version),
            seq: bigintColumn(row.seq),
            bytes: copyBytes(row.bytes, "snapshot"),
        };
    }

    #receiptFromRow(row: Record<string, unknown>): PublishReceipt {
        const snapshotVersion = nullableBigInt(row.snapshot_version);
        if (snapshotVersion === undefined) {
            return {
                seq: bigintColumn(row.seq),
                fingerprint: copyBytes(row.fingerprint, "event fingerprint"),
            };
        }
        return {
            seq: bigintColumn(row.seq),
            fingerprint: copyBytes(row.fingerprint, "event fingerprint"),
            snapshotVersion,
        };
    }

    #elementFromRow(row: Record<string, unknown>): ListElement {
        return {
            id: textColumn(row.id, "element id"),
            version: bigintColumn(row.version),
            position: bigintColumn(row.position),
            seq: bigintColumn(row.seq),
            bytes: copyBytes(row.bytes, "list element"),
        };
    }

    #prepare(sql: string): StatementSync {
        const statement = this.#database.prepare(sql);
        statement.setReadBigInts(true);
        return statement;
    }

    #get(sql: string, ...values: SQLInputValue[]): Record<string, unknown> | undefined {
        const result = this.#prepare(sql).get(...values);
        return result === undefined ? undefined : record(result, "query");
    }

    #requiredGet(sql: string, name: string, ...values: SQLInputValue[]): Record<string, unknown> {
        const result = this.#get(sql, ...values);
        if (result === undefined) {
            throw new Error(`Missing ${name} row in SQLite relay store`);
        }
        return result;
    }

    #all(sql: string, ...values: SQLInputValue[]): Record<string, unknown>[] {
        return this.#prepare(sql)
            .all(...values)
            .map((value) => record(value, "query"));
    }

    #run(sql: string, ...values: SQLInputValue[]): StatementResultingChanges {
        return this.#prepare(sql).run(...values);
    }

    #rollback(): void {
        try {
            this.#database.exec("ROLLBACK");
        } catch {
            // The original error is more useful when SQLite already ended the transaction.
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("SQLite relay store is closed");
        }
    }
}
