import { sha256 } from "@noble/hashes/sha2";
import {
    RelayError,
    parseSignedRelayEvent,
    relayEventFingerprint,
    signedRelayEventToJson,
    type RelayBlob,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { decodeBase64Url } from "../../utils/base64Url.js";
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
import type { PostgresDatabase, PostgresParameter, PostgresQuery } from "./database.js";
import { migratePostgresRelay } from "./migrations.js";

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

/** Shared LISTEN/NOTIFY channel used by Postgres stores and wake sources. */
export const POSTGRES_WAKE_CHANNEL = "murmur_relay_wake_v1";

const EVENT_PRUNE_LOCK = "5570743552625583470";
const TOPIC_PRUNE_LOCK = "5570743552625583471";

interface TopicRow extends Record<string, unknown> {
    readonly seq: unknown;
    readonly snapshot_version: unknown;
    readonly next_position: unknown;
    readonly element_count: unknown;
}

interface EventIdentityRow extends Record<string, unknown> {
    readonly seq: unknown;
    readonly fingerprint: unknown;
    readonly snapshot_version: unknown;
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name} in Postgres relay store`);
    }
    return value;
}

function nullableBigInt(value: unknown): bigint | undefined {
    return value === null ? undefined : bigintColumn(value);
}

function booleanColumn(value: unknown, name: string): boolean {
    if (typeof value !== "boolean") {
        throw new Error(`Invalid ${name} in Postgres relay store`);
    }
    return value;
}

function asJsonValue(value: unknown): unknown {
    if (typeof value === "string") {
        return JSON.parse(value) as unknown;
    }
    return value;
}

/** Shared Postgres implementation correct under concurrent publishers and instances. */
export class PostgresRelayStore implements RelayStore {
    readonly #database: PostgresDatabase;
    #closed = false;

    private constructor(database: PostgresDatabase) {
        this.#database = database;
    }

    /** Create a Postgres store after applying advisory-locked versioned migrations. */
    static async create(database: PostgresDatabase): Promise<PostgresRelayStore> {
        const store = new PostgresRelayStore(database);
        await migratePostgresRelay(database);
        return store;
    }

    /** Read one committed idempotency receipt without considering event age. */
    async readPublishReceipt(topic: string, id: string): Promise<PublishReceipt | undefined> {
        this.#assertOpen();
        const result = await this.#database.query<EventIdentityRow>(
            `SELECT seq, fingerprint, snapshot_version
             FROM murmur_relay_event_receipts
             WHERE topic = $1 AND id = $2`,
            [topic, id],
        );
        const row = result.rows[0];
        return row === undefined ? undefined : this.#receiptFromRow(row);
    }

    /** Publish under a per-topic advisory lock with a gapless topic sequence. */
    async publish(
        event: SignedRelayEvent,
        now: number,
        constraints: PublishConstraints,
    ): Promise<PublishOutcome> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
                event.topic,
            ]);
            await transaction.query(
                `INSERT INTO murmur_relay_topics (
                    id, seq, oldest_retained_seq, snapshot_version,
                    next_position, element_count, last_activity_at
                 ) VALUES ($1, 0, 1, 0, 0, 0, $2)
                 ON CONFLICT (id) DO NOTHING`,
                [event.topic, now.toString()],
            );
            const topicResult = await transaction.query<TopicRow>(
                `SELECT seq, snapshot_version, next_position, element_count
                 FROM murmur_relay_topics
                 WHERE id = $1`,
                [event.topic],
            );
            const topic = topicResult.rows[0];
            if (topic === undefined) {
                throw new Error("Missing locked topic in Postgres relay store");
            }

            const fingerprint = relayEventFingerprint(event);
            const seq = bigintColumn(topic.seq) + 1n;
            const candidateSnapshotVersion =
                event.snapshot === undefined
                    ? undefined
                    : bigintColumn(topic.snapshot_version) + 1n;
            const insertion = await transaction.query<{ seq: unknown }>(
                `INSERT INTO murmur_relay_event_receipts (
                    topic, id, seq, fingerprint, snapshot_version
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (topic, id) DO NOTHING
                 RETURNING seq`,
                [
                    event.topic,
                    event.id,
                    seq.toString(),
                    fingerprint,
                    candidateSnapshotVersion?.toString() ?? null,
                ],
            );
            if (insertion.rows.length === 0) {
                const existingResult = await transaction.query<EventIdentityRow>(
                    `SELECT seq, fingerprint, snapshot_version
                     FROM murmur_relay_event_receipts
                     WHERE topic = $1 AND id = $2`,
                    [event.topic, event.id],
                );
                const existing = existingResult.rows[0];
                if (existing === undefined) {
                    throw new Error("Missing duplicate event in Postgres relay store");
                }
                if (
                    !equalBytes(copyBytes(existing.fingerprint, "event fingerprint"), fingerprint)
                ) {
                    throw new RelayError(409, "Event identifier collision", {
                        error: "id_collision",
                    });
                }
                const receipt = this.#receiptFromRow(existing);
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

            const existingElements = await this.#readExistingElements(transaction, event);
            const snapshotResult = await transaction.query<{ version: unknown }>(
                "SELECT version FROM murmur_relay_snapshots WHERE topic = $1",
                [event.topic],
            );
            const snapshotGeneration = bigintColumn(topic.snapshot_version);
            const plan = planEventMutations(
                event,
                snapshotResult.rows[0] === undefined
                    ? undefined
                    : bigintColumn(snapshotResult.rows[0].version),
                snapshotGeneration,
                existingElements,
                bigintColumn(topic.element_count),
                bigintColumn(topic.next_position),
                constraints.maximumElementsPerTopic,
            );

            if (event.snapshot !== undefined && plan.snapshotVersion !== undefined) {
                if (event.snapshot.bytes === undefined) {
                    await transaction.query("DELETE FROM murmur_relay_snapshots WHERE topic = $1", [
                        event.topic,
                    ]);
                } else {
                    await transaction.query(
                        `INSERT INTO murmur_relay_snapshots (topic, version, seq, bytes)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (topic) DO UPDATE SET
                            version = excluded.version,
                            seq = excluded.seq,
                            bytes = excluded.bytes`,
                        [
                            event.topic,
                            plan.snapshotVersion.toString(),
                            seq.toString(),
                            event.snapshot.bytes,
                        ],
                    );
                }
            }

            for (const action of plan.listActions) {
                if (action.op === "append") {
                    await transaction.query(
                        `INSERT INTO murmur_relay_list_elements
                            (topic, id, version, position, seq, bytes)
                         VALUES ($1, $2, $3, $4, $5, $6)`,
                        [
                            event.topic,
                            action.id,
                            action.version.toString(),
                            action.position.toString(),
                            seq.toString(),
                            action.bytes,
                        ],
                    );
                } else if (action.op === "replace") {
                    await transaction.query(
                        `UPDATE murmur_relay_list_elements
                         SET version = $1, seq = $2, bytes = $3
                         WHERE topic = $4 AND id = $5`,
                        [
                            action.version.toString(),
                            seq.toString(),
                            action.bytes,
                            event.topic,
                            action.id,
                        ],
                    );
                } else {
                    await transaction.query(
                        `DELETE FROM murmur_relay_list_elements
                         WHERE topic = $1 AND id = $2`,
                        [event.topic, action.id],
                    );
                }
            }

            await transaction.query(
                `UPDATE murmur_relay_topics
                 SET seq = $1, snapshot_version = $2, next_position = $3,
                     element_count = $4, last_activity_at = $5
                 WHERE id = $6`,
                [
                    seq.toString(),
                    (plan.snapshotVersion ?? snapshotGeneration).toString(),
                    plan.nextPosition.toString(),
                    plan.elementCount.toString(),
                    now.toString(),
                    event.topic,
                ],
            );
            await transaction.query(
                `INSERT INTO murmur_relay_events (
                    topic, seq, id, fingerprint, event_json, observed_at, snapshot_version
                 ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
                [
                    event.topic,
                    seq.toString(),
                    event.id,
                    fingerprint,
                    JSON.stringify(signedRelayEventToJson(event)),
                    now.toString(),
                    plan.snapshotVersion?.toString() ?? null,
                ],
            );
            await transaction.query(`SELECT pg_notify('${POSTGRES_WAKE_CHANNEL}', $1)`, [
                event.topic,
            ]);
            if (plan.snapshotVersion === undefined) {
                return { seq, duplicate: false };
            }
            return {
                seq,
                duplicate: false,
                snapshotVersion: plan.snapshotVersion,
            };
        });
    }

    /** Read the topic head, snapshot, and initial list page from one MVCC snapshot. */
    async readState(
        topic: string,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<TopicState | undefined> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const topicResult = await transaction.query<{ seq: unknown }>(
                "SELECT seq FROM murmur_relay_topics WHERE id = $1",
                [topic],
            );
            const topicRow = topicResult.rows[0];
            if (topicRow === undefined) {
                return undefined;
            }
            const snapshotResult = await transaction.query<{
                version: unknown;
                seq: unknown;
                bytes: unknown;
            }>(
                `SELECT version, seq, bytes
                 FROM murmur_relay_snapshots
                 WHERE topic = $1`,
                [topic],
            );
            const snapshotRow = snapshotResult.rows[0];
            return {
                seq: bigintColumn(topicRow.seq),
                snapshot: snapshotRow === undefined ? null : this.#snapshotFromRow(snapshotRow),
                list: await this.#readListPage(
                    transaction,
                    topic,
                    0n,
                    limit,
                    constraints.maximumEncodedBytes,
                ),
            };
        }, "repeatable read");
    }

    /** Read one ordered list page after an opaque position cursor. */
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
        return this.#database.transaction(async (transaction) => {
            const topicResult = await transaction.query<{ present: unknown }>(
                "SELECT 1 AS present FROM murmur_relay_topics WHERE id = $1",
                [topic],
            );
            if (topicResult.rows.length === 0) {
                return undefined;
            }
            return this.#readListPage(
                transaction,
                topic,
                position,
                limit,
                constraints.maximumEncodedBytes,
            );
        }, "repeatable read");
    }

    /** Read retained events or return reset without ever hiding a pruned gap. */
    async readEvents(
        topic: string,
        since: bigint,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage | undefined> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const topicResult = await transaction.query<{
                seq: unknown;
                oldest_retained_seq: unknown;
            }>(
                `SELECT seq, oldest_retained_seq
                 FROM murmur_relay_topics
                 WHERE id = $1`,
                [topic],
            );
            const topicRow = topicResult.rows[0];
            if (topicRow === undefined) {
                return undefined;
            }
            const seq = bigintColumn(topicRow.seq);
            const oldestRetainedSeq = bigintColumn(topicRow.oldest_retained_seq);
            if (since > seq || since < oldestRetainedSeq - 1n) {
                return { events: [], reset: true, seq };
            }
            const result = await transaction.query<{
                seq: unknown;
                event_json: unknown;
            }>(
                `WITH candidates AS (
                    SELECT seq, event_json,
                        ROW_NUMBER() OVER (ORDER BY seq) AS row_number,
                        SUM(OCTET_LENGTH(event_json::text) + 64) OVER (
                            ORDER BY seq ROWS UNBOUNDED PRECEDING
                        ) AS cumulative_bytes
                    FROM murmur_relay_events
                    WHERE topic = $1 AND seq > $2
                 )
                 SELECT seq, event_json
                 FROM candidates
                 WHERE row_number = 1 OR cumulative_bytes <= $3
                 ORDER BY seq
                 LIMIT $4`,
                [topic, since.toString(), constraints.maximumEncodedBytes.toString(), limit],
            );
            const events = result.rows.map(
                (row): RetainedRelayEvent => ({
                    seq: bigintColumn(row.seq),
                    event: parseSignedRelayEvent(asJsonValue(row.event_json)),
                }),
            );
            return { events, reset: false, seq };
        }, "repeatable read");
    }

    /** Insert a valid content-addressed blob using race-safe idempotency. */
    async putBlob(blob: RelayBlob): Promise<void> {
        this.#assertOpen();
        let identifier: Uint8Array;
        try {
            identifier = decodeBase64Url(blob.id, 32);
        } catch {
            throw new RelayError(400, "Invalid blob identifier", { error: "malformed" });
        }
        if (!equalBytes(identifier, sha256(blob.bytes))) {
            throw new RelayError(400, "Blob hash mismatch", { error: "hash_mismatch" });
        }
        await this.#database.transaction(async (transaction) => {
            const insertion = await transaction.query<{ id: string }>(
                `INSERT INTO murmur_relay_blobs (id, bytes)
                 VALUES ($1, $2)
                 ON CONFLICT (id) DO NOTHING
                 RETURNING id`,
                [blob.id, blob.bytes],
            );
            if (insertion.rows.length > 0) {
                return;
            }
            const existingResult = await transaction.query<{ bytes: unknown }>(
                "SELECT bytes FROM murmur_relay_blobs WHERE id = $1",
                [blob.id],
            );
            const existing = existingResult.rows[0];
            if (
                existing === undefined ||
                !equalBytes(copyBytes(existing.bytes, "blob"), blob.bytes)
            ) {
                throw new RelayError(409, "Blob identifier collision", {
                    error: "id_collision",
                });
            }
        });
    }

    /** Fetch an isolated copy of one permanent ciphertext blob. */
    async getBlob(id: string): Promise<RelayBlob | undefined> {
        this.#assertOpen();
        const result = await this.#database.query<{ bytes: unknown }>(
            "SELECT bytes FROM murmur_relay_blobs WHERE id = $1",
            [id],
        );
        const row = result.rows[0];
        return row === undefined ? undefined : { id, bytes: copyBytes(row.bytes, "blob") };
    }

    /** Prune expired event rows under a cluster-wide try-lock and advance watermarks. */
    async pruneEvents(olderThan: number): Promise<number> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            if (!(await this.#tryPruneLock(transaction, EVENT_PRUNE_LOCK))) {
                return 0;
            }
            const result = await transaction.query<{ deleted_count: unknown }>(
                `WITH deleted AS (
                    DELETE FROM murmur_relay_events
                    WHERE observed_at < $1
                    RETURNING topic, seq
                ),
                watermarks AS (
                    SELECT topic, MAX(seq) + 1 AS oldest
                    FROM deleted
                    GROUP BY topic
                ),
                updated AS (
                    UPDATE murmur_relay_topics AS topics
                    SET oldest_retained_seq =
                        GREATEST(topics.oldest_retained_seq, watermarks.oldest)
                    FROM watermarks
                    WHERE topics.id = watermarks.topic
                    RETURNING topics.id
                )
                SELECT COUNT(*) AS deleted_count FROM deleted`,
                [olderThan.toString()],
            );
            const row = result.rows[0];
            if (row === undefined) {
                throw new Error("Missing event prune result");
            }
            return safeNumberColumn(row.deleted_count);
        });
    }

    /** Drop inactive topics under a cluster-wide try-lock. */
    async pruneInactiveTopics(olderThan: number): Promise<PruneResult> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            if (!(await this.#tryPruneLock(transaction, TOPIC_PRUNE_LOCK))) {
                return { topics: 0 };
            }
            const result = await transaction.query<{ topic_count: unknown }>(
                `WITH deleted AS (
                    DELETE FROM murmur_relay_topics
                    WHERE last_activity_at < $1
                    RETURNING id
                )
                SELECT COUNT(*) AS topic_count FROM deleted`,
                [olderThan.toString()],
            );
            const row = result.rows[0];
            if (row === undefined) {
                throw new Error("Missing topic prune result");
            }
            return { topics: safeNumberColumn(row.topic_count) };
        });
    }

    /** Confirm the shared database can execute a query. */
    async health(): Promise<void> {
        this.#assertOpen();
        await this.#database.query("SELECT 1 AS healthy");
    }

    /** Close the owned database adapter once. */
    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            await this.#database.close();
        }
    }

    async #readExistingElements(
        transaction: PostgresQuery,
        event: SignedRelayEvent,
    ): Promise<Map<string, ExistingElement>> {
        const ids = [...new Set((event.list ?? []).map((operation) => operation.id))];
        if (ids.length === 0) {
            return new Map();
        }
        const placeholders = ids.map((_, index) => `$${index + 2}`).join(", ");
        const parameters: PostgresParameter[] = [event.topic, ...ids];
        const result = await transaction.query<{ id: unknown; version: unknown }>(
            `SELECT id, version
             FROM murmur_relay_list_elements
             WHERE topic = $1 AND id IN (${placeholders})`,
            parameters,
        );
        return new Map(
            result.rows.map((row) => [
                textColumn(row.id, "element id"),
                { version: bigintColumn(row.version) },
            ]),
        );
    }

    async #readListPage(
        query: PostgresQuery,
        topic: string,
        after: bigint,
        limit: number,
        maximumEncodedBytes: number,
    ): Promise<ListPage> {
        const result = await query.query<{
            id: unknown;
            version: unknown;
            position: unknown;
            seq: unknown;
            bytes: unknown;
            row_number: unknown;
            available_count: unknown;
        }>(
            `WITH candidates AS (
                SELECT id, version, position, seq, bytes,
                    ROW_NUMBER() OVER (ORDER BY position) AS row_number,
                    COUNT(*) OVER () AS available_count,
                    SUM(
                        ((OCTET_LENGTH(bytes) * 4 + 2) / 3) +
                        OCTET_LENGTH(id) + 128
                    ) OVER (
                        ORDER BY position ROWS UNBOUNDED PRECEDING
                    ) AS cumulative_bytes
                FROM murmur_relay_list_elements
                WHERE topic = $1 AND position > $2
             )
             SELECT id, version, position, seq, bytes, row_number, available_count
             FROM candidates
             WHERE row_number = 1 OR cumulative_bytes <= $3
             ORDER BY position
             LIMIT $4`,
            [topic, after.toString(), maximumEncodedBytes.toString(), limit],
        );
        const lastRow = result.rows.at(-1);
        const hasMore =
            lastRow !== undefined &&
            bigintColumn(lastRow.row_number) < bigintColumn(lastRow.available_count);
        const elements = result.rows.map((row): ListElement => this.#elementFromRow(row));
        const last = elements.at(-1);
        return {
            elements,
            nextCursor: hasMore && last !== undefined ? encodeListCursor(last.position) : null,
        };
    }

    #snapshotFromRow(row: {
        readonly version: unknown;
        readonly seq: unknown;
        readonly bytes: unknown;
    }): TopicSnapshot {
        return {
            version: bigintColumn(row.version),
            seq: bigintColumn(row.seq),
            bytes: copyBytes(row.bytes, "snapshot"),
        };
    }

    #receiptFromRow(row: EventIdentityRow): PublishReceipt {
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

    #elementFromRow(row: {
        readonly id: unknown;
        readonly version: unknown;
        readonly position: unknown;
        readonly seq: unknown;
        readonly bytes: unknown;
    }): ListElement {
        return {
            id: textColumn(row.id, "element id"),
            version: bigintColumn(row.version),
            position: bigintColumn(row.position),
            seq: bigintColumn(row.seq),
            bytes: copyBytes(row.bytes, "list element"),
        };
    }

    async #tryPruneLock(transaction: PostgresQuery, lock: string): Promise<boolean> {
        const result = await transaction.query<{ locked: unknown }>(
            "SELECT pg_try_advisory_xact_lock($1::bigint) AS locked",
            [lock],
        );
        const row = result.rows[0];
        if (row === undefined) {
            throw new Error("Missing Postgres advisory lock result");
        }
        return booleanColumn(row.locked, "advisory lock result");
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Postgres relay store is closed");
        }
    }
}
