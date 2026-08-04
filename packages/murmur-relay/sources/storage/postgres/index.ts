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
import type { PostgresDatabase } from "./database.js";
import { createPostgresRelaySchema } from "./migrations.js";

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

/** Shared LISTEN/NOTIFY channel used only to reduce long-poll latency. */
export const POSTGRES_WAKE_CHANNEL = "murmur_relay_wake_v2";

function jsonValue(value: unknown): unknown {
    return typeof value === "string" ? (JSON.parse(value) as unknown) : value;
}

/** Fresh-schema Postgres/PGlite ordered event store. */
export class PostgresRelayStore implements RelayStore {
    readonly #database: PostgresDatabase;
    #closed = false;

    private constructor(database: PostgresDatabase) {
        this.#database = database;
    }

    /** Create the clean schema and store. */
    static async create(database: PostgresDatabase): Promise<PostgresRelayStore> {
        await createPostgresRelaySchema(database);
        return new PostgresRelayStore(database);
    }

    async readPublishReceipt(topicId: string, id: string): Promise<PublishReceipt | undefined> {
        this.#assertOpen();
        const result = await this.#database.query<{ seq: unknown; fingerprint: unknown }>(
            "SELECT seq, fingerprint FROM murmur_relay_receipts WHERE topic_id = $1 AND id = $2",
            [topicId, id],
        );
        const row = result.rows[0];
        return row === undefined
            ? undefined
            : {
                  seq: bigintColumn(row.seq),
                  fingerprint: copyBytes(row.fingerprint, "event fingerprint"),
              };
    }

    async publish(event: SignedRelayEvent, topicId: string, _now: number): Promise<PublishOutcome> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
                topicId,
            ]);
            await transaction.query(
                "INSERT INTO murmur_relay_topics (id, head) VALUES ($1, 0) ON CONFLICT DO NOTHING",
                [topicId],
            );
            const fingerprint = relayEventFingerprint(event);
            const existing = await transaction.query<{ seq: unknown; fingerprint: unknown }>(
                "SELECT seq, fingerprint FROM murmur_relay_receipts WHERE topic_id = $1 AND id = $2",
                [topicId, event.id],
            );
            const duplicate = existing.rows[0];
            if (duplicate !== undefined) {
                if (!equalBytes(copyBytes(duplicate.fingerprint, "fingerprint"), fingerprint)) {
                    throw new RelayError(409, "Event identifier collision", {
                        error: "id_collision",
                    });
                }
                return { seq: bigintColumn(duplicate.seq), duplicate: true };
            }
            const headResult = await transaction.query<{ head: unknown }>(
                "SELECT head FROM murmur_relay_topics WHERE id = $1",
                [topicId],
            );
            const head = headResult.rows[0];
            if (head === undefined) {
                throw new Error("Missing locked relay topic");
            }
            const seq = bigintColumn(head.head) + 1n;
            await transaction.query("UPDATE murmur_relay_topics SET head = $1 WHERE id = $2", [
                seq.toString(),
                topicId,
            ]);
            if (event.collapseKey !== undefined) {
                await transaction.query(
                    "DELETE FROM murmur_relay_events WHERE topic_id = $1 AND collapse_key = $2",
                    [topicId, event.collapseKey],
                );
            }
            await transaction.query(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, expires_at, collapse_key)
                 VALUES ($1, $2, $3::jsonb, $4, $5)`,
                [
                    topicId,
                    seq.toString(),
                    JSON.stringify(signedRelayEventToJson(event)),
                    event.expiresAt?.toString() ?? null,
                    event.collapseKey ?? null,
                ],
            );
            await transaction.query(
                `INSERT INTO murmur_relay_receipts (topic_id, id, seq, fingerprint)
                 VALUES ($1, $2, $3, $4)`,
                [topicId, event.id, seq.toString(), fingerprint],
            );
            await transaction.query(`SELECT pg_notify('${POSTGRES_WAKE_CHANNEL}', $1)`, [topicId]);
            return { seq, duplicate: false };
        });
    }

    async readEvents(
        topicId: string,
        since: bigint,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const topicResult = await transaction.query<{ head: unknown }>(
                "SELECT head FROM murmur_relay_topics WHERE id = $1",
                [topicId],
            );
            const topic = topicResult.rows[0];
            if (topic === undefined) {
                return { events: [], head: 0n, exhausted: true };
            }
            const result = await transaction.query<{
                seq: unknown;
                event_json: unknown;
                row_number: unknown;
                available_count: unknown;
            }>(
                `WITH candidates AS (
                    SELECT seq, event_json,
                        ROW_NUMBER() OVER (ORDER BY seq) AS row_number,
                        COUNT(*) OVER () AS available_count,
                        SUM(OCTET_LENGTH(event_json::text) + 64) OVER (
                            ORDER BY seq ROWS UNBOUNDED PRECEDING
                        ) AS cumulative_bytes
                    FROM murmur_relay_events
                    WHERE topic_id = $1 AND seq > $2
                      AND (expires_at IS NULL OR expires_at > $3)
                 )
                 SELECT seq, event_json, row_number, available_count FROM candidates
                 WHERE row_number = 1 OR cumulative_bytes <= $4
                 ORDER BY seq LIMIT $5`,
                [
                    topicId,
                    since.toString(),
                    now.toString(),
                    constraints.maximumEncodedBytes.toString(),
                    limit,
                ],
            );
            return {
                events: result.rows.map(
                    (row): RetainedRelayEvent => ({
                        seq: bigintColumn(row.seq),
                        event: parseSignedRelayEvent(jsonValue(row.event_json)),
                    }),
                ),
                head: bigintColumn(topic.head),
                exhausted:
                    result.rows.length === 0 ||
                    bigintColumn(result.rows.at(-1)!.row_number) ===
                        bigintColumn(result.rows.at(-1)!.available_count),
            };
        }, "repeatable read");
    }

    async pruneExpired(now: number): Promise<number> {
        this.#assertOpen();
        const result = await this.#database.query<{ count: unknown }>(
            `WITH deleted AS (
                DELETE FROM murmur_relay_events
                WHERE expires_at IS NOT NULL AND expires_at <= $1
                RETURNING seq
             ) SELECT COUNT(*) AS count FROM deleted`,
            [now.toString()],
        );
        const row = result.rows[0];
        if (row === undefined) {
            throw new Error("Missing expiration prune result");
        }
        return safeNumberColumn(row.count);
    }

    async health(): Promise<void> {
        this.#assertOpen();
        await this.#database.query("SELECT 1 AS healthy");
    }

    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            await this.#database.close();
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Postgres relay store is closed");
        }
    }
}
