import {
    RelayError,
    parseSignedRelayEvent,
    relayEventFingerprint,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { bigintColumn, copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import { encodeStoredRelayEvent, selectEventPage, type StoredPageCandidate } from "../page.js";
import type {
    EventPage,
    PageReadConstraints,
    PublishOutcome,
    PublishReceipt,
    RelayStore,
    StoredReadChallenge,
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

/** Bounded retained-candidate query kept visible for query-plan regression tests. */
export const POSTGRES_READ_EVENTS_QUERY = `
    SELECT seq, event_json, encoded_bytes
    FROM murmur_relay_events
    WHERE topic_id = $1 AND seq > $2
      AND (expires_at IS NULL OR expires_at > $3)
    ORDER BY seq
    LIMIT $4`;

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

    async issueReadChallenge(
        challenge: StoredReadChallenge,
        now: number,
        maximumOutstanding: number,
    ): Promise<boolean> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const stateResult = await transaction.query<{ outstanding: unknown }>(
                `SELECT outstanding FROM murmur_relay_challenge_state
                 WHERE singleton = 1 FOR UPDATE`,
            );
            const state = stateResult.rows[0];
            if (state === undefined) throw new Error("Missing challenge state");
            const deleted = await transaction.query<{ id: unknown }>(
                `DELETE FROM murmur_relay_read_challenges
                 WHERE expires_at <= $1 RETURNING id`,
                [now.toString()],
            );
            const outstanding = bigintColumn(state.outstanding) - BigInt(deleted.rows.length);
            const normalized = outstanding < 0n ? 0n : outstanding;
            await transaction.query(
                `UPDATE murmur_relay_challenge_state
                 SET outstanding = $1 WHERE singleton = 1`,
                [normalized.toString()],
            );
            if (normalized >= BigInt(maximumOutstanding)) return false;
            await transaction.query(
                `INSERT INTO murmur_relay_read_challenges
                    (id, topic_id, nonce, expires_at)
                 VALUES ($1, $2, $3, $4)`,
                [challenge.id, challenge.topicId, challenge.nonce, challenge.expiresAt.toString()],
            );
            await transaction.query(
                `UPDATE murmur_relay_challenge_state
                 SET outstanding = outstanding + 1 WHERE singleton = 1`,
            );
            return true;
        });
    }

    async consumeReadChallenge(id: string, now: number): Promise<StoredReadChallenge | undefined> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                `SELECT outstanding FROM murmur_relay_challenge_state
                 WHERE singleton = 1 FOR UPDATE`,
            );
            const result = await transaction.query<{
                id: unknown;
                topic_id: unknown;
                nonce: unknown;
                expires_at: unknown;
            }>(
                `DELETE FROM murmur_relay_read_challenges
                 WHERE id = $1
                 RETURNING id, topic_id, nonce, expires_at`,
                [id],
            );
            const row = result.rows[0];
            if (row === undefined) return undefined;
            await transaction.query(
                `UPDATE murmur_relay_challenge_state
                 SET outstanding = GREATEST(0, outstanding - 1)
                 WHERE singleton = 1`,
            );
            const expiresAt = safeNumberColumn(row.expires_at);
            if (expiresAt <= now) return undefined;
            if (typeof row.id !== "string" || typeof row.topic_id !== "string") {
                throw new Error("Invalid stored read challenge");
            }
            return {
                id: row.id,
                topicId: row.topic_id,
                nonce: copyBytes(row.nonce, "challenge nonce"),
                expiresAt,
            };
        });
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
                    `DELETE FROM murmur_relay_events
                     WHERE topic_id = $1 AND author_signing_key = $2 AND collapse_key = $3`,
                    [topicId, event.author.signingKey, event.collapseKey],
                );
            }
            const encoded = encodeStoredRelayEvent(event);
            await transaction.query(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)`,
                [
                    topicId,
                    seq.toString(),
                    encoded.json,
                    encoded.encodedBytes,
                    event.expiresAt?.toString() ?? null,
                    event.author.signingKey,
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
                encoded_bytes: unknown;
            }>(POSTGRES_READ_EVENTS_QUERY, [topicId, since.toString(), now.toString(), limit + 1]);
            return selectEventPage(
                result.rows.map(
                    (row): StoredPageCandidate => ({
                        seq: bigintColumn(row.seq),
                        event: parseSignedRelayEvent(jsonValue(row.event_json)),
                        encodedBytes: safeNumberColumn(row.encoded_bytes),
                    }),
                ),
                bigintColumn(topic.head),
                limit,
                constraints,
            );
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
