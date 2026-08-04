import { PGlite } from "@electric-sql/pglite";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, test } from "vitest";
import {
    relayEventSigningBytes,
    relayTopicId,
    signedRelayEventToJson,
    type RelayTopic,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import {
    parseRelayStoreBackend,
    PGliteDatabase,
    PostgresRelayStore,
    SqliteRelayStore,
    type RelayStore,
} from "../index.js";
import { postgresHydrateEventsQuery, POSTGRES_READ_EVENTS_QUERY } from "../postgres/index.js";
import { sqliteHydrateEventsQuery, SQLITE_READ_EVENTS_QUERY } from "../sqlite/index.js";

const NOW = 5_000;
const MAXIMUM_PAGE_BYTES = 2 * 1024 * 1024;

function signed(
    secretKey: Uint8Array,
    topic: RelayTopic,
    payload: number,
    collapseKey?: Uint8Array,
): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(randomBytes(32)),
        topic,
        author: { signingKey: ed25519.getPublicKey(secretKey) },
        createdAt: NOW,
        ...(collapseKey === undefined ? {} : { collapseKey }),
        payload: new Uint8Array([payload]),
        signature: new Uint8Array(64),
    };
    return { ...unsigned, signature: ed25519.sign(relayEventSigningBytes(unsigned), secretKey) };
}

async function stores(): Promise<readonly RelayStore[]> {
    return [
        new SqliteRelayStore(":memory:"),
        await PostgresRelayStore.create(new PGliteDatabase(new PGlite())),
    ];
}

describe("relay store conformance", () => {
    test("strictly parses the standalone relay store backend", () => {
        expect(parseRelayStoreBackend(undefined)).toBe("sqlite");
        expect(parseRelayStoreBackend("sqlite")).toBe("sqlite");
        expect(parseRelayStoreBackend("postgres")).toBe("postgres");
        for (const invalid of [
            "",
            "SQLite",
            "POSTGRES",
            " postgres",
            "postgres ",
            "pglite",
            "postgresql",
        ]) {
            expect(() => parseRelayStoreBackend(invalid)).toThrow(
                "MURMUR_RELAY_STORE must be exactly sqlite or postgres",
            );
        }
    });

    test("rejects a legacy SQLite schema before adding clean tables", () => {
        const database = new DatabaseSync(":memory:");
        database.exec("CREATE TABLE murmur_relay_topics (id TEXT PRIMARY KEY)");
        expect(() => new SqliteRelayStore(":memory:", { database })).toThrow("Incompatible legacy");
        database.close();
    });

    test("rejects the superseded SQLite schema version without migrating it", () => {
        const database = new DatabaseSync(":memory:");
        database.exec(`
            CREATE TABLE murmur_relay_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            ) STRICT;
            INSERT INTO murmur_relay_schema (singleton, version) VALUES (1, 2);
        `);
        expect(() => new SqliteRelayStore(":memory:", { database })).toThrow(
            "Unsupported SQLite relay schema version",
        );
        database.close();
    });

    test("fresh schemas use version 3 and retain author-scoped collapse indexes", async () => {
        const sqliteDatabase = new DatabaseSync(":memory:");
        const sqlite = new SqliteRelayStore(":memory:", { database: sqliteDatabase });
        try {
            expect(
                sqliteDatabase
                    .prepare("SELECT version FROM murmur_relay_schema WHERE singleton = 1")
                    .get(),
            ).toEqual({ version: 3 });
            const sqliteIndexes = sqliteDatabase
                .prepare(
                    `SELECT name, sql FROM sqlite_master
                     WHERE type = 'index' AND name LIKE 'murmur_relay_events_%'
                     ORDER BY name`,
                )
                .all() as readonly Record<string, unknown>[];
            expect(sqliteIndexes).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        name: "murmur_relay_events_page",
                        sql: expect.stringContaining("(topic_id, seq, encoded_bytes, expires_at)"),
                    }),
                    expect.objectContaining({
                        name: "murmur_relay_events_collapse",
                        sql: expect.stringContaining(
                            "(topic_id, author_signing_key, collapse_key)",
                        ),
                    }),
                ]),
            );
        } finally {
            await sqlite.close();
        }

        const postgresDatabase = new PGliteDatabase(new PGlite());
        const postgres = await PostgresRelayStore.create(postgresDatabase);
        try {
            const version = await postgresDatabase.query<{ version: unknown }>(
                "SELECT version FROM murmur_relay_schema WHERE singleton = 1",
            );
            expect(String(version.rows[0]?.version)).toBe("3");
            const indexes = await postgresDatabase.query<{ indexdef: unknown }>(
                `SELECT indexdef FROM pg_indexes
                 WHERE indexname = 'murmur_relay_events_collapse'`,
            );
            expect(String(indexes.rows[0]?.indexdef)).toContain(
                "(topic_id, author_signing_key, collapse_key)",
            );
        } finally {
            await postgres.close();
        }
    });

    test("SQLite and PGlite preserve heads while collapse removes older rows", async () => {
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "conformance",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        for (const store of await stores()) {
            try {
                const topicId = relayTopicId(topic);
                const key = new Uint8Array([1, 2, 3]);
                expect(
                    (await store.publish(signed(secretKey, topic, 1, key), topicId, NOW)).seq,
                ).toBe(1n);
                expect(
                    (await store.publish(signed(secretKey, topic, 2, key), topicId, NOW)).seq,
                ).toBe(2n);
                const page = await store.readEvents(topicId, 0n, 100, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                expect(page.head).toBe(2n);
                expect(page.events.map(({ seq }) => seq)).toEqual([2n]);
                expect(page.exhausted).toBe(true);

                const pagedTopic = { ...topic, name: "byte-page" };
                const pagedTopicId = relayTopicId(pagedTopic);
                await store.publish(signed(secretKey, pagedTopic, 3), pagedTopicId, NOW);
                await store.publish(signed(secretKey, pagedTopic, 4), pagedTopicId, NOW);
                const firstPage = await store.readEvents(pagedTopicId, 0n, 100, NOW, {
                    maximumEncodedBytes: 1,
                });
                expect(firstPage.events.map(({ seq }) => seq)).toEqual([1n]);
                expect(firstPage.exhausted).toBe(false);
                const secondPage = await store.readEvents(pagedTopicId, 1n, 100, NOW, {
                    maximumEncodedBytes: 1,
                });
                expect(secondPage.events.map(({ seq }) => seq)).toEqual([2n]);
                expect(secondPage.exhausted).toBe(true);
            } finally {
                await store.close();
            }
        }
    });

    test("collapse is scoped to the author signing key on public-write read topics", async () => {
        const readSecretKey = randomBytes(32);
        const firstAuthor = randomBytes(32);
        const secondAuthor = randomBytes(32);
        const topic = {
            type: "read" as const,
            name: "multi-writer-collapse",
            readKey: ed25519.getPublicKey(readSecretKey),
        };
        const collapseKey = new Uint8Array([9, 8, 7]);
        for (const store of await stores()) {
            try {
                const topicId = relayTopicId(topic);
                await store.publish(signed(firstAuthor, topic, 1, collapseKey), topicId, NOW);
                await store.publish(signed(secondAuthor, topic, 2, collapseKey), topicId, NOW);
                await store.publish(signed(firstAuthor, topic, 3, collapseKey), topicId, NOW);
                const page = await store.readEvents(topicId, 0n, 10, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                expect(page.events.map(({ seq }) => seq)).toEqual([2n, 3n]);
                expect(page.events.map(({ event }) => event.author.signingKey)).toEqual([
                    ed25519.getPublicKey(secondAuthor),
                    ed25519.getPublicKey(firstAuthor),
                ]);
                expect(page.head).toBe(3n);
                expect(page.exhausted).toBe(true);
            } finally {
                await store.close();
            }
        }
    });

    test("SQLite and PGlite use the same exact compact encoded-byte page budget", async () => {
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "exact-byte-budget",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        for (const store of await stores()) {
            try {
                const topicId = relayTopicId(topic);
                await store.publish(signed(secretKey, topic, 1), topicId, NOW);
                await store.publish(signed(secretKey, topic, 2), topicId, NOW);
                const complete = await store.readEvents(topicId, 0n, 10, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                const exactBytes = new TextEncoder().encode(
                    JSON.stringify({
                        events: complete.events.map(({ seq, event }) => ({
                            seq: seq.toString(),
                            event: signedRelayEventToJson(event),
                        })),
                        head: complete.head.toString(),
                        exhausted: true,
                    }),
                ).length;
                await expect(
                    store.readEvents(topicId, 0n, 10, NOW, {
                        maximumEncodedBytes: exactBytes,
                    }),
                ).resolves.toMatchObject({
                    events: [{ seq: 1n }, { seq: 2n }],
                    exhausted: true,
                });
                await expect(
                    store.readEvents(topicId, 0n, 10, NOW, {
                        maximumEncodedBytes: exactBytes - 1,
                    }),
                ).resolves.toMatchObject({
                    events: [{ seq: 1n }],
                    exhausted: false,
                });
            } finally {
                await store.close();
            }
        }
    });

    test("count pages use one lookahead candidate across holes", async () => {
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "count-lookahead",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        for (const store of await stores()) {
            try {
                const topicId = relayTopicId(topic);
                const collapsed = new Uint8Array([4]);
                await store.publish(signed(secretKey, topic, 1, collapsed), topicId, NOW);
                await store.publish(signed(secretKey, topic, 2), topicId, NOW);
                await store.publish(signed(secretKey, topic, 3, collapsed), topicId, NOW);
                await store.publish(signed(secretKey, topic, 4), topicId, NOW);
                const first = await store.readEvents(topicId, 0n, 2, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                expect(first.events.map(({ seq }) => seq)).toEqual([2n, 3n]);
                expect(first.exhausted).toBe(false);
                const second = await store.readEvents(topicId, 3n, 2, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                expect(second.events.map(({ seq }) => seq)).toEqual([4n]);
                expect(second.head).toBe(4n);
                expect(second.exhausted).toBe(true);
            } finally {
                await store.close();
            }
        }
    });

    test("SQLite hydrates only the selected event from 256 maximum-size candidates", async () => {
        const database = new DatabaseSync(":memory:");
        const hydrated: bigint[] = [];
        const store = new SqliteRelayStore(":memory:", {
            database,
            instrumentation: {
                eventJsonHydrated: (seq) => hydrated.push(seq),
            },
        });
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "bounded-sqlite-hydration",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        const topicId = relayTopicId(topic);
        const event = signed(secretKey, topic, 1);
        const eventJson = JSON.stringify(signedRelayEventToJson(event));
        try {
            database.exec("BEGIN IMMEDIATE");
            database
                .prepare("INSERT INTO murmur_relay_topics (id, head) VALUES (?, 256)")
                .run(topicId);
            const insert = database.prepare(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 VALUES (?, ?, ?, ?, NULL, ?, NULL)`,
            );
            for (let seq = 1; seq <= 256; seq += 1) {
                insert.run(
                    topicId,
                    BigInt(seq),
                    eventJson,
                    BigInt(MAXIMUM_PAGE_BYTES),
                    event.author.signingKey,
                );
            }
            database.exec("COMMIT");

            const page = await store.readEvents(topicId, 0n, 256, NOW, {
                maximumEncodedBytes: MAXIMUM_PAGE_BYTES,
            });
            expect(page.events.map(({ seq }) => seq)).toEqual([1n]);
            expect(page.head).toBe(256n);
            expect(page.exhausted).toBe(false);
            expect(hydrated).toEqual([1n]);
        } finally {
            await store.close();
        }
    });

    test("Postgres hydrates only the selected event from 256 maximum-size candidates", async () => {
        const database = new PGliteDatabase(new PGlite());
        const hydrated: bigint[] = [];
        const store = await PostgresRelayStore.create(database, {
            instrumentation: {
                eventJsonHydrated: (seq) => hydrated.push(seq),
            },
        });
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "bounded-postgres-hydration",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        const topicId = relayTopicId(topic);
        const event = signed(secretKey, topic, 1);
        const eventJson = JSON.stringify(signedRelayEventToJson(event));
        try {
            await database.query("INSERT INTO murmur_relay_topics (id, head) VALUES ($1, 256)", [
                topicId,
            ]);
            await database.query(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 SELECT $1, generated.seq, $2::jsonb, $3, NULL, $4, NULL
                 FROM generate_series(1, 256) AS generated(seq)`,
                [topicId, eventJson, MAXIMUM_PAGE_BYTES, event.author.signingKey],
            );

            const page = await store.readEvents(topicId, 0n, 256, NOW, {
                maximumEncodedBytes: MAXIMUM_PAGE_BYTES,
            });
            expect(page.events.map(({ seq }) => seq)).toEqual([1n]);
            expect(page.head).toBe(256n);
            expect(page.exhausted).toBe(false);
            expect(hydrated).toEqual([1n]);
        } finally {
            await store.close();
        }
    });

    test("SQLite metadata reads stay covering and bounded across 257 overflow events", async () => {
        const database = new DatabaseSync(":memory:");
        const hydrated: bigint[] = [];
        const store = new SqliteRelayStore(":memory:", {
            database,
            instrumentation: {
                eventJsonHydrated: (seq) => hydrated.push(seq),
            },
        });
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "overflow-metadata",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        const topicId = relayTopicId(topic);
        const baseEvent = signed(secretKey, topic, 1);
        const event = { ...baseEvent, payload: new Uint8Array(64 * 1024) };
        const eventJson = JSON.stringify(signedRelayEventToJson(event));
        const encodedBytes = new TextEncoder().encode(eventJson).length;
        try {
            expect(encodedBytes).toBeGreaterThan(64 * 1024);
            database.exec("BEGIN IMMEDIATE");
            database
                .prepare("INSERT INTO murmur_relay_topics (id, head) VALUES (?, 257)")
                .run(topicId);
            const insert = database.prepare(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 VALUES (?, ?, ?, ?, NULL, ?, NULL)`,
            );
            for (let seq = 1; seq <= 257; seq += 1) {
                insert.run(
                    topicId,
                    BigInt(seq),
                    eventJson,
                    BigInt(encodedBytes),
                    event.author.signingKey,
                );
            }
            database.exec("COMMIT");

            const plan = database
                .prepare(`EXPLAIN QUERY PLAN ${SQLITE_READ_EVENTS_QUERY}`)
                .all(topicId, 0n, BigInt(NOW), 257n) as readonly Record<string, unknown>[];
            const details = plan.map((row) => String(row["detail"])).join("\n");
            expect(details).toMatch(
                /SEARCH murmur_relay_events USING COVERING INDEX murmur_relay_events_page \(topic_id=\? AND seq>\?\)/,
            );
            expect(details).not.toMatch(/USE TEMP B-TREE|MATERIALIZE|CO-ROUTINE/);

            const metadata = database.prepare(SQLITE_READ_EVENTS_QUERY);
            metadata.setReadBigInts(true);
            let metadataRows: readonly Record<string, unknown>[] = [];
            const started = performance.now();
            for (let iteration = 0; iteration < 25; iteration += 1) {
                metadataRows = metadata.all(topicId, 0n, BigInt(NOW), 257n) as readonly Record<
                    string,
                    unknown
                >[];
            }
            const elapsed = performance.now() - started;
            expect(metadataRows).toHaveLength(257);
            expect(Object.keys(metadataRows[0]!)).toEqual(["seq", "encoded_bytes"]);
            expect(elapsed).toBeLessThan(5_000);

            const page = await store.readEvents(topicId, 0n, 256, NOW, {
                maximumEncodedBytes: MAXIMUM_PAGE_BYTES,
            });
            expect(page.events.length).toBeGreaterThan(0);
            expect(page.events.length).toBeLessThan(257);
            expect(hydrated).toEqual(page.events.map(({ seq }) => seq));
            expect(page.exhausted).toBe(false);
            const responseBytes = new TextEncoder().encode(
                JSON.stringify({
                    events: page.events.map(({ seq, event: retained }) => ({
                        seq: seq.toString(),
                        event: signedRelayEventToJson(retained),
                    })),
                    head: page.head.toString(),
                    exhausted: page.exhausted,
                }),
            ).length;
            expect(responseBytes).toBeLessThanOrEqual(MAXIMUM_PAGE_BYTES);
        } finally {
            await store.close();
        }
    });

    test("large SQLite catch-up stays on a bounded ordered index plan", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "large-catch-up",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        const topicId = relayTopicId(topic);
        const event = signed(secretKey, topic, 1);
        const eventJson = JSON.stringify(signedRelayEventToJson(event));
        const encodedBytes = new TextEncoder().encode(eventJson).length;
        const eventCount = 25_000;
        try {
            database.exec("BEGIN IMMEDIATE");
            database
                .prepare("INSERT INTO murmur_relay_topics (id, head) VALUES (?, ?)")
                .run(topicId, BigInt(eventCount));
            const insert = database.prepare(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 VALUES (?, ?, ?, ?, NULL, ?, NULL)`,
            );
            for (let seq = 1; seq <= eventCount; seq += 1) {
                insert.run(
                    topicId,
                    BigInt(seq),
                    eventJson,
                    BigInt(encodedBytes),
                    event.author.signingKey,
                );
            }
            database.exec("COMMIT");

            const plan = database
                .prepare(`EXPLAIN QUERY PLAN ${SQLITE_READ_EVENTS_QUERY}`)
                .all(topicId, 0n, BigInt(NOW), 65n) as readonly Record<string, unknown>[];
            const details = plan.map((row) => String(row["detail"])).join("\n");
            expect(details).toMatch(
                /SEARCH murmur_relay_events USING COVERING INDEX murmur_relay_events_page \(topic_id=\? AND seq>\?\)/,
            );
            expect(details).not.toMatch(/USE TEMP B-TREE|MATERIALIZE|CO-ROUTINE/);
            expect(SQLITE_READ_EVENTS_QUERY).not.toContain("event_json");
            const hydrationPlan = database
                .prepare(`EXPLAIN QUERY PLAN ${sqliteHydrateEventsQuery(2)}`)
                .all(topicId, 1n, 2n) as readonly Record<string, unknown>[];
            expect(hydrationPlan.map((row) => String(row["detail"])).join("\n")).toMatch(
                /SEARCH murmur_relay_events USING INDEX .* \(topic_id=\? AND seq=\?\)/,
            );

            let since = 0n;
            let read = 0;
            for (;;) {
                const page = await store.readEvents(topicId, since, 64, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                read += page.events.length;
                if (page.exhausted) break;
                since = page.events.at(-1)!.seq;
            }
            expect(read).toBe(eventCount);
        } finally {
            await store.close();
        }
    });

    test("large Postgres catch-up stays on a bounded ordered index plan", async () => {
        const database = new PGliteDatabase(new PGlite());
        const store = await PostgresRelayStore.create(database);
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "large-postgres-catch-up",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        const topicId = relayTopicId(topic);
        const event = signed(secretKey, topic, 1);
        const eventJson = JSON.stringify(signedRelayEventToJson(event));
        const encodedBytes = new TextEncoder().encode(eventJson).length;
        const eventCount = 25_000;
        try {
            await database.query("INSERT INTO murmur_relay_topics (id, head) VALUES ($1, $2)", [
                topicId,
                eventCount.toString(),
            ]);
            await database.query(
                `INSERT INTO murmur_relay_events
                    (topic_id, seq, event_json, encoded_bytes, expires_at,
                     author_signing_key, collapse_key)
                 SELECT $1, generated.seq, $2::jsonb, $3, NULL, $4, NULL
                 FROM generate_series(1, $5::integer) AS generated(seq)`,
                [topicId, eventJson, encodedBytes, event.author.signingKey, eventCount],
            );
            await database.query("ANALYZE murmur_relay_events");
            const explained = await database.query<Record<string, unknown>>(
                `EXPLAIN (FORMAT JSON) ${POSTGRES_READ_EVENTS_QUERY}`,
                [topicId, "0", NOW.toString(), 65],
            );
            const plan = JSON.stringify(explained.rows);
            expect(plan).toContain('"Node Type":"Limit"');
            expect(plan).toMatch(/"Node Type":"Index(?: Only)? Scan"/);
            expect(plan).not.toMatch(/"Node Type":"(?:WindowAgg|Aggregate|Sort)"/);
            expect(POSTGRES_READ_EVENTS_QUERY).not.toContain("event_json");
            const hydration = await database.query<Record<string, unknown>>(
                `EXPLAIN (FORMAT JSON) ${postgresHydrateEventsQuery(2)}`,
                [topicId, "1", "2"],
            );
            expect(JSON.stringify(hydration.rows)).toMatch(
                /"Node Type":"(?:Index|Bitmap Index)(?: Only)? Scan"/,
            );
        } finally {
            await store.close();
        }
    });

    test("PGlite challenges are shared and consumed exactly once across stores", async () => {
        const database = new PGliteDatabase(new PGlite());
        const first = await PostgresRelayStore.create(database);
        const second = await PostgresRelayStore.create(database);
        try {
            const challenge = {
                id: encodeBase64Url(randomBytes(32)),
                topicId: encodeBase64Url(randomBytes(32)),
                nonce: randomBytes(32),
                expiresAt: NOW + 1_000,
            };
            expect(await first.issueReadChallenge(challenge, NOW, 10)).toBe(true);
            const consumed = await Promise.all([
                first.consumeReadChallenge(challenge.id, NOW),
                second.consumeReadChallenge(challenge.id, NOW),
            ]);
            expect(consumed.filter((value) => value !== undefined)).toHaveLength(1);
        } finally {
            await first.close();
        }
    });
});
