import { PGlite } from "@electric-sql/pglite";
import { sha256 } from "@noble/hashes/sha2";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, test } from "vitest";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedDelivery,
} from "../../protocol/tests/helpers.js";
import {
    parseRelayStoreBackend,
    PGliteDatabase,
    PostgresRelayStore,
    SqliteRelayStore,
    type RelayStore,
} from "../index.js";

const NOW = 10_000;
const LIMITS = {
    maximumItems: 10,
    maximumBytes: 1_000_000,
    maximumSenderItems: 10,
    maximumSenderBytes: 1_000_000,
    maximumSenderReferences: 1_000,
    maximumAdmissionReferences: 1_000,
    maximumGlobalItems: 100,
    maximumGlobalBytes: 10_000_000,
    maximumGlobalReferences: 1_000,
};
const PAGE = { maximumEncodedBytes: 2_000_000 };
const INVITATION_LIMITS = {
    maximumPrincipalItems: 2,
    maximumPrincipalBytes: 1_000,
    maximumGlobalItems: 3,
    maximumGlobalBytes: 2_000,
    maximumRevocationKeyItems: 2,
};
const ADMISSION_PRINCIPAL = new Uint8Array(32).fill(250);

async function stores(): Promise<readonly RelayStore[]> {
    return [
        new SqliteRelayStore(":memory:"),
        await PostgresRelayStore.create(new PGliteDatabase(new PGlite())),
    ];
}

describe("identity queue store conformance", () => {
    test("strictly parses the configured backend and rejects an incomplete SQLite schema", () => {
        expect(parseRelayStoreBackend(undefined)).toBe("sqlite");
        expect(parseRelayStoreBackend("postgres")).toBe("postgres");
        expect(() => parseRelayStoreBackend("Postgres")).toThrow("exactly sqlite or postgres");

        const database = new DatabaseSync(":memory:");
        database.exec("CREATE TABLE murmur_queue_partial (id TEXT PRIMARY KEY)");
        expect(() => new SqliteRelayStore(":memory:", { database })).toThrow("Incomplete");
        database.close();
    });

    test("rejects legacy SQLite and Postgres relay schemas instead of coexisting", async () => {
        const sqlite = new DatabaseSync(":memory:");
        sqlite.exec("CREATE TABLE murmur_relay_events (id TEXT PRIMARY KEY)");
        expect(() => new SqliteRelayStore(":memory:", { database: sqlite })).toThrow(
            "Legacy SQLite relay schema",
        );
        sqlite.close();

        const postgres = new PGlite();
        await postgres.exec("CREATE TABLE murmur_relay_topics (id text PRIMARY KEY)");
        await expect(PostgresRelayStore.create(new PGliteDatabase(postgres))).rejects.toThrow(
            "Legacy Postgres relay schema",
        );
        await postgres.close();
    });

    test("migrates schema v3 invitation rows in place on both backends", async () => {
        const bundle = new TextEncoder().encode("pending v3 invitation");
        const digest = sha256(bundle);

        const sqlite = new DatabaseSync(":memory:");
        sqlite.exec(`
            CREATE TABLE murmur_queue_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            ) STRICT;
            INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 3);
            CREATE TABLE murmur_invitations (
                digest BLOB PRIMARY KEY CHECK (length(digest) = 32),
                bundle BLOB NOT NULL,
                encoded_bytes INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                admission_principal BLOB NOT NULL CHECK (length(admission_principal) = 32)
            ) STRICT;
        `);
        sqlite
            .prepare(
                `INSERT INTO murmur_invitations
                    (digest, bundle, encoded_bytes, expires_at, admission_principal)
                 VALUES (?, ?, ?, ?, ?)`,
            )
            .run(digest, bundle, BigInt(bundle.length), BigInt(NOW + 10), ADMISSION_PRINCIPAL);
        const sqliteStore = new SqliteRelayStore(":memory:", { database: sqlite });
        expect(await sqliteStore.readInvitation(digest, NOW)).toEqual({
            bundle,
            expiresAt: NOW + 10,
        });
        expect(sqlite.prepare("SELECT version FROM murmur_queue_schema").get()).toMatchObject({
            version: 4,
        });
        expect(
            sqlite
                .prepare(
                    `SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name = 'murmur_invitation_revocations'`,
                )
                .get(),
        ).toMatchObject({ name: "murmur_invitation_revocations" });
        await sqliteStore.close();

        const postgres = new PGlite();
        await postgres.exec(`
            CREATE TABLE murmur_queue_schema (
                singleton bigint PRIMARY KEY CHECK (singleton = 1),
                version bigint NOT NULL
            );
            INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, 3);
            CREATE TABLE murmur_queue_global (
                singleton bigint PRIMARY KEY,
                last_event_id uuid
            );
            CREATE TABLE murmur_invitations (
                digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
                bundle bytea NOT NULL,
                encoded_bytes bigint NOT NULL,
                expires_at bigint NOT NULL,
                admission_principal bytea NOT NULL
            );
        `);
        await postgres.query(
            `INSERT INTO murmur_invitations
                (digest, bundle, encoded_bytes, expires_at, admission_principal)
             VALUES ($1, $2, $3, $4, $5)`,
            [digest, bundle, bundle.length, NOW + 10, ADMISSION_PRINCIPAL],
        );
        const postgresStore = await PostgresRelayStore.create(new PGliteDatabase(postgres));
        expect(await postgresStore.readInvitation(digest, NOW)).toEqual({
            bundle,
            expiresAt: NOW + 10,
        });
        expect(
            (await postgres.query<{ version: unknown }>("SELECT version FROM murmur_queue_schema"))
                .rows[0],
        ).toMatchObject({ version: 4 });
        expect(
            (
                await postgres.query<{ name: unknown }>(
                    `SELECT to_regclass('murmur_invitation_revocations') AS name`,
                )
            ).rows[0],
        ).toMatchObject({ name: "murmur_invitation_revocations" });
        await postgresStore.close();
    });

    test("stores invitations by digest without extending expiry and releases cache quota", async () => {
        const firstBundle = new TextEncoder().encode("first public invitation");
        const secondBundle = new TextEncoder().encode("second public invitation");
        const thirdBundle = new TextEncoder().encode("third public invitation");
        const firstDigest = sha256(firstBundle);
        const secondDigest = sha256(secondBundle);
        const thirdDigest = sha256(thirdBundle);
        for (const store of await stores()) {
            try {
                expect(
                    await store.storeInvitation(
                        firstDigest,
                        firstBundle,
                        NOW + 10,
                        NOW,
                        INVITATION_LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).toEqual({ expiresAt: NOW + 10, duplicate: false });
                expect(
                    await store.storeInvitation(
                        firstDigest,
                        firstBundle,
                        NOW + 20,
                        NOW,
                        INVITATION_LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).toEqual({ expiresAt: NOW + 10, duplicate: true });
                expect(await store.readInvitation(firstDigest, NOW)).toEqual({
                    bundle: firstBundle,
                    expiresAt: NOW + 10,
                });
                await store.storeInvitation(
                    secondDigest,
                    secondBundle,
                    NOW + 20,
                    NOW,
                    INVITATION_LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.storeInvitation(
                        thirdDigest,
                        thirdBundle,
                        NOW + 20,
                        NOW,
                        INVITATION_LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({
                    status: 429,
                    body: { error: "invitation_admission_full" },
                });
                expect(await store.readInvitation(firstDigest, NOW + 10)).toBeUndefined();
                expect(await store.pruneExpired(NOW + 10)).toBeGreaterThanOrEqual(1);
                await expect(
                    store.storeInvitation(
                        thirdDigest,
                        thirdBundle,
                        NOW + 20,
                        NOW + 10,
                        INVITATION_LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("authorizes bounded single and authority-wide invitation revocation", async () => {
        const limits = {
            maximumPrincipalItems: 8,
            maximumPrincipalBytes: 8_000,
            maximumGlobalItems: 8,
            maximumGlobalBytes: 8_000,
            maximumRevocationKeyItems: 3,
        };
        const authority = new Uint8Array(32).fill(41);
        const attacker = new Uint8Array(32).fill(42);
        const firstBundle = new TextEncoder().encode("first revocable invitation");
        const secondBundle = new TextEncoder().encode("second revocable invitation");
        const expiredBundle = new TextEncoder().encode("expired revocable invitation");
        const overflowBundle = new TextEncoder().encode("overflow revocable invitation");
        const firstDigest = sha256(firstBundle);
        const secondDigest = sha256(secondBundle);
        const expiredDigest = sha256(expiredBundle);
        const overflowDigest = sha256(overflowBundle);
        for (const store of await stores()) {
            try {
                await store.storeInvitation(
                    firstDigest,
                    firstBundle,
                    NOW + 10,
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                    authority,
                );
                await store.storeInvitation(
                    secondDigest,
                    secondBundle,
                    NOW + 10,
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                    authority,
                );
                await expect(
                    store.revokeInvitations(attacker, firstDigest, NOW, 3),
                ).rejects.toMatchObject({
                    status: 401,
                    body: { error: "invitation_revocation_unauthorized" },
                });

                expect(await store.revokeInvitations(authority, firstDigest, NOW, 3)).toEqual({
                    revoked: 1,
                });
                expect(await store.readInvitation(firstDigest, NOW)).toBeUndefined();
                expect(await store.revokeInvitations(authority, firstDigest, NOW, 3)).toEqual({
                    revoked: 0,
                });
                await expect(
                    store.revokeInvitations(attacker, firstDigest, NOW, 3),
                ).rejects.toMatchObject({ status: 401 });
                await expect(
                    store.storeInvitation(
                        firstDigest,
                        firstBundle,
                        NOW + 10,
                        NOW,
                        limits,
                        ADMISSION_PRINCIPAL,
                        authority,
                    ),
                ).rejects.toMatchObject({
                    status: 410,
                    body: { error: "invitation_revoked" },
                });

                expect(await store.revokeInvitations(authority, null, NOW, 3)).toEqual({
                    revoked: 1,
                });
                expect(await store.revokeInvitations(authority, null, NOW, 3)).toEqual({
                    revoked: 0,
                });
                expect(await store.readInvitation(secondDigest, NOW)).toBeUndefined();

                await store.storeInvitation(
                    expiredDigest,
                    expiredBundle,
                    NOW + 1,
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                    authority,
                );
                await expect(
                    store.storeInvitation(
                        overflowDigest,
                        overflowBundle,
                        NOW + 10,
                        NOW,
                        limits,
                        ADMISSION_PRINCIPAL,
                        authority,
                    ),
                ).rejects.toMatchObject({
                    status: 429,
                    body: { error: "invitation_revocation_authority_full" },
                });
                expect(await store.revokeInvitations(authority, expiredDigest, NOW + 1, 3)).toEqual(
                    { revoked: 0 },
                );
            } finally {
                await store.close();
            }
        }
    });

    test("pages authority-wide revocation after its configured bound is lowered", async () => {
        const limits = {
            maximumPrincipalItems: 3,
            maximumPrincipalBytes: 8_000,
            maximumGlobalItems: 3,
            maximumGlobalBytes: 8_000,
            maximumRevocationKeyItems: 3,
        };
        const authority = new Uint8Array(32).fill(43);
        for (const store of await stores()) {
            try {
                const digests: Uint8Array[] = [];
                for (let index = 0; index < 3; index += 1) {
                    const bundle = new TextEncoder().encode(`revocable invitation ${index}`);
                    const digest = sha256(bundle);
                    digests.push(digest);
                    await store.storeInvitation(
                        digest,
                        bundle,
                        NOW + 10,
                        NOW,
                        limits,
                        ADMISSION_PRINCIPAL,
                        authority,
                    );
                }

                expect(await store.revokeInvitations(authority, null, NOW, 1)).toEqual({
                    revoked: 3,
                });
                for (const digest of digests) {
                    expect(await store.readInvitation(digest, NOW)).toBeUndefined();
                }
            } finally {
                await store.close();
            }
        }
    });

    test("does not let an expired cache backlog consume live admission quota", async () => {
        const backlogLimits = {
            maximumPrincipalItems: 200,
            maximumPrincipalBytes: 100_000,
            maximumGlobalItems: 200,
            maximumGlobalBytes: 100_000,
            maximumRevocationKeyItems: 200,
        };
        const liveLimits = {
            maximumPrincipalItems: 1,
            maximumPrincipalBytes: 1_000,
            maximumGlobalItems: 1,
            maximumGlobalBytes: 1_000,
            maximumRevocationKeyItems: 1,
        };
        for (const store of await stores()) {
            try {
                for (let index = 0; index <= 100; index += 1) {
                    const bundle = new TextEncoder().encode(`expired invitation ${index}`);
                    await store.storeInvitation(
                        sha256(bundle),
                        bundle,
                        NOW + 1,
                        NOW,
                        backlogLimits,
                        ADMISSION_PRINCIPAL,
                    );
                }
                const live = new TextEncoder().encode("live invitation");
                await expect(
                    store.storeInvitation(
                        sha256(live),
                        live,
                        NOW + 2,
                        NOW + 1,
                        liveLimits,
                        ADMISSION_PRINCIPAL,
                    ),
                ).resolves.toEqual({ expiresAt: NOW + 2, duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("atomically multicasts one event ID and trims each recipient independently", async () => {
        const aliceSecret = secret(1);
        const bobSecret = secret(2);
        const carolSecret = secret(3);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const carol = identity(carolSecret);
        for (const store of await stores()) {
            try {
                const delivery = signedDelivery(aliceSecret, recipients(alice, bob, carol));
                const published = await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL);
                expect(published.duplicate).toBe(false);
                expect(await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL)).toEqual({
                    eventId: published.eventId,
                    duplicate: true,
                });
                for (const recipient of [alice, bob, carol]) {
                    const page = await store.readQueue(recipient, null, 10, NOW, PAGE);
                    expect(page.deliveries.map(({ eventId: id }) => id)).toEqual([
                        published.eventId,
                    ]);
                    expect(page.head).toBe(published.eventId);
                }

                expect(await store.acknowledge(bob, published.eventId, NOW)).toMatchObject({
                    removed: 1,
                    sequence: 1,
                });
                expect(
                    (await store.readQueue(bob, published.eventId, 10, NOW, PAGE)).deliveries,
                ).toEqual([]);
                expect((await store.readQueue(alice, null, 10, NOW, PAGE)).deliveries).toHaveLength(
                    1,
                );
                await store.acknowledge(alice, published.eventId, NOW);
                await store.acknowledge(carol, published.eventId, NOW);
                await expect(store.acknowledge(alice, eventId(0), NOW)).rejects.toMatchObject({
                    status: 409,
                    body: { error: "ack_regression" },
                });

                const republished = await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL);
                expect(republished.duplicate).toBe(false);
                expect(republished.eventId > published.eventId).toBe(true);
            } finally {
                await store.close();
            }
        }
    });

    test("rejects pending ID collisions and all-or-nothing queue overflow", async () => {
        const aliceSecret = secret(4);
        const bob = identity(secret(5));
        const carol = identity(secret(6));
        for (const store of await stores()) {
            try {
                const first = signedDelivery(aliceSecret, recipients(bob), { id: 7 });
                const firstOutcome = await store.publish(
                    first,
                    NOW,
                    {
                        ...LIMITS,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob), {
                            id: 7,
                            ciphertext: new Uint8Array([99]),
                        }),
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 409 });
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob, carol), { id: 8 }),
                        NOW,
                        { ...LIMITS, maximumItems: 1 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429 });
                expect(await store.readQueue(carol, null, 10, NOW, PAGE)).toMatchObject({
                    deliveries: [],
                    head: null,
                });
                await store.acknowledge(bob, firstOutcome.eventId, NOW);
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob, carol), { id: 8 }),
                        NOW,
                        { ...LIMITS, maximumItems: 1 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("expiration destructively removes pending inbox data", async () => {
        const aliceSecret = secret(7);
        const bob = identity(secret(8));
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(aliceSecret, recipients(bob), {
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const expired = await store.readQueue(bob, null, 10, NOW + 2, PAGE);
                expect(expired).toMatchObject({
                    deliveries: [],
                    head: published.eventId,
                    acknowledgedThrough: null,
                    headSequence: 1,
                    exhausted: true,
                });
                await store.acknowledge(bob, published.eventId, NOW + 2);
                const baseline = await store.readQueue(bob, published.eventId, 10, NOW + 2, PAGE);
                expect(baseline).toMatchObject({
                    deliveries: [],
                    head: published.eventId,
                    acknowledgedThrough: published.eventId,
                    acknowledgedSequence: 1,
                    exhausted: true,
                });
            } finally {
                await store.close();
            }
        }
    });

    test("declared restore changes generations without deleting pending data", async () => {
        const aliceSecret = secret(40);
        const bob = identity(secret(41));
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(aliceSecret, recipients(bob), { id: 42 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const before = await store.readQueue(bob, null, 10, NOW, PAGE);
                await expect(store.declareRestored()).resolves.toBeGreaterThanOrEqual(1);
                const after = await store.readQueue(bob, null, 10, NOW, PAGE);
                expect(after.deliveries.map((delivery) => delivery.eventId)).toEqual([
                    published.eventId,
                ]);
                expect(after.headSequence).toBe(before.headSequence);
                expect(after.generation).not.toEqual(before.generation);
            } finally {
                await store.close();
            }
        }
    });

    test("enforces sender and global pending-storage quotas transactionally", async () => {
        const aliceSecret = secret(15);
        const bobSecret = secret(16);
        const recipient = identity(secret(17));
        for (const store of await stores()) {
            try {
                const limits = {
                    ...LIMITS,
                    maximumSenderItems: 1,
                    maximumGlobalItems: 1,
                };
                await store.publish(
                    signedDelivery(aliceSecret, recipients(recipient), { id: 18 }),
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(recipient), { id: 19 }),
                        NOW,
                        { ...limits, maximumGlobalItems: 10 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "sender_full" } });
                await expect(
                    store.publish(
                        signedDelivery(bobSecret, recipients(recipient), { id: 20 }),
                        NOW,
                        limits,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 503, body: { error: "relay_full" } });
                expect(
                    (await store.readQueue(recipient, null, 10, NOW, PAGE)).deliveries,
                ).toHaveLength(1);
            } finally {
                await store.close();
            }
        }
    });

    test("charges multicast fanout against the sender reference quota", async () => {
        const sender = secret(27);
        const first = identity(secret(28));
        const second = identity(secret(29));
        for (const store of await stores()) {
            try {
                await store.publish(
                    signedDelivery(sender, recipients(first, second), { id: 30 }),
                    NOW,
                    { ...LIMITS, maximumSenderReferences: 2 },
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(sender, recipients(first), { id: 31 }),
                        NOW,
                        {
                            ...LIMITS,
                            maximumSenderReferences: 2,
                        },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "sender_full" } });
            } finally {
                await store.close();
            }
        }
    });

    test("bounds exact outstanding fanout per admitted ingress principal", async () => {
        const firstSender = secret(32);
        const secondSender = secret(33);
        const first = identity(secret(34));
        const second = identity(secret(35));
        const principal = new Uint8Array(32).fill(36);
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(firstSender, recipients(first, second), { id: 37 }),
                    NOW,
                    { ...LIMITS, maximumAdmissionReferences: 2 },
                    principal,
                );
                await expect(
                    store.publish(
                        signedDelivery(secondSender, recipients(first), { id: 38 }),
                        NOW,
                        { ...LIMITS, maximumAdmissionReferences: 2 },
                        principal,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "admission_full" } });

                await store.acknowledge(first, published.eventId, NOW);
                await store.acknowledge(second, published.eventId, NOW);
                await expect(
                    store.publish(
                        signedDelivery(secondSender, recipients(first), { id: 38 }),
                        NOW,
                        { ...LIMITS, maximumAdmissionReferences: 2 },
                        principal,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("multicast UUIDv7 IDs are monotonic within every recipient inbox", async () => {
        const aliceSecret = secret(9);
        const bobSecret = secret(10);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const store = await PostgresRelayStore.create(new PGliteDatabase(new PGlite()));
        try {
            const targets = recipients(alice, bob);
            await Promise.all([
                store.publish(
                    signedDelivery(aliceSecret, targets, { id: 11 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                ),
                store.publish(
                    signedDelivery(bobSecret, targets, { id: 12 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                ),
            ]);
            const aliceOrder = (await store.readQueue(alice, null, 10, NOW, PAGE)).deliveries.map(
                ({ eventId }) => eventId,
            );
            const bobOrder = (await store.readQueue(bob, null, 10, NOW, PAGE)).deliveries.map(
                ({ eventId }) => eventId,
            );
            expect(aliceOrder).toHaveLength(2);
            expect(aliceOrder[1]! > aliceOrder[0]!).toBe(true);
            expect(bobOrder).toEqual(aliceOrder);
        } finally {
            await store.close();
        }
    });

    test("set-based multicast handles a broad recipient fanout", async () => {
        const sender = secret(23);
        const targets = recipients(
            ...Array.from({ length: 64 }, (_, index) => identity(secret(24 + index))),
        );
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(sender, targets, { id: 90 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                for (const target of [targets[0]!, targets.at(-1)!]) {
                    const page = await store.readQueue(target, null, 10, NOW, PAGE);
                    expect(page.deliveries.map(({ eventId }) => eventId)).toEqual([
                        published.eventId,
                    ]);
                }
            } finally {
                await store.close();
            }
        }
    });

    test("reclaims all SQLite queue metadata after acknowledgement or expiration", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const aliceSecret = secret(11);
        const recipient = identity(secret(12));
        try {
            const published = await store.publish(
                signedDelivery(aliceSecret, recipients(recipient), { id: 13 }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            await store.acknowledge(recipient, published.eventId, NOW);
            expect(
                database
                    .prepare(
                        `SELECT
                            (SELECT COUNT(*) FROM murmur_queues) AS queues,
                            (SELECT COUNT(*) FROM murmur_queue_references) AS refs,
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            (SELECT pending_items FROM murmur_queue_global) AS pending_items,
                            (SELECT pending_references
                             FROM murmur_queue_global) AS pending_refs`,
                    )
                    .get(),
            ).toEqual({
                queues: 1,
                refs: 0,
                deliveries: 0,
                pending_items: 0,
                pending_refs: 0,
            });

            await store.publish(
                signedDelivery(aliceSecret, recipients(recipient), {
                    id: 14,
                    expiresAt: NOW + 1,
                }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            await store.pruneExpired(NOW + 2);
            expect(
                database
                    .prepare(
                        `SELECT
                            (SELECT COUNT(*) FROM murmur_queues) AS queues,
                            (SELECT COUNT(*) FROM murmur_queue_references) AS refs,
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            (SELECT pending_items FROM murmur_queue_global) AS pending_items,
                            (SELECT pending_references
                             FROM murmur_queue_global) AS pending_refs`,
                    )
                    .get(),
            ).toEqual({
                queues: 1,
                refs: 0,
                deliveries: 0,
                pending_items: 0,
                pending_refs: 0,
            });
        } finally {
            await store.close();
        }
    });

    test("bounds each SQLite expiration transaction to one fixed delivery batch", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const sender = secret(21);
        const recipient = identity(secret(22));
        const limits = {
            ...LIMITS,
            maximumItems: 200,
            maximumSenderItems: 200,
            maximumGlobalItems: 200,
        };
        try {
            for (let index = 1; index <= 101; index += 1) {
                await store.publish(
                    signedDelivery(sender, recipients(recipient), {
                        id: index,
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                );
            }
            expect(await store.pruneExpired(NOW + 2)).toBe(100);
            const remaining = database
                .prepare(
                    `SELECT
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            queue.pending_items,
                            queue.pending_bytes,
                            (SELECT COUNT(*) FROM murmur_queue_references
                             WHERE recipient = queue.recipient) AS actual_items,
                            (SELECT COALESCE(SUM(encoded_bytes), 0)
                             FROM murmur_queue_references
                             WHERE recipient = queue.recipient) AS actual_bytes
                         FROM murmur_queues AS queue
                         WHERE recipient = ?`,
                )
                .get(recipient);
            expect(remaining).toMatchObject({
                deliveries: 1,
                pending_items: 1,
                actual_items: 1,
            });
            expect(remaining?.pending_bytes).toBe(remaining?.actual_bytes);
            expect(await store.pruneExpired(NOW + 2)).toBe(1);
        } finally {
            await store.close();
        }
    });

    test("commits a bounded prune even when the following publication is rejected", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const sender = secret(91);
        const earlierRecipient = identity(secret(92));
        const targetRecipient = identity(secret(93));
        const setupLimits = {
            ...LIMITS,
            maximumItems: 200,
            maximumSenderItems: 200,
            maximumGlobalItems: 200,
        };
        try {
            for (let index = 1; index <= 100; index += 1) {
                await store.publish(
                    signedDelivery(sender, recipients(earlierRecipient), {
                        id: index,
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    setupLimits,
                    ADMISSION_PRINCIPAL,
                );
            }
            await store.publish(
                signedDelivery(sender, recipients(targetRecipient), {
                    id: 101,
                    expiresAt: NOW + 2,
                }),
                NOW,
                setupLimits,
                ADMISSION_PRINCIPAL,
            );
            const replacement = signedDelivery(sender, recipients(targetRecipient), {
                id: 102,
                expiresAt: NOW + 60_000,
            });
            await expect(
                store.publish(
                    replacement,
                    NOW + 3,
                    {
                        ...setupLimits,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 429, body: { error: "queue_full" } });
            expect(
                database.prepare("SELECT COUNT(*) AS count FROM murmur_queue_deliveries").get(),
            ).toEqual({ count: 1 });
            await expect(
                store.publish(
                    replacement,
                    NOW + 3,
                    {
                        ...setupLimits,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                ),
            ).resolves.toMatchObject({ duplicate: false });
        } finally {
            await store.close();
        }
    });
});
