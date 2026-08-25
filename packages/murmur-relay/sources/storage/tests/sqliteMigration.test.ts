import { sha256 } from "@noble/hashes/sha2";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, test } from "vitest";
import { deliveryFingerprint } from "../../protocol/index.js";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedDelivery,
} from "../../protocol/tests/helpers.js";
import { encodeStoredDelivery } from "../page.js";
import { initialLossGeneration, SqliteRelayStore } from "../index.js";

const NOW = 10_000;
const PAGE = { maximumEncodedBytes: 2_000_000 };
const ADMISSION_PRINCIPAL = new Uint8Array(32).fill(250);

interface LegacyFixture {
    readonly bob: Uint8Array;
    readonly carol: Uint8Array;
    readonly acknowledgedThrough: string;
    readonly eventIds: readonly [string, string, string];
    readonly invitationDigest: Uint8Array;
    readonly invitationBundle: Uint8Array;
    readonly snapshot: object;
}

function normalizedRows(database: DatabaseSync, sql: string): readonly object[] {
    const statement = database.prepare(sql);
    statement.setReadBigInts(true);
    return statement
        .all()
        .map((row) =>
            Object.fromEntries(
                Object.entries(row).map(([key, value]) => [
                    key,
                    value instanceof Uint8Array ? Array.from(value) : value,
                ]),
            ),
        );
}

function legacySnapshot(database: DatabaseSync, version: 3 | 4): object {
    return {
        global: normalizedRows(
            database,
            `SELECT singleton, last_event_id, pending_items, pending_bytes,
                    pending_references
             FROM murmur_queue_global ORDER BY singleton`,
        ),
        queues: normalizedRows(
            database,
            `SELECT recipient, head, acknowledged_through, pending_items, pending_bytes
             FROM murmur_queues ORDER BY recipient`,
        ),
        deliveries: normalizedRows(
            database,
            `SELECT sender, delivery_id, event_id, fingerprint, delivery_json,
                    encoded_bytes, expires_at
             FROM murmur_queue_deliveries ORDER BY event_id`,
        ),
        references: normalizedRows(
            database,
            `SELECT recipient, event_id, sender, delivery_id, encoded_bytes,
                    admission_principal
             FROM murmur_queue_references ORDER BY recipient, event_id`,
        ),
        invitations: normalizedRows(
            database,
            `SELECT digest, bundle, encoded_bytes, expires_at, admission_principal
                    ${version === 4 ? ", revocation_key" : ""}
             FROM murmur_invitations ORDER BY digest`,
        ),
        revocations:
            version === 4
                ? normalizedRows(
                      database,
                      `SELECT digest, revocation_key, expires_at, admission_principal
                       FROM murmur_invitation_revocations ORDER BY digest`,
                  )
                : [],
    };
}

function createHistoricalSchema(database: DatabaseSync, version: 3 | 4): void {
    database.exec(`
        PRAGMA foreign_keys = ON;
        CREATE TABLE murmur_queue_schema (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            version INTEGER NOT NULL
        ) STRICT;
        INSERT INTO murmur_queue_schema (singleton, version) VALUES (1, ${version});
        CREATE TABLE murmur_queue_global (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            last_event_id TEXT CHECK (
                last_event_id IS NULL OR length(last_event_id) = 36
            ),
            pending_items INTEGER NOT NULL CHECK (pending_items >= 0),
            pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0),
            pending_references INTEGER NOT NULL CHECK (pending_references >= 0)
        ) STRICT;
        CREATE TABLE murmur_queues (
            recipient BLOB PRIMARY KEY CHECK (length(recipient) = 32),
            head TEXT NOT NULL CHECK (length(head) = 36),
            acknowledged_through TEXT CHECK (
                acknowledged_through IS NULL OR (
                    length(acknowledged_through) = 36
                    AND acknowledged_through <= head
                )
            ),
            pending_items INTEGER NOT NULL CHECK (pending_items >= 0),
            pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0)
        ) STRICT;
        CREATE TABLE murmur_queue_deliveries (
            sender BLOB NOT NULL CHECK (length(sender) = 32),
            delivery_id TEXT NOT NULL,
            event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36),
            fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
            delivery_json TEXT NOT NULL,
            encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0),
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (sender, delivery_id)
        ) STRICT;
        CREATE INDEX murmur_queue_delivery_expiration
            ON murmur_queue_deliveries(expires_at);
        CREATE TABLE murmur_queue_references (
            recipient BLOB NOT NULL REFERENCES murmur_queues(recipient)
                ON DELETE CASCADE,
            event_id TEXT NOT NULL CHECK (length(event_id) = 36),
            sender BLOB NOT NULL,
            delivery_id TEXT NOT NULL,
            encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0),
            admission_principal BLOB NOT NULL CHECK (length(admission_principal) = 32),
            PRIMARY KEY (recipient, event_id),
            FOREIGN KEY (sender, delivery_id)
                REFERENCES murmur_queue_deliveries(sender, delivery_id)
                ON DELETE CASCADE
        ) STRICT;
        CREATE INDEX murmur_queue_reference_delivery
            ON murmur_queue_references(sender, delivery_id);
        CREATE INDEX murmur_queue_reference_admission
            ON murmur_queue_references(admission_principal);
        CREATE TABLE murmur_invitations (
            digest BLOB PRIMARY KEY CHECK (length(digest) = 32),
            bundle BLOB NOT NULL,
            encoded_bytes INTEGER NOT NULL CHECK (
                encoded_bytes > 0 AND length(bundle) = encoded_bytes
            ),
            expires_at INTEGER NOT NULL,
            admission_principal BLOB NOT NULL CHECK (
                length(admission_principal) = 32
            )
            ${
                version === 4
                    ? `, revocation_key BLOB CHECK (
                           revocation_key IS NULL OR length(revocation_key) = 32
                       )`
                    : ""
            }
        ) STRICT;
        CREATE INDEX murmur_invitation_expiration
            ON murmur_invitations(expires_at);
        CREATE INDEX murmur_invitation_admission
            ON murmur_invitations(admission_principal);
        ${
            version === 4
                ? `CREATE INDEX murmur_invitation_revocation_key
                       ON murmur_invitations(revocation_key);
                   CREATE TABLE murmur_invitation_revocations (
                       digest BLOB PRIMARY KEY CHECK (length(digest) = 32),
                       revocation_key BLOB NOT NULL CHECK (length(revocation_key) = 32),
                       expires_at INTEGER NOT NULL,
                       admission_principal BLOB NOT NULL CHECK (
                           length(admission_principal) = 32
                       )
                   ) STRICT;
                   CREATE INDEX murmur_invitation_revocation_expiration
                       ON murmur_invitation_revocations(expires_at);
                   CREATE INDEX murmur_invitation_revocation_authority
                       ON murmur_invitation_revocations(revocation_key);
                   CREATE INDEX murmur_invitation_revocation_admission
                       ON murmur_invitation_revocations(admission_principal);`
                : ""
        }
    `);
}

function populateHistoricalSchema(database: DatabaseSync, version: 3 | 4): LegacyFixture {
    const senderSecret = secret(40 + version);
    const sender = identity(senderSecret);
    const bob = identity(secret(50 + version));
    const carol = identity(secret(60 + version));
    const eventIds = [eventId(1), eventId(2), eventId(3)] as const;
    const deliveries = eventIds.map((assignedEventId, index) => {
        const delivery = signedDelivery(senderSecret, recipients(bob, carol), {
            id: index + 1,
            now: NOW,
            expiresAt: NOW + 60_000,
            ciphertext: new Uint8Array([version, index + 1, 255 - index]),
        });
        return { assignedEventId, delivery, encoded: encodeStoredDelivery(delivery) };
    });
    const bobBytes = deliveries[1]!.encoded.encodedBytes + deliveries[2]!.encoded.encodedBytes;
    const carolBytes = deliveries.reduce((total, item) => total + item.encoded.encodedBytes, 0);
    database
        .prepare(
            `INSERT INTO murmur_queue_global
                (singleton, last_event_id, pending_items, pending_bytes, pending_references)
             VALUES (1, ?, 3, ?, 5)`,
        )
        .run(eventIds[2], BigInt(carolBytes));
    const insertQueue = database.prepare(
        `INSERT INTO murmur_queues
            (recipient, head, acknowledged_through, pending_items, pending_bytes)
         VALUES (?, ?, ?, ?, ?)`,
    );
    insertQueue.run(bob, eventIds[2], eventIds[0], 2n, BigInt(bobBytes));
    insertQueue.run(carol, eventIds[2], null, 3n, BigInt(carolBytes));

    const insertDelivery = database.prepare(
        `INSERT INTO murmur_queue_deliveries
            (sender, delivery_id, event_id, fingerprint, delivery_json, encoded_bytes,
             expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const item of deliveries) {
        insertDelivery.run(
            sender,
            item.delivery.id,
            item.assignedEventId,
            deliveryFingerprint(item.delivery),
            item.encoded.json,
            BigInt(item.encoded.encodedBytes),
            BigInt(item.delivery.expiresAt),
        );
    }

    const insertReference = database.prepare(
        `INSERT INTO murmur_queue_references
            (recipient, event_id, sender, delivery_id, encoded_bytes, admission_principal)
         VALUES (?, ?, ?, ?, ?, ?)`,
    );
    for (const [recipient, index] of [
        [carol, 2],
        [bob, 2],
        [carol, 0],
        [bob, 1],
        [carol, 1],
    ] as const) {
        const item = deliveries[index]!;
        insertReference.run(
            recipient,
            item.assignedEventId,
            sender,
            item.delivery.id,
            BigInt(item.encoded.encodedBytes),
            ADMISSION_PRINCIPAL,
        );
    }

    const invitationBundle = new TextEncoder().encode(`historical v${version} invitation`);
    const invitationDigest = sha256(invitationBundle);
    const revocationKey = new Uint8Array(32).fill(70 + version);
    database
        .prepare(
            `INSERT INTO murmur_invitations
                (digest, bundle, encoded_bytes, expires_at, admission_principal
                 ${version === 4 ? ", revocation_key" : ""})
             VALUES (?, ?, ?, ?, ? ${version === 4 ? ", ?" : ""})`,
        )
        .run(
            invitationDigest,
            invitationBundle,
            BigInt(invitationBundle.length),
            BigInt(NOW + 60_000),
            ADMISSION_PRINCIPAL,
            ...(version === 4 ? [revocationKey] : []),
        );
    if (version === 4) {
        const revokedDigest = sha256(new TextEncoder().encode("historical revoked invitation"));
        database
            .prepare(
                `INSERT INTO murmur_invitation_revocations
                    (digest, revocation_key, expires_at, admission_principal)
                 VALUES (?, ?, ?, ?)`,
            )
            .run(revokedDigest, revocationKey, BigInt(NOW + 50_000), ADMISSION_PRINCIPAL);
    }
    return {
        bob,
        carol,
        acknowledgedThrough: eventIds[0],
        eventIds,
        invitationDigest,
        invitationBundle,
        snapshot: legacySnapshot(database, version),
    };
}

function requiredBytes(value: unknown, name: string): Uint8Array {
    if (!(value instanceof Uint8Array)) throw new Error(`Missing ${name}`);
    return value;
}

async function withDatabasePath(operation: (path: string) => Promise<void>): Promise<void> {
    const directory = await mkdtemp(join(tmpdir(), "murmur-relay-migration-"));
    try {
        await operation(join(directory, "relay.sqlite"));
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
}

describe("SQLite continuity schema migration", () => {
    test.each([3, 4] as const)(
        "migrates a genuine v%i database to v5 without changing pending data",
        async (version) => {
            await withDatabasePath(async (path) => {
                let database = new DatabaseSync(path);
                createHistoricalSchema(database, version);
                const fixture = populateHistoricalSchema(database, version);
                database.close();

                let store = new SqliteRelayStore(path);
                const bobPage = await store.readQueue(
                    fixture.bob,
                    fixture.acknowledgedThrough,
                    10,
                    NOW,
                    PAGE,
                );
                expect(
                    bobPage.deliveries.map(({ eventId: id, sequence }) => [id, sequence]),
                ).toEqual([
                    [fixture.eventIds[1], 1],
                    [fixture.eventIds[2], 2],
                ]);
                expect(bobPage).toMatchObject({
                    head: fixture.eventIds[2],
                    headSequence: 2,
                    acknowledgedThrough: fixture.acknowledgedThrough,
                    acknowledgedSequence: 0,
                });
                const carolPage = await store.readQueue(fixture.carol, null, 10, NOW, PAGE);
                expect(carolPage.deliveries.map(({ sequence }) => sequence)).toEqual([1, 2, 3]);
                expect(carolPage).toMatchObject({ headSequence: 3, acknowledgedSequence: 0 });
                expect(await store.readInvitation(fixture.invitationDigest, NOW)).toEqual({
                    bundle: fixture.invitationBundle,
                    expiresAt: NOW + 60_000,
                });
                await store.close();

                database = new DatabaseSync(path);
                expect(database.prepare("SELECT version FROM murmur_queue_schema").get()).toEqual({
                    version: 5,
                });
                expect(legacySnapshot(database, version)).toEqual(fixture.snapshot);
                const global = database
                    .prepare(`SELECT generation_seed FROM murmur_queue_global WHERE singleton = 1`)
                    .get();
                const seed = requiredBytes(global?.generation_seed, "generation seed");
                expect(seed).toHaveLength(32);
                for (const recipient of [fixture.bob, fixture.carol]) {
                    const queue = database
                        .prepare(`SELECT loss_generation FROM murmur_queues WHERE recipient = ?`)
                        .get(recipient);
                    expect(requiredBytes(queue?.loss_generation, "loss generation")).toEqual(
                        initialLossGeneration(seed, recipient),
                    );
                }
                database.close();

                store = new SqliteRelayStore(path);
                expect(
                    await store.readQueue(fixture.bob, fixture.acknowledgedThrough, 10, NOW, PAGE),
                ).toEqual(bobPage);
                await store.close();
            });
        },
    );
});
