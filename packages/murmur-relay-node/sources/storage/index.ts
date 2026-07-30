import { DatabaseSync } from "node:sqlite";
import {
    decodeRelayEventWire,
    encodeBase64Url,
    encodeRelayEventWire,
    hashBytes,
    identityId,
    relayEventSignaturePayload,
    type RelayBlob,
    type RelayDelivery,
    type RelayEvent,
    type TopicSubscription,
} from "@slopus/murmur";
import type { PruneResult, RelayPublishResult, RelayStore } from "@murmur/relay";

function eventFingerprint(event: RelayEvent): string {
    return encodeBase64Url(
        hashBytes(new Uint8Array([...relayEventSignaturePayload(event), ...event.signature])),
    );
}

function deliveryId(recipient: string, eventId: string): string {
    return `${recipient}.${eventId}`;
}

function bytes(value: unknown, name: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`Invalid SQLite ${name}`);
    }
    return value;
}

function string(value: unknown, name: string): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid SQLite ${name}`);
    }
    return value;
}

/** Durable synchronous SQLite implementation of the relay storage contract. */
export class SqliteRelayStore implements RelayStore {
    readonly #database: DatabaseSync;
    #closed = false;

    constructor(path: string) {
        if (path.length === 0) {
            throw new Error("SQLite relay path cannot be empty");
        }
        this.#database = new DatabaseSync(path);
        this.#database.exec("PRAGMA foreign_keys = ON");
        if (path !== ":memory:") {
            this.#database.exec("PRAGMA journal_mode = WAL");
        }
        this.#database.exec(`
            CREATE TABLE IF NOT EXISTS topics (
                topic TEXT PRIMARY KEY,
                last_activity_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                topic TEXT NOT NULL REFERENCES topics(topic) ON DELETE CASCADE,
                recipient TEXT NOT NULL,
                PRIMARY KEY (topic, recipient)
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                topic TEXT NOT NULL REFERENCES topics(topic) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                event BLOB NOT NULL,
                explicit_recipients INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_topic ON events(topic);
            CREATE TABLE IF NOT EXISTS deliveries (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_id TEXT NOT NULL UNIQUE,
                recipient TEXT NOT NULL,
                event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                UNIQUE (recipient, event_id)
            );
            CREATE INDEX IF NOT EXISTS deliveries_recipient_sequence
                ON deliveries(recipient, sequence);
            CREATE TABLE IF NOT EXISTS queue_requests (
                request_key TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS queue_requests_expiry
                ON queue_requests(expires_at);
            CREATE TABLE IF NOT EXISTS blobs (
                id TEXT PRIMARY KEY,
                bytes BLOB NOT NULL
            );
        `);
    }

    async addSubscription(subscription: TopicSubscription, observedAt: number): Promise<number> {
        this.#ensureOpen();
        return this.#transaction(() => {
            this.#touchTopic(subscription.topic, observedAt);
            const recipient = identityId(subscription.subscriber);
            const inserted = this.#database
                .prepare("INSERT OR IGNORE INTO subscriptions(topic, recipient) VALUES (?, ?)")
                .run(subscription.topic, recipient).changes;
            if (inserted === 0) {
                return 0;
            }
            return Number(
                this.#database
                    .prepare(
                        `INSERT OR IGNORE INTO deliveries(delivery_id, recipient, event_id)
                         SELECT ? || '.' || id, ?, id
                         FROM events
                         WHERE topic = ? AND explicit_recipients = 0
                         ORDER BY sequence`,
                    )
                    .run(recipient, recipient, subscription.topic).changes,
            );
        });
    }

    async publish(event: RelayEvent, observedAt: number): Promise<RelayPublishResult> {
        this.#ensureOpen();
        return this.#transaction(() => {
            const fingerprint = eventFingerprint(event);
            const existing = this.#database
                .prepare("SELECT fingerprint FROM events WHERE id = ?")
                .get(event.id);
            if (existing !== undefined) {
                if (string(existing.fingerprint, "fingerprint") !== fingerprint) {
                    throw new Error("Event identifier collision");
                }
                return { disposition: "duplicate", recipients: [] };
            }
            this.#touchTopic(event.topic, observedAt);
            this.#database
                .prepare(
                    "INSERT INTO events(id, topic, fingerprint, event, explicit_recipients) VALUES (?, ?, ?, ?, ?)",
                )
                .run(
                    event.id,
                    event.topic,
                    fingerprint,
                    encodeRelayEventWire(event),
                    event.recipients.length > 0 ? 1 : 0,
                );
            if (event.recipients.length > 0) {
                const uniqueRecipients = [...new Set(event.recipients)].sort();
                for (const recipient of uniqueRecipients) {
                    this.#database
                        .prepare(
                            "INSERT INTO deliveries(delivery_id, recipient, event_id) VALUES (?, ?, ?)",
                        )
                        .run(deliveryId(recipient, event.id), recipient, event.id);
                }
                return { disposition: "inserted", recipients: uniqueRecipients };
            }

            this.#database
                .prepare(
                    `INSERT INTO deliveries(delivery_id, recipient, event_id)
                     SELECT recipient || '.' || ?, recipient, ?
                     FROM subscriptions
                     WHERE topic = ?`,
                )
                .run(event.id, event.id, event.topic);
            const recipients = this.#database
                .prepare(
                    `SELECT recipient
                     FROM subscriptions
                     WHERE topic = ?
                     ORDER BY recipient
                     LIMIT 10000`,
                )
                .all(event.topic)
                .map((row) => string(row.recipient, "recipient"));
            return { disposition: "inserted", recipients };
        });
    }

    async consumeQueueRequest(
        recipientId: string,
        requestId: string,
        expiresAt: number,
        observedAt: number,
    ): Promise<boolean> {
        this.#ensureOpen();
        return this.#transaction(() => {
            this.#database
                .prepare("DELETE FROM queue_requests WHERE expires_at <= ?")
                .run(observedAt);
            return (
                this.#database
                    .prepare(
                        "INSERT OR IGNORE INTO queue_requests(request_key, expires_at) VALUES (?, ?)",
                    )
                    .run(`${recipientId}/${requestId}`, expiresAt).changes === 1
            );
        });
    }

    async pull(recipientId: string, maximumDeliveries: number): Promise<readonly RelayDelivery[]> {
        this.#ensureOpen();
        return this.#database
            .prepare(
                `SELECT d.delivery_id, e.event
                 FROM deliveries d
                 JOIN events e ON e.id = d.event_id
                 WHERE d.recipient = ?
                 ORDER BY d.sequence
                 LIMIT ?`,
            )
            .all(recipientId, maximumDeliveries)
            .map((row) => ({
                deliveryId: string(row.delivery_id, "delivery ID"),
                event: decodeRelayEventWire(bytes(row.event, "event")),
            }));
    }

    async acknowledge(recipientId: string, identifier: string): Promise<void> {
        this.#ensureOpen();
        this.#database
            .prepare("DELETE FROM deliveries WHERE recipient = ? AND delivery_id = ?")
            .run(recipientId, identifier);
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        this.#ensureOpen();
        const existing = this.#database
            .prepare("SELECT bytes FROM blobs WHERE id = ?")
            .get(blob.id);
        if (existing !== undefined) {
            const stored = bytes(existing.bytes, "blob");
            if (
                stored.length !== blob.bytes.length ||
                stored.some((value, index) => value !== blob.bytes[index])
            ) {
                throw new Error("Blob identifier collision");
            }
            return;
        }
        this.#database
            .prepare("INSERT INTO blobs(id, bytes) VALUES (?, ?)")
            .run(blob.id, blob.bytes);
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        this.#ensureOpen();
        const row = this.#database.prepare("SELECT bytes FROM blobs WHERE id = ?").get(id);
        return row === undefined ? undefined : { id, bytes: bytes(row.bytes, "blob").slice() };
    }

    async pruneInactiveTopics(olderThan: number): Promise<PruneResult> {
        this.#ensureOpen();
        return this.#transaction(() => {
            const topicCount = Number(
                this.#database
                    .prepare("SELECT COUNT(*) AS count FROM topics WHERE last_activity_at < ?")
                    .get(olderThan)?.count ?? 0,
            );
            if (topicCount === 0) {
                return { topics: 0, deliveries: 0 };
            }
            const deliveryCount = this.#database
                .prepare(
                    `SELECT COUNT(*) AS count
                     FROM deliveries d
                     JOIN events e ON e.id = d.event_id
                     JOIN topics t ON t.topic = e.topic
                     WHERE t.last_activity_at < ?`,
                )
                .get(olderThan);
            const deliveries = Number(deliveryCount?.count ?? 0);
            this.#database.prepare("DELETE FROM topics WHERE last_activity_at < ?").run(olderThan);
            return { topics: topicCount, deliveries };
        });
    }

    /** Flush and close the database. */
    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        this.#database.close();
    }

    #touchTopic(topic: string, observedAt: number): void {
        this.#database
            .prepare(
                `INSERT INTO topics(topic, last_activity_at) VALUES (?, ?)
                 ON CONFLICT(topic) DO UPDATE SET
                    last_activity_at = MAX(last_activity_at, excluded.last_activity_at)`,
            )
            .run(topic, observedAt);
    }

    #transaction<T>(operation: () => T): T {
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const result = operation();
            this.#database.exec("COMMIT");
            return result;
        } catch (error: unknown) {
            this.#database.exec("ROLLBACK");
            throw error;
        }
    }

    #ensureOpen(): void {
        if (this.#closed) {
            throw new Error("SQLite relay store is closed");
        }
    }
}
