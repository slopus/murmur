import { sha256 } from "@noble/hashes/sha2";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, test } from "vitest";
import {
    DurableFanoutCoordinator,
    type DurableFanoutStore,
    type FanoutRetryScheduler,
    type FanoutTarget,
    type PendingFanoutManifest,
} from "../../fanout/index.js";
import { deliveryFingerprint, type SignedDelivery } from "../../protocol/index.js";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedAck,
    signedDelivery,
    signedRead,
} from "../../protocol/tests/helpers.js";
import { RelayService } from "../../relay/index.js";
import {
    SqliteRelayStore,
    advanceLossGeneration,
    type InvitationLimits,
    type PublishOutcome,
    type QueueLimits,
    type QueuePage,
} from "../index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";

const NOW = 1_700_000_000_000;
const DAY_MILLISECONDS = 24 * 60 * 60 * 1_000;
const RETENTION_MILLISECONDS = 180 * DAY_MILLISECONDS;
const INVITATION_TTL_MILLISECONDS = 5 * 60 * 1_000;
const PAGE = { maximumEncodedBytes: 32 * 1024 * 1024 };
const PRINCIPAL = new Uint8Array(32).fill(240);
const LIMITS: QueueLimits = {
    maximumItems: 1_000,
    maximumBytes: 64 * 1024 * 1024,
    maximumSenderItems: 1_000,
    maximumSenderBytes: 64 * 1024 * 1024,
    maximumSenderReferences: 100_000,
    maximumAdmissionReferences: 100_000,
    maximumGlobalItems: 10_000,
    maximumGlobalBytes: 256 * 1024 * 1024,
    maximumGlobalReferences: 100_000,
};
const INVITATION_LIMITS: InvitationLimits = {
    maximumPrincipalItems: 100,
    maximumPrincipalBytes: 10 * 1024 * 1024,
    maximumGlobalItems: 1_000,
    maximumGlobalBytes: 64 * 1024 * 1024,
    maximumRevocationKeyItems: 100,
};

function chaosDelivery(
    secretKey: Uint8Array,
    targets: readonly Uint8Array[],
    options: {
        readonly id?: number;
        readonly now?: number;
        readonly expiresAt?: number;
        readonly ciphertext?: Uint8Array;
    } = {},
): SignedDelivery {
    return signedDelivery(secretKey, targets, { ...options, now: options.now ?? NOW });
}

async function queue(
    store: SqliteRelayStore,
    recipient: Uint8Array,
    after: string | null = null,
    limit: number = 1_000,
    now: number = NOW,
): Promise<QueuePage> {
    return store.readQueue(recipient, after, limit, now, PAGE);
}

async function withDatabasePath<Result>(
    operation: (path: string) => Promise<Result>,
): Promise<Result> {
    const directory = await mkdtemp(join(tmpdir(), "murmur-relay-chaos-"));
    const path = join(directory, "relay.sqlite");
    try {
        return await operation(path);
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
}

function normalizePage(page: QueuePage): object {
    return {
        deliveries: page.deliveries.map((delivery) => ({
            eventId: delivery.eventId,
            sequence: delivery.sequence,
            id: delivery.delivery.id,
        })),
        head: page.head,
        headSequence: page.headSequence,
        acknowledgedThrough: page.acknowledgedThrough,
        acknowledgedSequence: page.acknowledgedSequence,
        generation: encodeBase64Url(page.generation),
        exhausted: page.exhausted,
    };
}

interface MutableManifest {
    readonly eventId: string;
    readonly delivery: SignedDelivery;
    readonly admissionPrincipal: string;
    readonly fingerprint: Uint8Array;
    pendingRecipients: Uint8Array[];
    completed: boolean;
}

class ManifestStore implements DurableFanoutStore {
    readonly manifests: MutableManifest[] = [];
    readonly #dedupe = new Map<string, MutableManifest>();
    #nextPendingIndex = 0;
    corrupt: "none" | "digest" | "duplicate" | "missing-status" = "none";

    async reserve(
        delivery: SignedDelivery,
        admissionPrincipal: string,
        _now: number,
    ): Promise<PublishOutcome> {
        const key = `${encodeBase64Url(delivery.sender)}:${delivery.id}`;
        const fingerprint = deliveryFingerprint(delivery);
        const existing = this.#dedupe.get(key);
        if (existing !== undefined) {
            if (!equalBytes(existing.fingerprint, fingerprint)) throw new Error("fanout collision");
            return { eventId: existing.eventId, duplicate: true };
        }
        const manifest: MutableManifest = {
            eventId: eventId(this.manifests.length + 1),
            delivery,
            admissionPrincipal,
            fingerprint,
            pendingRecipients: delivery.recipients.map((recipient) => recipient.slice()),
            completed: false,
        };
        this.manifests.push(manifest);
        this.#dedupe.set(key, manifest);
        return { eventId: manifest.eventId, duplicate: false };
    }

    async oldestPending(now: number): Promise<PendingFanoutManifest | undefined> {
        while (this.manifests[this.#nextPendingIndex]?.completed === true) {
            this.#nextPendingIndex += 1;
        }
        const manifest = this.manifests[this.#nextPendingIndex];
        if (manifest === undefined) return undefined;
        if (manifest.delivery.expiresAt <= now || manifest.pendingRecipients.length === 0) {
            throw new Error("Pending fanout cursor reached an inconsistent manifest");
        }
        if (!equalBytes(manifest.fingerprint, deliveryFingerprint(manifest.delivery))) {
            throw new Error("Corrupt fanout delivery digest");
        }
        const exact = new Set(manifest.delivery.recipients.map(encodeBase64Url));
        const pending = manifest.pendingRecipients.map(encodeBase64Url);
        if (
            this.corrupt === "digest" ||
            (this.corrupt === "duplicate" && pending.length > 0) ||
            (this.corrupt === "missing-status" && pending.length > 0) ||
            new Set(pending).size !== pending.length ||
            pending.some((recipient) => !exact.has(recipient))
        ) {
            throw new Error("Corrupt fanout manifest");
        }
        return {
            eventId: manifest.eventId,
            delivery: manifest.delivery,
            admissionPrincipal: manifest.admissionPrincipal,
            pendingRecipients: manifest.pendingRecipients.map((recipient) => recipient.slice()),
        };
    }

    async markDelivered(
        sender: Uint8Array,
        deliveryId: string,
        recipient: Uint8Array,
    ): Promise<void> {
        const manifest = this.#dedupe.get(`${encodeBase64Url(sender)}:${deliveryId}`);
        if (manifest === undefined) throw new Error("Missing fanout manifest");
        const encoded = encodeBase64Url(recipient);
        manifest.pendingRecipients = manifest.pendingRecipients.filter(
            (candidate) => encodeBase64Url(candidate) !== encoded,
        );
        if (manifest.pendingRecipients.length === 0) manifest.completed = true;
    }

    async pruneExpired(now: number): Promise<number> {
        let pruned = 0;
        for (const manifest of this.manifests) {
            if (!manifest.completed && manifest.delivery.expiresAt <= now) {
                manifest.pendingRecipients = [];
                manifest.completed = true;
                pruned += 1;
            }
        }
        return pruned;
    }
}

interface TargetRecord {
    readonly eventId: string;
    readonly sequence: number;
}

class SequencedTarget implements FanoutTarget {
    readonly inboxes = new Map<string, Map<string, TargetRecord>>();
    readonly attempts = new Map<string, number>();
    readonly failBefore = new Set<string>();
    readonly loseAfterCommit = new Set<string>();
    readonly permanentFailure = new Set<string>();

    async insert(
        recipient: Uint8Array,
        assignedEventId: string,
        delivery: SignedDelivery,
        _admissionPrincipal: string,
    ): Promise<void> {
        const encoded = encodeBase64Url(recipient);
        const attemptKey = `${assignedEventId}:${encoded}`;
        this.attempts.set(attemptKey, (this.attempts.get(attemptKey) ?? 0) + 1);
        if (this.permanentFailure.has(encoded)) throw new Error("permanent target failure");
        if (this.failBefore.delete(attemptKey)) throw new Error("target unavailable");
        if (!delivery.recipients.some((candidate) => equalBytes(candidate, recipient))) {
            throw new Error("Fanout target is not an exact delivery recipient");
        }
        let inbox = this.inboxes.get(encoded);
        if (inbox === undefined) {
            inbox = new Map();
            this.inboxes.set(encoded, inbox);
        }
        if (!inbox.has(assignedEventId)) {
            inbox.set(assignedEventId, { eventId: assignedEventId, sequence: inbox.size + 1 });
        }
        if (this.loseAfterCommit.delete(attemptKey)) {
            throw new Error("lost target commit response");
        }
    }
}

class RecordingScheduler implements FanoutRetryScheduler {
    readonly scheduled: number[] = [];

    async schedule(at: number): Promise<void> {
        this.scheduled.push(at);
    }
}

const fanoutDeliveryCache = new Map<string, SignedDelivery>();

function fanoutDelivery(index: number, targetCount: number, now: number = NOW): SignedDelivery {
    const cacheKey = `${index}:${targetCount}:${now}`;
    const cached = fanoutDeliveryCache.get(cacheKey);
    if (cached !== undefined) return cached;
    const sender = secret(100 + Math.floor(index / 250));
    const targets = recipients(
        ...Array.from({ length: targetCount }, (_, target) => identity(secret(target + 1))),
    );
    const delivery = chaosDelivery(sender, targets, {
        id: (index % 250) + 1,
        now,
        expiresAt: now + 60_000,
    });
    fanoutDeliveryCache.set(cacheKey, delivery);
    return delivery;
}

describe("SQLite relay and durable fanout chaos", () => {
    test("SQL-01 atomic multicast preserves exact counts and sequence allocation", async () => {
        const sender = secret(1);
        for (const recipientCount of [1, 2, 7, 8]) {
            const store = new SqliteRelayStore(":memory:");
            const targets = recipients(
                ...Array.from({ length: recipientCount }, (_, index) =>
                    identity(secret(10 + index)),
                ),
            );
            try {
                const outcome = await store.publish(
                    chaosDelivery(sender, targets, { id: recipientCount }),
                    NOW,
                    LIMITS,
                    PRINCIPAL,
                );
                for (const target of targets) {
                    const page = await queue(store, target);
                    expect(page.deliveries).toMatchObject([
                        { eventId: outcome.eventId, sequence: 1 },
                    ]);
                    expect(page.headSequence).toBe(1);
                }
            } finally {
                await store.close();
            }
        }

        for (const blockedIndex of [0, 2, 3]) {
            const store = new SqliteRelayStore(":memory:");
            const targets = recipients(
                ...Array.from({ length: 4 }, (_, index) => identity(secret(30 + index))),
            );
            try {
                const prefill = await store.publish(
                    chaosDelivery(sender, recipients(targets[blockedIndex]!), {
                        id: 40 + blockedIndex,
                    }),
                    NOW,
                    LIMITS,
                    PRINCIPAL,
                );
                await expect(
                    store.publish(
                        chaosDelivery(sender, targets, { id: 50 + blockedIndex }),
                        NOW,
                        { ...LIMITS, maximumItems: 1 },
                        PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429 });
                for (let index = 0; index < targets.length; index += 1) {
                    expect((await queue(store, targets[index]!)).deliveries).toHaveLength(
                        index === blockedIndex ? 1 : 0,
                    );
                }
                await store.acknowledge(targets[blockedIndex]!, prefill.eventId, NOW);
                await store.publish(
                    chaosDelivery(sender, targets, { id: 50 + blockedIndex }),
                    NOW,
                    { ...LIMITS, maximumItems: 1 },
                    PRINCIPAL,
                );
                for (let index = 0; index < targets.length; index += 1) {
                    const after = index === blockedIndex ? prefill.eventId : null;
                    expect(
                        (await queue(store, targets[index]!, after)).deliveries[0]!.sequence,
                    ).toBe(index === blockedIndex ? 2 : 1);
                }
            } finally {
                await store.close();
            }
        }

        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumRecipients: 8 },
            undefined,
            () => NOW,
        );
        try {
            await expect(
                relay.publish(
                    chaosDelivery(
                        sender,
                        recipients(
                            ...Array.from({ length: 9 }, (_, index) =>
                                identity(secret(60 + index)),
                            ),
                        ),
                        { id: 70, now: NOW },
                    ),
                    "sql-chaos",
                ),
            ).rejects.toMatchObject({ status: 413 });
        } finally {
            await relay.close();
        }
    });

    test("SQL-02 concurrent and reopened duplicate publication is one durable event", async () => {
        await withDatabasePath(async (path) => {
            const sender = secret(2);
            const bob = identity(secret(3));
            const delivery = chaosDelivery(sender, recipients(bob), { id: 2 });
            let store = new SqliteRelayStore(path);
            const concurrent = await Promise.all([
                store.publish(delivery, NOW, LIMITS, PRINCIPAL),
                store.publish(delivery, NOW, LIMITS, PRINCIPAL),
            ]);
            expect(new Set(concurrent.map((outcome) => outcome.eventId)).size).toBe(1);
            expect(concurrent.map((outcome) => outcome.duplicate).sort()).toEqual([false, true]);
            expect((await queue(store, bob)).deliveries).toHaveLength(1);
            await expect(
                store.publish(
                    chaosDelivery(sender, recipients(bob), {
                        id: 2,
                        ciphertext: new Uint8Array([9]),
                    }),
                    NOW,
                    LIMITS,
                    PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 409 });
            await store.close();

            store = new SqliteRelayStore(path);
            await expect(store.publish(delivery, NOW, LIMITS, PRINCIPAL)).resolves.toEqual({
                eventId: concurrent[0]!.eventId,
                duplicate: true,
            });
            expect((await queue(store, bob)).deliveries).toHaveLength(1);
            await store.close();
        });
    });

    test("SQL-03 paginates 100 events by UUID and contiguous recipient sequence", async () => {
        const store = new SqliteRelayStore(":memory:");
        const target = identity(secret(4));
        try {
            for (let index = 0; index < 100; index += 1) {
                await store.publish(
                    chaosDelivery(secret(10 + (index % 4)), recipients(target), {
                        id: Math.floor(index / 4) + 1,
                        now: NOW - index,
                    }),
                    NOW,
                    LIMITS,
                    PRINCIPAL,
                );
            }
            const full = await queue(store, target, null, 100);
            expect(full.deliveries.map((delivery) => delivery.sequence)).toEqual(
                Array.from({ length: 100 }, (_, index) => index + 1),
            );
            const ids = full.deliveries.map((delivery) => delivery.eventId);
            expect([...ids].sort()).toEqual(ids);
            expect(full).toMatchObject({
                head: ids.at(-1),
                headSequence: 100,
                acknowledgedSequence: 0,
                exhausted: true,
            });
            for (const pageSize of [1, 7, 100]) {
                const paged: string[] = [];
                let after: string | null = null;
                while (paged.length < 100) {
                    const page = await queue(store, target, after, pageSize);
                    paged.push(...page.deliveries.map((delivery) => delivery.eventId));
                    after = page.deliveries.at(-1)?.eventId ?? after;
                }
                expect(paged).toEqual(ids);
            }
        } finally {
            await store.close();
        }
    });

    test("SQL-04 signed acknowledgement is monotonic, idempotent, and generation-stable", async () => {
        const store = new SqliteRelayStore(":memory:");
        const relay = new RelayService(store, {}, undefined, () => NOW);
        const alice = secret(5);
        const bobSecret = secret(6);
        const bob = identity(bobSecret);
        try {
            const outcomes: PublishOutcome[] = [];
            for (let index = 0; index < 3; index += 1) {
                outcomes.push(
                    await relay.publish(
                        chaosDelivery(alice, recipients(bob), { id: 20 + index, now: NOW }),
                        "sql-chaos",
                    ),
                );
            }
            const before = await relay.readQueue(signedRead(bobSecret, { now: NOW }));
            const first = await relay.acknowledge(signedAck(bobSecret, outcomes[0]!.eventId, NOW));
            expect(first).toMatchObject({ removed: 1, sequence: 1 });
            expect(first.generation).toEqual(before.generation);
            await expect(
                relay.acknowledge(signedAck(bobSecret, outcomes[0]!.eventId, NOW)),
            ).resolves.toMatchObject({ removed: 0, sequence: 1, generation: before.generation });
            await expect(
                relay.acknowledge(
                    signedAck(bobSecret, "ffffffff-ffff-7fff-bfff-ffffffffffff", NOW),
                ),
            ).rejects.toMatchObject({ status: 409, body: { error: "ack_future" } });
            const forged = signedAck(bobSecret, outcomes[1]!.eventId, NOW);
            forged.signature[0] = forged.signature[0]! ^ 1;
            await expect(relay.acknowledge(forged)).rejects.toMatchObject({ status: 401 });
            await relay.acknowledge(signedAck(bobSecret, outcomes[2]!.eventId, NOW));
            const after = await relay.readQueue(
                signedRead(bobSecret, { after: outcomes[2]!.eventId, now: NOW }),
            );
            expect(after).toMatchObject({
                deliveries: [],
                acknowledgedSequence: 3,
                generation: before.generation,
            });
            await expect(
                relay.acknowledge(signedAck(bobSecret, outcomes[1]!.eventId, NOW)),
            ).rejects.toMatchObject({ status: 409, body: { error: "ack_regression" } });
        } finally {
            await relay.close();
        }
    });

    test("SQL-05 file-backed reopen preserves invitations, references, and continuity metadata", async () => {
        await withDatabasePath(async (path) => {
            const sender = secret(7);
            const bob = identity(secret(8));
            const carol = identity(secret(9));
            const bundle = new TextEncoder().encode("reopen invitation");
            const digest = sha256(bundle);
            let store = new SqliteRelayStore(path);
            const published = await store.publish(
                chaosDelivery(sender, recipients(bob, carol), { id: 7 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            await store.storeInvitation(
                digest,
                bundle,
                NOW + INVITATION_TTL_MILLISECONDS,
                NOW,
                INVITATION_LIMITS,
                PRINCIPAL,
            );
            const bobBefore = normalizePage(await queue(store, bob));
            const carolBefore = normalizePage(await queue(store, carol));
            await store.close();

            store = new SqliteRelayStore(path);
            expect(normalizePage(await queue(store, bob))).toEqual(bobBefore);
            expect(normalizePage(await queue(store, carol))).toEqual(carolBefore);
            expect(await store.readInvitation(digest, NOW)).toEqual({
                bundle,
                expiresAt: NOW + INVITATION_TTL_MILLISECONDS,
            });
            const bobGeneration = (await queue(store, bob)).generation;
            await store.acknowledge(bob, published.eventId, NOW);
            expect((await queue(store, bob, published.eventId)).generation).toEqual(bobGeneration);
            expect((await queue(store, carol)).deliveries).toHaveLength(1);
            await store.close();

            store = new SqliteRelayStore(path);
            const next = await store.publish(
                chaosDelivery(sender, recipients(bob, carol), { id: 8 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            expect((await queue(store, bob, published.eventId)).deliveries[0]).toMatchObject({
                eventId: next.eventId,
                sequence: 2,
            });
            expect(
                (await queue(store, carol)).deliveries.map((delivery) => delivery.sequence),
            ).toEqual([1, 2]);
            await store.close();
        });
    });

    test("SQL-06 exact expiry advances only unacknowledged inbox generations", async () => {
        const store = new SqliteRelayStore(":memory:");
        const sender = secret(10);
        const bob = identity(secret(11));
        const carol = identity(secret(12));
        const bundle = new TextEncoder().encode("expiring invitation");
        const digest = sha256(bundle);
        try {
            const published = await store.publish(
                chaosDelivery(sender, recipients(bob, carol), {
                    id: 10,
                    expiresAt: NOW + 1,
                }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            await store.storeInvitation(digest, bundle, NOW + 1, NOW, INVITATION_LIMITS, PRINCIPAL);
            const bobBefore = await queue(store, bob);
            const carolBefore = await queue(store, carol);
            await store.acknowledge(bob, published.eventId, NOW);
            expect(await store.readInvitation(digest, NOW)).toBeDefined();
            expect((await queue(store, carol, null, 10, NOW)).deliveries).toHaveLength(1);
            await expect(store.pruneExpired(NOW)).resolves.toBe(0);
            await expect(store.pruneExpired(NOW + 1)).resolves.toBeGreaterThanOrEqual(1);
            expect(await store.readInvitation(digest, NOW + 1)).toBeUndefined();
            expect((await queue(store, carol, null, 10, NOW + 1)).deliveries).toHaveLength(0);
            expect((await queue(store, bob, published.eventId, 10, NOW + 1)).generation).toEqual(
                bobBefore.generation,
            );
            expect((await queue(store, carol, null, 10, NOW + 1)).generation).toEqual(
                advanceLossGeneration(carolBefore.generation, 1),
            );
            await expect(store.pruneExpired(NOW + 1)).resolves.toBe(0);
            await expect(store.pruneExpired(NOW + 2)).resolves.toBe(0);
        } finally {
            await store.close();
        }

        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumDeliveryTtlMilliseconds: RETENTION_MILLISECONDS },
            undefined,
            () => NOW,
        );
        try {
            await expect(
                relay.publish(
                    chaosDelivery(sender, recipients(bob), {
                        id: 11,
                        now: NOW,
                        expiresAt: NOW + RETENTION_MILLISECONDS,
                    }),
                    "sql-chaos",
                ),
            ).resolves.toMatchObject({ duplicate: false });
            await expect(
                relay.publish(
                    chaosDelivery(sender, recipients(bob), {
                        id: 12,
                        now: NOW,
                        expiresAt: NOW + RETENTION_MILLISECONDS + 1,
                    }),
                    "sql-chaos",
                ),
            ).rejects.toMatchObject({ status: 401 });
        } finally {
            await relay.close();
        }
    });

    test("SQL-07 quota rejection is atomic and capacity recovers exactly once", async () => {
        const store = new SqliteRelayStore(":memory:");
        const alice = secret(13);
        const bobSender = secret(14);
        const target = identity(secret(15));
        try {
            const limits = {
                ...LIMITS,
                maximumItems: 1,
                maximumSenderItems: 1,
                maximumGlobalItems: 1,
            };
            const first = await store.publish(
                chaosDelivery(alice, recipients(target), { id: 13 }),
                NOW,
                limits,
                PRINCIPAL,
            );
            await expect(
                store.publish(
                    chaosDelivery(alice, recipients(target), { id: 14 }),
                    NOW,
                    { ...limits, maximumItems: 10, maximumGlobalItems: 10 },
                    PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 429, body: { error: "sender_full" } });
            await expect(
                store.publish(
                    chaosDelivery(bobSender, recipients(target), { id: 15 }),
                    NOW,
                    { ...limits, maximumItems: 10 },
                    PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 503, body: { error: "relay_full" } });
            expect((await queue(store, target)).headSequence).toBe(1);
            await store.acknowledge(target, first.eventId, NOW);
            await store.publish(
                chaosDelivery(bobSender, recipients(target), { id: 15 }),
                NOW,
                limits,
                PRINCIPAL,
            );
            const recovered = await queue(store, target, first.eventId);
            expect(recovered.deliveries[0]!.sequence).toBe(2);
            expect(recovered.acknowledgedSequence).toBe(1);
        } finally {
            await store.close();
        }
    });

    test("SQL-09 malformed persisted payload is isolated from a healthy inbox", async () => {
        await withDatabasePath(async (path) => {
            const sender = secret(30);
            const healthy = identity(secret(31));
            const damaged = identity(secret(32));
            let store = new SqliteRelayStore(path);
            const healthyOutcome = await store.publish(
                chaosDelivery(sender, recipients(healthy), { id: 40 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            const damagedOutcome = await store.publish(
                chaosDelivery(sender, recipients(damaged), { id: 41 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            await store.close();

            const database = new DatabaseSync(path);
            database
                .prepare("UPDATE murmur_queue_deliveries SET delivery_json = ? WHERE event_id = ?")
                .run("{", damagedOutcome.eventId);
            database.close();

            store = new SqliteRelayStore(path);
            await expect(store.health()).resolves.toBeUndefined();
            expect((await queue(store, healthy)).deliveries[0]!.eventId).toBe(
                healthyOutcome.eventId,
            );
            await expect(queue(store, damaged)).rejects.toThrow();
            expect((await queue(store, healthy)).deliveries).toHaveLength(1);
            await store.close();
        });
    });

    test("SQL-10A declared restore replaces generations but preserves pending sequence state", async () => {
        const store = new SqliteRelayStore(":memory:");
        const sender = secret(33);
        const bob = identity(secret(34));
        const carol = identity(secret(35));
        const future = identity(secret(36));
        try {
            const outcome = await store.publish(
                chaosDelivery(sender, recipients(bob, carol), { id: 42 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            const before = new Map([
                [encodeBase64Url(bob), await queue(store, bob)],
                [encodeBase64Url(carol), await queue(store, carol)],
            ]);
            const futureBefore = await queue(store, future);
            await expect(store.declareRestored()).resolves.toBe(2);
            for (const recipient of [bob, carol]) {
                const prior = before.get(encodeBase64Url(recipient))!;
                const after = await queue(store, recipient);
                expect(after.generation).not.toEqual(prior.generation);
                expect(after.deliveries).toMatchObject([{ eventId: outcome.eventId, sequence: 1 }]);
                expect(after).toMatchObject({
                    head: prior.head,
                    headSequence: prior.headSequence,
                    acknowledgedSequence: prior.acknowledgedSequence,
                });
            }
            const futureAfter = await queue(store, future);
            expect(futureAfter.generation).not.toEqual(futureBefore.generation);
            await store.publish(
                chaosDelivery(sender, recipients(future), { id: 43 }),
                NOW,
                LIMITS,
                PRINCIPAL,
            );
            expect((await queue(store, future)).generation).toEqual(futureAfter.generation);
        } finally {
            await store.close();
        }
    });

    test("SQL-10 close contention completes or reports closed and reopen remains healthy", async () => {
        await withDatabasePath(async (path) => {
            const sender = secret(37);
            const bob = identity(secret(38));
            const store = new SqliteRelayStore(path);
            const results = await Promise.race([
                Promise.allSettled([
                    store.publish(
                        chaosDelivery(sender, recipients(bob), { id: 44 }),
                        NOW,
                        LIMITS,
                        PRINCIPAL,
                    ),
                    store.health(),
                    store.close(),
                ]),
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error("SQLite close contention hung")), 1_000),
                ),
            ]);
            expect(results).toHaveLength(3);
            for (const result of results) {
                if (result.status === "rejected") {
                    expect(String(result.reason)).toMatch(/closed|not open/);
                }
            }
            const reopened = new SqliteRelayStore(path);
            await expect(reopened.health()).resolves.toBeUndefined();
            const page = await queue(reopened, bob);
            expect(page.deliveries.length === 0 || page.deliveries.length === 1).toBe(true);
            await reopened.close();
        });
    });

    test("SQL-11 signed skew, replay, method mutation, and identity mutation fail closed", async () => {
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumAuthenticationSkewMilliseconds: 1_000 },
            undefined,
            () => NOW,
        );
        const alice = secret(39);
        const bobSecret = secret(40);
        const bob = identity(bobSecret);
        try {
            for (const createdAt of [NOW - 1_000, NOW + 1_000]) {
                await expect(
                    relay.readQueue(signedRead(bobSecret, { now: createdAt })),
                ).resolves.toMatchObject({ deliveries: [] });
            }
            for (const createdAt of [NOW - 1_001, NOW + 1_001]) {
                await expect(
                    relay.readQueue(signedRead(bobSecret, { now: createdAt })),
                ).rejects.toMatchObject({ status: 401 });
            }
            const published = await relay.publish(
                chaosDelivery(alice, recipients(bob), { id: 45, now: NOW }),
                "sql-chaos",
            );
            await expect(
                relay.publish(
                    chaosDelivery(alice, recipients(bob), { id: 45, now: NOW }),
                    "sql-chaos",
                ),
            ).resolves.toEqual({ eventId: published.eventId, duplicate: true });
            const read = signedRead(bobSecret, { now: NOW });
            const wrongIdentity = { ...read, recipient: identity(secret(41)) };
            await expect(relay.readQueue(wrongIdentity)).rejects.toMatchObject({ status: 401 });
            const alteredAck = signedAck(bobSecret, published.eventId, NOW);
            alteredAck.signature[0] = alteredAck.signature[0]! ^ 1;
            await expect(relay.acknowledge(alteredAck)).rejects.toMatchObject({ status: 401 });
            await expect(
                relay.acknowledge(signedAck(bobSecret, published.eventId, NOW)),
            ).resolves.toMatchObject({ removed: 1, sequence: 1 });
        } finally {
            await relay.close();
        }
    });

    test("SQL-12 invitation cache stays digest-only, idempotent, exact, and quota-bounded", async () => {
        const store = new SqliteRelayStore(":memory:");
        const first = new TextEncoder().encode("anonymous invitation one");
        const second = new TextEncoder().encode("anonymous invitation two");
        const firstDigest = sha256(first);
        const secondDigest = sha256(second);
        const wrong = firstDigest.slice();
        wrong[0] = wrong[0]! ^ 1;
        try {
            await expect(
                store.storeInvitation(
                    firstDigest,
                    first,
                    NOW + INVITATION_TTL_MILLISECONDS,
                    NOW,
                    { ...INVITATION_LIMITS, maximumPrincipalItems: 1 },
                    PRINCIPAL,
                ),
            ).resolves.toEqual({
                expiresAt: NOW + INVITATION_TTL_MILLISECONDS,
                duplicate: false,
            });
            await expect(
                store.storeInvitation(
                    firstDigest,
                    first,
                    NOW + INVITATION_TTL_MILLISECONDS + 1,
                    NOW,
                    INVITATION_LIMITS,
                    PRINCIPAL,
                ),
            ).resolves.toEqual({
                expiresAt: NOW + INVITATION_TTL_MILLISECONDS,
                duplicate: true,
            });
            expect(await store.readInvitation(wrong, NOW)).toBeUndefined();
            await expect(
                store.storeInvitation(
                    secondDigest,
                    second,
                    NOW + INVITATION_TTL_MILLISECONDS,
                    NOW,
                    { ...INVITATION_LIMITS, maximumPrincipalItems: 1 },
                    PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 429 });
            expect(
                await store.readInvitation(firstDigest, NOW + INVITATION_TTL_MILLISECONDS - 1),
            ).toBeDefined();
            expect(
                await store.readInvitation(firstDigest, NOW + INVITATION_TTL_MILLISECONDS),
            ).toBeUndefined();
            await store.pruneExpired(NOW + INVITATION_TTL_MILLISECONDS);
            await expect(
                store.storeInvitation(
                    secondDigest,
                    second,
                    NOW + INVITATION_TTL_MILLISECONDS + 1,
                    NOW + INVITATION_TTL_MILLISECONDS,
                    { ...INVITATION_LIMITS, maximumPrincipalItems: 1 },
                    PRINCIPAL,
                ),
            ).resolves.toMatchObject({ duplicate: false });
        } finally {
            await store.close();
        }
    });

    test("FAN-01/02 manifest-first crashes and every target cut recover idempotently", async () => {
        const delivery = fanoutDelivery(1, 4);
        const store = new ManifestStore();
        const target = new SequencedTarget();
        const scheduler = new RecordingScheduler();
        const coordinator = new DurableFanoutCoordinator(store, target, scheduler, {
            now: () => NOW,
        });
        const accepted = await coordinator.publish(delivery, "fanout-chaos");
        expect(store.manifests[0]).toMatchObject({
            eventId: accepted.eventId,
            pendingRecipients: delivery.recipients,
            completed: false,
        });
        expect(target.inboxes.size).toBe(0);

        for (let index = 0; index < delivery.recipients.length; index += 1) {
            const recipient = encodeBase64Url(delivery.recipients[index]!);
            const attempt = `${accepted.eventId}:${recipient}`;
            if (index % 2 === 0) target.failBefore.add(attempt);
            else target.loseAfterCommit.add(attempt);
        }
        await expect(coordinator.retry()).resolves.toMatchObject({ pending: true });
        await expect(coordinator.retry()).resolves.toEqual({
            completedManifests: 1,
            pending: false,
        });
        expect(store.manifests[0]!.pendingRecipients).toEqual([]);
        expect(store.manifests[0]!.completed).toBe(true);
        for (const recipient of delivery.recipients) {
            const inbox = target.inboxes.get(encodeBase64Url(recipient));
            expect([...inbox!.values()]).toEqual([{ eventId: accepted.eventId, sequence: 1 }]);
        }
    });

    test("FAN-03/04 permanent failure and concurrent workers never fake completion", async () => {
        const delivery = fanoutDelivery(2, 3);
        const store = new ManifestStore();
        const target = new SequencedTarget();
        const scheduler = new RecordingScheduler();
        const first = new DurableFanoutCoordinator(store, target, scheduler, { now: () => NOW });
        const second = new DurableFanoutCoordinator(store, target, scheduler, { now: () => NOW });
        await first.publish(delivery, "fanout-chaos");
        const failed = encodeBase64Url(delivery.recipients[1]!);
        target.permanentFailure.add(failed);
        const outcomes = await Promise.all([first.retry(), second.retry()]);
        expect(outcomes.every((outcome) => outcome.pending)).toBe(true);
        expect(store.manifests[0]!.completed).toBe(false);
        expect(store.manifests[0]!.pendingRecipients.map(encodeBase64Url)).toEqual([failed]);
        target.permanentFailure.clear();
        await expect(first.retry()).resolves.toEqual({ completedManifests: 1, pending: false });
        expect(store.manifests[0]!.completed).toBe(true);
        for (const recipient of delivery.recipients) {
            expect(target.inboxes.get(encodeBase64Url(recipient))!.size).toBe(1);
        }
    });

    test("FAN-05 corrupted manifests fail closed without changed target insertion", async () => {
        for (const corruption of ["digest", "duplicate", "missing-status"] as const) {
            const delivery = fanoutDelivery(3, 3);
            const store = new ManifestStore();
            const target = new SequencedTarget();
            const coordinator = new DurableFanoutCoordinator(
                store,
                target,
                new RecordingScheduler(),
                { now: () => NOW },
            );
            await coordinator.publish(delivery, "fanout-chaos");
            store.corrupt = corruption;
            await expect(coordinator.retry()).rejects.toThrow("Corrupt fanout manifest");
            expect(target.inboxes.size).toBe(0);
            expect(store.manifests[0]!.completed).toBe(false);
        }
    });

    test(
        "FAN-06 32 fixed seeds settle 1,000 manifests with exact contiguous targets",
        { timeout: 60_000 },
        async () => {
            interface SoakResult {
                readonly completed: number;
                readonly references: number;
                readonly attempts: number;
                readonly schedules: number;
            }

            const run = async (seedValue: number): Promise<SoakResult> => {
                let state = seedValue >>> 0;
                const next = (maximum: number): number => {
                    state = (Math.imul(state ^ (state >>> 15), 0x2c1b3c6d) + 0x9e3779b9) >>> 0;
                    return state % maximum;
                };
                const store = new ManifestStore();
                const target = new SequencedTarget();
                const scheduler = new RecordingScheduler();
                let coordinator = new DurableFanoutCoordinator(store, target, scheduler, {
                    now: () => NOW,
                    maximumManifestsPerRun: 1_024,
                });
                let references = 0;
                for (let index = 0; index < 1_000; index += 1) {
                    const recipientCount = next(16) + 1;
                    const delivery = fanoutDelivery(index, recipientCount);
                    const outcome = await coordinator.publish(delivery, "fanout-soak");
                    references += recipientCount;
                    for (const recipient of delivery.recipients) {
                        const key = `${outcome.eventId}:${encodeBase64Url(recipient)}`;
                        if (next(100) < 5) target.loseAfterCommit.add(key);
                    }
                }
                for (let round = 0; round < 1_001; round += 1) {
                    if (next(100) < 2) {
                        coordinator = new DurableFanoutCoordinator(store, target, scheduler, {
                            now: () => NOW,
                            maximumManifestsPerRun: 1_024,
                        });
                    }
                    const outcome = await coordinator.retry();
                    if (!outcome.pending) break;
                    if (round === 1_000) {
                        throw new Error("Fanout soak did not settle in 1,001 rounds");
                    }
                }
                expect(store.manifests.every((manifest) => manifest.completed)).toBe(true);
                for (const inbox of target.inboxes.values()) {
                    expect([...inbox.values()].map((record) => record.sequence)).toEqual(
                        Array.from({ length: inbox.size }, (_, index) => index + 1),
                    );
                }
                return {
                    completed: store.manifests.filter((manifest) => manifest.completed).length,
                    references,
                    attempts: [...target.attempts.values()].reduce(
                        (total, value) => total + value,
                        0,
                    ),
                    schedules: scheduler.scheduled.length,
                };
            };

            for (let seedValue = 0x46414e00; seedValue <= 0x46414e1f; seedValue += 1) {
                const first = await run(seedValue);
                const replay = await run(seedValue);
                expect(first).toEqual(replay);
                expect(first.completed).toBe(1_000);
                await new Promise<void>((resolve) => setTimeout(resolve, 0));
            }
        },
    );
});
