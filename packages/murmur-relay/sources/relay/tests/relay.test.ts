import { describe, expect, test } from "vitest";
import {
    identity,
    recipients,
    secret,
    signedAck,
    signedDelivery,
    signedRead,
} from "../../protocol/tests/helpers.js";
import { SqliteRelayStore } from "../../storage/index.js";
import type {
    AcknowledgeOutcome,
    PageReadConstraints,
    RelayStorePublishOutcome,
    QueueLimits,
    QueuePage,
    RelayStore,
} from "../../storage/index.js";
import type { SignedDelivery } from "../../protocol/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { RelayService, type WakeSource } from "../index.js";

const NOW = 10_000;

describe("identity queue relay", () => {
    test("health waits for the wake subscription before reporting ready", async () => {
        let releaseSubscription: (() => void) | undefined;
        const subscriptionReady = new Promise<void>((resolve) => {
            releaseSubscription = resolve;
        });
        const wakeSource: WakeSource = {
            async notify(): Promise<void> {},
            async subscribe(): Promise<void> {
                await subscriptionReady;
            },
            async close(): Promise<void> {},
        };
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, wakeSource);
        let healthy = false;
        const health = relay.health().then(() => {
            healthy = true;
        });
        await Promise.resolve();
        expect(healthy).toBe(false);
        releaseSubscription?.();
        await health;
        expect(healthy).toBe(true);
        await relay.close();
    });

    test("health surfaces a failed wake subscription", async () => {
        const wakeSource: WakeSource = {
            async notify(): Promise<void> {},
            async subscribe(): Promise<void> {
                throw new Error("LISTEN connection refused");
            },
            async close(): Promise<void> {},
        };
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, wakeSource);
        await expect(relay.health()).rejects.toThrow("LISTEN connection refused");
        await relay.close();
    });

    test("publishes, authenticates reads, and trims only after a signed ack", async () => {
        let now = NOW;
        const aliceSecret = secret(1);
        const bobSecret = secret(2);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        try {
            const delivery = signedDelivery(aliceSecret, recipients(alice, bob), { now });
            const published = await relay.publish(delivery, "relay-tests");
            expect(published.duplicate).toBe(false);
            expect(await relay.publish(delivery, "relay-tests")).toEqual({
                eventId: published.eventId,
                duplicate: true,
            });
            const bobPage = await relay.readQueue(signedRead(bobSecret, { now }));
            expect(bobPage.deliveries).toHaveLength(1);
            expect(bobPage.head).toBe(published.eventId);

            const forged = { ...signedRead(bobSecret, { now }), recipient: alice };
            await expect(relay.readQueue(forged)).rejects.toMatchObject({ status: 401 });

            expect(
                await relay.acknowledge(signedAck(bobSecret, published.eventId, now)),
            ).toMatchObject({
                removed: 1,
                sequence: 1,
            });
            expect(
                (await relay.readQueue(signedRead(bobSecret, { after: published.eventId, now })))
                    .deliveries,
            ).toEqual([]);
            await expect(
                relay.readQueue(signedRead(bobSecret, { after: null, now })),
            ).rejects.toMatchObject({ status: 409, body: { error: "cursor_trimmed" } });

            now += 1;
        } finally {
            await relay.close();
        }
    });

    test("authenticates session deletion under the account key and rejects request replay", async () => {
        const ownerSecret = secret(51);
        const sessionId = new Uint8Array(32).fill(52);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            const request = signedDelivery(ownerSecret, [], {
                id: 53,
                now: NOW,
                ciphertext: canonicalJson({
                    version: 1,
                    type: "delete_session",
                    sessionId: encodeBase64Url(sessionId),
                }),
            });
            await expect(relay.deleteSession(request)).resolves.toBe(0);
            await expect(relay.deleteSession(request)).rejects.toMatchObject({
                status: 409,
                body: { error: "replay" },
            });
            await expect(
                relay.deleteSession({ ...request, signature: new Uint8Array(64) }),
            ).rejects.toMatchObject({ status: 401, body: { error: "unauthorized" } });
        } finally {
            await relay.close();
        }
    });

    test("authenticates terminal account deletion, treats absence as a no-op, and rejects replay", async () => {
        const accountSecret = secret(54);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            const request = signedDelivery(accountSecret, [], {
                id: 55,
                now: NOW,
                ciphertext: canonicalJson({ version: 1, type: "delete_account" }),
            });
            await expect(relay.deleteAccount(request)).resolves.toBeUndefined();
            await expect(relay.deleteAccount(request)).rejects.toMatchObject({
                status: 409,
                body: { error: "replay" },
            });
            await expect(
                relay.deleteAccount({ ...request, signature: new Uint8Array(64) }),
            ).rejects.toMatchObject({ status: 401, body: { error: "unauthorized" } });
            await expect(
                relay.deleteAccount(
                    signedDelivery(secret(56), [], {
                        id: 56,
                        now: NOW,
                        ciphertext: canonicalJson({ version: 1, type: "delete_account" }),
                    }),
                ),
            ).resolves.toBeUndefined();
        } finally {
            await relay.close();
        }
    });

    test("derives device delivery ownership from the authoritative roster", async () => {
        const accountSecret = secret(57);
        const account = identity(accountSecret);
        const deviceSecret = secret(58);
        const device = identity(deviceSecret);
        const recipient = identity(secret(59));
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            await relay.mutateDeviceRoster(
                signedDelivery(accountSecret, recipients(device), {
                    id: 57,
                    now: NOW,
                    ciphertext: canonicalJson({
                        version: 1,
                        type: "register",
                        deviceKey: encodeBase64Url(device),
                        resetGeneration: 0,
                        keyPackage: encodeBase64Url(new Uint8Array([1])),
                        encryptedMetadata: encodeBase64Url(new Uint8Array([2])),
                    }),
                }),
                "relay-tests",
            );
            await expect(
                relay.publish(
                    signedDelivery(deviceSecret, recipients(recipient), { id: 58, now: NOW }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 401, body: { error: "unauthorized" } });
            await expect(
                relay.publish(
                    signedDelivery(deviceSecret, recipients(recipient), {
                        id: 59,
                        now: NOW,
                        senderAccount: account,
                    }),
                    "relay-tests",
                ),
            ).resolves.toMatchObject({ duplicate: false });
        } finally {
            await relay.close();
        }
    });

    test("notifies a connected account device when its owner roster changes", async () => {
        const accountSecret = secret(60);
        const account = identity(accountSecret);
        const deviceSecret = secret(61);
        const device = identity(deviceSecret);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            await relay.mutateDeviceRoster(
                signedDelivery(accountSecret, recipients(device), {
                    id: 60,
                    now: NOW,
                    ciphertext: canonicalJson({
                        version: 1,
                        type: "register",
                        deviceKey: encodeBase64Url(device),
                        resetGeneration: 0,
                        keyPackage: encodeBase64Url(new Uint8Array([1])),
                        encryptedMetadata: encodeBase64Url(new Uint8Array()),
                    }),
                }),
                "relay-tests",
            );
            const subscription = await relay.openQueueEventStream(
                signedRead(deviceSecret, { limit: 1, now: NOW }),
            );
            const iterator = subscription.events[Symbol.asyncIterator]();
            await expect(iterator.next()).resolves.toMatchObject({
                value: { type: "continuity" },
            });
            await expect(iterator.next()).resolves.toMatchObject({
                value: { delivery: { sender: account } },
            });
            await expect(relay.recordDeviceAccess(device, NOW + 1_000)).resolves.toBe(true);
            await expect(iterator.next()).resolves.toMatchObject({
                value: { type: "device_roster_changed", accountKey: account },
            });
            subscription.close();
        } finally {
            await relay.close();
        }
    });

    test("enforces signatures, ciphertext, recipient, TTL, and signed-request time limits", async () => {
        let now = NOW;
        const aliceSecret = secret(3);
        const alice = identity(aliceSecret);
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                maximumCiphertextBytes: 4,
                maximumRecipients: 1,
                maximumDeliveryTtlMilliseconds: 1_000,
                maximumAuthenticationSkewMilliseconds: 1,
            },
            undefined,
            () => now,
        );
        try {
            await expect(
                Reflect.apply(relay.publish, relay, [
                    signedDelivery(aliceSecret, recipients(alice), { now }),
                ]),
            ).rejects.toMatchObject({ status: 400, body: { error: "malformed" } });
            await expect(
                relay.publish(
                    {
                        ...signedDelivery(aliceSecret, recipients(alice), { now }),
                        ciphertext: new Uint8Array([9]),
                    },
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 401 });
            await expect(
                relay.publish(
                    signedDelivery(aliceSecret, recipients(alice), {
                        now,
                        ciphertext: new Uint8Array(5),
                    }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                relay.publish(
                    signedDelivery(aliceSecret, recipients(alice, identity(secret(4))), { now }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                relay.publish(
                    signedDelivery(aliceSecret, recipients(alice), {
                        now,
                        expiresAt: now + 1_001,
                    }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 401 });
            await expect(
                relay.publish(
                    signedDelivery(aliceSecret, recipients(alice), {
                        now: 0,
                        expiresAt: now + 1,
                    }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 401 });
            await expect(
                relay.publish(
                    signedDelivery(aliceSecret, recipients(alice), {
                        now: now + 1,
                        expiresAt: now + 1,
                    }),
                    "relay-tests",
                ),
            ).rejects.toMatchObject({ status: 401 });
            now += 10 * 60 * 1_000;
            await expect(
                relay.readQueue(signedRead(aliceSecret, { now: NOW })),
            ).rejects.toMatchObject({ status: 401 });
        } finally {
            await relay.close();
        }
    });

    test("long polling closes the registration race and wakes on publication", async () => {
        const aliceSecret = secret(5);
        const bobSecret = secret(6);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            const waiting = relay.readQueue(
                signedRead(bobSecret, { now: NOW, waitMilliseconds: 5_000 }),
            );
            await Promise.resolve();
            const published = await relay.publish(
                signedDelivery(aliceSecret, recipients(alice, bob), { now: NOW }),
                "relay-tests",
            );
            const page = await waiting;
            expect(page.deliveries.map(({ eventId }) => eventId)).toEqual([published.eventId]);
        } finally {
            await relay.close();
        }
    });

    test("streams exact queued deliveries in recipient UUIDv7 order", async () => {
        const aliceSecret = secret(51);
        const bobSecret = secret(52);
        const bob = identity(bobSecret);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const controller = new AbortController();
        try {
            await expect(
                relay.openQueueEventStream(
                    signedRead(bobSecret, { now: NOW, limit: 1, waitMilliseconds: 1 }),
                ),
            ).rejects.toMatchObject({ status: 400 });
            const subscription = await relay.openQueueEventStream(
                signedRead(bobSecret, { now: NOW, limit: 1 }),
                controller.signal,
            );
            await expect(
                relay.openQueueEventStream(signedRead(bobSecret, { now: NOW, limit: 1 })),
            ).rejects.toMatchObject({ status: 429 });
            const iterator = subscription.events[Symbol.asyncIterator]();
            const waiting = iterator.next();
            await Promise.resolve();
            const firstDelivery = signedDelivery(aliceSecret, recipients(bob), {
                id: 51,
                now: NOW,
            });
            const secondDelivery = signedDelivery(aliceSecret, recipients(bob), {
                id: 52,
                now: NOW,
            });
            const firstPublished = await relay.publish(firstDelivery, "relay-tests");
            const secondPublished = await relay.publish(secondDelivery, "relay-tests");
            expect(await waiting).toMatchObject({
                done: false,
                value: {
                    type: "continuity",
                    headSequence: 0,
                    acknowledgedSequence: 0,
                },
            });
            expect(await iterator.next()).toEqual({
                done: false,
                value: {
                    eventId: firstPublished.eventId,
                    sequence: 1,
                    delivery: firstDelivery,
                },
            });
            expect(await iterator.next()).toEqual({
                done: false,
                value: {
                    eventId: secondPublished.eventId,
                    sequence: 2,
                    delivery: secondDelivery,
                },
            });
            expect(secondPublished.eventId > firstPublished.eventId).toBe(true);
            subscription.close();
            await expect(iterator.next()).resolves.toMatchObject({ done: true });
        } finally {
            controller.abort();
            await relay.close();
        }
    });

    test("expired queue data disappears and acknowledgement becomes a no-op", async () => {
        let now = NOW;
        const aliceSecret = secret(7);
        const bobSecret = secret(8);
        const bob = identity(bobSecret);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        try {
            const published = await relay.publish(
                signedDelivery(aliceSecret, recipients(bob), {
                    now,
                    expiresAt: now + 1,
                }),
                "relay-tests",
            );
            now += 2;
            const page = await relay.readQueue(signedRead(bobSecret, { now }));
            expect(page).toMatchObject({
                deliveries: [],
                head: published.eventId,
                headSequence: 1,
                exhausted: true,
            });
            expect(await relay.acknowledge(signedAck(bobSecret, published.eventId, now))).toEqual({
                removed: 0,
                sequence: 1,
                generation: expect.any(Uint8Array),
            });
        } finally {
            await relay.close();
        }
    });

    test("abort during the registration recheck is handled and identity waits are bounded", async () => {
        let readCount = 0;
        let releaseSecondRead: (() => void) | undefined;
        let secondReadStarted: (() => void) | undefined;
        const secondRead = new Promise<void>((resolve) => {
            secondReadStarted = resolve;
        });
        const release = new Promise<void>((resolve) => {
            releaseSecondRead = resolve;
        });
        const emptyPage: QueuePage = {
            deliveries: [],
            head: null,
            headSequence: 0,
            acknowledgedThrough: null,
            acknowledgedSequence: 0,
            generation: new Uint8Array(32),
            exhausted: true,
        };
        const store: RelayStore = {
            async readDeviceRoster() {
                return undefined;
            },
            async recordDeviceAccess() {
                return false;
            },
            async readDeviceAccount() {
                return undefined;
            },
            async readSessionState() {
                return undefined;
            },
            async mutateDeviceRoster() {
                throw new Error("not used");
            },
            async uploadDirectoryPrekeys() {
                throw new Error("not used");
            },
            async claimDirectory() {
                throw new Error("not used");
            },
            async publish(
                _delivery: SignedDelivery,
                _now: number,
                _limits: QueueLimits,
            ): Promise<RelayStorePublishOutcome> {
                throw new Error("Unused");
            },
            async deleteSessionDeliveries(): Promise<number> {
                throw new Error("Unused");
            },
            async deleteAccountState(): Promise<void> {
                throw new Error("Unused");
            },
            async readQueue(
                _recipient: Uint8Array,
                _after: string | null,
                _limit: number,
                _now: number,
                _constraints: PageReadConstraints,
            ): Promise<QueuePage> {
                readCount += 1;
                if (readCount === 2) {
                    secondReadStarted?.();
                    await release;
                }
                return emptyPage;
            },
            async acknowledge(): Promise<AcknowledgeOutcome> {
                throw new Error("Unused");
            },
            async declareRestored(): Promise<number> {
                throw new Error("Unused");
            },
            async pruneExpired(): Promise<number> {
                return 0;
            },
            async health(): Promise<void> {},
            async close(): Promise<void> {},
        };
        const bobSecret = secret(9);
        const relay = new RelayService(
            store,
            { maximumConcurrentLongPolls: 2, maximumConcurrentLongPollsPerIdentity: 1 },
            undefined,
            () => NOW,
        );
        const controller = new AbortController();
        try {
            const waiting = relay.readQueue(
                signedRead(bobSecret, { now: NOW, waitMilliseconds: 5_000 }),
                controller.signal,
            );
            await secondRead;
            await expect(
                relay.readQueue(signedRead(bobSecret, { now: NOW, waitMilliseconds: 5_000 })),
            ).rejects.toMatchObject({ status: 429 });
            controller.abort();
            releaseSecondRead?.();
            await expect(waiting).rejects.toMatchObject({
                status: 400,
                body: { error: "aborted" },
            });
        } finally {
            releaseSecondRead?.();
            await relay.close();
        }
    });
});
