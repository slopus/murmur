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
    PublishOutcome,
    QueueLimits,
    QueuePage,
    RelayStore,
} from "../../storage/index.js";
import type { SignedDelivery } from "../../protocol/index.js";
import { RelayService } from "../index.js";

const NOW = 10_000;

describe("identity queue relay", () => {
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

            expect(await relay.acknowledge(signedAck(bobSecret, published.eventId, now))).toEqual({
                removed: 1,
            });
            expect(
                (await relay.readQueue(signedRead(bobSecret, { after: published.eventId, now })))
                    .deliveries,
            ).toEqual([]);
            expect(
                (await relay.readQueue(signedRead(bobSecret, { after: null, now }))).deliveries,
            ).toEqual([]);

            now += 1;
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
                head: null,
                exhausted: true,
            });
            expect(await relay.acknowledge(signedAck(bobSecret, published.eventId, now))).toEqual({
                removed: 0,
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
            acknowledgedThrough: null,
            exhausted: true,
        };
        const store: RelayStore = {
            async storeInvitation() {
                throw new Error("Unused");
            },
            async readInvitation() {
                throw new Error("Unused");
            },
            async publish(
                _delivery: SignedDelivery,
                _now: number,
                _limits: QueueLimits,
            ): Promise<PublishOutcome> {
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
