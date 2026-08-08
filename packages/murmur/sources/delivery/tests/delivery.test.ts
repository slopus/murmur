import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    HttpDeliveryTransport,
    InboxProcessor,
    InboxStateRollbackError,
    OversizedInboxDeliveryError,
    TerminalInboxDeliveryError,
    DeliveryCursorTrimmedError,
    createSignedDelivery,
    createSignedInboxRead,
    parseInboxPage,
    type DeliveryFetch,
    type DeliveryTransport,
    type SignedInboxAck,
    type SignedInboxRead,
} from "../index.js";

const NOW = 1_700_000_000_000;

function relayEventId(sequence: number, time: number = NOW): string {
    const timestamp = time.toString(16).padStart(12, "0");
    return `${timestamp.slice(0, 8)}-${timestamp.slice(8)}-7000-8000-${sequence
        .toString(16)
        .padStart(12, "0")}`;
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "delivery-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

describe("delivery client", () => {
    test("interoperates with the relay and acknowledges after the local transaction", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        try {
            await transport.publish(
                createSignedDelivery(alice, [bob.publicKey], utf8Encode("hello"), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            const processor = new InboxProcessor(
                { identity: bob, store, transport },
                async (transaction, queued) => {
                    await transaction.set("application/message", queued.delivery.ciphertext);
                },
                { now: () => NOW },
            );
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 1,
                rejected: 0,
                exhausted: true,
            });
            expect(utf8Decode((await store.get("application/message"))!)).toBe("hello");
            const page = await transport.read(createSignedInboxRead(bob, { createdAt: NOW }));
            expect(page.deliveries).toHaveLength(0);
        } finally {
            await relay.close();
        }
    });

    test("retries acknowledgement after a crash without applying twice", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const http = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        let failAcknowledgement = true;
        const transport: DeliveryTransport = {
            publish: (delivery, signal) => http.publish(delivery, signal),
            read: (read, signal) => http.read(read, signal),
            acknowledge: async (acknowledgement, signal) => {
                if (failAcknowledgement) {
                    failAcknowledgement = false;
                    throw new Error("injected acknowledgement failure");
                }
                return http.acknowledge(acknowledgement, signal);
            },
        };
        let applications = 0;
        try {
            await http.publish(
                createSignedDelivery(alice, [bob.publicKey], utf8Encode("once"), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            const processor = new InboxProcessor(
                { identity: bob, store, transport },
                async (transaction) => {
                    applications += 1;
                    await transaction.set("application/applied", utf8Encode("yes"));
                },
                { now: () => NOW },
            );
            await expect(processor.synchronize()).rejects.toThrow(
                "injected acknowledgement failure",
            );
            expect(applications).toBe(1);
            expect(await processor.cursor()).not.toBeNull();
            await expect(processor.synchronize()).resolves.toMatchObject({ processed: 0 });
            expect(applications).toBe(1);
        } finally {
            await relay.close();
        }
    });

    test("rolls back transient failures and durably advances terminal failures", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        let terminal = false;
        try {
            await transport.publish(
                createSignedDelivery(alice, [bob.publicKey], utf8Encode("bad"), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            const processor = new InboxProcessor(
                { identity: bob, store, transport },
                async (transaction) => {
                    await transaction.set("application/partial", utf8Encode("rollback"));
                    if (!terminal) throw new Error("transient");
                    throw new TerminalInboxDeliveryError("unsupported_frame");
                },
                { now: () => NOW, maximumRejections: 1 },
            );
            await expect(processor.synchronize()).rejects.toThrow("transient");
            expect(await store.get("application/partial")).toBeUndefined();
            expect(await processor.cursor()).toBeNull();

            terminal = true;
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 0,
                rejected: 1,
            });
            expect(await store.get("application/partial")).toBeUndefined();
            expect(await processor.rejections()).toMatchObject([{ code: "unsupported_frame" }]);
        } finally {
            await relay.close();
        }
    });

    test("persists and acknowledges an oversized terminal head", async () => {
        const identity = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const eventId = relayEventId(1);
        const acknowledgements: SignedInboxAck[] = [];
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async (_read: SignedInboxRead) => {
                throw new OversizedInboxDeliveryError(eventId, eventId, null);
            },
            acknowledge: async (acknowledgement) => {
                acknowledgements.push(acknowledgement);
                return { removed: 1 };
            },
        };
        const processor = new InboxProcessor(
            { identity, store, transport },
            async () => {
                throw new Error("handler must not run");
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).resolves.toEqual({
            processed: 0,
            rejected: 1,
            cursor: eventId,
            exhausted: true,
        });
        expect(acknowledgements.map((value) => value.through)).toEqual([eventId]);
        expect(await processor.rejections()).toEqual([{ eventId, code: "delivery_too_large" }]);
    });

    test("does not advance on inconsistent relay metadata", async () => {
        const identity = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("x"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => ({
                deliveries: [
                    {
                        eventId: relayEventId(2),
                        delivery,
                    },
                ],
                head: relayEventId(1),
                acknowledgedThrough: null,
                exhausted: true,
            }),
            acknowledge: async () => {
                throw new Error("unexpected acknowledgement");
            },
        };
        const processor = new InboxProcessor(
            { identity, store, transport },
            async () => undefined,
            { now: () => NOW },
        );
        await expect(processor.synchronize()).rejects.toThrow("out-of-order");
        expect(await processor.cursor()).toBeNull();
    });

    test("rejects a post-trim delivery-ID replay without applying twice", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const delivery = createSignedDelivery(alice, [bob.publicKey], utf8Encode("once"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        let applications = 0;
        try {
            const processor = new InboxProcessor(
                { identity: bob, store, transport },
                async () => {
                    applications += 1;
                },
                { now: () => NOW },
            );
            await transport.publish(delivery);
            await expect(processor.synchronize()).resolves.toMatchObject({ processed: 1 });
            await expect(transport.publish(delivery)).resolves.toMatchObject({
                duplicate: false,
            });
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 0,
                rejected: 1,
            });
            expect(applications).toBe(1);
            expect((await processor.rejections()).at(-1)).toMatchObject({
                code: "duplicate_delivery",
            });
        } finally {
            await relay.close();
        }
    });

    test("terminally rejects an expired signed delivery before its handler", async () => {
        const identity = generateIdentityKeyPair();
        const sender = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const eventId = relayEventId(3);
        const signed = createSignedDelivery(sender, [identity.publicKey], utf8Encode("stale"), {
            createdAt: NOW - 60_000,
            expiresAt: NOW - 1,
        });
        const delivery = {
            ...signed,
            sender: new Uint8Array(32),
            signature: new Uint8Array(64),
        };
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => ({
                deliveries: [{ eventId, delivery }],
                head: eventId,
                acknowledgedThrough: null,
                exhausted: true,
            }),
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store, transport },
            async () => {
                applications += 1;
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 0,
            rejected: 1,
        });
        expect(applications).toBe(0);
        expect(await processor.rejections()).toEqual([{ eventId, code: "expired_delivery" }]);
    });

    test("enforces the signed page limit for a custom transport", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("x"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => ({
                deliveries: [
                    {
                        eventId: relayEventId(4),
                        delivery,
                    },
                    {
                        eventId: relayEventId(5),
                        delivery,
                    },
                ],
                head: relayEventId(5),
                acknowledgedThrough: null,
                exhausted: true,
            }),
            acknowledge: async () => ({ removed: 0 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => undefined,
            { now: () => NOW },
        );
        await expect(processor.synchronize({ limit: 1 })).rejects.toThrow("page limit");
        expect(await processor.cursor()).toBeNull();
    });

    test("surfaces a stale local backup as explicit unrecoverable rollback", async () => {
        const identity = generateIdentityKeyPair();
        const remoteCursor = relayEventId(6);
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                throw new DeliveryCursorTrimmedError("cursor_trimmed", remoteCursor);
            },
            acknowledge: async () => ({ removed: 0 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => undefined,
            { now: () => NOW },
        );
        const error = await processor.synchronize().catch((value: unknown) => value);
        expect(error).toBeInstanceOf(InboxStateRollbackError);
        expect(error).toMatchObject({
            localCursor: null,
            acknowledgedThrough: remoteCursor,
        });
    });

    test("times out a relay request when the caller supplies no signal", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("x"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const fetch: DeliveryFetch = async (_input, init) =>
            new Promise<Response>((_resolve, reject) => {
                init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), {
                    once: true,
                });
            });
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch,
            requestTimeoutMilliseconds: 5,
        });
        await expect(transport.publish(delivery)).rejects.toThrow("timed out");
    });

    test("terminally drains new IDs when the exact replay index is full", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const first = createSignedDelivery(alice, [bob.publicKey], utf8Encode("first"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const overflow = createSignedDelivery(alice, [bob.publicKey], utf8Encode("overflow"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        let applications = 0;
        try {
            await transport.publish(first);
            await transport.publish(overflow);
            const processor = new InboxProcessor(
                { identity: bob, store: new MemoryMurmurStore(), transport },
                async () => {
                    applications += 1;
                },
                { now: () => NOW, maximumReplayEntries: 1 },
            );
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 1,
                rejected: 1,
                exhausted: true,
            });
            expect(applications).toBe(1);
            expect((await processor.rejections()).at(-1)).toMatchObject({
                code: "replay_capacity",
            });

            await transport.publish(overflow);
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 0,
                rejected: 1,
            });
            expect(applications).toBe(1);
            expect((await processor.rejections()).at(-1)).toMatchObject({
                code: "probable_duplicate_delivery",
            });
        } finally {
            await relay.close();
        }
    });

    test("keeps staged scans bounded and protects the Murmur namespace", async () => {
        const identity = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        await store.set("application/a", utf8Encode("a"));
        await store.set("application/b", utf8Encode("b"));
        const eventId = relayEventId(7);
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("x"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const page = {
            deliveries: [{ eventId, delivery }],
            head: eventId,
            acknowledgedThrough: null,
            exhausted: true,
        } as const;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => page,
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store, transport },
            async (transaction) => {
                await transaction.delete("application/a");
                const result = await transaction.scan("application/", { limit: 1 });
                expect([...result.keys()]).toEqual(["application/b"]);
                await transaction.set("murmur/session/attack", utf8Encode("no"));
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).rejects.toThrow(
            "cannot mutate delivery processor state",
        );
        expect(await store.get("application/a")).toEqual(utf8Encode("a"));
        expect(await processor.cursor()).toBeNull();
    });

    test("ignores local clock jumps for replay and delivery expiry", async () => {
        const identity = generateIdentityKeyPair();
        const sender = generateIdentityKeyPair();
        const delivery = createSignedDelivery(sender, [identity.publicKey], utf8Encode("once"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const eventIds = [relayEventId(8), relayEventId(9), relayEventId(10)];
        let reads = 0;
        let clock = NOW;
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                const eventId = eventIds[reads++]!;
                return {
                    deliveries: [{ eventId, delivery }],
                    head: eventId,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            { now: () => clock },
        );
        await expect(processor.synchronize()).resolves.toMatchObject({ processed: 1 });
        clock = NOW + 365 * 24 * 60 * 60 * 1_000;
        await expect(processor.synchronize()).rejects.toThrow("trusted clock window");
        clock = NOW;
        await expect(processor.synchronize()).resolves.toMatchObject({ rejected: 1 });
        expect(applications).toBe(1);
    });

    test("accepts the relay hard TTL boundary despite local clock lag", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("edge"), {
            createdAt: NOW,
            expiresAt: NOW + 90 * 24 * 60 * 60 * 1_000,
        });
        const eventId = relayEventId(15);
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => ({
                deliveries: [{ eventId, delivery }],
                head: eventId,
                acknowledgedThrough: null,
                exhausted: true,
            }),
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            {
                now: () => NOW - 60 * 60 * 1_000,
                maximumRelayClockSkewMilliseconds: 60 * 60 * 1_000,
            },
        );
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 1,
            rejected: 0,
        });
        expect(applications).toBe(1);
    });

    test("filters invalid IDs but not valid TTL-policy failures", async () => {
        const identity = generateIdentityKeyPair();
        const sender = generateIdentityKeyPair();
        const tooLong = createSignedDelivery(sender, [identity.publicKey], utf8Encode("long"), {
            createdAt: NOW,
            expiresAt: NOW + 90 * 24 * 60 * 60 * 1_000 + 1,
        });
        const invalid = createSignedDelivery(sender, [identity.publicKey], utf8Encode("bad"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        invalid.signature[0] = (invalid.signature[0] ?? 0) ^ 1;
        const queued = [
            { eventId: relayEventId(11), delivery: tooLong },
            { eventId: relayEventId(12), delivery: tooLong },
            { eventId: relayEventId(13), delivery: invalid },
            { eventId: relayEventId(14), delivery: invalid },
        ];
        let read = 0;
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                const next = queued[read++]!;
                return {
                    deliveries: [next],
                    head: next.eventId,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            { now: () => NOW },
        );
        for (let index = 0; index < queued.length; index += 1) {
            await expect(processor.synchronize()).resolves.toMatchObject({ rejected: 1 });
        }
        expect(applications).toBe(0);
        expect((await processor.rejections()).map(({ code }) => code)).toEqual([
            "delivery_ttl_too_long",
            "delivery_ttl_too_long",
            "invalid_delivery",
            "probable_terminal_replay",
        ]);
    });

    test("rotates terminal replay shards instead of accumulating them forever", async () => {
        const recipient = generateIdentityKeyPair();
        const sender = generateIdentityKeyPair();
        const epoch = 90 * 24 * 60 * 60 * 1_000;
        let now = NOW;
        const invalid = createSignedDelivery(sender, [recipient.publicKey], utf8Encode("invalid"), {
            createdAt: NOW,
            expiresAt: NOW + 4 * epoch,
        });
        invalid.signature[0] = (invalid.signature[0] ?? 0) ^ 1;
        const queued = [
            { eventId: relayEventId(30, NOW), delivery: invalid },
            { eventId: relayEventId(31, NOW + 1), delivery: invalid },
            { eventId: relayEventId(32, NOW + 3 * epoch), delivery: invalid },
        ];
        let read = 0;
        const store = new MemoryMurmurStore();
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                const next = queued[read++]!;
                return {
                    deliveries: [next],
                    head: next.eventId,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity: recipient, store, transport },
            async () => {
                throw new Error("handler must not run");
            },
            { now: () => now },
        );

        await processor.synchronize();
        now = NOW + 1;
        await processor.synchronize();
        const firstEpoch = Math.floor(NOW / epoch)
            .toString()
            .padStart(12, "0");
        for (let shard = 0; shard < 256; shard += 1) {
            await store.set(
                `murmur/delivery/replay/terminal/${firstEpoch}/${shard
                    .toString(16)
                    .padStart(2, "0")}`,
                new Uint8Array(4 * 1_024),
            );
        }
        now = NOW + 3 * epoch;
        await processor.synchronize();

        expect((await processor.rejections()).map(({ code }) => code)).toEqual([
            "invalid_delivery",
            "probable_terminal_replay",
            "invalid_delivery",
        ]);
        expect((await store.list("murmur/delivery/replay/terminal/")).size).toBe(1);
    });

    test("rejects oversized page arrays before decoding their entries", () => {
        expect(() =>
            parseInboxPage(
                {
                    deliveries: [{ malformed: true }, { malformed: true }],
                    head: null,
                    acknowledgedThrough: null,
                    exhausted: true,
                },
                1,
            ),
        ).toThrow("Invalid inbox page");
    });

    test("does not prune replay state from an invalid future page", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("once"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        const first = relayEventId(16);
        const invalidFuture = relayEventId(17, NOW + 120_000);
        const replay = relayEventId(18, NOW + 30_000);
        let read = 0;
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                read += 1;
                if (read === 1) {
                    return {
                        deliveries: [{ eventId: first, delivery }],
                        head: first,
                        acknowledgedThrough: null,
                        exhausted: true,
                    };
                }
                if (read === 2) {
                    return {
                        deliveries: [{ eventId: invalidFuture, delivery }],
                        head: first,
                        acknowledgedThrough: first,
                        exhausted: true,
                    };
                }
                return {
                    deliveries: [{ eventId: replay, delivery }],
                    head: replay,
                    acknowledgedThrough: first,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).resolves.toMatchObject({ processed: 1 });
        await expect(processor.synchronize()).rejects.toThrow("out-of-order");
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 0,
            rejected: 1,
        });
        expect(applications).toBe(1);
        expect((await processor.rejections()).at(-1)).toMatchObject({
            code: "duplicate_delivery",
        });
    });

    test("rejects an implausible relay timestamp without blacklisting the delivery", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("valid"), {
            createdAt: NOW,
            expiresAt: NOW + 30 * 24 * 60 * 60 * 1_000,
        });
        let read = 0;
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                read += 1;
                const eventId =
                    read === 1 ? relayEventId(19, Date.UTC(2001, 0, 1)) : relayEventId(20);
                return {
                    deliveries: [{ eventId, delivery }],
                    head: eventId,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).rejects.toThrow("trusted clock window");
        expect(await processor.cursor()).toBeNull();
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 1,
            rejected: 0,
        });
        expect(applications).toBe(1);
    });

    test("does not let an old plausible relay time poison a future delivery", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(identity, [identity.publicKey], utf8Encode("valid"), {
            createdAt: NOW,
            expiresAt: NOW + 60_000,
        });
        let read = 0;
        let applications = 0;
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unexpected publish");
            },
            read: async () => {
                read += 1;
                const eventId =
                    read === 1 ? relayEventId(21, NOW - 10 * 60 * 1_000) : relayEventId(22);
                return {
                    deliveries: [{ eventId, delivery }],
                    head: eventId,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 1 }),
        };
        const processor = new InboxProcessor(
            { identity, store: new MemoryMurmurStore(), transport },
            async () => {
                applications += 1;
            },
            { now: () => NOW },
        );
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 0,
            rejected: 1,
        });
        expect((await processor.rejections()).at(-1)).toMatchObject({
            code: "future_delivery",
        });
        await expect(processor.synchronize()).resolves.toMatchObject({
            processed: 1,
            rejected: 0,
        });
        expect(applications).toBe(1);
    });
});
