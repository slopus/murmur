import { createRootContext, type Context } from "@steve.kite/stdlib";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    createSignedDelivery,
    type DeliveryFetch,
    type DeliveryTransport,
    type SignedDelivery,
} from "../../delivery/index.js";
import {
    decodeIdentityRoot,
    destroyIdentity,
    generateIdentityKeyPair,
} from "../../crypto/index.js";
import { MemoryMurmurStore, type MurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";
import { MurmurClient, type MurmurSessionLimits, type MurmurUpdate } from "../index.js";
import { decodeSessionRecord, encodeSessionRecord } from "../impl/sessionRecords.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "session-tests",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(
    relay: RelayService,
    store = new MemoryMurmurStore(),
    limits: MurmurSessionLimits = {},
): Promise<MurmurClient> {
    return MurmurClient.open(ctx, {
        relay: "https://relay.test",
        fetch: relayFetch(relay),
        store,
        limits,
        now: () => NOW,
    });
}

async function activate(
    value: MurmurClient,
    id: Uint8Array,
    process?: (update: MurmurUpdate) => void | Promise<void>,
): Promise<number> {
    await value.activateSession(ctx, id);
    return process === undefined ? 0 : consume(value, process);
}

async function consume(
    value: MurmurClient,
    process: (update: MurmurUpdate) => void | Promise<void>,
): Promise<number> {
    let consumed = 0;
    await value.synchronize(
        ctx,
        { waitMilliseconds: 0 },
        {
            onUpdates: async (_ctx, updates) => {
                for (const update of updates) await process(update);
                consumed += updates.length;
            },
        },
    );
    return consumed;
}

async function prefixCount(store: MurmurStore, prefix: string): Promise<number> {
    const entries = await store.scan(ctx, prefix, { limit: 256 });
    try {
        return entries.size;
    } finally {
        for (const value of entries.values()) zeroBytes(value);
    }
}

describe("stateful MLS sessions", () => {
    test("refreshes and reports owner devices after a connected relay invalidation", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const value = await client(relay);
        const controller = new AbortController();
        let connect!: () => void;
        const connected = new Promise<void>((resolve) => {
            connect = resolve;
        });
        let report!: (devices: Awaited<ReturnType<MurmurClient["devices"]>>) => void;
        const changed = new Promise<Awaited<ReturnType<MurmurClient["devices"]>>>((resolve) => {
            report = resolve;
        });
        const realtime = value.sync(ctx, {
            abort: controller.signal,
            onConnected: () => connect(),
            onDevicesChanged: (_ctx, devices) => report(devices),
        });
        try {
            await connected;
            await expect(relay.recordDeviceAccess(value.deviceKey, NOW + 1_000)).resolves.toBe(
                true,
            );
            await expect(changed).resolves.toMatchObject([
                { deviceKey: value.deviceKey, lastAccessedAt: NOW + 1_000 },
            ]);
        } finally {
            controller.abort();
            await realtime;
            value.close(ctx);
            await relay.close();
        }
    });

    test("retries terminal account deletion and wipes every local key only after confirmation", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const store = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let dropFirstConfirmation = true;
        const transport: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => base.publish(ctx, delivery, signal),
            deleteSession: (_ctx, delivery, signal) => base.deleteSession(ctx, delivery, signal),
            deleteAccount: async (_ctx, delivery, signal) => {
                await base.deleteAccount(ctx, delivery, signal);
                if (dropFirstConfirmation) {
                    dropFirstConfirmation = false;
                    throw new DeliveryTransportError(0, "connection_lost");
                }
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
            uploadDirectoryPrekeys: (_ctx, delivery, signal) =>
                base.uploadDirectoryPrekeys(ctx, delivery, signal),
            claimDirectory: (_ctx, account, ticket, signal) =>
                base.claimDirectory(ctx, account, ticket, signal),
        };
        const value = await MurmurClient.open(ctx, { transport, store, now: () => NOW });
        const account = value.identity;
        try {
            await store.set(ctx, "application/unrelated", new Uint8Array([1, 2, 3]));
            await expect(value.deleteAccount(ctx)).rejects.toMatchObject({
                code: "connection_lost",
            });
            expect(await prefixCount(store, "")).toBeGreaterThan(0);
            expect(await relay.readDeviceRoster(account)).toBeUndefined();

            await expect(value.deleteAccount(ctx)).resolves.toBeUndefined();
            expect(await prefixCount(store, "")).toBe(0);
            expect(() => value.identity).toThrow("closed");
            await expect(value.sessions(ctx)).rejects.toThrow("closed");
        } finally {
            value.close(ctx);
            await relay.close();
        }
    });

    test("queues initial group messages offline and relays Commit, Welcome, then messages after restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const published: SignedDelivery[] = [];
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const recording: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                published.push(delivery);
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        let alice = await MurmurClient.open(ctx, {
            transport: recording,
            store: aliceStore,
            now: () => NOW,
        });
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("offline group"),
                members: [await bob.createKeyPackage(ctx)],
            });
            const first = await alice.send(ctx, session.id, utf8Encode("first offline"));
            const second = await alice.send(ctx, session.id, utf8Encode("second offline"));

            expect(published).toEqual([]);
            expect(await alice.session(ctx, session.id)).toMatchObject({ status: "creating" });
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/session-outbox/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(5);
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/post-commit-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(3);

            const aliceIdentity = alice.deviceKey;
            alice.close(ctx);
            alice = await MurmurClient.open(ctx, {
                transport: recording,
                store: aliceStore,
                now: () => NOW,
            });

            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 3,
                pendingOutboxes: 3,
                transientPublicationFailures: 0,
                terminalPublicationFailures: 0,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([3, 1, 2]);
            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 3,
                pendingOutboxes: 0,
                transientPublicationFailures: 0,
                terminalPublicationFailures: 0,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([3, 1, 2, 2, 2, 2]);
            expect(published.slice(3, 5).map((delivery) => delivery.id)).toEqual([first, second]);
            expect(
                published.map((delivery) => delivery.recipients.map(encodeBase64Url).sort()),
            ).toEqual([[], [encodeBase64Url(bob.deviceKey)], [], [], [], []]);
            expect(
                published
                    .filter((delivery) => delivery.sessionControl !== null)
                    .map((delivery) =>
                        delivery.sessionControl!.coveredDevices.map(encodeBase64Url).sort(),
                    ),
            ).toEqual(
                Array.from({ length: 5 }, () =>
                    [encodeBase64Url(aliceIdentity), encodeBase64Url(bob.deviceKey)].sort(),
                ),
            );

            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await bob.session(ctx, session.id)).toMatchObject({ status: "pending" });
            const received: string[] = [];
            expect(
                await activate(bob, session.id, async (update) => {
                    received.push(utf8Decode(update.bytes));
                }),
            ).toBe(2);
            expect(received).toEqual(["first offline", "second offline"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("streams realtime events in order and publishes local outboxes without polling", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const aliceController = new AbortController();
        const bobController = new AbortController();
        const resumedController = new AbortController();
        let aliceRealtime: Promise<void> | undefined;
        let bobRealtime: Promise<void> | undefined;
        let resumed: Promise<void> | undefined;
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("realtime SSE"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            const received: string[] = [];
            let finishFirst!: () => void;
            const firstComplete = new Promise<void>((resolve) => {
                finishFirst = resolve;
            });
            let connected = 0;
            let disconnected = 0;
            aliceRealtime = alice.sync(ctx, { abort: aliceController.signal });
            bobRealtime = bob.sync(ctx, {
                abort: bobController.signal,
                onConnected: (_ctx) => {
                    connected += 1;
                },
                onDisconnected: (_ctx) => {
                    disconnected += 1;
                },
                onUpdates: async (_ctx, updates) => {
                    for (const update of updates) {
                        received.push(utf8Decode(update.bytes));
                    }
                    if (received.length === 1) {
                        bobController.abort();
                        finishFirst();
                    }
                },
            });
            await alice.send(ctx, session.id, utf8Encode("first"));
            await alice.send(ctx, session.id, utf8Encode("second"));
            let timeout: ReturnType<typeof setTimeout> | undefined;
            try {
                await Promise.race([
                    firstComplete,
                    new Promise<never>((_resolve, reject) => {
                        timeout = setTimeout(
                            () => reject(new Error("First realtime SSE connection timed out")),
                            5_000,
                        );
                    }),
                ]);
            } finally {
                if (timeout !== undefined) clearTimeout(timeout);
            }
            await bobRealtime;
            expect(received).toEqual(["first"]);
            expect({ connected, disconnected }).toEqual({ connected: 1, disconnected: 1 });

            let finishSecond!: () => void;
            const secondComplete = new Promise<void>((resolve) => {
                finishSecond = resolve;
            });
            resumed = bob.sync(ctx, {
                abort: resumedController.signal,
                onUpdates: async (_ctx, updates) => {
                    for (const update of updates) {
                        received.push(utf8Decode(update.bytes));
                    }
                    if (received.length === 2) {
                        aliceController.abort();
                        resumedController.abort();
                        finishSecond();
                    }
                },
            });
            timeout = undefined;
            try {
                await Promise.race([
                    secondComplete,
                    new Promise<never>((_resolve, reject) => {
                        timeout = setTimeout(
                            () => reject(new Error("Resumed realtime SSE connection timed out")),
                            5_000,
                        );
                    }),
                ]);
            } finally {
                if (timeout !== undefined) clearTimeout(timeout);
            }
            await Promise.all([aliceRealtime, resumed]);
            expect(received).toEqual(["first", "second"]);
        } finally {
            aliceController.abort();
            bobController.abort();
            resumedController.abort();
            await Promise.allSettled(
                [aliceRealtime, bobRealtime, resumed].filter(
                    (value): value is Promise<void> => value !== undefined,
                ),
            );
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("delivers one identity-wide ordered batch across sessions", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const first = await alice.createSession(ctx, {
                descriptor: utf8Encode("first session"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await bob.activateSession(ctx, first.id);

            const second = await alice.createSession(ctx, {
                descriptor: utf8Encode("second session"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await bob.activateSession(ctx, second.id);

            await alice.send(ctx, first.id, utf8Encode("first update"));
            await alice.send(ctx, second.id, utf8Encode("second update"));
            await alice.synchronize(ctx);

            const batches: (readonly MurmurUpdate[])[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        batches.push(updates);
                    },
                },
            );
            expect(batches).toHaveLength(1);
            expect(batches[0]!.map((update) => utf8Decode(update.bytes))).toEqual([
                "first update",
                "second update",
            ]);
            expect(batches[0]!.map((update) => encodeBase64Url(update.sessionId))).toEqual([
                encodeBase64Url(first.id),
                encodeBase64Url(second.id),
            ]);
            expect(batches[0]![0]!.id < batches[0]![1]!.id).toBe(true);
            expect(await bob.session(ctx, first.id)).toMatchObject({ bufferedEvents: 0 });
            expect(await bob.session(ctx, second.id)).toMatchObject({ bufferedEvents: 0 });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("bootstraps pending, activates, and exchanges opaque events", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const bobKeyPackage = await bob.createKeyPackage(ctx);
            const created = await alice.createSession(ctx, {
                descriptor: utf8Encode("opaque descriptor"),
                members: [bobKeyPackage],
            });

            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            const pending = await bob.session(ctx, created.id);
            expect(pending).toMatchObject({
                status: "pending",
                bufferedEvents: 0,
            });
            expect(utf8Decode(pending!.descriptor)).toBe("opaque descriptor");

            await expect(bob.send(ctx, created.id, utf8Encode("from pending"))).resolves.toEqual(
                expect.any(String),
            );
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            const aliceReceived: string[] = [];
            await consume(alice, async (event) => {
                aliceReceived.push(utf8Decode(event.bytes));
            });
            expect(aliceReceived).toEqual(["from pending"]);

            await alice.send(ctx, created.id, utf8Encode("hello"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, created.id)).toMatchObject({
                status: "pending",
                bufferedEvents: 2,
            });

            const received: string[] = [];
            await activate(bob, created.id, async (event) => {
                received.push(utf8Decode(event.bytes));
                await bobStore.set(ctx, "application/last", event.bytes);
            });
            expect(received).toEqual(["from pending", "hello"]);
            expect(utf8Decode((await bobStore.get(ctx, "application/last"))!)).toBe("hello");
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("restores identity and pending session state from the supplied store", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const store = new MemoryMurmurStore();
        const first = await client(relay, store);
        const identity = first.identity;
        first.close(ctx);
        const reopened = await client(relay, store);
        try {
            expect(reopened.identity).toEqual(identity);
        } finally {
            reopened.close(ctx);
            await relay.close();
        }
    });

    test("cleans opening identity material when the store commit rejects", async () => {
        const backing = new MemoryMurmurStore();
        const supplied = generateIdentityKeyPair();
        let encodedIdentity: Uint8Array | undefined;
        const store: MurmurStore = {
            get: (storeContext, key) => backing.get(storeContext, key),
            set: (storeContext, key, value) => {
                encodedIdentity = value;
                return backing.set(storeContext, key, value);
            },
            delete: (storeContext, key) => backing.delete(storeContext, key),
            list: (storeContext, prefix) => backing.list(storeContext, prefix),
            scan: (storeContext, prefix, options) => backing.scan(storeContext, prefix, options),
            tx: async <Result>(
                transactionContext: Context,
                operation: (ctx: Context) => Promise<Result>,
            ): Promise<Result> =>
                backing.tx(transactionContext, async (transaction) => {
                    await operation(transaction);
                    throw new Error("injected commit rejection");
                }),
        };
        const transport: DeliveryTransport = {
            publish: async (_ctx) => {
                throw new Error("unused");
            },
            read: async (_ctx) => {
                throw new Error("unused");
            },
            acknowledge: async (_ctx) => {
                throw new Error("unused");
            },
        };
        try {
            await expect(
                MurmurClient.open(ctx, {
                    identity: supplied,
                    store,
                    transport,
                    now: () => NOW,
                }),
            ).rejects.toThrow("injected commit rejection");
            expect(encodedIdentity).toBeDefined();
            expect(encodedIdentity?.every((byte) => byte === 0)).toBe(true);
            expect(supplied.secretKey.some((byte) => byte !== 0)).toBe(true);
        } finally {
            destroyIdentity(supplied);
        }
    });

    test("adds members asynchronously and enforces admin removal", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("group"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.status).toBe("pending");
            await activate(carol, session.id);

            await bob.send(ctx, session.id, utf8Encode("from bob"));
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);
            await carol.synchronize(ctx);
            const carolEvents: string[] = [];
            await consume(carol, async (event) => {
                carolEvents.push(utf8Decode(event.bytes));
            });
            expect(carolEvents).toEqual(["from bob"]);

            await expect(bob.removeMember(ctx, session.id, carol.identity)).rejects.toThrow(
                "Only an admin",
            );
            await alice.grantAdmin(ctx, session.id, bob.identity);
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect((await bob.session(ctx, session.id))?.admins).toContainEqual(bob.identity);

            await expect(bob.grantAdmin(ctx, session.id, carol.identity)).rejects.toThrow(
                "may not grant admin",
            );
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });

            await bob.grantAdmin(ctx, session.id, carol.identity);
            for (
                let cycle = 0;
                cycle < 8 &&
                !(await alice.session(ctx, session.id))?.admins.some(
                    (admin) => encodeBase64Url(admin) === encodeBase64Url(carol.identity),
                );
                cycle += 1
            ) {
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await carol.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect((await alice.session(ctx, session.id))?.admins).toContainEqual(carol.identity);
            await expect(bob.revokeAdmin(ctx, session.id, carol.identity)).rejects.toThrow(
                "Only the session owner",
            );
            await alice.revokeAdmin(ctx, session.id, carol.identity);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect((await bob.session(ctx, session.id))?.admins).not.toContainEqual(carol.identity);

            await bob.removeMember(ctx, session.id, carol.identity);
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(2);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(2);
            expect(await carol.session(ctx, session.id)).toBeUndefined();
            expect((await alice.session(ctx, session.id))?.owner).toEqual(alice.identity);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    }, 120_000);

    test("rejects an unauthorized membership Commit on every honest member", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        const carol = await client(relay);
        const dave = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("unauthorized add"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            // Model a compromised client that lies to its own local authorization check.
            const stateKey = `murmur/session-states/${encodeBase64Url(session.id)}`;
            const state = (await bobStore.get(ctx, stateKey))!;
            const record = decodeSessionRecord(state);
            try {
                await bobStore.set(
                    ctx,
                    stateKey,
                    encodeSessionRecord({
                        ...record,
                        roles: { ...record.roles, anyoneCanAddMembers: true },
                    }),
                );
            } finally {
                zeroBytes(record.epoch);
                if (record.previousEpoch !== undefined) zeroBytes(record.previousEpoch);
                zeroBytes(state);
            }

            await bob.addMember(ctx, session.id, await dave.createKeyPackage(ctx));
            await expect(bob.synchronize(ctx, { waitMilliseconds: 0 })).resolves.toMatchObject({
                transientPublicationFailures: 1,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });

            expect(await alice.session(ctx, session.id)).toMatchObject({
                members: expect.arrayContaining([alice.identity, bob.identity, carol.identity]),
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                    sendPolicy: "everyone",
                },
            });
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);
            expect(await alice.issues(ctx)).toEqual([]);
            expect(await carol.issues(ctx)).toEqual([]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            dave.close(ctx);
            await relay.close();
        }
    });

    test("quarantines a Welcome whose encrypted roles disagree with its signed summary", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceIdentity = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let aliceDeviceIdentity: ReturnType<typeof decodeIdentityRoot> | undefined;
        let tamperCreation = true;
        const transport: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (tamperCreation && delivery.sessionControl?.type === "create") {
                    tamperCreation = false;
                    return base.publish(
                        ctx,
                        createSignedDelivery(aliceDeviceIdentity!, [], delivery.ciphertext, {
                            id: delivery.id,
                            createdAt: delivery.createdAt,
                            expiresAt: delivery.expiresAt,
                            senderAccount: delivery.senderAccount,
                            ownerAccount: delivery.ownerAccount!,
                            sessionId: delivery.sessionId!,
                            sessionControl: {
                                ...delivery.sessionControl,
                                roles: {
                                    ...delivery.sessionControl.roles,
                                    sendPolicy: "admins",
                                },
                            },
                        }),
                        signal,
                    );
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
            uploadDirectoryPrekeys: (_ctx, delivery, signal) =>
                base.uploadDirectoryPrekeys(ctx, delivery, signal),
            claimDirectory: (_ctx, account, ticket, signal) =>
                base.claimDirectory(ctx, account, ticket, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            identity: aliceIdentity,
            transport,
            store: aliceStore,
            now: () => NOW,
        });
        const storedDevice = await aliceStore.get(ctx, "murmur/identity/root");
        if (storedDevice === undefined) throw new Error("Missing test device identity");
        try {
            aliceDeviceIdentity = decodeIdentityRoot(storedDevice);
        } finally {
            zeroBytes(storedDevice);
        }
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("bootstrap visible mismatch"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            const outcome = await bob.synchronize(ctx);

            expect(outcome.issues).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "visible_session_metadata_mismatch",
                        kind: "bootstrap",
                    }),
                ]),
            );
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            expect(await prefixCount(bobStore, "murmur/pending-membership-controls/")).toBe(0);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            if (aliceDeviceIdentity !== undefined) destroyIdentity(aliceDeviceIdentity);
            destroyIdentity(aliceIdentity);
            await relay.close();
        }
    });

    test("durably quarantines signed visible metadata that disagrees with MLS content", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobIdentity = generateIdentityKeyPair();
        const bobStore = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let bobDeviceIdentity: ReturnType<typeof decodeIdentityRoot> | undefined;
        let tamperNextApplication = false;
        const transport: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (
                    tamperNextApplication &&
                    delivery.sessionControl?.type === "message" &&
                    delivery.sessionControl.content === "application"
                ) {
                    tamperNextApplication = false;
                    return base.publish(
                        ctx,
                        createSignedDelivery(bobDeviceIdentity!, [], delivery.ciphertext, {
                            id: delivery.id,
                            createdAt: delivery.createdAt,
                            expiresAt: delivery.expiresAt,
                            senderAccount: delivery.senderAccount,
                            ownerAccount: delivery.ownerAccount!,
                            sessionId: delivery.sessionId!,
                            sessionControl: {
                                ...delivery.sessionControl,
                                content: "protocol",
                            },
                        }),
                        signal,
                    );
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
            uploadDirectoryPrekeys: (_ctx, delivery, signal) =>
                base.uploadDirectoryPrekeys(ctx, delivery, signal),
            claimDirectory: (_ctx, account, ticket, signal) =>
                base.claimDirectory(ctx, account, ticket, signal),
        };
        const bob = await MurmurClient.open(ctx, {
            identity: bobIdentity,
            transport,
            store: bobStore,
            now: () => NOW,
        });
        const storedDevice = await bobStore.get(ctx, "murmur/identity/root");
        if (storedDevice === undefined) throw new Error("Missing test device identity");
        try {
            bobDeviceIdentity = decodeIdentityRoot(storedDevice);
        } finally {
            zeroBytes(storedDevice);
        }
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("visible mismatch"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            tamperNextApplication = true;
            await bob.send(ctx, session.id, utf8Encode("must quarantine"));
            await bob.synchronize(ctx);
            const outcome = await alice.synchronize(ctx);
            expect(outcome.issues).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "visible_session_metadata_mismatch",
                        kind: "application",
                    }),
                ]),
            );
            const received: string[] = [];
            await consume(alice, async (update) => {
                received.push(utf8Decode(update.bytes));
            });
            expect(received).toEqual([]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            if (bobDeviceIdentity !== undefined) destroyIdentity(bobDeviceIdentity);
            destroyIdentity(bobIdentity);
            await relay.close();
        }
    });

    test("allows a non-owner member to leave asynchronously", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("leave"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);

            await bob.leave(ctx, session.id);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });

            expect((await alice.session(ctx, session.id))?.members).toEqual([alice.identity]);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("arbitrates concurrent Commits and rebases a losing staged send", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let blockBobCommit = false;
        const bobTransport: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (blockBobCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(429, "commit_blocked");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await client(relay);
        const bob = await MurmurClient.open(ctx, {
            transport: bobTransport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("concurrent commits"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.grantAdmin(ctx, session.id, bob.identity);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });

            blockBobCommit = true;
            await bob.removeMember(ctx, session.id, carol.identity);
            expect(await bob.synchronize(ctx, { waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });
            await bob.send(ctx, session.id, utf8Encode("survives losing commit"));

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });

            blockBobCommit = false;
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });

            const received: string[] = [];
            await consume(alice, async (update) => {
                received.push(utf8Decode(update.bytes));
            });
            expect(received).toEqual(["survives losing commit"]);
            expect(await alice.session(ctx, session.id)).toMatchObject({
                members: expect.arrayContaining([alice.identity, bob.identity]),
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                    sendPolicy: "everyone",
                },
            });
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(2);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(2);
            expect(await carol.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("fails a stale add generation and permits a deliberate re-add", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("removal generation"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.grantAdmin(ctx, session.id, bob.identity);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });

            await bob.removeMember(ctx, session.id, carol.identity);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });

            // Alice has not observed Bob's removal yet, so this snapshots the old generation.
            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(2);
            expect(await alice.issues(ctx)).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "add_intent_removal_generation_advanced",
                        sessionId: session.id,
                    }),
                ]),
            );

            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await carol.session(ctx, session.id)).toBeUndefined();

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(carol, session.id);

            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("terminalizes Add intents whose policy or admin authorization is lost", async () => {
        const run = async (authority: "admin" | "policy"): Promise<void> => {
            const relay = new RelayService(
                new SqliteRelayStore(":memory:"),
                {},
                undefined,
                () => NOW,
            );
            const aliceStore = new MemoryMurmurStore();
            const bobStore = new MemoryMurmurStore();
            const carolStore = new MemoryMurmurStore();
            const daveStore = new MemoryMurmurStore();
            const alice = await client(relay, aliceStore);
            const bob = await client(relay, bobStore);
            const carol = await client(relay, carolStore);
            const dave = await client(relay, daveStore);
            try {
                const session = await alice.createSession(ctx, {
                    descriptor: utf8Encode(`authorization loss ${authority}`),
                    members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
                    anyoneCanAddMembers: authority === "policy",
                });
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
                await carol.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.activateSession(ctx, session.id);
                await carol.activateSession(ctx, session.id);

                const actor = authority === "admin" ? bob : carol;
                const actorStore = authority === "admin" ? bobStore : carolStore;
                if (authority === "admin") {
                    await alice.grantAdmin(ctx, session.id, bob.identity);
                    await alice.synchronize(ctx, { waitMilliseconds: 0 });
                    await alice.synchronize(ctx, { waitMilliseconds: 0 });
                    await bob.synchronize(ctx, { waitMilliseconds: 0 });
                    await carol.synchronize(ctx, { waitMilliseconds: 0 });
                    expect((await bob.session(ctx, session.id))?.admins).toContainEqual(
                        bob.identity,
                    );
                }

                await actor.addMember(ctx, session.id, await dave.createKeyPackage(ctx));
                expect(await prefixCount(actorStore, "murmur/session-intents/")).toBe(1);
                if (authority === "admin") {
                    await alice.revokeAdmin(ctx, session.id, bob.identity);
                } else {
                    await alice.setPolicies(ctx, session.id, {
                        adminsAssignAdmins: false,
                        anyoneCanAddMembers: false,
                    });
                }
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await actor.synchronize(ctx, { waitMilliseconds: 0 });

                expect(await prefixCount(actorStore, "murmur/session-intents/")).toBe(0);
                const issues = (await actor.issues(ctx)).filter(
                    (issue) => issue.code === "intent_authorization_lost",
                );
                expect(issues).toEqual([
                    expect.objectContaining({
                        code: "intent_authorization_lost",
                        sessionId: session.id,
                        kind: "session",
                        operationId: expect.any(String),
                    }),
                ]);
                await actor.synchronize(ctx, { waitMilliseconds: 0 });
                expect(
                    (await actor.issues(ctx)).filter(
                        (issue) => issue.code === "intent_authorization_lost",
                    ),
                ).toHaveLength(1);
                expect((await actor.session(ctx, session.id))?.members).toHaveLength(3);
                expect(await dave.session(ctx, session.id)).toBeUndefined();
            } finally {
                alice.close(ctx);
                bob.close(ctx);
                carol.close(ctx);
                dave.close(ctx);
                await relay.close();
            }
        };

        await run("policy");
        await run("admin");
    }, 120_000);

    test("publishes a Welcome only after the retried Add Commit is adopted", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let blockBobCommit = false;
        const bobTransport: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (blockBobCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(429, "commit_blocked");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await MurmurClient.open(ctx, {
            transport: bobTransport,
            store: bobStore,
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("retried welcome"),
                anyoneCanAddMembers: true,
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await prefixCount(bobStore, "murmur/admission-barriers/")).toBe(0);
            await activate(bob, session.id);

            blockBobCommit = true;
            await bob.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            expect(await bob.synchronize(ctx, { waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await carol.session(ctx, session.id)).toBeUndefined();

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });

            blockBobCommit = false;
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await carol.session(ctx, session.id)).toBeUndefined();

            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await carol.session(ctx, session.id)).toMatchObject({
                status: "pending",
                policies: {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                    sendPolicy: "everyone",
                },
            });

            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(carol, session.id);
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("converges concurrent adds of one account to one membership", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let blockBobAdd = false;
        const bobTransport: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (blockBobAdd && (delivery.ciphertext[0] === 1 || delivery.ciphertext[0] === 3)) {
                    throw new DeliveryTransportError(429, "add_blocked");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await client(relay);
        const bob = await MurmurClient.open(ctx, {
            transport: bobTransport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("same account add"),
                anyoneCanAddMembers: true,
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);

            blockBobAdd = true;
            await bob.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            expect(await bob.synchronize(ctx, { waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);

            blockBobAdd = false;
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(carol, session.id);

            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("sends on the current epoch before an asynchronous add converges", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const published: SignedDelivery[] = [];
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const transport: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                published.push(delivery);
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("offline add"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await activate(bob, session.id);
            published.length = 0;

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            const messageId = await alice.send(ctx, session.id, utf8Encode("welcome carol"));
            expect(published).toEqual([]);

            expect(await alice.synchronize(ctx, { waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                pendingOutboxes: 3,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([2, 2, 3]);
            expect(published[0]?.id).toBe(messageId);
            expect(
                published.map((delivery) => delivery.recipients.map(encodeBase64Url).sort()),
            ).toEqual([[], [], []]);
            expect(
                published.map((delivery) =>
                    delivery.sessionControl!.coveredDevices.map(encodeBase64Url).sort(),
                ),
            ).toEqual([
                [encodeBase64Url(alice.deviceKey), encodeBase64Url(bob.deviceKey)].sort(),
                [encodeBase64Url(alice.deviceKey), encodeBase64Url(bob.deviceKey)].sort(),
                [
                    encodeBase64Url(alice.deviceKey),
                    encodeBase64Url(bob.deviceKey),
                    encodeBase64Url(carol.deviceKey),
                ].sort(),
            ]);

            expect(await alice.synchronize(ctx, { waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                pendingOutboxes: 1,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([2, 2, 3, 3, 1, 2]);
            expect(published.at(-2)?.recipients).toEqual([carol.deviceKey]);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await carol.synchronize(ctx, { waitMilliseconds: 0 });
            const bobReceived: string[] = [];
            const carolReceived: string[] = [];
            await consume(bob, async (update) => {
                bobReceived.push(utf8Decode(update.bytes));
            });
            await activate(carol, session.id, async (update) => {
                carolReceived.push(utf8Decode(update.bytes));
            });
            expect(bobReceived).toEqual(["welcome carol"]);
            expect(carolReceived).toEqual([]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("retries an exact durable outbox after restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let failPublish = false;
        const unreliable: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (failPublish) throw new DeliveryTransportError(429, "queue_full");
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        let alice = await MurmurClient.open(ctx, {
            transport: unreliable,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("restart"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            failPublish = true;
            await expect(alice.send(ctx, session.id, utf8Encode("durable"))).resolves.toEqual(
                expect.any(String),
            );
            await expect(alice.synchronize(ctx)).resolves.toMatchObject({
                pendingOutboxes: 1,
                transientPublicationFailures: 2,
                terminalPublicationFailures: 0,
            });
            alice.close(ctx);
            alice = await MurmurClient.open(ctx, {
                transport: base,
                store: aliceStore,
                now: () => NOW,
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["durable"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("terminally advances past an authenticated malformed session delivery", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const attacker = generateIdentityKeyPair();
        const transport = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        try {
            await transport.publish(
                ctx,
                createSignedDelivery(attacker, [alice.deviceKey], new Uint8Array([99, 1]), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            expect((await alice.synchronize(ctx)).inbox.rejected).toBe(1);
            await alice.synchronize(ctx);
        } finally {
            destroyIdentity(attacker);
            alice.close(ctx);
            await relay.close();
        }
    });

    test("automatically commits a batch only after onUpdates resolves", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("activation"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("buffered"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);

            await bob.activateSession(ctx, session.id);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });
            let firstId: string | undefined;
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: async (_ctx, updates) => {
                            expect(updates).toHaveLength(1);
                            firstId = updates[0]!.id;
                            await bobStore.set(ctx, "application/staged", updates[0]!.bytes);
                            throw new Error("application update failed");
                        },
                    },
                ),
            ).rejects.toThrow("application update failed");
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });

            let replayId: string | undefined;
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        replayId = updates[0]?.id;
                    },
                },
            );
            expect(replayId).toBe(firstId);
            expect(utf8Decode((await bobStore.get(ctx, "application/staged"))!)).toBe("buffered");
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 0,
            });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("keeps an active session usable when its application buffer is full", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay, new MemoryMurmurStore(), {
            maximumBufferedEventsPerSession: 1,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("bounded"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            await alice.send(ctx, session.id, utf8Encode("first"));
            await alice.send(ctx, session.id, utf8Encode("second"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });
            const events: string[] = [];
            await consume(bob, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["first"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("drops a bounded pending session instead of blocking the identity inbox", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay, new MemoryMurmurStore(), {
            maximumBufferedEventsPerSession: 1,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("pending overflow"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("first"));
            await alice.send(ctx, session.id, utf8Encode("second"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            await bob.synchronize(ctx);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("opens a valid prior-epoch message delivered after a membership Commit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("old epoch"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx);
            await bob.send(ctx, session.id, utf8Encode("from prior epoch"));
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);

            const events: string[] = [];
            await consume(alice, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["from prior epoch"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("isolates a terminal outbox failure from inbound queue progress", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let rejectPublications = false;
        const isolated: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (rejectPublications) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const aliceStore = new MemoryMurmurStore();
        const alice = await MurmurClient.open(ctx, {
            transport: isolated,
            store: aliceStore,
            now: () => NOW,
        });
        const attacker = generateIdentityKeyPair();
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("isolated outbox"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("will be rejected"));
            rejectPublications = true;
            await base.publish(
                ctx,
                createSignedDelivery(attacker, [alice.deviceKey], new Uint8Array([99, 1]), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            const outcome = await alice.synchronize(ctx);
            expect(outcome).toMatchObject({
                pendingOutboxes: 0,
                terminalPublicationFailures: 2,
                transientPublicationFailures: 0,
            });
            expect(outcome.issues[0]?.code).toContain("outbox_application_limit");
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/session-outbox-order/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);
            await alice.synchronize(ctx);
        } finally {
            destroyIdentity(attacker);
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("quarantines a corrupt durable outbox without blocking later delivery", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("corrupt outbox"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, session.id);

            const corruptedId = await alice.send(ctx, session.id, utf8Encode("corrupted"));
            await aliceStore.set(
                ctx,
                `murmur/session-outbox/${corruptedId}`,
                new Uint8Array([1, 2, 3]),
            );
            expect(await alice.synchronize(ctx)).toMatchObject({
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                issues: [{ code: "corrupt_outbox" }],
            });
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/session-outbox-order/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/epoch-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);

            await alice.send(ctx, session.id, utf8Encode("healthy"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["healthy"]);

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            expect((await alice.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(3);
            expect((await carol.session(ctx, session.id))?.members).toHaveLength(3);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("preflights every Welcome before publishing a multi-member Commit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("corrupt multi-Welcome"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            const outboxes = await aliceStore.scan(ctx, "murmur/session-outbox/", {
                limit: 10,
            });
            const bootstrapIds: string[] = [];
            for (const [key, bytes] of outboxes) {
                try {
                    const value = JSON.parse(utf8Decode(bytes)) as { readonly kind?: unknown };
                    if (value.kind === "bootstrap") {
                        bootstrapIds.push(key.slice("murmur/session-outbox/".length));
                    }
                } finally {
                    zeroBytes(bytes);
                }
            }
            expect(bootstrapIds).toHaveLength(2);
            await aliceStore.set(
                ctx,
                `murmur/session-outbox/${bootstrapIds.at(-1)!}`,
                new Uint8Array([1, 2, 3]),
            );

            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 0,
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                issues: [
                    {
                        code: "corrupt_membership_operation",
                        kind: "commit",
                        sessionId: session.id,
                    },
                ],
            });
            expect(await alice.session(ctx, session.id)).toBeUndefined();
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            expect(await carol.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("does not publish a Commit with a missing Welcome index", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore);
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("missing Welcome index"),
                members: [await bob.createKeyPackage(ctx)],
            });
            const indexes = await aliceStore.scan(ctx, "murmur/bootstrap-outboxes/", {
                limit: 10,
            });
            expect(indexes.size).toBe(1);
            for (const [key, value] of indexes) {
                zeroBytes(value);
                await aliceStore.delete(ctx, key);
            }

            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 0,
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                issues: [{ code: "corrupt_membership_operation", sessionId: session.id }],
            });
            expect(await alice.session(ctx, session.id)).toBeUndefined();
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("quarantines corrupt session state without blocking a healthy session", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const damaged = await alice.createSession(ctx, {
                descriptor: utf8Encode("damaged state"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await activate(bob, damaged.id);

            const healthy = await alice.createSession(ctx, {
                descriptor: utf8Encode("healthy state"),
                members: [await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await carol.synchronize(ctx);
            await activate(carol, healthy.id);

            await aliceStore.set(
                ctx,
                `murmur/session-states/${encodeBase64Url(damaged.id)}`,
                new Uint8Array([1, 2, 3]),
            );
            await alice.send(ctx, healthy.id, utf8Encode("still delivered"));
            expect(await alice.synchronize(ctx)).toMatchObject({
                terminalPublicationFailures: 1,
                pendingOutboxes: 0,
                issues: [{ code: "corrupt_session_state", sessionId: damaged.id }],
            });
            await alice.synchronize(ctx);
            await carol.synchronize(ctx);
            const received: string[] = [];
            await consume(carol, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["still delivered"]);
            expect(await alice.session(ctx, damaged.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("rejects resource-poisoning operations before durable session mutation", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const bob = await client(relay);
        const outboxConstrained = await client(relay, new MemoryMurmurStore(), {
            maximumOutboxes: 1,
            maximumDeliveryCiphertextBytes: 1_024,
        });
        const ciphertextConstrained = await client(relay, new MemoryMurmurStore(), {
            maximumDeliveryCiphertextBytes: 64 * 1_024,
        });
        try {
            await expect(
                outboxConstrained.createSession(ctx, {
                    descriptor: utf8Encode("too many outboxes"),
                    members: [await bob.createKeyPackage(ctx)],
                }),
            ).rejects.toThrow("outbox capacity");
            expect((await outboxConstrained.sessions(ctx)).sessions).toEqual([]);

            const session = await ciphertextConstrained.createSession(ctx, {
                descriptor: utf8Encode("bounded send"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await ciphertextConstrained.synchronize(ctx);
            await bob.synchronize(ctx);
            await expect(
                ciphertextConstrained.send(ctx, session.id, new Uint8Array(100_000)),
            ).rejects.toThrow("configured limit");
            await ciphertextConstrained.send(ctx, session.id, utf8Encode("small"));
            await ciphertextConstrained.synchronize(ctx);
            await bob.synchronize(ctx);
            const received: string[] = [];
            await activate(bob, session.id, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["small"]);
        } finally {
            outboxConstrained.close(ctx);
            ciphertextConstrained.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("keeps normal delivery below the relay TTL under clock skew", async () => {
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {},
            undefined,
            () => NOW - 1,
        );
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("clock skew"),
                members: [await bob.createKeyPackage(ctx)],
            });
            expect((await alice.synchronize(ctx)).transientPublicationFailures).toBe(0);
            await bob.synchronize(ctx);
            await activate(bob, session.id);
            await alice.send(ctx, session.id, utf8Encode("accepted"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            const events: string[] = [];
            await consume(bob, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["accepted"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("queues a creating-session message while its Welcome publication is blocked", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let failWelcome = true;
        const welcomeFailing: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (failWelcome && delivery.ciphertext[0] === 1) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            transport: welcomeFailing,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("failed add"),
                members: [await bob.createKeyPackage(ctx)],
            });
            const outcome = await alice.synchronize(ctx);
            expect(outcome).toMatchObject({
                published: 1,
                terminalPublicationFailures: 0,
                transientPublicationFailures: 1,
                pendingOutboxes: 2,
            });
            expect(outcome.issues[0]).toMatchObject({
                kind: "bootstrap",
                sessionId: session.id,
            });
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            expect(await alice.session(ctx, session.id)).toMatchObject({
                status: "active",
                members: [alice.identity, bob.identity],
            });
            const queued = await alice.send(ctx, session.id, utf8Encode("queued while offline"));
            expect(queued).toEqual(expect.any(String));
            expect(
                (
                    await aliceStore.scan(ctx, "murmur/post-commit-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(2);

            failWelcome = false;
            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 3,
                pendingOutboxes: 1,
            });
            await bob.synchronize(ctx);
            expect(await alice.session(ctx, session.id)).toMatchObject({
                status: "active",
            });
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "pending",
            });
            const received: string[] = [];
            await activate(bob, session.id, async (update) => {
                received.push(utf8Decode(update.bytes));
            });
            expect(received).toEqual(["queued while offline"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("keeps current-epoch application work ahead of an asynchronous removal", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let failPrivateOnce = false;
        const ordered: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (failPrivateOnce && delivery.ciphertext[0] === 2) {
                    failPrivateOnce = false;
                    throw new DeliveryTransportError(503, "overloaded");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            transport: ordered,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("ordered outboxes"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.removeMember(ctx, session.id, carol.identity);
            const sendId = await alice.send(ctx, session.id, utf8Encode("after remove"));
            expect(sendId).toEqual(expect.any(String));
            failPrivateOnce = true;
            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 2,
                transientPublicationFailures: 1,
                pendingOutboxes: 2,
            });
            await alice.synchronize(ctx);
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["after remove"]);
            expect((await bob.session(ctx, session.id))?.members).toHaveLength(2);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("does not publish a Welcome until its recoverable Commit is adopted", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let failCommit = true;
        const recoverable: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (failCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            transport: recoverable,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("recover commit"),
                members: [await bob.createKeyPackage(ctx)],
            });
            const blocked = await alice.synchronize(ctx);
            expect(blocked).toMatchObject({
                published: 0,
                transientPublicationFailures: 1,
                pendingOutboxes: 3,
            });
            expect(blocked.issues.some((issue) => issue.kind === "commit")).toBe(true);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            expect(await alice.session(ctx, session.id)).toMatchObject({ status: "creating" });

            failCommit = false;
            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 3,
                pendingOutboxes: 1,
            });
            expect(await alice.session(ctx, session.id)).toMatchObject({
                status: "active",
                members: [alice.identity, bob.identity],
            });
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toMatchObject({
                status: "pending",
                members: [alice.identity, bob.identity],
            });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("revokes prior-epoch send authority immediately on Remove", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("remove"),
                members: [await bob.createKeyPackage(ctx), await carol.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await carol.synchronize(ctx);
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.removeMember(ctx, session.id, carol.identity);
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await carol.send(ctx, session.id, utf8Encode("after removal"));
            await expect(carol.synchronize(ctx)).resolves.toMatchObject({
                terminalPublicationFailures: 1,
            });
            const outcome = await alice.synchronize(ctx);
            expect(outcome.inbox.rejected).toBe(0);
            const events: string[] = [];
            await consume(alice, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual([]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("lists local sessions through bounded cursor pages", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            await alice.createSession(ctx, {
                descriptor: utf8Encode("first page"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.createSession(ctx, {
                descriptor: utf8Encode("second page"),
                members: [await carol.createKeyPackage(ctx)],
            });
            const first = await alice.sessions(ctx, { limit: 1 });
            expect(first.sessions).toHaveLength(1);
            expect(first.cursor).not.toBeNull();
            const second = await alice.sessions(ctx, { limit: 1, after: first.cursor! });
            expect(second.sessions).toHaveLength(1);
            expect(second.sessions[0]?.id).not.toEqual(first.sessions[0]?.id);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("refuses local reuse of a one-use KeyPackage", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const keyPackage = await bob.createKeyPackage(ctx);
            await alice.createSession(ctx, {
                descriptor: utf8Encode("first use"),
                members: [keyPackage],
            });
            await expect(
                alice.createSession(ctx, {
                    descriptor: utf8Encode("second use"),
                    members: [keyPackage],
                }),
            ).rejects.toThrow("already used");
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("can abandon a blocked creating session without leaving local outboxes", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const blocked: DeliveryTransport = {
            publish: (_ctx, delivery, signal) => {
                if (delivery.ciphertext[0] === 1) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const alice = await MurmurClient.open(ctx, {
            transport: blocked,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("abandon"),
                members: [await bob.createKeyPackage(ctx)],
            });
            expect(await alice.synchronize(ctx)).toMatchObject({
                pendingOutboxes: 2,
                transientPublicationFailures: 1,
            });
            await alice.abandonSession(ctx, session.id);
            expect(await alice.session(ctx, session.id)).toBeUndefined();
            expect((await alice.synchronize(ctx)).pendingOutboxes).toBe(0);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("allows a fresh Welcome after pending capacity is freed", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const alice = await client(relay);
        const bob = await client(relay, new MemoryMurmurStore(), {
            maximumPendingSessions: 1,
        });
        const carolIdentity = generateIdentityKeyPair();
        let capturedBootstrap: SignedDelivery | undefined;
        const capturing: DeliveryTransport = {
            publish: async (_ctx, delivery, signal) => {
                if (delivery.ciphertext[0] === 1 && capturedBootstrap === undefined) {
                    capturedBootstrap = delivery;
                    return { eventId: delivery.id, duplicate: false };
                }
                return base.publish(ctx, delivery, signal);
            },
            read: (_ctx, request, signal) => base.read(ctx, request, signal),
            acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            readDeviceRoster: (_ctx, account, signal) =>
                base.readDeviceRoster(ctx, account, signal),
            mutateDeviceRoster: (_ctx, delivery, signal) =>
                base.mutateDeviceRoster(ctx, delivery, signal),
        };
        const carol = await MurmurClient.open(ctx, {
            identity: carolIdentity,
            transport: capturing,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const first = await alice.createSession(ctx, {
                descriptor: utf8Encode("first pending"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            const second = await carol.createSession(ctx, {
                descriptor: utf8Encode("capacity retry"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await carol.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, first.id)).toMatchObject({ status: "pending" });
            expect(await bob.session(ctx, second.id)).toBeUndefined();

            await bob.ignoreSession(ctx, first.id);
            expect(capturedBootstrap).toBeDefined();
            await base.publish(ctx, capturedBootstrap!);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, second.id)).toMatchObject({ status: "pending" });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            destroyIdentity(carolIdentity);
            await relay.close();
        }
    });

    test("refuses close while serialized operations are active or queued", async () => {
        let releaseRead!: () => void;
        let readStarted!: () => void;
        const readGate = new Promise<void>((resolve) => {
            releaseRead = resolve;
        });
        const started = new Promise<void>((resolve) => {
            readStarted = resolve;
        });
        const transport: DeliveryTransport = {
            publish: async (_ctx) => ({
                eventId: "018bcfe5-6800-7000-8000-000000000000",
                duplicate: false,
            }),
            read: async (_ctx) => {
                readStarted();
                await readGate;
                return {
                    deliveries: [],
                    head: null,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async (_ctx) => ({ removed: 0 }),
        };
        const murmur = await MurmurClient.open(ctx, {
            transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const synchronizing = murmur.synchronize(ctx);
        await started;
        const discovering = murmur.createKeyPackage(ctx);
        expect(() => murmur.close(ctx)).toThrow("operation is pending");
        releaseRead();
        await synchronizing;
        await discovering;
        const reading = murmur.sessions(ctx);
        expect(() => murmur.close(ctx)).toThrow("operation is pending");
        await reading;
        murmur.close(ctx);
    });
});
