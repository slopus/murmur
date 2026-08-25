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
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import {
    DISCOVERY_INVITATION_TTL_MILLISECONDS,
    createDiscoveryBundle,
    type DiscoveryTransport,
} from "../../identity/discovery/index.js";
import { MemoryMurmurStore, type MurmurStore, type StoreTransaction } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";
import { MurmurClient, type MurmurSessionLimits, type MurmurUpdate } from "../index.js";
import { decodeSessionRecord, encodeSessionRecord } from "../impl/sessionRecords.js";

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "session-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(
    relay: RelayService,
    store = new MemoryMurmurStore(),
    limits: MurmurSessionLimits = {},
): Promise<MurmurClient> {
    return MurmurClient.open({
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
    await value.activateSession(id);
    return process === undefined ? 0 : consume(value, process);
}

async function consume(
    value: MurmurClient,
    process: (update: MurmurUpdate) => void | Promise<void>,
): Promise<number> {
    let consumed = 0;
    await value.synchronize(
        { waitMilliseconds: 0 },
        {
            onUpdates: async (updates) => {
                for (const update of updates) await process(update);
                consumed += updates.length;
            },
        },
    );
    return consumed;
}

describe("stateful MLS sessions", () => {
    test("queues initial group messages offline and relays Welcome, Commit, then messages after restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const published: SignedDelivery[] = [];
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const recording: DeliveryTransport = {
            publish: async (delivery, signal) => {
                published.push(delivery);
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        let alice = await MurmurClient.open({
            transport: recording,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("offline group"),
                members: [await bob.discovery()],
            });
            const first = await alice.send(session.id, utf8Encode("first offline"));
            const second = await alice.send(session.id, utf8Encode("second offline"));

            expect(published).toEqual([]);
            expect(await alice.session(session.id)).toMatchObject({ status: "creating" });
            expect(
                (
                    await aliceStore.scan("murmur/session-outbox/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(4);
            expect(
                (
                    await aliceStore.scan("murmur/post-commit-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(2);

            const aliceIdentity = alice.identity;
            alice.close();
            alice = await MurmurClient.open({
                transport: recording,
                store: aliceStore,
                now: () => NOW,
            });

            expect(await alice.synchronize()).toMatchObject({
                published: 4,
                pendingOutboxes: 0,
                transientPublicationFailures: 0,
                terminalPublicationFailures: 0,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([1, 3, 2, 2]);
            expect(published.slice(2).map((delivery) => delivery.id)).toEqual([first, second]);
            expect(
                published.map((delivery) => delivery.recipients.map(encodeBase64Url).sort()),
            ).toEqual([
                [encodeBase64Url(bob.identity)],
                [encodeBase64Url(aliceIdentity)],
                [encodeBase64Url(aliceIdentity), encodeBase64Url(bob.identity)].sort(),
                [encodeBase64Url(aliceIdentity), encodeBase64Url(bob.identity)].sort(),
            ]);

            await bob.synchronize({ waitMilliseconds: 0 });
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
            const received: string[] = [];
            expect(
                await activate(bob, session.id, async (update) => {
                    received.push(utf8Decode(update.bytes));
                }),
            ).toBe(2);
            expect(received).toEqual(["first offline", "second offline"]);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("creates a session from a 32-byte relay-cached invitation digest", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const digest = await bob.createInvitation();
            expect(digest).toHaveLength(32);
            const resolved = await alice.resolveInvitation(digest);
            expect(resolved.identityKey).toEqual(bob.identity);
            expect(resolved.expiresAt - resolved.createdAt).toBe(
                DISCOVERY_INVITATION_TTL_MILLISECONDS,
            );

            const session = await alice.createSession({
                descriptor: utf8Encode("digest invitation"),
                members: [resolved],
            });
            await alice.synchronize();
            await bob.synchronize();
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
        } finally {
            alice.close();
            bob.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("realtime SSE"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            const received: string[] = [];
            let finishFirst!: () => void;
            const firstComplete = new Promise<void>((resolve) => {
                finishFirst = resolve;
            });
            let connected = 0;
            let disconnected = 0;
            aliceRealtime = alice.sync({ abort: aliceController.signal });
            bobRealtime = bob.sync({
                abort: bobController.signal,
                onConnected: () => {
                    connected += 1;
                },
                onDisconnected: () => {
                    disconnected += 1;
                },
                onUpdates: async (updates) => {
                    for (const update of updates) {
                        received.push(utf8Decode(update.bytes));
                    }
                    if (received.length === 1) {
                        bobController.abort();
                        finishFirst();
                    }
                },
            });
            await alice.send(session.id, utf8Encode("first"));
            await alice.send(session.id, utf8Encode("second"));
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
            resumed = bob.sync({
                abort: resumedController.signal,
                onUpdates: async (updates) => {
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
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("rejects an expired digest and drops its matching private KeyPackage", async () => {
        let now = NOW;
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => now,
        });
        try {
            const digest = await bob.createInvitation();
            const resolved = await alice.resolveInvitation(digest);
            const session = await alice.createSession({
                descriptor: utf8Encode("expires"),
                members: [resolved],
            });

            now += DISCOVERY_INVITATION_TTL_MILLISECONDS;
            await expect(alice.resolveInvitation(digest)).rejects.toMatchObject({
                status: 404,
                code: "invitation_not_found",
            });
            await alice.synchronize();
            const synchronized = await bob.synchronize();
            expect(synchronized.inbox.rejected).toBe(1);
            expect(await bob.session(session.id)).toBeUndefined();
            expect(await bobStore.scan("murmur/key-packages/", { limit: 10 })).toHaveLength(0);
            expect(await bobStore.scan("murmur/key-package-expiries/", { limit: 10 })).toHaveLength(
                0,
            );
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("drops private KeyPackages when invitation upload fails", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const store = new MemoryMurmurStore();
        const discoveryTransport: DiscoveryTransport = {
            upload: async () => {
                throw new Error("injected invitation upload failure");
            },
            download: async () => {
                throw new Error("unused");
            },
        };
        const bob = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", {
                fetch: relayFetch(relay),
            }),
            discoveryTransport,
            store,
            now: () => NOW,
        });
        try {
            await expect(bob.createInvitation()).rejects.toThrow(
                "injected invitation upload failure",
            );
            expect(await store.scan("murmur/key-packages/", { limit: 10 })).toHaveLength(0);
            expect(await store.scan("murmur/key-package-expiries/", { limit: 10 })).toHaveLength(0);
        } finally {
            bob.close();
            await relay.close();
        }
    });

    test("delivers one identity-wide ordered batch across sessions", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const first = await alice.createSession({
                descriptor: utf8Encode("first session"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await bob.activateSession(first.id);

            const second = await alice.createSession({
                descriptor: utf8Encode("second session"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await bob.activateSession(second.id);

            await alice.send(first.id, utf8Encode("first update"));
            await alice.send(second.id, utf8Encode("second update"));
            await alice.synchronize();

            const batches: (readonly MurmurUpdate[])[] = [];
            await bob.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (updates) => {
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
            expect(await bob.session(first.id)).toMatchObject({ bufferedEvents: 0 });
            expect(await bob.session(second.id)).toMatchObject({ bufferedEvents: 0 });
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("bootstraps pending, activates, and exchanges opaque events", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const bobDiscovery = await bob.discovery();
            const created = await alice.createSession({
                descriptor: utf8Encode("opaque descriptor"),
                members: [bobDiscovery],
            });

            await alice.synchronize();
            await bob.synchronize();
            const pending = await bob.session(created.id);
            expect(pending).toMatchObject({
                status: "pending",
                bufferedEvents: 0,
            });
            expect(utf8Decode(pending!.descriptor)).toBe("opaque descriptor");

            await expect(bob.send(created.id, utf8Encode("from pending"))).resolves.toEqual(
                expect.any(String),
            );
            await bob.synchronize({ waitMilliseconds: 0 });
            const aliceReceived: string[] = [];
            await consume(alice, async (event) => {
                aliceReceived.push(utf8Decode(event.bytes));
            });
            expect(aliceReceived).toEqual(["from pending"]);

            await alice.send(created.id, utf8Encode("hello"));
            await alice.synchronize();
            await bob.synchronize();
            expect(await bob.session(created.id)).toMatchObject({
                status: "pending",
                bufferedEvents: 2,
            });

            const received: string[] = [];
            await activate(bob, created.id, async (event) => {
                received.push(utf8Decode(event.bytes));
                await bobStore.set("application/last", event.bytes);
            });
            expect(received).toEqual(["from pending", "hello"]);
            expect(utf8Decode((await bobStore.get("application/last"))!)).toBe("hello");
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("restores identity and pending session state from the supplied store", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const store = new MemoryMurmurStore();
        const first = await client(relay, store);
        const identity = first.identity;
        first.close();
        const reopened = await client(relay, store);
        try {
            expect(reopened.identity).toEqual(identity);
        } finally {
            reopened.close();
            await relay.close();
        }
    });

    test("cleans opening identity material when the store commit rejects", async () => {
        const backing = new MemoryMurmurStore();
        const supplied = generateIdentityKeyPair();
        let encodedIdentity: Uint8Array | undefined;
        const store: MurmurStore = {
            get: (key) => backing.get(key),
            set: (key, value) => backing.set(key, value),
            delete: (key) => backing.delete(key),
            list: (prefix) => backing.list(prefix),
            scan: (prefix, options) => backing.scan(prefix, options),
            transaction: async <Result>(
                operation: (transaction: StoreTransaction) => Promise<Result>,
            ): Promise<Result> =>
                backing.transaction(async (transaction) => {
                    const rejecting: StoreTransaction = {
                        ...transaction,
                        set: async (key, value) => {
                            encodedIdentity = value;
                            await transaction.set(key, value);
                        },
                    };
                    await operation(rejecting);
                    throw new Error("injected commit rejection");
                }),
        };
        const transport: DeliveryTransport = {
            publish: async () => {
                throw new Error("unused");
            },
            read: async () => {
                throw new Error("unused");
            },
            acknowledge: async () => {
                throw new Error("unused");
            },
        };
        try {
            await expect(
                MurmurClient.open({
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
            const session = await alice.createSession({
                descriptor: utf8Encode("group"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize();
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize();
            await carol.synchronize();
            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await bob.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.status).toBe("pending");
            await activate(carol, session.id);

            await bob.send(session.id, utf8Encode("from bob"));
            await bob.synchronize();
            await alice.synchronize();
            await carol.synchronize();
            const carolEvents: string[] = [];
            await consume(carol, async (event) => {
                carolEvents.push(utf8Decode(event.bytes));
            });
            expect(carolEvents).toEqual(["from bob"]);

            await expect(bob.removeMember(session.id, carol.identity)).rejects.toThrow(
                "Only an admin",
            );
            await alice.grantAdmin(session.id, bob.identity);
            await alice.synchronize();
            await bob.synchronize();
            expect((await bob.session(session.id))?.admins).toContainEqual(bob.identity);

            await expect(bob.grantAdmin(session.id, carol.identity)).rejects.toThrow(
                "may not grant admin",
            );
            await alice.setPolicies(session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });

            await bob.grantAdmin(session.id, carol.identity);
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            expect((await alice.session(session.id))?.admins).toContainEqual(carol.identity);
            await expect(bob.revokeAdmin(session.id, carol.identity)).rejects.toThrow(
                "Only the session owner",
            );
            await alice.revokeAdmin(session.id, carol.identity);
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            expect((await bob.session(session.id))?.admins).not.toContainEqual(carol.identity);

            await bob.removeMember(session.id, carol.identity);
            await bob.synchronize();
            await alice.synchronize();
            await bob.synchronize();
            await carol.synchronize();
            expect((await alice.session(session.id))?.members).toHaveLength(2);
            expect((await bob.session(session.id))?.members).toHaveLength(2);
            expect(await carol.session(session.id)).toBeUndefined();
            expect((await alice.session(session.id))?.owner).toEqual(alice.identity);
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("rejects an unauthorized membership Commit on every honest member", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        const carol = await client(relay);
        const dave = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("unauthorized add"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            // Model a compromised client that lies to its own local authorization check.
            const stateKey = `murmur/session-states/${encodeBase64Url(session.id)}`;
            const state = (await bobStore.get(stateKey))!;
            const record = decodeSessionRecord(state);
            try {
                await bobStore.set(
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

            await bob.addMember(session.id, await dave.discovery());
            await bob.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });

            expect(await alice.session(session.id)).toMatchObject({
                members: expect.arrayContaining([alice.identity, bob.identity, carol.identity]),
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                },
            });
            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.members).toHaveLength(3);
            for (const member of [alice, carol]) {
                expect(await member.issues()).toEqual(
                    expect.arrayContaining([
                        expect.objectContaining({ code: "unauthorized_commit" }),
                    ]),
                );
            }
        } finally {
            alice.close();
            bob.close();
            carol.close();
            dave.close();
            await relay.close();
        }
    });

    test("allows a non-owner member to leave asynchronously", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("leave"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);

            await bob.leave(session.id);
            await bob.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });

            expect((await alice.session(session.id))?.members).toEqual([alice.identity]);
            expect(await bob.session(session.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
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
            publish: async (delivery, signal) => {
                if (blockBobCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(429, "commit_blocked");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await client(relay);
        const bob = await MurmurClient.open({
            transport: bobTransport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("concurrent commits"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.grantAdmin(session.id, bob.identity);
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });

            blockBobCommit = true;
            await bob.removeMember(session.id, carol.identity);
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });
            await bob.send(session.id, utf8Encode("survives losing commit"));

            await alice.setPolicies(session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });

            blockBobCommit = false;
            await bob.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });

            const received: string[] = [];
            await consume(alice, async (update) => {
                received.push(utf8Decode(update.bytes));
            });
            expect(received).toEqual(["survives losing commit"]);
            expect(await alice.session(session.id)).toMatchObject({
                members: expect.arrayContaining([alice.identity, bob.identity]),
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                },
            });
            expect((await alice.session(session.id))?.members).toHaveLength(2);
            expect((await bob.session(session.id))?.members).toHaveLength(2);
            expect(await carol.session(session.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("fails a stale add generation and permits a deliberate re-add", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("removal generation"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.grantAdmin(session.id, bob.identity);
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });

            await bob.removeMember(session.id, carol.identity);
            await bob.synchronize({ waitMilliseconds: 0 });

            // Alice has not observed Bob's removal yet, so this snapshots the old generation.
            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize({ waitMilliseconds: 0 });
            expect((await alice.session(session.id))?.members).toHaveLength(2);
            expect(await alice.issues()).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: "add_intent_removal_generation_advanced",
                        sessionId: session.id,
                    }),
                ]),
            );

            await carol.synchronize({ waitMilliseconds: 0 });
            expect(await carol.session(session.id)).toBeUndefined();

            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await activate(carol, session.id);

            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await bob.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.members).toHaveLength(3);
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("replaces a pending Welcome after its Add Commit loses", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let blockBobCommit = false;
        const bobTransport: DeliveryTransport = {
            publish: async (delivery, signal) => {
                if (blockBobCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(429, "commit_blocked");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await client(relay);
        const bob = await MurmurClient.open({
            transport: bobTransport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("replacement welcome"),
                anyoneCanAddMembers: true,
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);

            blockBobCommit = true;
            await bob.addMember(session.id, await carol.discovery());
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });
            await carol.synchronize({ waitMilliseconds: 0 });
            expect(await carol.session(session.id)).toMatchObject({
                status: "pending",
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: true,
                },
            });

            await alice.setPolicies(session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });

            blockBobCommit = false;
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            expect(await carol.session(session.id)).toMatchObject({
                status: "pending",
                policies: {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                },
            });

            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(carol, session.id);
            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await bob.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.members).toHaveLength(3);
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
            publish: async (delivery, signal) => {
                if (blockBobAdd && (delivery.ciphertext[0] === 1 || delivery.ciphertext[0] === 3)) {
                    throw new DeliveryTransportError(429, "add_blocked");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await client(relay);
        const bob = await MurmurClient.open({
            transport: bobTransport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("same account add"),
                anyoneCanAddMembers: true,
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);

            blockBobAdd = true;
            await bob.addMember(session.id, await carol.discovery());
            expect(await bob.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                transientPublicationFailures: 1,
            });

            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            expect((await carol.session(session.id))?.members).toHaveLength(3);

            blockBobAdd = false;
            await bob.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(carol, session.id);

            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await bob.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.members).toHaveLength(3);
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
            publish: async (delivery, signal) => {
                published.push(delivery);
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await MurmurClient.open({
            transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("offline add"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await activate(bob, session.id);
            published.length = 0;

            await alice.addMember(session.id, await carol.discovery());
            const messageId = await alice.send(session.id, utf8Encode("welcome carol"));
            expect(published).toEqual([]);

            expect(await alice.synchronize({ waitMilliseconds: 0 })).toMatchObject({
                published: 3,
                pendingOutboxes: 1,
            });
            expect(published.map((delivery) => delivery.ciphertext[0])).toEqual([2, 1, 3]);
            expect(published[0]?.id).toBe(messageId);
            expect(
                published.map((delivery) => delivery.recipients.map(encodeBase64Url).sort()),
            ).toEqual([
                [encodeBase64Url(alice.identity), encodeBase64Url(bob.identity)].sort(),
                [encodeBase64Url(carol.identity)],
                [encodeBase64Url(alice.identity), encodeBase64Url(bob.identity)].sort(),
            ]);

            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await carol.synchronize({ waitMilliseconds: 0 });
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
            alice.close();
            bob.close();
            carol.close();
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
            publish: async (delivery, signal) => {
                if (failPublish) throw new DeliveryTransportError(429, "queue_full");
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        let alice = await MurmurClient.open({
            transport: unreliable,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("restart"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            failPublish = true;
            await expect(alice.send(session.id, utf8Encode("durable"))).resolves.toEqual(
                expect.any(String),
            );
            await expect(alice.synchronize()).resolves.toMatchObject({
                pendingOutboxes: 1,
                transientPublicationFailures: 1,
                terminalPublicationFailures: 0,
            });
            alice.close();
            alice = await MurmurClient.open({
                transport: base,
                store: aliceStore,
                now: () => NOW,
            });
            await alice.synchronize();
            await bob.synchronize();
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["durable"]);
        } finally {
            alice.close();
            bob.close();
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
                createSignedDelivery(attacker, [alice.identity], new Uint8Array([99, 1]), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            expect((await alice.synchronize()).inbox.rejected).toBe(1);
            await alice.synchronize();
        } finally {
            destroyIdentity(attacker);
            alice.close();
            await relay.close();
        }
    });

    test("automatically commits a batch only after onUpdates resolves", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bobStore = new MemoryMurmurStore();
        const bob = await client(relay, bobStore);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("activation"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.send(session.id, utf8Encode("buffered"));
            await alice.synchronize();
            await bob.synchronize();

            await bob.activateSession(session.id);
            await bob.synchronize({ waitMilliseconds: 0 });
            expect(await bob.session(session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });
            let firstId: string | undefined;
            await expect(
                bob.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: async (updates) => {
                            expect(updates).toHaveLength(1);
                            firstId = updates[0]!.id;
                            await bobStore.set("application/staged", updates[0]!.bytes);
                            throw new Error("application update failed");
                        },
                    },
                ),
            ).rejects.toThrow("application update failed");
            expect(await bob.session(session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });

            let replayId: string | undefined;
            await bob.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (updates) => {
                        replayId = updates[0]?.id;
                    },
                },
            );
            expect(replayId).toBe(firstId);
            expect(utf8Decode((await bobStore.get("application/staged"))!)).toBe("buffered");
            expect(await bob.session(session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 0,
            });
        } finally {
            alice.close();
            bob.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("bounded"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            await alice.send(session.id, utf8Encode("first"));
            await alice.send(session.id, utf8Encode("second"));
            await alice.synchronize();
            await bob.synchronize();
            expect(await bob.session(session.id)).toMatchObject({
                status: "active",
                bufferedEvents: 1,
            });
            const events: string[] = [];
            await consume(bob, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["first"]);
        } finally {
            alice.close();
            bob.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("pending overflow"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.send(session.id, utf8Encode("first"));
            await alice.send(session.id, utf8Encode("second"));
            await alice.synchronize();
            await bob.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
            await bob.synchronize();
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("opens a valid prior-epoch message delivered after a membership Commit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("old epoch"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize();
            await bob.send(session.id, utf8Encode("from prior epoch"));
            await bob.synchronize();
            await alice.synchronize();

            const events: string[] = [];
            await consume(alice, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["from prior epoch"]);
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
            publish: async (delivery, signal) => {
                if (rejectPublications) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const aliceStore = new MemoryMurmurStore();
        const alice = await MurmurClient.open({
            transport: isolated,
            store: aliceStore,
            now: () => NOW,
        });
        const attacker = generateIdentityKeyPair();
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("isolated outbox"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.send(session.id, utf8Encode("will be rejected"));
            rejectPublications = true;
            await base.publish(
                createSignedDelivery(attacker, [alice.identity], new Uint8Array([99, 1]), {
                    createdAt: NOW,
                    expiresAt: NOW + 60_000,
                }),
            );
            const outcome = await alice.synchronize();
            expect(outcome).toMatchObject({
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                transientPublicationFailures: 0,
            });
            expect(outcome.issues[0]?.code).toContain("outbox_application_limit");
            expect(
                (
                    await aliceStore.scan("murmur/session-outbox-order/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);
            await alice.synchronize();
        } finally {
            destroyIdentity(attacker);
            alice.close();
            bob.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("corrupt outbox"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, session.id);

            const corruptedId = await alice.send(session.id, utf8Encode("corrupted"));
            await aliceStore.set(`murmur/session-outbox/${corruptedId}`, new Uint8Array([1, 2, 3]));
            expect(await alice.synchronize()).toMatchObject({
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                issues: [{ code: "corrupt_outbox" }],
            });
            expect(
                (
                    await aliceStore.scan("murmur/session-outbox-order/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);
            expect(
                (
                    await aliceStore.scan("murmur/epoch-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(0);

            await alice.send(session.id, utf8Encode("healthy"));
            await alice.synchronize();
            await bob.synchronize();
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["healthy"]);

            await alice.addMember(session.id, await carol.discovery());
            await alice.synchronize();
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize();
            await carol.synchronize();
            expect((await alice.session(session.id))?.members).toHaveLength(3);
            expect((await bob.session(session.id))?.members).toHaveLength(3);
            expect((await carol.session(session.id))?.members).toHaveLength(3);
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("corrupt multi-Welcome"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            const outboxes = await aliceStore.scan("murmur/session-outbox/", {
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
                `murmur/session-outbox/${bootstrapIds.at(-1)!}`,
                new Uint8Array([1, 2, 3]),
            );

            expect(await alice.synchronize()).toMatchObject({
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
            expect(await alice.session(session.id)).toBeUndefined();
            await bob.synchronize();
            await carol.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
            expect(await carol.session(session.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("does not publish a Commit with a missing Welcome index", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore);
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("missing Welcome index"),
                members: [await bob.discovery()],
            });
            const indexes = await aliceStore.scan("murmur/bootstrap-outboxes/", {
                limit: 10,
            });
            expect(indexes.size).toBe(1);
            for (const [key, value] of indexes) {
                zeroBytes(value);
                await aliceStore.delete(key);
            }

            expect(await alice.synchronize()).toMatchObject({
                published: 0,
                pendingOutboxes: 0,
                terminalPublicationFailures: 1,
                issues: [{ code: "corrupt_membership_operation", sessionId: session.id }],
            });
            expect(await alice.session(session.id)).toBeUndefined();
            await bob.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
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
            const damaged = await alice.createSession({
                descriptor: utf8Encode("damaged state"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await activate(bob, damaged.id);

            const healthy = await alice.createSession({
                descriptor: utf8Encode("healthy state"),
                members: [await carol.discovery()],
            });
            await alice.synchronize();
            await carol.synchronize();
            await activate(carol, healthy.id);

            await aliceStore.set(
                `murmur/session-states/${encodeBase64Url(damaged.id)}`,
                new Uint8Array([1, 2, 3]),
            );
            await alice.send(healthy.id, utf8Encode("still delivered"));
            expect(await alice.synchronize()).toMatchObject({
                terminalPublicationFailures: 1,
                pendingOutboxes: 0,
                issues: [{ code: "corrupt_session_state", sessionId: damaged.id }],
            });
            await alice.synchronize();
            await carol.synchronize();
            const received: string[] = [];
            await consume(carol, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["still delivered"]);
            expect(await alice.session(damaged.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
                outboxConstrained.createSession({
                    descriptor: utf8Encode("too many outboxes"),
                    members: [await bob.discovery()],
                }),
            ).rejects.toThrow("outbox capacity");
            expect((await outboxConstrained.sessions()).sessions).toEqual([]);

            const session = await ciphertextConstrained.createSession({
                descriptor: utf8Encode("bounded send"),
                members: [await bob.discovery()],
            });
            await ciphertextConstrained.synchronize();
            await bob.synchronize();
            await expect(
                ciphertextConstrained.send(session.id, new Uint8Array(100_000)),
            ).rejects.toThrow("configured limit");
            await ciphertextConstrained.send(session.id, utf8Encode("small"));
            await ciphertextConstrained.synchronize();
            await bob.synchronize();
            const received: string[] = [];
            await activate(bob, session.id, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["small"]);
        } finally {
            outboxConstrained.close();
            ciphertextConstrained.close();
            bob.close();
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
            const session = await alice.createSession({
                descriptor: utf8Encode("clock skew"),
                members: [await bob.discovery()],
            });
            expect((await alice.synchronize()).transientPublicationFailures).toBe(0);
            await bob.synchronize();
            await activate(bob, session.id);
            await alice.send(session.id, utf8Encode("accepted"));
            await alice.synchronize();
            await bob.synchronize();
            const events: string[] = [];
            await consume(bob, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual(["accepted"]);
        } finally {
            alice.close();
            bob.close();
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
            publish: (delivery, signal) => {
                if (failWelcome && delivery.ciphertext[0] === 1) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await MurmurClient.open({
            transport: welcomeFailing,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("failed add"),
                members: [await bob.discovery()],
            });
            const outcome = await alice.synchronize();
            expect(outcome).toMatchObject({
                published: 0,
                terminalPublicationFailures: 0,
                transientPublicationFailures: 1,
                pendingOutboxes: 2,
            });
            expect(outcome.issues[0]).toMatchObject({
                kind: "bootstrap",
                sessionId: session.id,
            });
            await bob.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
            expect(await alice.session(session.id)).toMatchObject({
                status: "creating",
                members: [alice.identity],
            });
            const queued = await alice.send(session.id, utf8Encode("queued while offline"));
            expect(queued).toEqual(expect.any(String));
            expect(
                (
                    await aliceStore.scan("murmur/post-commit-outboxes/", {
                        limit: 10,
                    })
                ).size,
            ).toBe(1);

            failWelcome = false;
            expect(await alice.synchronize()).toMatchObject({
                published: 3,
                pendingOutboxes: 0,
            });
            await bob.synchronize();
            expect(await alice.session(session.id)).toMatchObject({
                status: "active",
            });
            expect(await bob.session(session.id)).toMatchObject({
                status: "pending",
            });
            const received: string[] = [];
            await activate(bob, session.id, async (update) => {
                received.push(utf8Decode(update.bytes));
            });
            expect(received).toEqual(["queued while offline"]);
        } finally {
            alice.close();
            bob.close();
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
            publish: (delivery, signal) => {
                if (failPrivateOnce && delivery.ciphertext[0] === 2) {
                    failPrivateOnce = false;
                    throw new DeliveryTransportError(503, "overloaded");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await MurmurClient.open({
            transport: ordered,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("ordered outboxes"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await carol.synchronize();
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.removeMember(session.id, carol.identity);
            const sendId = await alice.send(session.id, utf8Encode("after remove"));
            expect(sendId).toEqual(expect.any(String));
            failPrivateOnce = true;
            expect(await alice.synchronize()).toMatchObject({
                published: 1,
                transientPublicationFailures: 1,
                pendingOutboxes: 2,
            });
            await alice.synchronize();
            await alice.synchronize();
            await bob.synchronize();
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(["after remove"]);
            expect((await bob.session(session.id))?.members).toHaveLength(2);
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("retains and recovers a Commit after its Welcome was published", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let failCommit = true;
        const recoverable: DeliveryTransport = {
            publish: (delivery, signal) => {
                if (failCommit && delivery.ciphertext[0] === 3) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await MurmurClient.open({
            transport: recoverable,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("recover commit"),
                members: [await bob.discovery()],
            });
            const blocked = await alice.synchronize();
            expect(blocked).toMatchObject({
                published: 1,
                transientPublicationFailures: 1,
                pendingOutboxes: 1,
            });
            expect(blocked.issues.some((issue) => issue.kind === "commit")).toBe(true);
            await bob.synchronize();
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
            expect(await alice.session(session.id)).toMatchObject({ status: "creating" });

            failCommit = false;
            await alice.synchronize();
            expect(await alice.session(session.id)).toMatchObject({
                status: "active",
                members: [alice.identity, bob.identity],
            });
            expect(await bob.session(session.id)).toMatchObject({
                status: "pending",
                members: [alice.identity, bob.identity],
            });
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("revokes prior-epoch send authority immediately on Remove", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("remove"),
                members: [await bob.discovery(), await carol.discovery()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await carol.synchronize();
            await activate(bob, session.id);
            await activate(carol, session.id);

            await alice.removeMember(session.id, carol.identity);
            await alice.synchronize();
            await bob.synchronize();
            await carol.send(session.id, utf8Encode("after removal"));
            await carol.synchronize();
            const outcome = await alice.synchronize();
            expect(outcome.inbox.rejected).toBe(1);
            const events: string[] = [];
            await consume(alice, async (event) => {
                events.push(utf8Decode(event.bytes));
            });
            expect(events).toEqual([]);
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("lists local sessions through bounded cursor pages", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        const carol = await client(relay);
        try {
            await alice.createSession({
                descriptor: utf8Encode("first page"),
                members: [await bob.discovery()],
            });
            await alice.createSession({
                descriptor: utf8Encode("second page"),
                members: [await carol.discovery()],
            });
            const first = await alice.sessions({ limit: 1 });
            expect(first.sessions).toHaveLength(1);
            expect(first.cursor).not.toBeNull();
            const second = await alice.sessions({ limit: 1, after: first.cursor! });
            expect(second.sessions).toHaveLength(1);
            expect(second.sessions[0]?.id).not.toEqual(first.sessions[0]?.id);
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("refuses local reuse of a one-use discovery bundle", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const alice = await client(relay);
        const bob = await client(relay);
        try {
            const discovery = await bob.discovery();
            await alice.createSession({
                descriptor: utf8Encode("first use"),
                members: [discovery],
            });
            await expect(
                alice.createSession({
                    descriptor: utf8Encode("second use"),
                    members: [discovery],
                }),
            ).rejects.toThrow("already used");
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("retains a discovery claim through the KeyPackage lifetime", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const bobIdentity = generateIdentityKeyPair();
        let aliceNow = NOW;
        const alice = await MurmurClient.open({
            transport: base,
            store: new MemoryMurmurStore(),
            now: () => aliceNow,
        });
        const bob = await MurmurClient.open({
            identity: bobIdentity,
            transport: base,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const original = await bob.discovery();
            await alice.createSession({
                descriptor: utf8Encode("first wrapper"),
                members: [original],
            });

            aliceNow = original.expiresAt + 1;
            const replacement = createDiscoveryBundle(bobIdentity, original.keyPackages, {
                createdAt: aliceNow,
                expiresAt: aliceNow + 24 * 60 * 60 * 1_000,
            });
            await expect(
                alice.createSession({
                    descriptor: utf8Encode("replacement wrapper"),
                    members: [replacement],
                }),
            ).rejects.toThrow("already used");
        } finally {
            alice.close();
            bob.close();
            destroyIdentity(bobIdentity);
            await relay.close();
        }
    });

    test("can abandon a blocked creating session without leaving local outboxes", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        const blocked: DeliveryTransport = {
            publish: (delivery, signal) => {
                if (delivery.ciphertext[0] === 1) {
                    throw new DeliveryTransportError(413, "limit");
                }
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const alice = await MurmurClient.open({
            transport: blocked,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("abandon"),
                members: [await bob.discovery()],
            });
            expect(await alice.synchronize()).toMatchObject({
                pendingOutboxes: 2,
                transientPublicationFailures: 1,
            });
            await alice.abandonSession(session.id);
            expect(await alice.session(session.id)).toBeUndefined();
            expect((await alice.synchronize()).pendingOutboxes).toBe(0);
        } finally {
            alice.close();
            bob.close();
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
            publish: (delivery, signal) => {
                if (delivery.ciphertext[0] === 1) capturedBootstrap = delivery;
                return base.publish(delivery, signal);
            },
            read: (request, signal) => base.read(request, signal),
            acknowledge: (request, signal) => base.acknowledge(request, signal),
        };
        const carol = await MurmurClient.open({
            identity: carolIdentity,
            transport: capturing,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const first = await alice.createSession({
                descriptor: utf8Encode("first pending"),
                members: [await bob.discovery()],
            });
            await alice.synchronize();
            const second = await carol.createSession({
                descriptor: utf8Encode("capacity retry"),
                members: [await bob.discovery()],
            });
            await carol.synchronize();
            await bob.synchronize();
            expect(await bob.session(first.id)).toMatchObject({ status: "pending" });
            expect(await bob.session(second.id)).toBeUndefined();

            await bob.ignoreSession(first.id);
            expect(capturedBootstrap).toBeDefined();
            await base.publish(
                createSignedDelivery(
                    carolIdentity,
                    capturedBootstrap!.recipients,
                    capturedBootstrap!.ciphertext,
                    {
                        createdAt: NOW,
                        expiresAt: NOW + 60_000,
                    },
                ),
            );
            await bob.synchronize();
            expect(await bob.session(second.id)).toMatchObject({ status: "pending" });
        } finally {
            alice.close();
            bob.close();
            carol.close();
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
            publish: async () => ({
                eventId: "018bcfe5-6800-7000-8000-000000000000",
                duplicate: false,
            }),
            read: async () => {
                readStarted();
                await readGate;
                return {
                    deliveries: [],
                    head: null,
                    acknowledgedThrough: null,
                    exhausted: true,
                };
            },
            acknowledge: async () => ({ removed: 0 }),
        };
        const murmur = await MurmurClient.open({
            transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const synchronizing = murmur.synchronize();
        await started;
        const discovering = murmur.discovery();
        expect(() => murmur.close()).toThrow("operation is pending");
        releaseRead();
        await synchronizing;
        await discovering;
        const reading = murmur.sessions();
        expect(() => murmur.close()).toThrow("operation is pending");
        await reading;
        murmur.close();
    });
});
