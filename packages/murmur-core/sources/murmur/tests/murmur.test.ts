import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import { describe, expect, it } from "vitest";
import {
    decodeIdentityRoot,
    destroyIdentity,
    type IdentityKeyPair,
    type IdentityPublicKey,
} from "../../crypto/index.js";
import { FriendChannel, identityId, type FriendControlEnvelope } from "../../identity/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
} from "../../mls/index.js";
import { MemoryMurmurStore, type MurmurStore, type StoreTransaction } from "../../storage/index.js";
import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    type RelayFetch,
} from "../../transport/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import { decodeFriendControlFrame, encodeFriendControlFrame } from "../impl/controlCodec.js";
import {
    decodeGroup,
    decodeRelayOutbox,
    decodeStagedCommit,
    encodeGroupEvent,
    encodeRelayOutbox,
} from "../impl/stateCodec.js";
import { createCapabilityEvent, friendControlAccess, groupAccess } from "../impl/topics.js";
import { Murmur } from "../index.js";

function inProcessFetch(relay: RelayService): RelayFetch {
    const handler = createRelayFetchHandler(relay);
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function converge(peers: readonly Murmur[], rounds: number = 4): Promise<void> {
    for (let round = 0; round < rounds; round += 1) {
        for (const peer of peers) {
            await peer.sync();
        }
    }
}

async function waitFor(
    predicate: () => Promise<boolean>,
    timeoutMilliseconds: number = 5_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMilliseconds;
    while (!(await predicate())) {
        if (Date.now() >= deadline) {
            throw new Error("Timed out waiting for autonomous Murmur convergence");
        }
        await new Promise<void>((resolve) => {
            setTimeout(resolve, 25);
        });
    }
}

class ProbeStore implements MurmurStore {
    readonly #inner: MurmurStore;
    readonly scans: {
        readonly prefix: string;
        readonly limit: number;
        readonly returned: number;
    }[] = [];
    readonly lists: string[] = [];

    constructor(inner: MurmurStore) {
        this.#inner = inner;
    }

    get(key: string): Promise<Uint8Array | undefined> {
        return this.#inner.get(key);
    }

    set(key: string, value: Uint8Array): Promise<void> {
        return this.#inner.set(key, value);
    }

    delete(key: string): Promise<void> {
        return this.#inner.delete(key);
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        this.lists.push(prefix);
        return this.#inner.list(prefix);
    }

    async scan(
        prefix: string,
        options: { readonly after?: string; readonly limit: number },
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        const result = await this.#inner.scan(prefix, options);
        this.scans.push({
            prefix,
            limit: options.limit,
            returned: result.size,
        });
        return result;
    }

    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#inner.transaction(operation);
    }
}

class TransactionFaultStore implements MurmurStore {
    readonly #inner = new MemoryMurmurStore();
    #failurePredicate: ((keys: readonly string[]) => boolean) | undefined;

    failNextMatchingTransaction(predicate: (keys: readonly string[]) => boolean): void {
        this.#failurePredicate = predicate;
    }

    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#inner.get(key);
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#inner.set(key, value);
    }

    async delete(key: string): Promise<void> {
        await this.#inner.delete(key);
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#inner.list(prefix);
    }

    async scan(
        prefix: string,
        options: { readonly after?: string; readonly limit: number },
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#inner.scan(prefix, options);
    }

    async transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#inner.transaction(async (transaction) => {
            const changedKeys: string[] = [];
            const observed: StoreTransaction = {
                get: async (key): Promise<Uint8Array | undefined> => transaction.get(key),
                set: async (key, value): Promise<void> => {
                    changedKeys.push(key);
                    await transaction.set(key, value);
                },
                delete: async (key): Promise<void> => {
                    changedKeys.push(key);
                    await transaction.delete(key);
                },
                list: async (prefix): Promise<ReadonlyMap<string, Uint8Array>> =>
                    transaction.list(prefix),
                scan: async (prefix, options): Promise<ReadonlyMap<string, Uint8Array>> =>
                    transaction.scan(prefix, options),
            };
            const result = await operation(observed);
            if (this.#failurePredicate?.(changedKeys) === true) {
                this.#failurePredicate = undefined;
                throw new Error("injected transaction failure");
            }
            return result;
        });
    }
}

describe("stateful Murmur facade", () => {
    it("restores identity and converges friends, invitations, MLS events, and removal", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const charlieStore = new MemoryMurmurStore();
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch,
        });
        const originalAliceKey = alice.identityKey;
        await alice.close();
        alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "ignored" },
            fetch,
        });
        expect(alice.identityKey).toEqual(originalAliceKey);
        expect(alice.profile.name).toBe("Alice");

        let bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        const charlie = await Murmur.open({
            relay: "https://relay.test",
            store: charlieStore,
            initialProfile: { name: "Charlie" },
            fetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("pending-incoming");
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 6);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("active");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("active");

            await alice.friends.request(charlie.identityKey);
            await converge([alice, charlie]);
            await charlie.friends.accept(alice.identityKey);
            await converge([charlie, alice], 6);

            await bob.setProfile({ name: "Bob Two" });
            await converge([bob, alice]);
            expect((await alice.friends.get(bob.identityKey))?.profile?.name).toBe("Bob Two");

            const descriptor = utf8Encode("unknown/application-descriptor");
            const groupId = await alice.groups.create(descriptor, [bob.identityKey]);
            await converge([alice, bob], 10).catch((error: unknown) => {
                throw new Error("initial Bob addition failed", { cause: error });
            });
            expect((await bob.groups.get(groupId))?.group.descriptor).toEqual(descriptor);
            const initialMetadata = [
                ...(await aliceStore.list("murmur/v1/groups/")).entries(),
            ].find(([key]) => key.endsWith("/meta"));
            if (initialMetadata === undefined) {
                throw new Error("Initial group metadata was not persisted");
            }
            const stableTopicSecret = decodeGroup(initialMetadata[1]).topicSecret;

            await alice.groups.send(groupId, utf8Encode("opaque from Alice"));
            await bob.groups.send(groupId, utf8Encode("opaque from Bob"));
            await converge([alice, bob], 6);
            const aliceEvents = await alice.groups.get(groupId, { limit: 10 });
            const bobEvents = await bob.groups.get(groupId, { limit: 10 });
            expect(aliceEvents?.events.map((event) => utf8Decode(event.bytes))).toEqual([
                "opaque from Alice",
                "opaque from Bob",
            ]);
            expect(bobEvents?.events.map((event) => utf8Decode(event.bytes))).toEqual([
                "opaque from Alice",
                "opaque from Bob",
            ]);

            await bob.close();
            await alice.groups.send(groupId, utf8Encode("while Bob is offline"));
            await converge([alice], 4);
            bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                fetch,
            });
            await converge([bob, alice], 4);
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("while Bob is offline");

            await alice.groups.add(groupId, charlie.identityKey);
            await converge([alice, bob, charlie], 12).catch((error: unknown) => {
                throw new Error("Charlie addition failed", { cause: error });
            });
            expect((await charlie.groups.get(groupId))?.group.members).toHaveLength(3);

            await alice.groups.remove(groupId, charlie.identityKey);
            await bob.groups.remove(groupId, charlie.identityKey);
            await converge([alice, bob, charlie], 10).catch((error: unknown) => {
                throw new Error("Charlie removal failed", { cause: error });
            });
            expect((await charlie.groups.get(groupId))?.group.status).toBe("removed");
            expect((await alice.groups.get(groupId))?.group.epoch).toBe(
                (await bob.groups.get(groupId))?.group.epoch,
            );
            const removedMetadata = [
                ...(await aliceStore.list("murmur/v1/groups/")).entries(),
            ].find(([key]) => key.endsWith("/meta"));
            if (removedMetadata === undefined) {
                throw new Error("Removed group metadata was not persisted");
            }
            const removedTopicSecret = decodeGroup(removedMetadata[1]).topicSecret;
            expect(removedTopicSecret).toEqual(stableTopicSecret);
            removedTopicSecret.fill(0);
            stableTopicSecret.fill(0);
            await expect(
                charlie.groups.send(groupId, utf8Encode("forged after removal")),
            ).rejects.toThrow("Active group");

            await alice.groups.send(groupId, utf8Encode("after removal"));
            await converge([alice, bob, charlie], 6);
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("after removal");
            expect(
                (await charlie.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).not.toContain("after removal");

            await alice.close();
            alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                fetch,
            });
            expect(
                (await alice.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("after removal");

            await bob.friends.end(alice.identityKey);
            await converge([bob, alice]);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
        } finally {
            await Promise.all([alice.close(), bob.close(), charlie.close()]);
            await relay.close();
        }
    }, 90_000);

    it("retries an accepted-then-thrown publication with exact signed bytes", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        const publishedBodies: string[] = [];
        let throwAfterFirstAcceptance = true;
        const fetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            const body =
                request.method === "POST" && new URL(request.url).pathname === "/v1/events"
                    ? await request.clone().text()
                    : undefined;
            const response = await handler(request);
            if (body !== undefined) {
                publishedBodies.push(body);
                if (throwAfterFirstAcceptance && response.ok) {
                    throwAfterFirstAcceptance = false;
                    throw new Error("accepted then disconnected");
                }
            }
            return response;
        };
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Alice" },
            fetch,
        });
        const bobStore = new MemoryMurmurStore();
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await expect(alice.sync()).rejects.toThrow("accepted then disconnected");
            await alice.sync();
            expect(publishedBodies).toHaveLength(2);
            expect(publishedBodies[1]).toBe(publishedBodies[0]);
            await bob.sync();
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("pending-incoming");
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    });

    it("durably converges rejection and ignores replayed sync passes", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Alice" },
            fetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Bob" },
            fetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.reject(alice.identityKey);
            await converge([bob, alice], 4);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("ended");

            await converge([alice, bob], 4);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("ended");
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    });

    it("rolls back MLS ratchets and invitation adoption across persistence failures", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new TransactionFaultStore();
        const bobStore = new TransactionFaultStore();
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 6);

            bobStore.failNextMatchingTransaction(
                (keys) =>
                    keys.some(
                        (key) => key.startsWith("murmur/v1/groups/") && key.endsWith("/meta"),
                    ) && keys.some((key) => key.startsWith("murmur/v1/cursors/")),
            );
            const groupId = await alice.groups.create(utf8Encode("opaque"), [bob.identityKey]);
            await expect(converge([alice, bob], 12)).rejects.toThrow(
                "Murmur persistence transaction failed",
            );
            expect(await bob.groups.get(groupId)).toBeUndefined();
            await converge([alice, bob], 12);
            expect((await bob.groups.get(groupId))?.group.members).toHaveLength(2);

            aliceStore.failNextMatchingTransaction(
                (keys) =>
                    keys.some(
                        (key) => key.startsWith("murmur/v1/groups/") && key.endsWith("/epoch"),
                    ) && keys.some((key) => key.startsWith("murmur/v1/relay-outbox/")),
            );
            await alice.groups.send(groupId, utf8Encode("survives rollback"));
            await expect(alice.sync()).rejects.toThrow("injected transaction failure");
            await converge([alice, bob], 8);
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["survives rollback"]);
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 30_000);

    it("quarantines an invalid group injection and advances to later valid events", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const store = new MemoryMurmurStore();
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store,
            initialProfile: { name: "Alice" },
            fetch,
        });
        try {
            const groupId = await alice.groups.create(utf8Encode("unknown descriptor"));
            const metadata = [...(await store.list("murmur/v1/groups/")).entries()].find(([key]) =>
                key.endsWith("/meta"),
            );
            if (metadata === undefined) {
                throw new Error("Group metadata was not persisted");
            }
            const record = decodeGroup(metadata[1]);
            const access = groupAccess(record.topicSecret);
            try {
                await relay.publish(createCapabilityEvent(access, new Uint8Array([0xff, 0x00])));
            } finally {
                access.readSecretKey?.fill(0);
                access.writeSecretKey?.fill(0);
            }
            await alice.sync();
            expect((await store.list("murmur/v1/quarantine/")).size).toBe(1);

            await alice.groups.send(groupId, utf8Encode("valid after invalid"));
            await converge([alice], 4);
            expect(
                (await alice.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["valid after invalid"]);
        } finally {
            await alice.close();
            await relay.close();
        }
    });

    it("converges without caller-driven sync and closes after active publication", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        let publicationStarted: (() => void) | undefined;
        let releasePublication: (() => void) | undefined;
        const started = new Promise<void>((resolve) => {
            publicationStarted = resolve;
        });
        const gate = new Promise<void>((resolve) => {
            releasePublication = resolve;
        });
        let gateNextPublication = false;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (
                gateNextPublication &&
                request.method === "POST" &&
                new URL(request.url).pathname === "/v1/events"
            ) {
                gateNextPublication = false;
                publicationStarted?.();
                await gate;
            }
            return handler(request);
        };
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        const bobStore = new MemoryMurmurStore();
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch: inProcessFetch(relay),
        });
        try {
            await alice.friends.request(bob.identityKey);
            await waitFor(
                async () =>
                    (await bob.friends.get(alice.identityKey))?.status === "pending-incoming",
            );
            await bob.friends.accept(alice.identityKey);
            await waitFor(
                async () => (await alice.friends.get(bob.identityKey))?.status === "active",
            );

            gateNextPublication = true;
            await alice.setProfile({ name: "Alice gated" });
            await started;
            let closed = false;
            const closing = alice.close().then(() => {
                closed = true;
            });
            await Promise.resolve();
            expect(closed).toBe(false);
            releasePublication?.();
            await closing;
            expect(closed).toBe(true);
            expect(() => alice.identityKey).toThrow("Murmur is closed");
        } finally {
            releasePublication?.();
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 15_000);

    it("delivers a terminal intent after an ambiguous pending request and restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        let throwAfterAcceptance = true;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            const response = await handler(request);
            if (
                throwAfterAcceptance &&
                response.ok &&
                request.method === "POST" &&
                new URL(request.url).pathname === "/v1/events"
            ) {
                throwAfterAcceptance = false;
                throw new Error("ambiguous request acceptance");
            }
            return response;
        };
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch: inProcessFetch(relay),
        });
        try {
            await alice.friends.request(bob.identityKey);
            await expect(alice.sync()).rejects.toThrow("ambiguous request acceptance");
            await alice.friends.end(bob.identityKey);
            await alice.close();
            alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                fetch: aliceFetch,
            });
            await converge([alice, bob], 8);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("ended");

            await alice.friends.request(bob.identityKey);
            await converge([alice, bob], 8);
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("pending-incoming");
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("active");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("active");
            const aliceQuarantine = await aliceStore.list("murmur/v1/quarantine/");
            const bobQuarantine = await bobStore.list("murmur/v1/quarantine/");
            expect(
                [...aliceQuarantine.values()].map(
                    (bytes) => decodeSignedRelayEventWire(bytes).topic.name,
                ),
            ).toEqual([]);
            expect(
                [...bobQuarantine.values()].map(
                    (bytes) => decodeSignedRelayEventWire(bytes).topic.name,
                ),
            ).toEqual([]);
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 15_000);

    it("preserves causal successor requests regardless of old-end topic order", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch,
        });
        let bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 6);

            for (let iteration = 0; iteration < 6; iteration += 1) {
                await alice.friends.end(bob.identityKey);
                await alice.friends.request(bob.identityKey);
                if (iteration % 2 === 0) {
                    await bob.close();
                    bob = await Murmur.open({
                        relay: "https://relay.test",
                        store: bobStore,
                        fetch,
                    });
                }
                await converge([alice, bob], 8);
                expect((await bob.friends.get(alice.identityKey))?.status).toBe("pending-incoming");
                await bob.friends.accept(alice.identityKey);
                await converge([bob, alice], 6);
                expect((await alice.friends.get(bob.identityKey))?.status).toBe("active");
                expect((await bob.friends.get(alice.identityKey))?.status).toBe("active");
            }
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 30_000);

    it("catches up a winning removal before publishing an old-epoch send", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        let blockAliceGroupPublication = false;
        const blockedBodies: string[] = [];
        const acceptedBodies: string[] = [];
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (request.method === "POST" && new URL(request.url).pathname === "/v1/events") {
                const body = await request.clone().text();
                const wire = JSON.parse(body) as { readonly topic?: { readonly name?: unknown } };
                if (wire.topic?.name === "group-events") {
                    if (blockAliceGroupPublication) {
                        blockedBodies.push(body);
                        throw new Error("blocked old-epoch group publication");
                    }
                    acceptedBodies.push(body);
                }
            }
            return handler(request);
        };
        const sharedFetch = inProcessFetch(relay);
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Bob" },
            fetch: sharedFetch,
        });
        const charlie = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Charlie" },
            fetch: sharedFetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await alice.friends.request(charlie.identityKey);
            await converge([alice, bob, charlie]);
            await bob.friends.accept(alice.identityKey);
            await charlie.friends.accept(alice.identityKey);
            await converge([bob, charlie, alice], 8);
            const groupId = await alice.groups.create(utf8Encode("removal race"), [
                bob.identityKey,
                charlie.identityKey,
            ]);
            await converge([alice, bob, charlie], 14);

            acceptedBodies.length = 0;
            blockAliceGroupPublication = true;
            await alice.groups.send(groupId, utf8Encode("must be resealed"));
            await expect(alice.sync()).rejects.toThrow("blocked old-epoch group publication");
            expect(blockedBodies).toHaveLength(1);

            await bob.groups.remove(groupId, charlie.identityKey);
            await converge([bob], 6);
            blockAliceGroupPublication = false;
            await converge([alice, bob, charlie], 10);

            expect(acceptedBodies).toHaveLength(1);
            expect(acceptedBodies[0]).not.toBe(blockedBodies[0]);
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("must be resealed");
            expect((await charlie.groups.get(groupId))?.group.status).toBe("removed");
            expect(
                (await charlie.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).not.toContain("must be resealed");
        } finally {
            blockAliceGroupPublication = false;
            await Promise.all([alice.close(), bob.close(), charlie.close()]);
            await relay.close();
        }
    }, 90_000);

    it("retires staged Adds when a competing removal removes the local member", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const charlieStore = new MemoryMurmurStore();
        let blockAliceGroups = false;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (
                blockAliceGroups &&
                request.method === "POST" &&
                new URL(request.url).pathname === "/v1/events"
            ) {
                const event = decodeSignedRelayEventWire(utf8Encode(await request.clone().text()));
                if (event.topic.name === "group-events") {
                    throw new Error("blocked staged Add publication");
                }
            }
            return handler(request);
        };
        const sharedFetch = inProcessFetch(relay);
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch: sharedFetch,
        });
        let charlie = await Murmur.open({
            relay: "https://relay.test",
            store: charlieStore,
            initialProfile: { name: "Charlie" },
            fetch: sharedFetch,
        });
        const aliceIdentity = alice.identityKey;
        const charlieIdentity = charlie.identityKey;
        try {
            await alice.friends.request(bob.identityKey);
            await alice.friends.request(charlie.identityKey);
            await converge([alice, bob, charlie], 4);
            await bob.friends.accept(alice.identityKey);
            await charlie.friends.accept(alice.identityKey);
            await converge([bob, charlie, alice], 8);

            for (let iteration = 0; iteration < 9; iteration += 1) {
                blockAliceGroups = false;
                const groupId = await alice.groups.create(
                    utf8Encode(`local-removal-race-${iteration}`),
                    [bob.identityKey],
                );
                await converge([alice, bob, charlie], 7);
                expect((await bob.groups.get(groupId))?.group.members).toHaveLength(2);

                blockAliceGroups = true;
                await alice.groups.add(groupId, charlie.identityKey);
                const encodedGroupId = encodeBase64Url(groupId);
                const stagedKey = `murmur/v1/groups/${encodedGroupId}/staged`;
                await waitFor(async () => {
                    try {
                        await alice.sync();
                    } catch (error: unknown) {
                        if (
                            !(error instanceof Error) ||
                            error.message !== "blocked staged Add publication"
                        ) {
                            throw error;
                        }
                    }
                    const checkpoint = await aliceStore.get(stagedKey);
                    if (checkpoint === undefined) {
                        return false;
                    }
                    checkpoint.fill(0);
                    return true;
                }, 30_000);
                const stagedBytes = await aliceStore.get(stagedKey);
                if (stagedBytes === undefined) {
                    throw new Error("Expected a staged Add");
                }
                const staged = decodeStagedCommit(stagedBytes);
                stagedBytes.fill(0);
                if (staged.keyPackageReference === undefined) {
                    throw new Error("Staged Add lost its KeyPackage reference");
                }
                const reference = staged.keyPackageReference.slice();
                staged.nextEpoch.fill(0);
                staged.fingerprint.fill(0);
                staged.peer.fill(0);
                staged.keyPackageReference.fill(0);
                staged.welcome?.fill(0);
                staged.tree?.fill(0);
                const encodedReference = encodeBase64Url(reference);
                const charlieBundleKey = `murmur/v1/key-packages/local/${identityId({
                    publicKey: aliceIdentity,
                })}/${encodedReference}`;
                const charlieBundle = await charlieStore.get(charlieBundleKey);
                expect(charlieBundle).toBeDefined();
                charlieBundle?.fill(0);

                await alice.groups.send(groupId, utf8Encode(`orphan-${iteration}`));
                const metadataBytes = await aliceStore.get(
                    `murmur/v1/groups/${encodedGroupId}/meta`,
                );
                if (metadataBytes === undefined) {
                    throw new Error("Expected group metadata");
                }
                const metadata = decodeGroup(metadataBytes);
                metadataBytes.fill(0);
                const access = groupAccess(metadata.topicSecret);
                const syntheticPayload = utf8Encode(`synthetic-${iteration}`);
                try {
                    const synthetic = createCapabilityEvent(access, syntheticPayload);
                    const operationId = encodeBase64Url(new Uint8Array(24).fill(iteration + 1));
                    const encodedOutbox = encodeRelayOutbox({
                        event: synthetic,
                        purpose: {
                            type: "group-application",
                            groupId: encodedGroupId,
                            operationId,
                        },
                        attempted: false,
                    });
                    try {
                        await aliceStore.set(
                            `murmur/v1/relay-outbox/${synthetic.id}`,
                            encodedOutbox,
                        );
                    } finally {
                        encodedOutbox.fill(0);
                    }
                } finally {
                    syntheticPayload.fill(0);
                    metadata.topicSecret.fill(0);
                    access.readSecretKey?.fill(0);
                    access.writeSecretKey?.fill(0);
                }

                await bob.groups.remove(groupId, alice.identityKey);
                await converge([bob], 4);
                if (iteration === 0 || iteration === 8) {
                    await Promise.all([alice.close(), charlie.close()]);
                    blockAliceGroups = false;
                    alice = await Murmur.open({
                        relay: "https://relay.test",
                        store: aliceStore,
                        fetch: aliceFetch,
                    });
                    charlie = await Murmur.open({
                        relay: "https://relay.test",
                        store: charlieStore,
                        fetch: sharedFetch,
                    });
                } else {
                    blockAliceGroups = false;
                }
                await converge([alice, charlie, bob], 6);

                expect((await alice.groups.get(groupId))?.group.status).toBe("removed");
                expect(await aliceStore.get(stagedKey)).toBeUndefined();
                expect(
                    await aliceStore.get(`murmur/v1/groups/${encodedGroupId}/epoch`),
                ).toBeUndefined();
                const operations = await aliceStore.list(
                    `murmur/v1/groups/${encodedGroupId}/operations/`,
                );
                expect(operations.size).toBe(0);
                for (const bytes of operations.values()) {
                    bytes.fill(0);
                }
                expect(
                    await aliceStore.get(
                        `murmur/v1/key-packages/remote-consumed/${identityId({
                            publicKey: charlieIdentity,
                        })}/${encodedReference}`,
                    ),
                ).toBeUndefined();
                expect(await charlieStore.get(charlieBundleKey)).toBeUndefined();

                const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
                try {
                    const decodedOutboxes = [...outboxes.values()].map(decodeRelayOutbox);
                    const groupOutboxes = decodedOutboxes.filter(
                        (record) =>
                            (record.purpose.type === "group-application" ||
                                record.purpose.type === "group-commit") &&
                            record.purpose.groupId === encodedGroupId,
                    );
                    expect(groupOutboxes).toHaveLength(0);
                    for (const record of decodedOutboxes) {
                        record.event.author.signingKey.fill(0);
                        record.event.payload.fill(0);
                        record.event.signature.fill(0);
                        record.event.collapseKey?.fill(0);
                    }
                } finally {
                    for (const bytes of outboxes.values()) {
                        bytes.fill(0);
                    }
                }
                const localPackages = await charlieStore.list(
                    `murmur/v1/key-packages/local/${identityId({
                        publicKey: aliceIdentity,
                    })}/`,
                );
                expect(localPackages.size).toBeLessThanOrEqual(8);
                for (const bytes of localPackages.values()) {
                    bytes.fill(0);
                }
                reference.fill(0);
            }
        } finally {
            blockAliceGroups = false;
            await Promise.all([alice.close(), bob.close(), charlie.close()]);
            await relay.close();
        }
    }, 600_000);

    it("opens from a metadata index and paginates O(limit) retained events", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const memory = new MemoryMurmurStore();
        const first = await Murmur.open({
            relay: "https://relay.test",
            store: memory,
            initialProfile: { name: "Alice" },
            fetch,
        });
        const groupId = await first.groups.create(utf8Encode("large history"));
        await first.close();
        const encodedGroupId = encodeBase64Url(groupId);
        await memory.transaction(async (transaction) => {
            for (let sequence = 1n; sequence <= 2_500n; sequence += 1n) {
                await transaction.set(
                    `murmur/v1/groups/${encodedGroupId}/events/${sequence
                        .toString()
                        .padStart(20, "0")}`,
                    encodeGroupEvent({
                        sequence,
                        sender: new Uint8Array(32),
                        bytes: utf8Encode(`event-${sequence}`),
                    }),
                );
            }
        });
        const probe = new ProbeStore(memory);
        const reopened = await Murmur.open({
            relay: "https://relay.test",
            store: probe,
            fetch,
        });
        try {
            expect(
                probe.lists.some((prefix) => prefix.includes(`/groups/${encodedGroupId}/events/`)),
            ).toBe(false);
            const page = await reopened.groups.get(groupId, { limit: 7 });
            expect(page?.events).toHaveLength(7);
            expect(page?.nextAfter).toBe(7n);
            expect(
                probe.scans.find((scan) =>
                    scan.prefix.includes(`/groups/${encodedGroupId}/events/`),
                ),
            ).toEqual({
                prefix: `murmur/v1/groups/${encodedGroupId}/events/`,
                limit: 8,
                returned: 8,
            });
        } finally {
            await reopened.close();
            await relay.close();
        }
    }, 15_000);

    it("rejects invitation cursor and fingerprint tampering without poisoning later adoption", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let aliceRoot: IdentityKeyPair | undefined;
        let bobRoot: IdentityKeyPair | undefined;
        let tamper: "cursor" | "fingerprint" | undefined;
        let tampered = 0;
        const tamperedDescriptors: string[] = [];
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (
                tamper === undefined ||
                request.method !== "POST" ||
                new URL(request.url).pathname !== "/v1/events" ||
                aliceRoot === undefined ||
                bobRoot === undefined
            ) {
                return handler(request);
            }
            const original = decodeSignedRelayEventWire(utf8Encode(await request.clone().text()));
            if (original.topic.name !== "control") {
                return handler(request);
            }
            const receiver = new FriendChannel(bobRoot, {
                publicKey: aliceRoot.publicKey,
            });
            let opened;
            try {
                opened = receiver.open(
                    JSON.parse(utf8Decode(original.payload)) as FriendControlEnvelope,
                );
            } catch {
                receiver.destroy();
                return handler(request);
            }
            receiver.destroy();
            const frame = decodeFriendControlFrame(opened.message.payload);
            opened.message.payload.fill(0);
            if (frame.type !== "group-invitation") {
                return handler(request);
            }
            const changed =
                tamper === "cursor"
                    ? {
                          ...frame,
                          commitSequence: frame.commitSequence + 10_000n,
                      }
                    : {
                          ...frame,
                          commitFingerprint: Uint8Array.from(
                              frame.commitFingerprint,
                              (byte, index) => (index === 0 ? byte ^ 1 : byte),
                          ),
                      };
            const frameBytes = encodeFriendControlFrame(changed);
            const sender = new FriendChannel(aliceRoot, {
                publicKey: bobRoot.publicKey,
            } satisfies IdentityPublicKey);
            const access = friendControlAccess(sender);
            try {
                const envelope = sender.seal({
                    ...opened.message,
                    payload: frameBytes,
                });
                const payload = utf8Encode(JSON.stringify(envelope));
                try {
                    const replacement = createCapabilityEvent(access, payload);
                    const replacementBody = utf8Decode(encodeSignedRelayEventWire(replacement));
                    tampered += 1;
                    tamperedDescriptors.push(utf8Decode(frame.descriptor));
                    tamper = undefined;
                    return handler(
                        new Request(request.url, {
                            method: "POST",
                            headers: request.headers,
                            body: replacementBody,
                        }),
                    );
                } finally {
                    payload.fill(0);
                }
            } finally {
                frameBytes.fill(0);
                access.readSecretKey?.fill(0);
                access.writeSecretKey?.fill(0);
                sender.destroy();
            }
        };
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch: inProcessFetch(relay),
        });
        try {
            const aliceRootBytes = await aliceStore.get("murmur/v1/root");
            const bobRootBytes = await bobStore.get("murmur/v1/root");
            if (aliceRootBytes === undefined || bobRootBytes === undefined) {
                throw new Error("Test identity root was not persisted");
            }
            aliceRoot = decodeIdentityRoot(aliceRootBytes);
            bobRoot = decodeIdentityRoot(bobRootBytes);
            aliceRootBytes.fill(0);
            bobRootBytes.fill(0);

            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);

            tamper = "cursor";
            const cursorGroup = await alice.groups.create(utf8Encode("bad cursor"), [
                bob.identityKey,
            ]);
            for (
                let round = 0;
                round < 24 && !tamperedDescriptors.includes("bad cursor");
                round += 1
            ) {
                await converge([alice, bob], 1);
            }
            expect(tamperedDescriptors).toContain("bad cursor");
            expect(await bob.groups.get(cursorGroup)).toBeUndefined();

            tamper = "fingerprint";
            const fingerprintGroup = await alice.groups.create(utf8Encode("bad fingerprint"), [
                bob.identityKey,
            ]);
            for (
                let round = 0;
                round < 24 && !tamperedDescriptors.includes("bad fingerprint");
                round += 1
            ) {
                await converge([alice, bob], 1);
            }
            expect(tamperedDescriptors).toEqual(["bad cursor", "bad fingerprint"]);
            expect(await bob.groups.get(fingerprintGroup)).toBeUndefined();
            expect(tampered).toBe(2);

            const validGroup = await alice.groups.create(utf8Encode("valid later"), [
                bob.identityKey,
            ]);
            await converge([alice, bob], 12);
            expect((await bob.groups.get(validGroup))?.group.members).toHaveLength(2);
        } finally {
            if (aliceRoot !== undefined) {
                destroyIdentity(aliceRoot);
            }
            if (bobRoot !== undefined) {
                destroyIdentity(bobRoot);
            }
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 30_000);

    it("acknowledges more than 64 consumed KeyPackages across restart with bounded pools", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        let bobRoot: IdentityKeyPair | undefined;
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);

            const bobId = identityId({ publicKey: bob.identityKey });
            const remotePrefix = `murmur/v1/key-packages/remote/${bobId}/`;
            const consumedPrefix = `murmur/v1/key-packages/remote-consumed/${bobId}/`;
            const rootBytes = await bobStore.get("murmur/v1/root");
            if (rootBytes === undefined) {
                throw new Error("Bob root was not persisted");
            }
            bobRoot = decodeIdentityRoot(rootBytes);
            rootBytes.fill(0);
            const floodChannel = new FriendChannel(bobRoot, {
                publicKey: alice.identityKey,
            });
            const floodAccess = friendControlAccess(floodChannel);
            try {
                for (let index = 0; index < 70; index += 1) {
                    const bundle = createMlsKeyPackage(bobRoot);
                    const reference = mlsKeyPackageReference(bundle.keyPackage);
                    const frameBytes = encodeFriendControlFrame({
                        type: "key-package-announce",
                        reference,
                        keyPackage: encodeMlsKeyPackage(bundle.keyPackage),
                    });
                    const envelope = floodChannel.seal(floodChannel.createMessage(frameBytes));
                    const payload = utf8Encode(JSON.stringify(envelope));
                    try {
                        const event = createCapabilityEvent(floodAccess, payload);
                        const response = await fetch("https://relay.test/v1/events", {
                            method: "POST",
                            headers: { "content-type": "application/json" },
                            body: utf8Decode(encodeSignedRelayEventWire(event)),
                        });
                        expect(response.ok).toBe(true);
                    } finally {
                        payload.fill(0);
                        frameBytes.fill(0);
                        reference.fill(0);
                        destroyMlsKeyPackageBundle(bundle);
                    }
                }
                await alice.sync();
                expect((await aliceStore.list(remotePrefix)).size).toBeLessThanOrEqual(8);
            } finally {
                floodChannel.destroy();
                floodAccess.readSecretKey?.fill(0);
                floodAccess.writeSecretKey?.fill(0);
            }
            const remote = await aliceStore.list(remotePrefix);
            for (const [key, bytes] of remote) {
                bytes.fill(0);
                await aliceStore.delete(key);
            }
            const seededConsumedKeys: string[] = [];
            for (let index = 0; index < 70; index += 1) {
                const reference = new Uint8Array(32);
                new DataView(reference.buffer).setUint32(28, index + 1);
                const consumedKey = `${consumedPrefix}${encodeBase64Url(reference)}`;
                seededConsumedKeys.push(consumedKey);
                await aliceStore.set(consumedKey, reference);
                reference.fill(0);
            }

            const groupId = await alice.groups.create(utf8Encode("paged KeyPackages"));
            await alice.groups.add(groupId, bob.identityKey);
            await alice.sync();
            await alice.close();
            alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                fetch,
            });
            await converge([bob, alice], 14);

            const remainingConsumed = await aliceStore.list(consumedPrefix);
            expect(remainingConsumed.size).toBeLessThanOrEqual(8);
            expect(seededConsumedKeys.some((key) => remainingConsumed.has(key))).toBe(false);
            expect((await aliceStore.list(remotePrefix)).size).toBeLessThanOrEqual(8);
            expect(
                (
                    await bobStore.list(
                        `murmur/v1/key-packages/local/${identityId({
                            publicKey: alice.identityKey,
                        })}/`,
                    )
                ).size,
            ).toBeLessThanOrEqual(8);
            expect((await alice.groups.get(groupId))?.group.members).toHaveLength(2);
        } finally {
            if (bobRoot !== undefined) {
                destroyIdentity(bobRoot);
            }
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 90_000);

    it("deletes expired remote KeyPackages and never reserves them for an Add", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        let bobRoot: IdentityKeyPair | undefined;
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);
            const groupId = await alice.groups.create(utf8Encode("expired package"));

            const remotePrefix = `murmur/v1/key-packages/remote/${identityId({
                publicKey: bob.identityKey,
            })}/`;
            for (const key of (await aliceStore.list(remotePrefix)).keys()) {
                await aliceStore.delete(key);
            }
            const rootBytes = await bobStore.get("murmur/v1/root");
            if (rootBytes === undefined) {
                throw new Error("Bob root was not persisted");
            }
            bobRoot = decodeIdentityRoot(rootBytes);
            rootBytes.fill(0);
            const expired = createMlsKeyPackage(bobRoot, Math.floor(Date.now() / 1_000) - 100, 1);
            const reference = mlsKeyPackageReference(expired.keyPackage);
            const expiredKey = `${remotePrefix}${encodeBase64Url(reference)}`;
            try {
                await aliceStore.set(expiredKey, encodeMlsKeyPackage(expired.keyPackage));
            } finally {
                destroyMlsKeyPackageBundle(expired);
                reference.fill(0);
            }

            await alice.groups.add(groupId, bob.identityKey);
            await alice.sync();
            expect(await aliceStore.get(expiredKey)).toBeUndefined();
            expect((await alice.groups.get(groupId))?.group.members).toHaveLength(1);
            expect(
                (await aliceStore.list(`murmur/v1/groups/${encodeBase64Url(groupId)}/operations/`))
                    .size,
            ).toBe(1);
        } finally {
            if (bobRoot !== undefined) {
                destroyIdentity(bobRoot);
            }
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 15_000);
});
