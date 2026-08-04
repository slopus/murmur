import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import { describe, expect, it } from "vitest";
import { MemoryMurmurStore, type MurmurStore, type StoreTransaction } from "../../storage/index.js";
import type { RelayFetch } from "../../transport/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { decodeGroup } from "../impl/stateCodec.js";
import { createCapabilityEvent, groupAccess } from "../impl/topics.js";
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
        alice.close();
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

            bob.close();
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

            alice.close();
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
            alice.close();
            bob.close();
            charlie.close();
            await relay.close();
        }
    }, 30_000);

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
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
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
            alice.close();
            bob.close();
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
            alice.close();
            bob.close();
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
            alice.close();
            bob.close();
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
            alice.close();
            await relay.close();
        }
    });
});
