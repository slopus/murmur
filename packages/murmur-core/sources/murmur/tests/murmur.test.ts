import { DatabaseSync } from "node:sqlite";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import { describe, expect, it } from "vitest";
import {
    decodeIdentityRoot,
    destroyIdentity,
    randomBytes,
    type IdentityKeyPair,
    type IdentityPublicKey,
} from "../../crypto/index.js";
import {
    FriendChannel,
    identityId,
    validateIdentityProfile,
    type FriendControlEnvelope,
    type IdentityProfile,
} from "../../identity/index.js";
import {
    createMlsKeyPackage,
    decodeMlsTreeCommit,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
} from "../../mls/index.js";
import { MemoryMurmurStore, type MurmurStore, type StoreTransaction } from "../../storage/index.js";
import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    relayTopicId,
    type RelayFetch,
} from "../../transport/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    decodeFriendControlFrame,
    destroyFriendControlFrame,
    encodeFriendControlFrame,
    type FriendControlFrame,
} from "../impl/controlCodec.js";
import { sealGroupRelayPayload } from "../impl/groupEnvelope.js";
import {
    decodeGroup,
    decodeGroupOperation,
    decodeRelayOutbox,
    decodeStagedCommit,
    encodeGroupEvent,
    encodeGroupOperation,
    encodeRelayOutbox,
} from "../impl/stateCodec.js";
import { createCapabilityEvent, friendControlAccess, groupAccess } from "../impl/topics.js";
import { destroyGroupOperation, destroyRelayOutboxRecord } from "../impl/groupProcessing.js";
import { Murmur, MurmurKeyPackagePoolExhaustedError } from "../index.js";

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

async function exhaustFriendKeyPackagePool(
    victim: Murmur,
    victimStore: MurmurStore,
    hostile: Murmur,
    hostileStore: MurmurStore,
    fetch: RelayFetch,
): Promise<MurmurKeyPackagePoolExhaustedError> {
    const rootBytes = await hostileStore.get("murmur/v1/root");
    if (rootBytes === undefined) {
        throw new Error("Hostile friend root was not persisted");
    }
    const hostileRoot = decodeIdentityRoot(rootBytes);
    rootBytes.fill(0);
    const channel = new FriendChannel(hostileRoot, {
        publicKey: victim.identityKey,
    });
    const access = friendControlAccess(channel);
    const peerId = identityId({ publicKey: hostile.identityKey });
    const localPrefix = `murmur/v1/key-packages/local/${peerId}/`;
    const consumedPrefix = `murmur/v1/key-packages/local-consumed/${peerId}/`;
    try {
        for (let round = 0; round < 8; round += 1) {
            const local = await victimStore.list(localPrefix);
            const consumed = await victimStore.list(consumedPrefix);
            const available = [...local.keys()]
                .filter(
                    (key) =>
                        !consumed.has(`${consumedPrefix}${key.slice(key.lastIndexOf("/") + 1)}`),
                )
                .slice(0, 2)
                .map((key) => decodeBase64Url(key.slice(key.lastIndexOf("/") + 1)));
            for (const bytes of local.values()) {
                bytes.fill(0);
            }
            for (const bytes of consumed.values()) {
                bytes.fill(0);
            }
            if (available.length === 0) {
                break;
            }
            const bogus = new Uint8Array(32);
            bogus.fill(round + 1);
            const frameBytes = encodeFriendControlFrame({
                type: "key-package-request",
                consumedReferences: [...available, bogus],
            });
            const envelope = channel.seal(channel.createMessage(frameBytes));
            const payload = utf8Encode(JSON.stringify(envelope));
            try {
                const response = await fetch("https://relay.test/v1/events", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: utf8Decode(
                        encodeSignedRelayEventWire(createCapabilityEvent(access, payload)),
                    ),
                });
                expect(response.ok).toBe(true);
                try {
                    await victim.sync();
                } catch (error: unknown) {
                    if (error instanceof MurmurKeyPackagePoolExhaustedError) {
                        return error;
                    }
                    throw error;
                }
            } finally {
                for (const reference of available) {
                    reference.fill(0);
                }
                bogus.fill(0);
                frameBytes.fill(0);
                payload.fill(0);
            }
        }
        throw new Error("Hostile friend did not exhaust the bounded KeyPackage pool");
    } finally {
        channel.destroy();
        access.readSecretKey?.fill(0);
        access.writeSecretKey?.fill(0);
        destroyIdentity(hostileRoot);
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
    it("rejects malformed public JavaScript profiles with a domain error", async () => {
        const invalidProfiles = [null, [], {}, { avatar: new Uint8Array() }];
        for (const invalid of invalidProfiles) {
            const profile = invalid as unknown as IdentityProfile;
            expect(() => validateIdentityProfile(profile)).toThrow(
                "Invalid identity profile: expected an object with a string name",
            );
            await expect(
                Murmur.open({
                    relay: "https://relay.test",
                    store: new MemoryMurmurStore(),
                    initialProfile: profile,
                    fetch: async (): Promise<Response> => {
                        throw new Error("Invalid profile must fail before network access");
                    },
                }),
            ).rejects.toThrow("Invalid identity profile: expected an object with a string name");
        }

        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const murmur = await Murmur.open({
            relay: "https://relay.test",
            store: new MemoryMurmurStore(),
            initialProfile: { name: "Valid" },
            fetch: inProcessFetch(relay),
        });
        try {
            for (const invalid of invalidProfiles) {
                await expect(
                    murmur.setProfile(invalid as unknown as IdentityProfile),
                ).rejects.toThrow(
                    "Invalid identity profile: expected an object with a string name",
                );
            }
        } finally {
            await murmur.close();
            await relay.close();
        }
    });

    it("restores identity and converges friends, invitations, MLS events, and removal", async () => {
        const database = new DatabaseSync(":memory:");
        const relay = new RelayService(
            new SqliteRelayStore(":memory:", {
                database,
            }),
        );
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

            const rawGroupRows = database
                .prepare("SELECT event_json FROM murmur_relay_events ORDER BY seq")
                .all()
                .flatMap((row) => {
                    if (typeof row.event_json !== "string") {
                        throw new Error("Relay event JSON probe returned a non-string");
                    }
                    const wire = JSON.parse(row.event_json) as {
                        readonly topic?: { readonly name?: unknown };
                    };
                    return wire.topic?.name === "group-events" ? [row.event_json] : [];
                });
            expect(rawGroupRows.length).toBeGreaterThanOrEqual(3);
            const identityEncodings = [
                encodeBase64Url(alice.identityKey),
                encodeBase64Url(bob.identityKey),
            ];
            for (const raw of rawGroupRows) {
                for (const identity of identityEncodings) {
                    expect(raw).not.toContain(identity);
                }
                const retained = decodeSignedRelayEventWire(utf8Encode(raw));
                expect(() => decodeMlsTreeCommit(retained.payload)).toThrow();
            }

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
                const inner = utf8Encode("opaque-envelope-probe");
                const sealed = sealGroupRelayPayload(record.topicSecret, access.topic, inner);
                const tampered = sealed.slice();
                tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 1;
                const wrongSecret = randomBytes(32);
                const wrongAccess = groupAccess(wrongSecret);
                const wrongEnvelope = sealGroupRelayPayload(wrongSecret, wrongAccess.topic, inner);
                try {
                    await relay.publish(createCapabilityEvent(access, tampered));
                    await relay.publish(createCapabilityEvent(access, wrongEnvelope));
                } finally {
                    inner.fill(0);
                    sealed.fill(0);
                    tampered.fill(0);
                    wrongSecret.fill(0);
                    wrongEnvelope.fill(0);
                    wrongAccess.readSecretKey?.fill(0);
                    wrongAccess.writeSecretKey?.fill(0);
                }
                await alice.sync();
                expect((await store.list("murmur/v1/quarantine/")).size).toBe(2);

                for (let index = 0; index < 40; index += 1) {
                    await relay.publish(
                        createCapabilityEvent(access, new Uint8Array([0xff, index & 0xff])),
                    );
                }
            } finally {
                access.readSecretKey?.fill(0);
                access.writeSecretKey?.fill(0);
            }
            await alice.sync();
            expect((await store.list("murmur/v1/quarantine/")).size).toBe(32);

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

    it("converges without caller-driven sync and aborts active publication on close", async () => {
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
                await Promise.race([
                    gate,
                    new Promise<never>((_resolve, reject) => {
                        const abort = (): void =>
                            reject(request.signal.reason ?? new Error("publication aborted"));
                        if (request.signal.aborted) {
                            abort();
                        } else {
                            request.signal.addEventListener("abort", abort, { once: true });
                        }
                    }),
                ]);
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
            await alice.close();
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

    it("retires KeyPackages, compensates, and rejects a retained invitation after friendship end", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let aliceRoot: IdentityKeyPair | undefined;
        let bobRoot: IdentityKeyPair | undefined;
        let holdInvitations = false;
        let retainedInvitationBody: string | undefined;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (
                !holdInvitations ||
                request.method !== "POST" ||
                new URL(request.url).pathname !== "/v1/events" ||
                aliceRoot === undefined ||
                bobRoot === undefined
            ) {
                return handler(request);
            }
            const body = await request.clone().text();
            const event = decodeSignedRelayEventWire(utf8Encode(body));
            if (event.topic.name !== "control") {
                return handler(request);
            }
            const receiver = new FriendChannel(bobRoot, {
                publicKey: aliceRoot.publicKey,
            });
            let opened;
            try {
                opened = receiver.open(
                    JSON.parse(utf8Decode(event.payload)) as FriendControlEnvelope,
                );
            } catch {
                receiver.destroy();
                return handler(request);
            }
            receiver.destroy();
            const frame = decodeFriendControlFrame(opened.message.payload);
            opened.message.payload.fill(0);
            try {
                if (frame.type !== "group-invitation") {
                    return handler(request);
                }
                retainedInvitationBody = body;
                throw new Error("held group invitation");
            } finally {
                destroyFriendControlFrame(frame);
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

            holdInvitations = true;
            const groupId = await alice.groups.create(utf8Encode("held invite"), [bob.identityKey]);
            for (let round = 0; round < 16 && retainedInvitationBody === undefined; round += 1) {
                await alice.sync().catch(() => undefined);
                await bob.sync().catch(() => undefined);
            }
            expect(retainedInvitationBody).toBeDefined();

            await alice.friends.end(bob.identityKey);
            holdInvitations = false;
            await converge([alice, bob], 8);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
            expect((await bob.friends.get(alice.identityKey))?.status).toBe("ended");
            expect((await alice.groups.get(groupId))?.group.members).toEqual([alice.identityKey]);

            if (retainedInvitationBody === undefined) {
                throw new Error("Expected a retained invitation body");
            }
            await handler(
                new Request("https://relay.test/v1/events", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: retainedInvitationBody,
                }),
            );
            await bob.sync();
            expect(await bob.groups.get(groupId)).toBeUndefined();

            await alice.groups.send(groupId, utf8Encode("after retained invitation compensation"));
            await converge([alice], 4);
            expect(
                (await alice.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("after retained invitation compensation");
            const encodedGroupId = encodeBase64Url(groupId);
            expect(
                (await aliceStore.list(`murmur/v1/groups/${encodedGroupId}/operations/`)).size,
            ).toBe(0);
            expect(
                await aliceStore.get(`murmur/v1/groups/${encodedGroupId}/staged`),
            ).toBeUndefined();
            expect((await aliceStore.list("murmur/v1/relay-outbox/")).size).toBe(0);

            const alicePeer = identityId({ publicKey: bob.identityKey });
            const bobPeer = identityId({ publicKey: alice.identityKey });
            for (const [store, peerId] of [
                [aliceStore, alicePeer],
                [bobStore, bobPeer],
            ] as const) {
                for (const prefix of [
                    `murmur/v1/key-packages/local/${peerId}/`,
                    `murmur/v1/key-packages/local-consumed/${peerId}/`,
                    `murmur/v1/key-packages/remote/${peerId}/`,
                    `murmur/v1/key-packages/remote-consumed/${peerId}/`,
                ]) {
                    const records = await store.list(prefix);
                    expect(records.size).toBe(0);
                    for (const bytes of records.values()) {
                        bytes.fill(0);
                    }
                }
            }
        } finally {
            holdInvitations = false;
            if (aliceRoot !== undefined) {
                destroyIdentity(aliceRoot);
            }
            if (bobRoot !== undefined) {
                destroyIdentity(bobRoot);
            }
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 120_000);

    it("compensates remote and ambiguous invitations but retains confirmed membership", async () => {
        for (const scenario of ["queued-remote", "accepted-restart", "confirmed"] as const) {
            const relay = new RelayService(new SqliteRelayStore(":memory:"));
            const handler = createRelayFetchHandler(relay);
            const aliceStore = new MemoryMurmurStore();
            const bobStore = new MemoryMurmurStore();
            let aliceRoot: IdentityKeyPair | undefined;
            let bobRoot: IdentityKeyPair | undefined;
            let blockInvitation = scenario !== "confirmed";
            let invitationAccepted = false;
            let blockGroupPublications = false;
            let watchGroupPublications = false;
            const compensationEventIds = new Set<string>();
            const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
                const request = new Request(input, init);
                if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/events") {
                    return handler(request);
                }
                const body = await request.clone().text();
                const event = decodeSignedRelayEventWire(utf8Encode(body));
                if (event.topic.name === "group-events" && watchGroupPublications) {
                    compensationEventIds.add(event.id);
                    if (blockGroupPublications) {
                        throw new Error("blocked invitation compensation");
                    }
                }
                if (
                    !blockInvitation ||
                    event.topic.name !== "control" ||
                    aliceRoot === undefined ||
                    bobRoot === undefined
                ) {
                    return handler(request);
                }
                const receiver = new FriendChannel(bobRoot, {
                    publicKey: aliceRoot.publicKey,
                });
                let frame: FriendControlFrame | undefined;
                try {
                    const opened = receiver.open(
                        JSON.parse(utf8Decode(event.payload)) as FriendControlEnvelope,
                    );
                    frame = decodeFriendControlFrame(opened.message.payload);
                    opened.message.payload.fill(0);
                } catch {
                    return handler(request);
                } finally {
                    receiver.destroy();
                }
                try {
                    if (frame.type !== "group-invitation") {
                        return handler(request);
                    }
                    if (scenario === "accepted-restart" && !invitationAccepted) {
                        await handler(request);
                        invitationAccepted = true;
                    }
                    throw new Error(`held ${scenario} group invitation`);
                } finally {
                    destroyFriendControlFrame(frame);
                }
            };
            const bobFetch = inProcessFetch(relay);
            let alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                initialProfile: { name: `Alice ${scenario}` },
                fetch: aliceFetch,
            });
            const bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                initialProfile: { name: `Bob ${scenario}` },
                fetch: bobFetch,
            });
            const aliceIdentity = alice.identityKey;
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

                const groupId = await alice.groups.create(
                    utf8Encode(`invitation liveness ${scenario}`),
                    [bob.identityKey],
                );
                const encodedGroupId = encodeBase64Url(groupId);
                let invitationOperationId: string | undefined;
                if (scenario === "confirmed") {
                    await converge([alice, bob], 10);
                    expect((await bob.groups.get(groupId))?.group.members).toHaveLength(2);
                } else {
                    await waitFor(async () => {
                        try {
                            await alice.sync();
                        } catch {
                            // The deliberately held invitation remains an exact durable outbox.
                        }
                        const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
                        try {
                            for (const encoded of outboxes.values()) {
                                const record = decodeRelayOutbox(encoded);
                                try {
                                    if (
                                        record.purpose.type === "group-invitation" &&
                                        record.purpose.groupId === encodedGroupId
                                    ) {
                                        expect(record.purpose.peerId).toBe(
                                            identityId({ publicKey: bob.identityKey }),
                                        );
                                        invitationOperationId = record.purpose.operationId;
                                    }
                                } finally {
                                    destroyRelayOutboxRecord(record);
                                }
                            }
                        } finally {
                            for (const encoded of outboxes.values()) {
                                encoded.fill(0);
                            }
                        }
                        return (
                            invitationOperationId !== undefined &&
                            (await alice.groups.get(groupId))?.group.members.length === 2
                        );
                    }, 30_000);
                    expect(invitationOperationId).toBeDefined();
                    expect(invitationAccepted).toBe(scenario === "accepted-restart");
                }

                if (scenario === "accepted-restart") {
                    await bob.sync();
                    expect((await bob.groups.get(groupId))?.group.members).toHaveLength(2);
                    await alice.close();
                    alice = await Murmur.open({
                        relay: "https://relay.test",
                        store: aliceStore,
                        fetch: aliceFetch,
                    });
                }

                watchGroupPublications = true;
                blockGroupPublications = scenario !== "confirmed";
                if (scenario === "queued-remote") {
                    await bob.friends.end(aliceIdentity);
                    await bob.sync();
                    await waitFor(async () => {
                        try {
                            await alice.sync();
                        } catch {
                            // Invitation and compensation publication are intentionally held.
                        }
                        return (await alice.friends.get(bob.identityKey))?.status === "ended";
                    }, 30_000);
                } else {
                    await alice.friends.end(bob.identityKey);
                }

                if (scenario !== "confirmed") {
                    await waitFor(async () => {
                        try {
                            await alice.sync();
                        } catch {
                            // The compensating Remove is intentionally retained for inspection.
                        }
                        return compensationEventIds.size > 0;
                    }, 30_000);
                    const operations = await aliceStore.list(
                        `murmur/v1/groups/${encodedGroupId}/operations/`,
                    );
                    try {
                        const decoded = [...operations.values()].map(decodeGroupOperation);
                        try {
                            const removals = decoded.filter(
                                (operation) =>
                                    operation.type === "remove" &&
                                    encodeBase64Url(operation.peer) ===
                                        encodeBase64Url(bob.identityKey),
                            );
                            expect(removals).toHaveLength(1);
                            expect(removals[0]?.id).toBe(invitationOperationId);
                        } finally {
                            for (const operation of decoded) {
                                destroyGroupOperation(operation);
                            }
                        }
                    } finally {
                        for (const encoded of operations.values()) {
                            encoded.fill(0);
                        }
                    }
                    const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
                    try {
                        const purposes = [...outboxes.values()].map(decodeRelayOutbox);
                        try {
                            expect(
                                purposes.some(
                                    (record) => record.purpose.type === "group-invitation",
                                ),
                            ).toBe(false);
                        } finally {
                            for (const record of purposes) {
                                destroyRelayOutboxRecord(record);
                            }
                        }
                    } finally {
                        for (const encoded of outboxes.values()) {
                            encoded.fill(0);
                        }
                    }
                }

                blockInvitation = false;
                blockGroupPublications = false;
                await converge([alice, bob], 12);
                if (scenario === "confirmed") {
                    expect(compensationEventIds.size).toBe(0);
                    expect((await alice.groups.get(groupId))?.group.members).toHaveLength(2);
                    expect((await bob.groups.get(groupId))?.group.members).toHaveLength(2);
                } else {
                    expect(compensationEventIds.size).toBe(1);
                    expect((await alice.groups.get(groupId))?.group.members).toEqual([
                        alice.identityKey,
                    ]);
                    if (scenario === "accepted-restart") {
                        expect((await bob.groups.get(groupId))?.group.status).toBe("removed");
                    } else {
                        expect(await bob.groups.get(groupId)).toBeUndefined();
                    }
                }

                watchGroupPublications = false;
                await alice.groups.send(groupId, utf8Encode(`after ${scenario} end`));
                await converge([alice, bob], 6);
                expect(
                    (await alice.groups.get(groupId))?.events.map((event) =>
                        utf8Decode(event.bytes),
                    ),
                ).toContain(`after ${scenario} end`);
                if (scenario === "confirmed") {
                    expect(
                        (await bob.groups.get(groupId))?.events.map((event) =>
                            utf8Decode(event.bytes),
                        ),
                    ).toContain(`after ${scenario} end`);
                }

                expect(
                    (await aliceStore.list(`murmur/v1/groups/${encodedGroupId}/operations/`)).size,
                ).toBe(0);
                expect(
                    await aliceStore.get(`murmur/v1/groups/${encodedGroupId}/staged`),
                ).toBeUndefined();
                expect((await aliceStore.list("murmur/v1/relay-outbox/")).size).toBe(0);
                const peerId = identityId({ publicKey: bob.identityKey });
                for (const prefix of [
                    `murmur/v1/key-packages/local/${peerId}/`,
                    `murmur/v1/key-packages/local-consumed/${peerId}/`,
                    `murmur/v1/key-packages/remote/${peerId}/`,
                    `murmur/v1/key-packages/remote-consumed/${peerId}/`,
                ]) {
                    const records = await aliceStore.list(prefix);
                    expect(records.size).toBe(0);
                    for (const bytes of records.values()) {
                        bytes.fill(0);
                    }
                }
            } finally {
                blockInvitation = false;
                blockGroupPublications = false;
                watchGroupPublications = false;
                if (aliceRoot !== undefined) {
                    destroyIdentity(aliceRoot);
                }
                if (bobRoot !== undefined) {
                    destroyIdentity(bobRoot);
                }
                await Promise.all([alice.close(), bob.close()]);
                await relay.close();
            }
        }
    }, 240_000);

    it("drops queued Adds after local and remote friendship end without blocking later work", async () => {
        for (const ending of ["local", "remote"] as const) {
            const relay = new RelayService(new SqliteRelayStore(":memory:"));
            const handler = createRelayFetchHandler(relay);
            const aliceStore = new MemoryMurmurStore();
            const bobStore = new MemoryMurmurStore();
            const carolStore = new MemoryMurmurStore();
            let watchBobControl = false;
            const controlsAfterEnd: FriendControlFrame["type"][] = [];
            let aliceIdentityKey: Uint8Array | undefined;
            let bobRoot: IdentityKeyPair | undefined;
            let bobControlTopicId: string | undefined;
            const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
                const request = new Request(input, init);
                const body =
                    request.method === "POST" && new URL(request.url).pathname === "/v1/events"
                        ? await request.clone().text()
                        : undefined;
                const response = await handler(request);
                if (
                    watchBobControl &&
                    body !== undefined &&
                    bobRoot !== undefined &&
                    aliceIdentityKey !== undefined
                ) {
                    const event = decodeSignedRelayEventWire(utf8Encode(body));
                    if (relayTopicId(event.topic) === bobControlTopicId) {
                        const channel = new FriendChannel(bobRoot, {
                            publicKey: aliceIdentityKey,
                        });
                        try {
                            const opened = channel.open(
                                JSON.parse(utf8Decode(event.payload)) as FriendControlEnvelope,
                            );
                            const frame = decodeFriendControlFrame(opened.message.payload);
                            opened.message.payload.fill(0);
                            try {
                                controlsAfterEnd.push(frame.type);
                            } finally {
                                destroyFriendControlFrame(frame);
                            }
                        } finally {
                            channel.destroy();
                        }
                    }
                }
                return response;
            };
            let alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                initialProfile: { name: `Alice ${ending}` },
                fetch: aliceFetch,
            });
            const bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                initialProfile: { name: `Bob ${ending}` },
                fetch: inProcessFetch(relay),
            });
            const carol = await Murmur.open({
                relay: "https://relay.test",
                store: carolStore,
                initialProfile: { name: `Carol ${ending}` },
                fetch: inProcessFetch(relay),
            });
            try {
                aliceIdentityKey = alice.identityKey;
                await alice.friends.request(bob.identityKey);
                await alice.friends.request(carol.identityKey);
                await converge([alice, bob, carol]);
                await bob.friends.accept(alice.identityKey);
                await carol.friends.accept(alice.identityKey);
                await converge([bob, carol, alice], 8);

                const bobRootBytes = await bobStore.get("murmur/v1/root");
                if (bobRootBytes === undefined) {
                    throw new Error("Bob root was not persisted");
                }
                bobRoot = decodeIdentityRoot(bobRootBytes);
                bobRootBytes.fill(0);
                const controlChannel = new FriendChannel(bobRoot, {
                    publicKey: aliceIdentityKey,
                });
                const controlAccess = friendControlAccess(controlChannel);
                bobControlTopicId = relayTopicId(controlAccess.topic);
                controlChannel.destroy();
                controlAccess.readSecretKey?.fill(0);
                controlAccess.writeSecretKey?.fill(0);

                const removalGroup = await alice.groups.create(
                    utf8Encode(`remove survives ${ending} end`),
                    [bob.identityKey],
                );
                await converge([alice, bob], 10);
                await alice.groups.remove(removalGroup, bob.identityKey);

                const raceGroup = await alice.groups.create(
                    utf8Encode(`queued Add ${ending} end`),
                    [bob.identityKey],
                );
                await alice.groups.add(raceGroup, carol.identityKey);
                await alice.groups.send(raceGroup, utf8Encode(`after ${ending} end`));

                if (ending === "local") {
                    await alice.friends.end(bob.identityKey);
                    watchBobControl = true;
                }
                await alice.close();

                if (ending === "local") {
                    const queued = await aliceStore.list(
                        `murmur/v1/groups/${encodeBase64Url(raceGroup)}/operations/`,
                    );
                    try {
                        const operations = [...queued.values()].map(decodeGroupOperation);
                        try {
                            expect(
                                operations.some(
                                    (operation) =>
                                        operation.type === "add" &&
                                        encodeBase64Url(operation.peer) ===
                                            encodeBase64Url(bob.identityKey),
                                ),
                            ).toBe(false);
                        } finally {
                            for (const operation of operations) {
                                destroyGroupOperation(operation);
                            }
                        }
                    } finally {
                        for (const encoded of queued.values()) {
                            encoded.fill(0);
                        }
                    }
                } else {
                    await bob.friends.end(aliceIdentityKey);
                    await bob.sync();
                    watchBobControl = true;
                }

                alice = await Murmur.open({
                    relay: "https://relay.test",
                    store: aliceStore,
                    fetch: aliceFetch,
                });
                await converge([alice, bob, carol], 16);

                expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");
                expect((await bob.friends.get(alice.identityKey))?.status).toBe("ended");
                expect((await bob.groups.get(removalGroup))?.group.status).toBe("removed");
                expect((await bob.groups.get(raceGroup))?.group).toBeUndefined();
                expect(
                    (await alice.groups.get(raceGroup))?.group.members.map(encodeBase64Url).sort(),
                ).toEqual([alice.identityKey, carol.identityKey].map(encodeBase64Url).sort());
                expect(
                    (await carol.groups.get(raceGroup))?.events.map((event) =>
                        utf8Decode(event.bytes),
                    ),
                ).toContain(`after ${ending} end`);

                const peerId = identityId({ publicKey: bob.identityKey });
                for (const key of [
                    `murmur/v1/key-packages/requests/${peerId}`,
                    `murmur/v1/key-packages/needed/${peerId}`,
                ]) {
                    const marker = await aliceStore.get(key);
                    expect(marker).toBeUndefined();
                    marker?.fill(0);
                }
                for (const prefix of [
                    `murmur/v1/key-packages/local/${peerId}/`,
                    `murmur/v1/key-packages/local-consumed/${peerId}/`,
                    `murmur/v1/key-packages/remote/${peerId}/`,
                    `murmur/v1/key-packages/remote-consumed/${peerId}/`,
                ]) {
                    const records = await aliceStore.list(prefix);
                    expect(records.size).toBe(0);
                    for (const bytes of records.values()) {
                        bytes.fill(0);
                    }
                }
                const operations = await aliceStore.list("murmur/v1/groups/");
                try {
                    for (const [key, encoded] of operations) {
                        if (!key.includes("/operations/")) {
                            continue;
                        }
                        const operation = decodeGroupOperation(encoded);
                        try {
                            expect(
                                operation.type === "add" &&
                                    encodeBase64Url(operation.peer) ===
                                        encodeBase64Url(bob.identityKey),
                            ).toBe(false);
                        } finally {
                            destroyGroupOperation(operation);
                        }
                    }
                } finally {
                    for (const encoded of operations.values()) {
                        encoded.fill(0);
                    }
                }
                const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
                try {
                    for (const encoded of outboxes.values()) {
                        const record = decodeRelayOutbox(encoded);
                        try {
                            expect(
                                record.purpose.type === "friend-control" &&
                                    relayTopicId(record.event.topic) === bobControlTopicId,
                            ).toBe(false);
                        } finally {
                            destroyRelayOutboxRecord(record);
                        }
                    }
                } finally {
                    for (const encoded of outboxes.values()) {
                        encoded.fill(0);
                    }
                }
                expect(controlsAfterEnd).not.toContain("key-package-request");
                expect(controlsAfterEnd.every((type) => type === "friendship-ended")).toBe(true);
            } finally {
                watchBobControl = false;
                if (bobRoot !== undefined) {
                    destroyIdentity(bobRoot);
                }
                await Promise.all([alice.close(), bob.close(), carol.close()]);
                await relay.close();
            }
        }
    }, 180_000);

    it("drops a persisted Add queued after remote end before requesting control", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
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
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);
            const groupId = await alice.groups.create(utf8Encode("persisted stale Add"));
            await converge([alice], 2);

            await bob.friends.end(alice.identityKey);
            await converge([bob, alice], 6);
            expect((await alice.friends.get(bob.identityKey))?.status).toBe("ended");

            const encodedGroupId = encodeBase64Url(groupId);
            const operationId = encodeBase64Url(randomBytes(24));
            const operationBytes = encodeGroupOperation({
                id: operationId,
                type: "add",
                peer: bob.identityKey,
                createdAt: Date.now(),
            });
            try {
                await aliceStore.set(
                    `murmur/v1/groups/${encodedGroupId}/operations/${operationId}`,
                    operationBytes,
                );
            } finally {
                operationBytes.fill(0);
            }
            await alice.groups.send(groupId, utf8Encode("after persisted stale Add"));
            await converge([alice], 6);

            expect(
                (await alice.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("after persisted stale Add");
            const operations = await aliceStore.list(
                `murmur/v1/groups/${encodedGroupId}/operations/`,
            );
            expect(operations.size).toBe(0);
            for (const encoded of operations.values()) {
                encoded.fill(0);
            }
            const peerId = identityId({ publicKey: bob.identityKey });
            for (const key of [
                `murmur/v1/key-packages/needed/${peerId}`,
                `murmur/v1/key-packages/requests/${peerId}`,
            ]) {
                const marker = await aliceStore.get(key);
                expect(marker).toBeUndefined();
                marker?.fill(0);
            }
            const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
            try {
                const records = [...outboxes.values()].map(decodeRelayOutbox);
                expect(records.some((record) => record.purpose.type === "friend-control")).toBe(
                    false,
                );
                for (const record of records) {
                    destroyRelayOutboxRecord(record);
                }
            } finally {
                for (const encoded of outboxes.values()) {
                    encoded.fill(0);
                }
            }
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 60_000);

    it("compensates a winning staged Add when friendship ends before invitation", async () => {
        for (const ending of ["local", "remote"] as const) {
            const relay = new RelayService(new SqliteRelayStore(":memory:"));
            const handler = createRelayFetchHandler(relay);
            const aliceStore = new MemoryMurmurStore();
            const bobStore = new MemoryMurmurStore();
            let interceptAdd = false;
            let disconnected = false;
            let blockGroupReads = false;
            let blockCompensatingRemove = false;
            let compensatingRemoveBlocked = false;
            let acceptedAddId: string | undefined;
            const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
                const request = new Request(input, init);
                const path = new URL(request.url).pathname;
                if (disconnected && path === "/v1/events/read") {
                    throw new Error("disconnected after staged Add acceptance");
                }
                if (blockGroupReads && path === "/v1/events/read") {
                    const read = JSON.parse(await request.clone().text()) as {
                        readonly topic?: { readonly name?: unknown };
                    };
                    if (read.topic?.name === "group-events") {
                        throw new Error("blocked group read before remote end");
                    }
                }
                if (request.method === "POST" && path === "/v1/events") {
                    const event = decodeSignedRelayEventWire(
                        utf8Encode(await request.clone().text()),
                    );
                    if (interceptAdd && event.topic.name === "group-events") {
                        if (acceptedAddId === undefined) {
                            await handler(request);
                            acceptedAddId = event.id;
                            disconnected = true;
                            throw new Error("accepted staged Add then disconnected");
                        }
                        if (blockCompensatingRemove && event.id !== acceptedAddId) {
                            compensatingRemoveBlocked = true;
                            throw new Error("blocked compensating Remove");
                        }
                    }
                }
                return handler(request);
            };
            const sharedFetch = inProcessFetch(relay);
            let alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                initialProfile: { name: `Alice ${ending}` },
                fetch: aliceFetch,
            });
            const bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                initialProfile: { name: `Bob ${ending}` },
                fetch: sharedFetch,
            });
            const aliceIdentity = alice.identityKey;
            try {
                await alice.friends.request(bob.identityKey);
                await converge([alice, bob]);
                await bob.friends.accept(alice.identityKey);
                await converge([bob, alice], 8);

                const legitimateGroup = await alice.groups.create(
                    utf8Encode(`legitimate membership ${ending}`),
                    [bob.identityKey],
                );
                await converge([alice, bob], 10);
                const phantomGroup = await alice.groups.create(
                    utf8Encode(`staged phantom ${ending}`),
                );

                interceptAdd = true;
                await alice.groups.add(phantomGroup, bob.identityKey);
                await expect(alice.sync()).rejects.toThrow();
                expect(acceptedAddId).toBeDefined();
                const encodedGroupId = encodeBase64Url(phantomGroup);
                const stagedKey = `murmur/v1/groups/${encodedGroupId}/staged`;
                const stagedAddBytes = await aliceStore.get(stagedKey);
                if (stagedAddBytes === undefined) {
                    throw new Error("Accepted Add was not retained as staged state");
                }
                const stagedAdd = decodeStagedCommit(stagedAddBytes);
                stagedAddBytes.fill(0);
                try {
                    expect(stagedAdd.type).toBe("add");
                } finally {
                    stagedAdd.fingerprint.fill(0);
                    stagedAdd.nextEpoch.fill(0);
                    stagedAdd.peer.fill(0);
                    stagedAdd.keyPackageReference?.fill(0);
                    stagedAdd.welcome?.fill(0);
                    stagedAdd.tree?.fill(0);
                }

                if (ending === "local") {
                    await alice.friends.end(bob.identityKey);
                    await alice.close();
                } else {
                    await alice.close();
                    await bob.friends.end(aliceIdentity);
                    await bob.sync();
                    disconnected = false;
                    blockGroupReads = true;
                    alice = await Murmur.open({
                        relay: "https://relay.test",
                        store: aliceStore,
                        fetch: aliceFetch,
                    });
                    await waitFor(async () => {
                        try {
                            await alice.sync();
                        } catch (error: unknown) {
                            if (
                                !(error instanceof Error) ||
                                !error.message.includes("blocked group read before remote end")
                            ) {
                                throw error;
                            }
                        }
                        return (await alice.friends.get(bob.identityKey))?.status === "ended";
                    }, 30_000);
                    await alice.close();
                    blockGroupReads = false;
                }

                disconnected = false;
                blockCompensatingRemove = true;
                alice = await Murmur.open({
                    relay: "https://relay.test",
                    store: aliceStore,
                    fetch: aliceFetch,
                });
                await waitFor(async () => {
                    try {
                        await alice.sync();
                    } catch (error: unknown) {
                        if (
                            !(error instanceof Error) ||
                            !error.message.includes("blocked compensating Remove")
                        ) {
                            throw error;
                        }
                    }
                    return compensatingRemoveBlocked;
                }, 30_000);
                expect(
                    (await alice.groups.get(phantomGroup))?.group.members.map(encodeBase64Url),
                ).toContain(encodeBase64Url(bob.identityKey));
                const stagedRemoveBytes = await aliceStore.get(stagedKey);
                if (stagedRemoveBytes === undefined) {
                    throw new Error("Compensating Remove was not durably staged");
                }
                const stagedRemove = decodeStagedCommit(stagedRemoveBytes);
                stagedRemoveBytes.fill(0);
                try {
                    expect(stagedRemove.type).toBe("remove");
                    expect(stagedRemove.peer).toEqual(bob.identityKey);
                } finally {
                    stagedRemove.fingerprint.fill(0);
                    stagedRemove.nextEpoch.fill(0);
                    stagedRemove.peer.fill(0);
                    stagedRemove.keyPackageReference?.fill(0);
                    stagedRemove.welcome?.fill(0);
                    stagedRemove.tree?.fill(0);
                }

                await alice.close();
                blockCompensatingRemove = false;
                alice = await Murmur.open({
                    relay: "https://relay.test",
                    store: aliceStore,
                    fetch: aliceFetch,
                });
                await converge([alice, bob], 12);

                expect(
                    (await alice.groups.get(phantomGroup))?.group.members.map(encodeBase64Url),
                ).toEqual([encodeBase64Url(alice.identityKey)]);
                expect(await bob.groups.get(phantomGroup)).toBeUndefined();
                expect((await alice.groups.get(legitimateGroup))?.group.members).toHaveLength(2);
                expect((await bob.groups.get(legitimateGroup))?.group.members).toHaveLength(2);

                await alice.groups.send(
                    phantomGroup,
                    utf8Encode(`after compensating Remove ${ending}`),
                );
                await converge([alice], 4);
                expect(
                    (await alice.groups.get(phantomGroup))?.events.map((event) =>
                        utf8Decode(event.bytes),
                    ),
                ).toContain(`after compensating Remove ${ending}`);

                expect(await aliceStore.get(stagedKey)).toBeUndefined();
                expect(
                    (await aliceStore.list(`murmur/v1/groups/${encodedGroupId}/operations/`)).size,
                ).toBe(0);
                const peerId = identityId({ publicKey: bob.identityKey });
                for (const prefix of [
                    `murmur/v1/key-packages/local/${peerId}/`,
                    `murmur/v1/key-packages/local-consumed/${peerId}/`,
                    `murmur/v1/key-packages/remote/${peerId}/`,
                    `murmur/v1/key-packages/remote-consumed/${peerId}/`,
                ]) {
                    const records = await aliceStore.list(prefix);
                    expect(records.size).toBe(0);
                    for (const bytes of records.values()) {
                        bytes.fill(0);
                    }
                }
                const outboxes = await aliceStore.list("murmur/v1/relay-outbox/");
                expect(outboxes.size).toBe(0);
                for (const bytes of outboxes.values()) {
                    bytes.fill(0);
                }
            } finally {
                interceptAdd = false;
                disconnected = false;
                blockGroupReads = false;
                blockCompensatingRemove = false;
                compensatingRemoveBlocked = false;
                await Promise.all([alice.close(), bob.close()]);
                await relay.close();
            }
        }
    }, 240_000);

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

    it("rebases a staged Commit after inbound applications and restart", async () => {
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
                    throw new Error("blocked staged Commit");
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
        const charlie = await Murmur.open({
            relay: "https://relay.test",
            store: charlieStore,
            initialProfile: { name: "Charlie" },
            fetch: sharedFetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await alice.friends.request(charlie.identityKey);
            await converge([alice, bob, charlie], 4);
            await bob.friends.accept(alice.identityKey);
            await charlie.friends.accept(alice.identityKey);
            await converge([bob, charlie, alice], 8);

            const groupId = await alice.groups.create(utf8Encode("rebase"), [bob.identityKey]);
            await converge([alice, bob, charlie], 8);
            blockAliceGroups = true;
            await alice.groups.add(groupId, charlie.identityKey);
            let blocked = false;
            const stagedKey = `murmur/v1/groups/${encodeBase64Url(groupId)}/staged`;
            await waitFor(async () => {
                try {
                    await alice.sync();
                } catch (error: unknown) {
                    if (
                        error instanceof Error &&
                        (error.message === "blocked staged Commit" ||
                            (error.cause instanceof Error &&
                                error.cause.message === "blocked staged Commit"))
                    ) {
                        blocked = true;
                    } else {
                        throw error;
                    }
                }
                const staged = await aliceStore.get(stagedKey);
                if (staged === undefined) {
                    return false;
                }
                staged.fill(0);
                return blocked;
            }, 30_000);

            for (let index = 0; index < 7; index += 1) {
                await bob.groups.send(groupId, utf8Encode(`before-commit-${index}`));
            }
            await bob.setProfile({ name: "Bob after stage" });
            await bob.sync();

            await alice.close();
            blockAliceGroups = false;
            alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                fetch: aliceFetch,
            });
            await converge([alice, bob, charlie], 10);

            const aliceGroup = await alice.groups.get(groupId);
            const charlieGroup = await charlie.groups.get(groupId);
            expect(aliceGroup?.group.members).toHaveLength(3);
            expect(charlieGroup?.group.members).toHaveLength(3);
            expect(aliceGroup?.events.map((event) => utf8Decode(event.bytes))).toEqual(
                Array.from({ length: 7 }, (_, index) => `before-commit-${index}`),
            );
            expect((await alice.friends.get(bob.identityKey))?.profile?.name).toBe(
                "Bob after stage",
            );
        } finally {
            blockAliceGroups = false;
            await Promise.all([alice.close(), bob.close(), charlie.close()]);
            await relay.close();
        }
    }, 120_000);

    it("reinstalls a removed member through a fresh authenticated invitation", async () => {
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
            await converge([bob, alice], 8);

            const groupId = await alice.groups.create(utf8Encode("re-add"), [bob.identityKey]);
            await converge([alice, bob], 8);
            await alice.groups.send(groupId, utf8Encode("before removal"));
            await converge([alice, bob], 4);
            await alice.groups.remove(groupId, bob.identityKey);
            await converge([alice, bob], 8);
            expect((await bob.groups.get(groupId))?.group.status).toBe("removed");

            await alice.groups.add(groupId, bob.identityKey);
            await converge([alice, bob], 10);
            expect((await bob.groups.get(groupId))?.group.status).toBe("active");
            await bob.close();
            bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                fetch,
            });

            await alice.groups.send(groupId, utf8Encode("after re-add from Alice"));
            await bob.groups.send(groupId, utf8Encode("after re-add from Bob"));
            await converge([alice, bob], 8);
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["before removal", "after re-add from Alice", "after re-add from Bob"]);
            expect(
                (await alice.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["before removal", "after re-add from Alice", "after re-add from Bob"]);
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 120_000);

    it("isolates topic failures and resets a cursor on an explicitly fresh relay", async () => {
        let relay = new RelayService(new SqliteRelayStore(":memory:"));
        let handler = createRelayFetchHandler(relay);
        let failGroupReads = false;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> =>
            handler(new Request(input, init));
        const bobFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (
                failGroupReads &&
                request.method === "POST" &&
                new URL(request.url).pathname === "/v1/read-challenges"
            ) {
                const body = (await request.clone().json()) as {
                    readonly topic?: { readonly name?: string };
                };
                if (body.topic?.name === "group-events") {
                    throw new Error("isolated group read failure");
                }
            }
            return handler(request);
        };
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
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
            fetch: bobFetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);
            const groupId = await alice.groups.create(utf8Encode("relay reset"), [bob.identityKey]);
            await converge([alice, bob], 8);
            for (let index = 0; index < 4; index += 1) {
                await alice.groups.send(groupId, utf8Encode(`old-${index}`));
            }
            await converge([alice, bob], 4);

            failGroupReads = true;
            await alice.setProfile({ name: "Alice despite group failure" });
            await alice.sync();
            await expect(bob.sync()).rejects.toThrow("isolated group read failure");
            expect((await bob.friends.get(alice.identityKey))?.profile?.name).toBe(
                "Alice despite group failure",
            );
            failGroupReads = false;

            await relay.close();
            relay = new RelayService(new SqliteRelayStore(":memory:"));
            handler = createRelayFetchHandler(relay);
            await alice.groups.send(groupId, utf8Encode("fresh relay event"));
            await alice.sync();
            await bob.sync();
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("fresh relay event");
        } finally {
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 120_000);

    it("converges five hundred durable sends in one restarted sync cycle", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        let offline = false;
        const aliceFetch: RelayFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (offline) {
                throw new Error("sender offline");
            }
            return handler(request);
        };
        const bobFetch = inProcessFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        let alice = await Murmur.open({
            relay: "https://relay.test",
            store: aliceStore,
            initialProfile: { name: "Alice" },
            fetch: aliceFetch,
        });
        let bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch: bobFetch,
        });
        try {
            await alice.friends.request(bob.identityKey);
            await converge([alice, bob]);
            await bob.friends.accept(alice.identityKey);
            await converge([bob, alice], 8);
            const groupId = await alice.groups.create(utf8Encode("backlog"), [bob.identityKey]);
            await converge([alice, bob], 8);

            offline = true;
            for (let index = 0; index < 500; index += 1) {
                await alice.groups.send(groupId, utf8Encode(`offline-${index}`));
            }
            await Promise.all([alice.close(), bob.close()]);
            offline = false;
            alice = await Murmur.open({
                relay: "https://relay.test",
                store: aliceStore,
                fetch: aliceFetch,
            });
            bob = await Murmur.open({
                relay: "https://relay.test",
                store: bobStore,
                fetch: bobFetch,
            });
            await alice.sync();
            await bob.sync();
            const page = await bob.groups.get(groupId, { limit: 1_000 });
            expect(page?.events).toHaveLength(500);
            expect(utf8Decode(page!.events[0]!.bytes)).toBe("offline-0");
            expect(utf8Decode(page!.events[499]!.bytes)).toBe("offline-499");
            const encodedGroupId = encodeBase64Url(groupId);
            const replay = await bobStore.list(`murmur/v1/groups/${encodedGroupId}/replay/`);
            const replayOrder = await bobStore.list(
                `murmur/v1/groups/${encodedGroupId}/replay-order/`,
            );
            expect(replay.size).toBeLessThanOrEqual(128);
            expect(replayOrder.size).toBeLessThanOrEqual(128);
            for (const bytes of [...replay.values(), ...replayOrder.values()]) {
                bytes.fill(0);
            }
        } finally {
            offline = false;
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 180_000);

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

    it("isolates one hostile KeyPackage pool while unrelated groups keep converging", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const fetch = inProcessFetch(relay);
        const ownerStore = new MemoryMurmurStore();
        const hostileStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const carolStore = new MemoryMurmurStore();
        const owner = await Murmur.open({
            relay: "https://relay.test",
            store: ownerStore,
            initialProfile: { name: "Owner" },
            fetch,
        });
        const hostile = await Murmur.open({
            relay: "https://relay.test",
            store: hostileStore,
            initialProfile: { name: "Hostile Alice" },
            fetch,
        });
        const bob = await Murmur.open({
            relay: "https://relay.test",
            store: bobStore,
            initialProfile: { name: "Bob" },
            fetch,
        });
        const carol = await Murmur.open({
            relay: "https://relay.test",
            store: carolStore,
            initialProfile: { name: "Carol" },
            fetch,
        });
        try {
            for (const peer of [hostile, bob, carol]) {
                await owner.friends.request(peer.identityKey);
            }
            await converge([owner, hostile, bob, carol], 4);
            await hostile.friends.accept(owner.identityKey);
            await bob.friends.accept(owner.identityKey);
            await carol.friends.accept(owner.identityKey);
            await converge([hostile, bob, carol, owner], 10);

            const exhausted = await exhaustFriendKeyPackagePool(
                owner,
                ownerStore,
                hostile,
                hostileStore,
                fetch,
            );
            const exhaustedPeer = exhausted.peerIdentityKey;
            try {
                expect(exhaustedPeer).toEqual(hostile.identityKey);
            } finally {
                exhaustedPeer.fill(0);
            }

            let surfaced = 0;
            const syncOwner = async (): Promise<void> => {
                try {
                    await owner.sync();
                } catch (error: unknown) {
                    expect(error).toBeInstanceOf(MurmurKeyPackagePoolExhaustedError);
                    if (error instanceof MurmurKeyPackagePoolExhaustedError) {
                        const peer = error.peerIdentityKey;
                        try {
                            expect(peer).toEqual(hostile.identityKey);
                        } finally {
                            peer.fill(0);
                        }
                    }
                    surfaced += 1;
                }
            };

            const groupId = await owner.groups.create(utf8Encode("unrelated Bob/Carol"), [
                bob.identityKey,
                carol.identityKey,
            ]);
            for (let round = 0; round < 18; round += 1) {
                await syncOwner();
                await bob.sync();
                await carol.sync();
                if (
                    (await bob.groups.get(groupId))?.group.members.length === 3 &&
                    (await carol.groups.get(groupId))?.group.members.length === 3
                ) {
                    break;
                }
            }
            expect((await bob.groups.get(groupId))?.group.members).toHaveLength(3);
            expect((await carol.groups.get(groupId))?.group.members).toHaveLength(3);

            for (let index = 0; index < 3; index += 1) {
                await owner.groups.send(groupId, utf8Encode(`unrelated-${index}`));
                await syncOwner();
                await bob.sync();
                await carol.sync();
            }
            expect(
                (await bob.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["unrelated-0", "unrelated-1", "unrelated-2"]);
            expect(
                (await carol.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toEqual(["unrelated-0", "unrelated-1", "unrelated-2"]);
            expect(surfaced).toBeGreaterThan(0);

            await waitFor(
                async () => owner.convergenceError instanceof MurmurKeyPackagePoolExhaustedError,
                5_000,
            );
            expect(owner.convergenceError).toBeInstanceOf(MurmurKeyPackagePoolExhaustedError);

            await owner.friends.end(hostile.identityKey);
            expect(owner.convergenceError).toBeUndefined();
            await converge([owner, hostile, bob, carol], 4);

            await owner.groups.send(groupId, utf8Encode("after hostile end"));
            await converge([owner, bob, carol], 5);
            expect(
                (await carol.groups.get(groupId))?.events.map((event) => utf8Decode(event.bytes)),
            ).toContain("after hostile end");
        } finally {
            await Promise.all([owner.close(), hostile.close(), bob.close(), carol.close()]);
            await relay.close();
        }
    }, 90_000);

    it("surfaces bounded KeyPackage starvation from abandoned peer claims", async () => {
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

            const rootBytes = await bobStore.get("murmur/v1/root");
            if (rootBytes === undefined) {
                throw new Error("Bob root was not persisted");
            }
            bobRoot = decodeIdentityRoot(rootBytes);
            rootBytes.fill(0);
            const channel = new FriendChannel(bobRoot, {
                publicKey: alice.identityKey,
            });
            const access = friendControlAccess(channel);
            const peerId = identityId({ publicKey: bob.identityKey });
            const localPrefix = `murmur/v1/key-packages/local/${peerId}/`;
            const consumedPrefix = `murmur/v1/key-packages/local-consumed/${peerId}/`;
            let surfaced: Error | undefined;
            try {
                for (let round = 0; round < 6 && surfaced === undefined; round += 1) {
                    const local = await aliceStore.list(localPrefix);
                    const consumed = await aliceStore.list(consumedPrefix);
                    const available = [...local.keys()]
                        .filter(
                            (key) =>
                                !consumed.has(
                                    `${consumedPrefix}${key.slice(key.lastIndexOf("/") + 1)}`,
                                ),
                        )
                        .slice(0, 2)
                        .map((key) => decodeBase64Url(key.slice(key.lastIndexOf("/") + 1)));
                    for (const bytes of local.values()) {
                        bytes.fill(0);
                    }
                    for (const bytes of consumed.values()) {
                        bytes.fill(0);
                    }
                    if (available.length === 0) {
                        break;
                    }
                    const bogus = new Uint8Array(32);
                    bogus.fill(round + 1);
                    const frameBytes = encodeFriendControlFrame({
                        type: "key-package-request",
                        consumedReferences: [...available, bogus],
                    });
                    const envelope = channel.seal(channel.createMessage(frameBytes));
                    const payload = utf8Encode(JSON.stringify(envelope));
                    try {
                        const response = await fetch("https://relay.test/v1/events", {
                            method: "POST",
                            headers: { "content-type": "application/json" },
                            body: utf8Decode(
                                encodeSignedRelayEventWire(createCapabilityEvent(access, payload)),
                            ),
                        });
                        expect(response.ok).toBe(true);
                        await alice.sync();
                    } catch (error: unknown) {
                        surfaced = error instanceof Error ? error : new Error("Unknown error");
                    } finally {
                        for (const reference of available) {
                            reference.fill(0);
                        }
                        bogus.fill(0);
                        frameBytes.fill(0);
                        payload.fill(0);
                    }
                }
            } finally {
                channel.destroy();
                access.readSecretKey?.fill(0);
                access.writeSecretKey?.fill(0);
            }
            expect(surfaced).toBeInstanceOf(MurmurKeyPackagePoolExhaustedError);
            expect((await aliceStore.list(localPrefix)).size).toBeLessThanOrEqual(8);
            expect((await aliceStore.list(consumedPrefix)).size).toBeLessThanOrEqual(8);
        } finally {
            if (bobRoot !== undefined) {
                destroyIdentity(bobRoot);
            }
            await Promise.all([alice.close(), bob.close()]);
            await relay.close();
        }
    }, 30_000);

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
