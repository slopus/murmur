import { describe, expect, it } from "vitest";
import type { IdentityPublicKey } from "../../crypto/index.js";
import { generateIdentityKeyPair, randomBytes } from "../../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../../storage/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode, zeroBytes } from "../../utils/index.js";
import type { FriendOutboxItem, FriendRequestEnvelope, FriendResponseEnvelope } from "../index.js";
import {
    FriendBook,
    FriendChannel,
    FriendControlIdCollisionError,
    FriendExchangeIdCollisionError,
    acceptFriendControl,
    createFriendRequest,
    createFriendResponse,
    deserializePublicIdentity,
    identityId,
    openFriendRequest,
    openFriendResponse,
    serializePublicIdentity,
} from "../index.js";

function requestEnvelope(item: FriendOutboxItem): FriendRequestEnvelope {
    if (item.kind !== "request" || item.envelope.type !== "friend-request") {
        throw new Error("Expected request outbox item");
    }
    return item.envelope;
}

function responseEnvelope(item: FriendOutboxItem): FriendResponseEnvelope {
    if (item.kind !== "response" || item.envelope.type !== "friend-response") {
        throw new Error("Expected response outbox item");
    }
    return item.envelope;
}

class FailingOutboxStore implements MurmurStore {
    readonly #memory = new MemoryMurmurStore();

    get(key: string): Promise<Uint8Array | undefined> {
        return this.#memory.get(key);
    }

    set(key: string, value: Uint8Array): Promise<void> {
        return this.#memory.set(key, value);
    }

    delete(key: string): Promise<void> {
        return this.#memory.delete(key);
    }

    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#memory.list(prefix);
    }

    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#memory.transaction(async (transaction) =>
            operation({
                ...transaction,
                set: async (key, value): Promise<void> => {
                    if (key.includes("/friend-outbox/")) {
                        throw new Error("outbox unavailable");
                    }
                    await transaction.set(key, value);
                },
            }),
        );
    }
}

describe("friend request protocol", () => {
    it("serializes exactly one strict public identity key", () => {
        const alice = generateIdentityKeyPair();
        const wire = serializePublicIdentity(alice);

        expect(wire).toEqual({ publicKey: encodeBase64Url(alice.publicKey) });
        expect(deserializePublicIdentity(wire).publicKey).toEqual(alice.publicKey);
        expect(identityId(alice)).toBe(wire.publicKey);
        expect(() =>
            deserializePublicIdentity({
                signingKey: wire.publicKey,
                encryptionKey: wire.publicKey,
            } as never),
        ).toThrow("serialized public identity");

        const compressedIdentity = new Uint8Array(32);
        compressedIdentity[0] = 1;
        for (const publicKey of [new Uint8Array(32), compressedIdentity]) {
            expect(() => serializePublicIdentity({ publicKey })).toThrow(
                "Invalid Ed25519 identity point",
            );
            expect(() =>
                deserializePublicIdentity({ publicKey: encodeBase64Url(publicKey) }),
            ).toThrow("Invalid Ed25519 identity point");
        }
    });

    it("keeps both identity IDs and all request content out of the outer envelope", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const request = createFriendRequest(alice, bob, {
            id: encodeBase64Url(randomBytes(24)),
            responseAddress: "opaque:alice-response",
            profile: { name: "Alice", metadata: { role: "agent" } },
            privateData: utf8Encode("private bootstrap bytes"),
        });
        const wire = JSON.stringify(request);
        const opened = openFriendRequest(bob, request);

        expect(Object.keys(request).sort()).toEqual([
            "ciphertext",
            "ephemeralPublicKey",
            "nonce",
            "type",
            "version",
        ]);
        expect(wire).not.toContain(identityId(alice));
        expect(wire).not.toContain(identityId(bob));
        expect(wire).not.toContain("Alice");
        expect(wire).not.toContain("alice-response");
        expect(opened).toMatchObject({
            sender: { publicKey: alice.publicKey },
            responseAddress: "opaque:alice-response",
            profile: { name: "Alice", metadata: { role: "agent" } },
        });
        expect(utf8Decode(opened.privateData ?? new Uint8Array())).toBe("private bootstrap bytes");
    });

    it("enforces implicit recipient binding and authenticated ciphertext", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const request = createFriendRequest(alice, bob, {
            id: encodeBase64Url(randomBytes(24)),
            responseAddress: "reply",
            profile: { name: "Alice" },
        });

        expect(() => openFriendRequest(eve, request)).toThrow();
        expect(() =>
            openFriendRequest(bob, {
                ...request,
                ciphertext: `${request.ciphertext.slice(0, -1)}${
                    request.ciphertext.endsWith("A") ? "B" : "A"
                }`,
            }),
        ).toThrow();
    });

    it("treats re-encryption as a replay and changed authenticated content as a collision", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const id = encodeBase64Url(randomBytes(24));
        const first = createFriendRequest(alice, bob, {
            id,
            responseAddress: "reply",
            profile: { name: "Alice" },
        });
        const duplicate = createFriendRequest(alice, bob, {
            id,
            responseAddress: "reply",
            profile: { name: "Alice" },
        });
        const collision = createFriendRequest(alice, bob, {
            id,
            responseAddress: "reply",
            profile: { name: "Different Alice" },
        });
        const book = new FriendBook(bob, new MemoryMurmurStore());

        await book.receiveRequest(first, 1);
        await expect(book.receiveRequest(duplicate, 2)).resolves.toMatchObject({
            status: "duplicate",
        });
        await expect(book.receiveRequest(collision, 2)).rejects.toBeInstanceOf(
            FriendExchangeIdCollisionError,
        );
    });
});

describe("durable friendship lifecycle and outbox", () => {
    it("atomically queues exact request/response publications through active and ended", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const aliceFriends = new FriendBook(alice, aliceStore);
        const bobFriends = new FriendBook(bob, bobStore);

        const request = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-friend-inbox",
            responseAddress: "alice-response",
            privateData: utf8Encode("alice bootstrap"),
            now: 10,
        });
        expect((await aliceFriends.get(bob))?.localResponseAddress).toBe("alice-response");
        expect(await aliceFriends.listOutbox()).toEqual([request]);

        const incoming = await bobFriends.receiveRequest(requestEnvelope(request), 11);
        expect(incoming.record).toMatchObject({
            status: "pending-incoming",
            peerResponseAddress: "alice-response",
            profile: { name: "Alice" },
        });

        const prepared = await bobFriends.respond(alice, {
            decision: "accepted",
            profile: { name: "Bob" },
            responseAddress: "bob-response",
            privateData: utf8Encode("bob bootstrap"),
            now: 12,
        });
        expect(prepared.outbox.destination).toBe("alice-response");
        expect(await bobFriends.listOutbox()).toEqual([prepared.outbox]);

        const responseWire = JSON.stringify(prepared.outbox.envelope);
        expect(responseWire).not.toContain(identityId(alice));
        expect(responseWire).not.toContain(identityId(bob));
        const accepted = await aliceFriends.receiveResponse(
            bob,
            responseEnvelope(prepared.outbox),
            13,
        );
        expect(accepted.record).toMatchObject({
            status: "active",
            localResponseAddress: "alice-response",
            peerResponseAddress: "bob-response",
            profile: { name: "Bob" },
        });

        await expect(
            aliceFriends.confirmOutbox(
                { ...request, destination: "wrong-destination" },
                "accepted",
            ),
        ).rejects.toThrow("exactly match");
        expect(await aliceFriends.confirmOutbox(request, "duplicate")).toBe(true);
        expect(await aliceFriends.listOutbox()).toEqual([]);

        await aliceFriends.end(bob, 15);
        await bobFriends.end(alice, 15);
        expect((await new FriendBook(alice, aliceStore).get(bob))?.status).toBe("ended");
    });

    it("rolls back lifecycle state when its owned outbox cannot persist", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const book = new FriendBook(alice, new FailingOutboxStore());

        await expect(
            book.createRequest(bob, {
                profile: { name: "Alice" },
                destination: "bob-inbox",
                responseAddress: "alice-response",
                now: 1,
            }),
        ).rejects.toThrow("outbox unavailable");
        expect(await book.get(bob)).toBeUndefined();
        expect(await book.listOutbox()).toEqual([]);
    });

    it("converges simultaneous crossed requests on one canonical contender", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        const aliceRequest = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        const bobRequest = await bobFriends.createRequest(alice, {
            profile: { name: "Bob" },
            destination: "alice-inbox",
            responseAddress: "bob-response",
            now: 1,
        });

        const aliceResult = await aliceFriends.receiveRequest(requestEnvelope(bobRequest), 2);
        const bobResult = await bobFriends.receiveRequest(requestEnvelope(aliceRequest), 2);
        const winnerIsAlice = identityId(alice) < identityId(bob);
        expect(winnerIsAlice ? aliceResult.status : bobResult.status).toBe("superseded");
        expect(winnerIsAlice ? bobResult.status : aliceResult.status).toBe("opened");

        const responderBook = winnerIsAlice ? bobFriends : aliceFriends;
        const winnerBook = winnerIsAlice ? aliceFriends : bobFriends;
        const responderIdentity: IdentityPublicKey = winnerIsAlice ? bob : alice;
        const winnerIdentity: IdentityPublicKey = winnerIsAlice ? alice : bob;
        const response = await responderBook.respond(winnerIdentity, {
            decision: "accepted",
            profile: { name: winnerIsAlice ? "Bob" : "Alice" },
            responseAddress: winnerIsAlice ? "bob-response" : "alice-response",
            now: 3,
        });
        await winnerBook.receiveResponse(responderIdentity, responseEnvelope(response.outbox), 4);

        expect((await aliceFriends.get(bob))?.status).toBe("active");
        expect((await bobFriends.get(alice))?.status).toBe("active");
        expect(await responderBook.listOutbox()).toHaveLength(1);
    });

    it("authenticates peer-bound responses and rejects response-ID collisions", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        const pending = await aliceFriends.get(bob);
        if (pending === undefined) {
            throw new Error("Expected pending outgoing state");
        }
        const responseId = encodeBase64Url(randomBytes(24));
        const first = createFriendResponse(bob, alice, {
            id: responseId,
            requestId: pending.requestId,
            decision: "accepted",
            responseAddress: "bob-response",
            profile: { name: "Bob" },
        });
        const collision = createFriendResponse(bob, alice, {
            id: responseId,
            requestId: pending.requestId,
            decision: "accepted",
            responseAddress: "bob-response",
            profile: { name: "Different Bob" },
        });

        expect(openFriendResponse(alice, bob, first)).toMatchObject({
            responder: { publicKey: bob.publicKey },
            decision: "accepted",
        });
        expect(() => openFriendResponse(alice, eve, first)).toThrow();
        await aliceFriends.receiveResponse(bob, first, 2);
        await expect(aliceFriends.receiveResponse(bob, collision, 3)).rejects.toBeInstanceOf(
            FriendExchangeIdCollisionError,
        );
    });
});

describe("friend control channel", () => {
    it("derives matching exportable topic capabilities without exposing identities", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceChannel = new FriendChannel(alice, bob, { now: () => 100 });
        const bobChannel = new FriendChannel(bob, alice, { now: () => 150 });
        const message = aliceChannel.createMessage(utf8Encode("opaque MLS Welcome bytes"), {
            kind: "temporary",
            expiresAt: 200,
        });
        const envelope = aliceChannel.seal(message);
        const wire = JSON.stringify(envelope);
        const aliceTopicSecret = aliceChannel.exportTopicSecretKey();
        const bobTopicSecret = bobChannel.exportTopicSecretKey();

        expect(Object.keys(envelope).sort()).toEqual(["ciphertext", "nonce", "type", "version"]);
        expect(wire).not.toContain(identityId(alice));
        expect(wire).not.toContain(identityId(bob));
        expect(aliceChannel.topicPublicKey).toEqual(bobChannel.topicPublicKey);
        expect(aliceTopicSecret).toEqual(bobTopicSecret);
        zeroBytes(aliceTopicSecret);
        expect(aliceTopicSecret.every((byte) => byte === 0)).toBe(true);
        const authorization = utf8Encode("topic authorization");
        expect(
            bobChannel.verifyTopicBytes(authorization, aliceChannel.signTopicBytes(authorization)),
        ).toBe(true);
        expect(bobChannel.open(envelope).message.payload).toEqual(message.payload);
        zeroBytes(bobTopicSecret);
    });

    it("rejects temporary control content at and after semantic expiration", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const sender = new FriendChannel(alice, bob, { now: () => 100 });
        const beforeExpiry = new FriendChannel(bob, alice, { now: () => 199 });
        const atExpiry = new FriendChannel(bob, alice, { now: () => 200 });
        const envelope = sender.seal(
            sender.createMessage(utf8Encode("temporary"), {
                kind: "temporary",
                expiresAt: 200,
            }),
        );

        expect(utf8Decode(beforeExpiry.open(envelope).message.payload)).toBe("temporary");
        expect(() => atExpiry.open(envelope)).toThrow("expired");
        await expect(
            acceptFriendControl(atExpiry, new MemoryMurmurStore(), envelope, async () => undefined),
        ).rejects.toThrow("expired");
    });

    it("commits replay state atomically and detects same-ID content collisions", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceChannel = new FriendChannel(alice, bob, { now: () => 1 });
        const bobChannel = new FriendChannel(bob, alice, { now: () => 1 });
        const store = new MemoryMurmurStore();
        const original = aliceChannel.createMessage(utf8Encode("first"));
        const first = aliceChannel.seal(original);
        const retry = aliceChannel.seal(original);
        const collision = aliceChannel.seal({
            ...original,
            payload: utf8Encode("second"),
        });
        let calls = 0;
        const persist = async (): Promise<void> => {
            calls += 1;
        };

        await expect(
            acceptFriendControl(bobChannel, store, first, async () => {
                throw new Error("application failed");
            }),
        ).rejects.toThrow("application failed");
        await expect(acceptFriendControl(bobChannel, store, first, persist)).resolves.toMatchObject(
            { status: "opened" },
        );
        await expect(acceptFriendControl(bobChannel, store, retry, persist)).resolves.toMatchObject(
            { status: "duplicate" },
        );
        expect(calls).toBe(1);
        await expect(
            acceptFriendControl(bobChannel, store, collision, persist),
        ).rejects.toBeInstanceOf(FriendControlIdCollisionError);
    });
});
