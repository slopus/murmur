import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair, randomBytes } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
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

describe("friend request protocol", () => {
    it("serializes exactly one public identity key", () => {
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
    });

    it("keeps request identity, profile, response address, and private data confidential", () => {
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

        expect(wire).not.toContain(encodeBase64Url(alice.publicKey));
        expect(wire).not.toContain("Alice");
        expect(wire).not.toContain("alice-response");
        expect(wire).not.toContain("bootstrap");
        expect(opened.sender.publicKey).toEqual(alice.publicKey);
        expect(opened.profile).toEqual({
            name: "Alice",
            metadata: { role: "agent" },
        });
        expect(opened.responseAddress).toBe("opaque:alice-response");
        expect(utf8Decode(opened.privateData ?? new Uint8Array())).toBe("private bootstrap bytes");
    });

    it("enforces recipient binding, authenticated ciphertext, and valid recipient identity", () => {
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
                recipient: identityId(eve),
            }),
        ).toThrow("misaddressed");
        expect(() =>
            openFriendRequest(bob, {
                ...request,
                ciphertext: `${request.ciphertext.slice(0, -1)}${
                    request.ciphertext.endsWith("A") ? "B" : "A"
                }`,
            }),
        ).toThrow();
    });

    it("detects an authenticated request-ID collision after replay checking", async () => {
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

describe("durable friendship lifecycle", () => {
    it("moves both peers through pending request, response, active, and ended states", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const aliceFriends = new FriendBook(alice, aliceStore);
        const bobFriends = new FriendBook(bob, bobStore);

        const request = await aliceFriends.createRequest(
            bob,
            { name: "Alice" },
            "alice-response",
            utf8Encode("alice bootstrap"),
            10,
        );
        expect((await aliceFriends.get(bob))?.status).toBe("pending-outgoing");

        const incoming = await bobFriends.receiveRequest(request, 11);
        expect(incoming.status).toBe("opened");
        expect(incoming.record).toMatchObject({
            status: "pending-incoming",
            peerResponseAddress: "alice-response",
            profile: { name: "Alice" },
        });

        const prepared = await bobFriends.respond(
            alice,
            "accepted",
            { name: "Bob" },
            "bob-response",
            utf8Encode("bob bootstrap"),
            12,
        );
        expect(prepared.record.status).toBe("active");

        const accepted = await aliceFriends.receiveResponse(prepared.envelope, 13);
        expect(accepted.record).toMatchObject({
            status: "active",
            peerResponseAddress: "bob-response",
            profile: { name: "Bob" },
        });
        expect(await aliceFriends.receiveResponse(prepared.envelope, 14)).toMatchObject({
            status: "duplicate",
            record: { status: "active" },
        });

        await aliceFriends.end(bob, 15);
        await bobFriends.end(alice, 15);
        expect((await aliceFriends.get(bob))?.status).toBe("ended");
        expect((await bobFriends.get(alice))?.status).toBe("ended");

        const restored = new FriendBook(alice, aliceStore);
        expect((await restored.get(bob))?.status).toBe("ended");
        expect(await restored.list()).toHaveLength(1);
    });

    it("persists outgoing envelopes atomically with state and rolls back both on failure", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const book = new FriendBook(alice, store);

        await expect(
            book.createRequest(
                bob,
                { name: "Alice" },
                "reply",
                undefined,
                1,
                async (transaction, envelope) => {
                    await transaction.set("outbox/request", utf8Encode(JSON.stringify(envelope)));
                    throw new Error("outbox failed");
                },
            ),
        ).rejects.toThrow("outbox failed");

        expect(await book.get(bob)).toBeUndefined();
        expect(await store.get("outbox/request")).toBeUndefined();
    });

    it("rejects invalid transitions and supports a fresh request after ended", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const book = new FriendBook(alice, new MemoryMurmurStore());

        await book.createRequest(bob, { name: "Alice" }, "reply", undefined, 1);
        await expect(
            book.createRequest(bob, { name: "Alice" }, "reply", undefined, 2),
        ).rejects.toThrow("pending-outgoing");
        await book.end(bob, 3);
        await expect(
            book.createRequest(bob, { name: "Alice" }, "reply", undefined, 2),
        ).rejects.toThrow("backwards");
        await expect(
            book.createRequest(bob, { name: "Alice" }, "reply", undefined, 4),
        ).resolves.toMatchObject({ type: "friend-request" });
    });

    it("authenticates recipient-bound responses and detects response-ID collisions", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        await aliceFriends.createRequest(bob, { name: "Alice" }, "alice-response", undefined, 1);
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

        expect(JSON.stringify(first)).not.toContain(encodeBase64Url(bob.publicKey));
        expect(JSON.stringify(first)).not.toContain("bob-response");
        expect(openFriendResponse(alice, first)).toMatchObject({
            responder: { publicKey: bob.publicKey },
            decision: "accepted",
            profile: { name: "Bob" },
        });
        expect(() => openFriendResponse(eve, first)).toThrow();
        await aliceFriends.receiveResponse(first, 2);
        await expect(aliceFriends.receiveResponse(collision, 3)).rejects.toBeInstanceOf(
            FriendExchangeIdCollisionError,
        );
    });

    it("persists a rejected response as ended without activating the sender", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        await aliceFriends.createRequest(bob, { name: "Alice" }, "alice-response", undefined, 1);
        const pending = await aliceFriends.get(bob);
        if (pending === undefined) {
            throw new Error("Expected pending outgoing state");
        }
        const rejected = createFriendResponse(bob, alice, {
            id: encodeBase64Url(randomBytes(24)),
            requestId: pending.requestId,
            decision: "rejected",
        });

        expect(await aliceFriends.receiveResponse(rejected, 2)).toMatchObject({
            status: "opened",
            record: { status: "ended" },
        });
    });
});

describe("friend control channel", () => {
    it("derives one symmetric topic capability and exchanges opaque durable or temporary data", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const aliceChannel = new FriendChannel(alice, bob);
        const bobChannel = new FriendChannel(bob, alice);
        const eveChannel = new FriendChannel(eve, alice);
        const message = aliceChannel.createMessage(
            utf8Encode("opaque MLS Welcome bytes"),
            { kind: "temporary", expiresAt: 200 },
            100,
        );
        const envelope = aliceChannel.seal(message);
        const opened = bobChannel.open(envelope);
        const authorization = utf8Encode("relay event authorization");
        const signature = aliceChannel.signTopicBytes(authorization);

        expect(aliceChannel.topicPublicKey).toEqual(bobChannel.topicPublicKey);
        expect(eveChannel.topicPublicKey).not.toEqual(aliceChannel.topicPublicKey);
        expect(JSON.stringify(envelope)).not.toContain("Welcome");
        expect(utf8Decode(opened.message.payload)).toBe("opaque MLS Welcome bytes");
        expect(opened.message.retention).toEqual({
            kind: "temporary",
            expiresAt: 200,
        });
        expect(bobChannel.verifyTopicBytes(authorization, signature)).toBe(true);
        expect(eveChannel.verifyTopicBytes(authorization, signature)).toBe(false);
        expect(() => eveChannel.open(envelope)).toThrow();
    });

    it("commits application persistence and replay state atomically", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceChannel = new FriendChannel(alice, bob);
        const bobChannel = new FriendChannel(bob, alice);
        const store = new MemoryMurmurStore();
        const message = aliceChannel.createMessage(
            utf8Encode("descriptor update"),
            { kind: "durable" },
            1,
        );
        const envelope = aliceChannel.seal(message);
        const retriedEnvelope = aliceChannel.seal(message);
        let persistCalls = 0;
        const persist = async (
            transaction: Parameters<Parameters<typeof acceptFriendControl>[3]>[0],
            opened: Parameters<Parameters<typeof acceptFriendControl>[3]>[1],
        ): Promise<void> => {
            persistCalls += 1;
            await transaction.set("application/control", opened.message.payload);
        };

        expect(await acceptFriendControl(bobChannel, store, envelope, persist)).toMatchObject({
            status: "opened",
        });
        expect(
            await acceptFriendControl(bobChannel, store, retriedEnvelope, persist),
        ).toMatchObject({ status: "duplicate" });
        expect(persistCalls).toBe(1);
        expect(utf8Decode((await store.get("application/control")) ?? new Uint8Array())).toBe(
            "descriptor update",
        );
    });

    it("rolls back replay markers and detects same-ID content collisions", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceChannel = new FriendChannel(alice, bob);
        const bobChannel = new FriendChannel(bob, alice);
        const store = new MemoryMurmurStore();
        const original = aliceChannel.createMessage(utf8Encode("first"), { kind: "durable" }, 1);
        const first = aliceChannel.seal(original);
        const collision = aliceChannel.seal({
            ...original,
            payload: utf8Encode("second"),
        });

        await expect(
            acceptFriendControl(bobChannel, store, first, async () => {
                throw new Error("application failed");
            }),
        ).rejects.toThrow("application failed");
        await expect(
            acceptFriendControl(bobChannel, store, first, async () => undefined),
        ).resolves.toMatchObject({ status: "opened" });
        await expect(
            acceptFriendControl(bobChannel, store, collision, async () => undefined),
        ).rejects.toBeInstanceOf(FriendControlIdCollisionError);
    });
});
