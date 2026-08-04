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
    FriendOutboxIdCollisionError,
    acceptFriendControl,
    createFriendRequest,
    createFriendResponse,
    deserializePublicIdentity,
    identityId,
    openFriendRequest,
    openFriendResponse,
    serializePublicIdentity,
} from "../index.js";

function fixedId(byte: number): string {
    const bytes = new Uint8Array(24);
    bytes.fill(byte);
    return encodeBase64Url(bytes);
}

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

    scan(
        prefix: string,
        options: { readonly after?: string; readonly limit: number },
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#memory.scan(prefix, options);
    }

    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#memory.transaction(async (transaction) =>
            operation({
                ...transaction,
                set: async (key, value): Promise<void> => {
                    if (key.includes("/outbox/")) {
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
            previousRequestId: null,
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
            previousRequestId: null,
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
            previousRequestId: null,
            responseAddress: "reply",
            profile: { name: "Alice" },
        });
        const duplicate = createFriendRequest(alice, bob, {
            id,
            previousRequestId: null,
            responseAddress: "reply",
            profile: { name: "Alice" },
        });
        const collision = createFriendRequest(alice, bob, {
            id,
            previousRequestId: null,
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

        expect(await aliceFriends.listOutbox()).toEqual([]);
        expect(await aliceFriends.confirmOutbox(request, "duplicate")).toBe(false);

        await aliceFriends.end(bob, 15);
        await bobFriends.end(alice, 15);
        expect((await new FriendBook(alice, aliceStore).get(bob))?.status).toBe("ended");
        const aliceIntent = (await aliceFriends.listOutbox())[0];
        const bobIntent = (await bobFriends.listOutbox()).find(
            (item) => item.kind === "control-intent",
        );
        expect(aliceIntent).toMatchObject({
            kind: "control-intent",
            intent: { type: "friendship-ended" },
        });
        expect(bobIntent).toMatchObject({
            kind: "control-intent",
            intent: { type: "friendship-ended" },
        });
        await aliceFriends.end(bob, 16);
        expect(await aliceFriends.listOutbox()).toEqual([aliceIntent]);
        if (aliceIntent === undefined) {
            throw new Error("Expected durable termination intent");
        }
        expect(await new FriendBook(alice, aliceStore).confirmOutbox(aliceIntent, "accepted")).toBe(
            true,
        );
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

    it("compares canonical outbox semantics and rejects an unrelated persisted requester", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const mallory = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const book = new FriendBook(alice, store);
        const request = await book.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        const entries = await store.list("murmur/v1/friend-book/");
        const outbox = [...entries].find(([key]) => key.includes("/outbox/"));
        const record = [...entries].find(([key]) => key.includes("/records/"));
        if (outbox === undefined || record === undefined) {
            throw new Error("Expected persisted friend state");
        }
        const outboxJson = JSON.parse(utf8Decode(outbox[1])) as Record<string, unknown>;
        await store.set(
            outbox[0],
            utf8Encode(JSON.stringify(Object.fromEntries(Object.entries(outboxJson).reverse()))),
        );
        expect(await book.confirmOutbox(request, "accepted")).toBe(true);

        const recordJson = JSON.parse(utf8Decode(record[1])) as Record<string, unknown>;
        recordJson.requester = { publicKey: identityId(mallory) };
        await store.set(record[0], utf8Encode(JSON.stringify(recordJson)));
        await expect(book.get(bob)).rejects.toThrow("neither owner nor peer");
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
        const winnerKeyPair = winnerIsAlice ? alice : bob;
        const winnerIdentity: IdentityPublicKey = winnerKeyPair;
        const losingRequest = winnerIsAlice ? bobRequest : aliceRequest;
        const lateLosingResponse = createFriendResponse(winnerKeyPair, responderIdentity, {
            id: fixedId(88),
            requestId: losingRequest.id,
            decision: "accepted",
            responseAddress: "late-response",
            profile: { name: "Late winner" },
        });
        await expect(
            responderBook.receiveResponse(winnerIdentity, lateLosingResponse, 2),
        ).resolves.toMatchObject({
            status: "superseded",
            record: { status: "pending-incoming" },
        });
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
        expect(() =>
            openFriendResponse(alice, bob, {
                ...first,
                ephemeralPublicKey: "!".repeat(44),
            }),
        ).toThrow("misaddressed");
        expect(() => openFriendResponse(alice, eve, first)).toThrow();
        await aliceFriends.receiveResponse(bob, first, 2);
        await expect(aliceFriends.receiveResponse(bob, collision, 3)).rejects.toBeInstanceOf(
            FriendExchangeIdCollisionError,
        );
    });

    it("ends pending outgoing with request plus terminal intent and treats a late response as replay", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const friends = new FriendBook(alice, store);
        await friends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 10,
        });
        const pending = await friends.get(bob);
        if (pending === undefined) {
            throw new Error("Expected pending outgoing friend");
        }

        await friends.end(bob, 11);
        expect((await friends.get(bob))?.nextRequestPredecessorId).toBe(pending.requestId);
        const terminalOutbox = await friends.listOutbox();
        expect(terminalOutbox.map((item) => item.kind).sort()).toEqual([
            "control-intent",
            "request",
        ]);
        expect(terminalOutbox).toContainEqual(
            expect.objectContaining({
                kind: "request",
                id: pending.requestId,
            }),
        );
        expect(terminalOutbox).toContainEqual(
            expect.objectContaining({
                kind: "control-intent",
                intent: {
                    type: "friendship-ended",
                    requestId: pending.requestId,
                },
            }),
        );
        expect((await new FriendBook(alice, store).get(bob))?.status).toBe("ended");

        const late = createFriendResponse(bob, alice, {
            id: fixedId(90),
            requestId: pending.requestId,
            decision: "accepted",
            responseAddress: "bob-response",
            profile: { name: "Bob" },
        });
        await expect(friends.receiveResponse(bob, late, 12)).resolves.toMatchObject({
            status: "superseded",
            record: {
                status: "ended",
                nextRequestPredecessorId: pending.requestId,
            },
        });
        await expect(
            new FriendBook(alice, store).receiveResponse(bob, late, 13),
        ).resolves.toMatchObject({
            status: "duplicate",
            record: { status: "ended" },
        });
    });

    it("retains an accepted response when the responder ends before publication", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        const bobStore = new MemoryMurmurStore();
        const bobFriends = new FriendBook(bob, bobStore);
        const prepared = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 20,
        });
        await bobFriends.receiveRequest(prepared.envelope, 21);
        await bobFriends.respond(alice, {
            decision: "accepted",
            profile: { name: "Bob" },
            responseAddress: "bob-response",
            now: 22,
        });
        await bobFriends.end(alice, 23);

        const outbox = await new FriendBook(bob, bobStore).listOutbox();
        expect(outbox.map((item) => item.kind).sort()).toEqual(["control-intent", "response"]);
        expect((await bobFriends.get(alice))?.nextRequestPredecessorId).toBe(prepared.id);
    });

    it("accepts a responder successor before the original response or terminal arrives", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        const first = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response-1",
            now: 30,
        });
        await bobFriends.receiveRequest(first.envelope, 31);
        const accepted = await bobFriends.respond(alice, {
            decision: "accepted",
            profile: { name: "Bob" },
            responseAddress: "bob-response-1",
            now: 32,
        });
        await bobFriends.end(alice, 33);
        const successor = await bobFriends.createRequest(alice, {
            profile: { name: "Bob successor" },
            destination: "alice-inbox",
            responseAddress: "bob-response-2",
            now: 34,
        });

        await expect(aliceFriends.receiveRequest(successor.envelope, 35)).resolves.toMatchObject({
            status: "opened",
            record: {
                status: "pending-incoming",
                previousRequestId: first.id,
            },
        });
        await expect(
            aliceFriends.receiveResponse(bob, accepted.outbox.envelope, 36),
        ).resolves.toMatchObject({
            status: "superseded",
            record: { requestId: successor.id },
        });
        const successorResponse = await aliceFriends.respond(bob, {
            decision: "accepted",
            profile: { name: "Alice successor" },
            responseAddress: "alice-response-2",
            now: 37,
        });
        await bobFriends.receiveResponse(alice, successorResponse.outbox.envelope, 38);
        expect((await aliceFriends.get(bob))?.status).toBe("active");
        expect((await bobFriends.get(alice))?.status).toBe("active");
    });

    it("accepts a successor before an original rejection arrives", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        const first = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 40,
        });
        await bobFriends.receiveRequest(first.envelope, 41);
        const rejected = await bobFriends.respond(alice, {
            decision: "rejected",
            now: 42,
        });
        await bobFriends.end(alice, 43);
        const successor = await bobFriends.createRequest(alice, {
            profile: { name: "Bob successor" },
            destination: "alice-inbox",
            responseAddress: "bob-response",
            now: 44,
        });

        await aliceFriends.receiveRequest(successor.envelope, 45);
        await expect(
            aliceFriends.receiveResponse(bob, rejected.outbox.envelope, 46),
        ).resolves.toMatchObject({
            status: "superseded",
            record: {
                status: "pending-incoming",
                requestId: successor.id,
            },
        });
    });

    it("ends pending incoming with an exact durable rejected response", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const bobStore = new MemoryMurmurStore();
        const bobFriends = new FriendBook(bob, bobStore);
        const request = createFriendRequest(alice, bob, {
            id: fixedId(31),
            previousRequestId: null,
            responseAddress: "alice-response",
            profile: { name: "Alice" },
        });
        await bobFriends.receiveRequest(request, 1);

        await bobFriends.end(alice, 2);
        const restored = new FriendBook(bob, bobStore);
        const outbox = await restored.listOutbox();
        expect(outbox).toHaveLength(1);
        expect(outbox[0]).toMatchObject({
            kind: "response",
            destination: "alice-response",
        });
        if (outbox[0]?.kind !== "response") {
            throw new Error("Expected rejected response outbox item");
        }
        expect(openFriendResponse(alice, bob, outbox[0].envelope)).toMatchObject({
            decision: "rejected",
            requestId: fixedId(31),
        });
        await restored.end(alice, 3);
        expect(await restored.listOutbox()).toEqual(outbox);
    });

    it("requires the durable causal predecessor for a new request after ended", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        const initial = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        await bobFriends.receiveRequest(requestEnvelope(initial), 1);
        await bobFriends.end(alice, 2);
        const rejection = (await bobFriends.listOutbox())[0];
        if (rejection?.kind !== "response") {
            throw new Error("Expected rejection");
        }
        await aliceFriends.receiveResponse(bob, rejection.envelope, 2);

        const next = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice again" },
            destination: "bob-inbox",
            responseAddress: "alice-response-2",
            now: 3,
        });
        const stale = createFriendRequest(alice, bob, {
            id: fixedId(32),
            previousRequestId: null,
            responseAddress: "stale-response",
            profile: { name: "Stale Alice" },
        });

        await expect(bobFriends.receiveRequest(stale, 3)).rejects.toThrow("causal predecessor");
        await expect(bobFriends.receiveRequest(requestEnvelope(next), 1)).rejects.toThrow(
            "backwards",
        );
        await expect(bobFriends.receiveRequest(requestEnvelope(next), 3)).resolves.toMatchObject({
            status: "opened",
            record: { status: "pending-incoming" },
        });
        await bobFriends.end(alice, 4);
        const olderGeneration = createFriendRequest(alice, bob, {
            id: fixedId(33),
            previousRequestId: initial.id,
            responseAddress: "older-generation-response",
            profile: { name: "Delayed older Alice" },
        });
        await expect(bobFriends.receiveRequest(olderGeneration, 5)).rejects.toThrow(
            "causal predecessor",
        );
    });

    it("uses a retained pending-end request as the immediate successor predecessor", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const aliceFriends = new FriendBook(alice, aliceStore);
        const first = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        await aliceFriends.end(bob, 2);
        expect((await aliceFriends.get(bob))?.nextRequestPredecessorId).toBe(first.id);

        const successor = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice successor" },
            destination: "bob-inbox",
            responseAddress: "alice-response-2",
            now: 3,
        });
        expect(openFriendRequest(bob, successor.envelope)).toMatchObject({
            id: successor.id,
            previousRequestId: first.id,
        });
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        await bobFriends.receiveRequest(first.envelope, 3);
        await expect(bobFriends.receiveRequest(successor.envelope, 4)).resolves.toMatchObject({
            status: "opened",
            record: {
                status: "pending-incoming",
                requestId: successor.id,
                previousRequestId: first.id,
            },
        });
    });

    it("does not let a late response regress a retained successor generation", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const aliceFriends = new FriendBook(alice, aliceStore);
        const bobFriends = new FriendBook(bob, bobStore);

        const request1 = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice 1" },
            destination: "bob-inbox",
            responseAddress: "alice-response-1",
            now: 1,
        });
        await bobFriends.receiveRequest(requestEnvelope(request1), 1);
        await bobFriends.end(alice, 2);
        const response1 = (await bobFriends.listOutbox()).find((item) => item.kind === "response");
        if (response1?.kind !== "response") {
            throw new Error("Expected response to request 1");
        }
        await aliceFriends.end(bob, 2);

        const request2 = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice 2" },
            destination: "bob-inbox",
            responseAddress: "alice-response-2",
            now: 3,
        });
        await aliceFriends.end(bob, 4);
        expect((await aliceFriends.get(bob))?.nextRequestPredecessorId).toBe(request2.id);

        await expect(
            new FriendBook(alice, aliceStore).receiveResponse(bob, response1.envelope, 5),
        ).resolves.toMatchObject({
            status: "superseded",
            record: {
                nextRequestPredecessorId: request2.id,
            },
        });

        const bobNext = await bobFriends.createRequest(alice, {
            profile: { name: "Bob next" },
            destination: "alice-inbox",
            responseAddress: "bob-response-next",
            now: 6,
        });
        await expect(
            new FriendBook(alice, aliceStore).receiveRequest(requestEnvelope(bobNext), 6),
        ).rejects.toThrow("causal predecessor");
    });

    it("does not regress a newer shared predecessor from an older tracker response", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobFriends = new FriendBook(bob, new MemoryMurmurStore());
        const aliceFriends = new FriendBook(alice, aliceStore);
        const request1 = await aliceFriends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        await bobFriends.receiveRequest(requestEnvelope(request1), 1);
        await bobFriends.end(alice, 2);
        const response1 = (await bobFriends.listOutbox()).find((item) => item.kind === "response");
        if (response1?.kind !== "response") {
            throw new Error("Expected first response");
        }
        await aliceFriends.end(bob, 2);
        await aliceFriends.receiveResponse(bob, response1.envelope, 3);

        const newer = await bobFriends.createRequest(alice, {
            profile: { name: "Bob newer" },
            destination: "alice-inbox",
            responseAddress: "bob-newer-response",
            now: 4,
        });
        await aliceFriends.receiveRequest(requestEnvelope(newer), 4);
        await aliceFriends.end(bob, 5);
        expect((await aliceFriends.get(bob))?.nextRequestPredecessorId).toBe(newer.id);

        const olderLate = createFriendResponse(bob, alice, {
            id: fixedId(99),
            requestId: request1.id,
            decision: "rejected",
        });
        await expect(
            new FriendBook(alice, aliceStore).receiveResponse(bob, olderLate, 6),
        ).resolves.toMatchObject({
            status: "superseded",
            record: {
                nextRequestPredecessorId: newer.id,
            },
        });
    });

    it("fails closed on forced same-kind, cross-kind, and termination outbox IDs", async () => {
        const repeated = fixedId(44);
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        const sameKind = new FriendBook(alice, new MemoryMurmurStore(), {
            generateId: () => repeated,
        });
        const firstReserved = await sameKind.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        expect(await sameKind.confirmOutbox(firstReserved, "accepted")).toBe(true);
        await expect(
            sameKind.createRequest(carol, {
                profile: { name: "Alice" },
                destination: "carol-inbox",
                responseAddress: "alice-response",
                now: 1,
            }),
        ).rejects.toBeInstanceOf(FriendOutboxIdCollisionError);
        expect(await sameKind.get(carol)).toBeUndefined();

        const crossStore = new MemoryMurmurStore();
        const crossKind = new FriendBook(bob, crossStore, {
            generateId: () => repeated,
        });
        await crossKind.createRequest(carol, {
            profile: { name: "Bob" },
            destination: "carol-inbox",
            responseAddress: "bob-response",
            now: 1,
        });
        await crossKind.receiveRequest(
            createFriendRequest(alice, bob, {
                id: fixedId(45),
                previousRequestId: null,
                responseAddress: "alice-response",
                profile: { name: "Alice" },
            }),
            1,
        );
        await expect(
            crossKind.respond(alice, {
                decision: "accepted",
                profile: { name: "Bob" },
                responseAddress: "bob-response",
                now: 2,
            }),
        ).rejects.toBeInstanceOf(FriendOutboxIdCollisionError);
        expect((await crossKind.get(alice))?.status).toBe("pending-incoming");

        const terminalStore = new MemoryMurmurStore();
        const terminal = new FriendBook(bob, terminalStore, {
            generateId: () => repeated,
        });
        await terminal.receiveRequest(
            createFriendRequest(alice, bob, {
                id: fixedId(46),
                previousRequestId: null,
                responseAddress: "alice-response",
                profile: { name: "Alice" },
            }),
            1,
        );
        await terminal.respond(alice, {
            decision: "accepted",
            profile: { name: "Bob" },
            responseAddress: "bob-response",
            now: 2,
        });
        await expect(terminal.end(alice, 3)).rejects.toBeInstanceOf(FriendOutboxIdCollisionError);
        expect((await terminal.get(alice))?.status).toBe("active");
    });

    it("rejects encoded overbounds before decoding request and persisted outbox fields", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const request = createFriendRequest(alice, bob, {
            id: fixedId(55),
            previousRequestId: null,
            responseAddress: "alice-response",
            profile: { name: "Alice" },
        });
        expect(() =>
            openFriendRequest(bob, {
                ...request,
                ephemeralPublicKey: "!".repeat(44),
            }),
        ).toThrow("misaddressed");
        expect(() =>
            openFriendRequest(bob, {
                ...request,
                nonce: "!".repeat(17),
            }),
        ).toThrow("misaddressed");
        expect(() =>
            openFriendRequest(bob, {
                ...request,
                ciphertext: "!".repeat(Math.ceil((2 * 1024 * 1024 * 4) / 3) + 1),
            }),
        ).toThrow("misaddressed");
        expect(() =>
            createFriendRequest(alice, bob, {
                id: "!".repeat(33),
                previousRequestId: null,
                responseAddress: "reply",
                profile: { name: "Alice" },
            }),
        ).toThrow("24 bytes");

        const store = new MemoryMurmurStore();
        const friends = new FriendBook(alice, store);
        await friends.createRequest(bob, {
            profile: { name: "Alice" },
            destination: "bob-inbox",
            responseAddress: "alice-response",
            now: 1,
        });
        const entries = await store.list("murmur/v1/friend-book/");
        const outboxEntry = [...entries].find(([key]) => key.includes("/outbox/"));
        if (outboxEntry === undefined) {
            throw new Error("Expected outbox entry");
        }
        const corrupt = JSON.parse(utf8Decode(outboxEntry[1])) as {
            envelope: { ephemeralPublicKey: string };
        };
        corrupt.envelope.ephemeralPublicKey = "!".repeat(44);
        await store.set(outboxEntry[0], utf8Encode(JSON.stringify(corrupt)));
        await expect(friends.listOutbox()).rejects.toThrow("outbox envelope");
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
        const reverse = bobChannel.seal(
            bobChannel.createMessage(utf8Encode("independent reverse direction")),
        );
        expect(utf8Decode(aliceChannel.open(reverse).message.payload)).toBe(
            "independent reverse direction",
        );
        expect(() => bobChannel.open({ ...envelope, nonce: "!".repeat(17) })).toThrow("ciphertext");
        zeroBytes(bobTopicSecret);
    });

    it("is sealed and idempotently unusable after destruction", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const channel = new FriendChannel(alice, bob);
        const message = channel.createMessage(utf8Encode("before destroy"));
        channel.destroy();
        channel.destroy();

        expect(() => channel.self).toThrow("destroyed");
        expect(() => channel.peer).toThrow("destroyed");
        expect(() => channel.topicPublicKey).toThrow("destroyed");
        expect(() => channel.exportTopicSecretKey()).toThrow("destroyed");
        expect(() => channel.createMessage(new Uint8Array())).toThrow("destroyed");
        expect(() => channel.seal(message)).toThrow("destroyed");
        expect(() => channel.signTopicBytes(new Uint8Array())).toThrow("destroyed");
        expect(() => channel.verifyTopicBytes(new Uint8Array(), new Uint8Array(64))).toThrow(
            "destroyed",
        );
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
        let failedPayload: Uint8Array | undefined;
        const persist = async (): Promise<void> => {
            calls += 1;
        };

        await expect(
            acceptFriendControl(bobChannel, store, first, async (_transaction, opened) => {
                failedPayload = opened.message.payload;
                throw new Error("application failed");
            }),
        ).rejects.toThrow("application failed");
        expect(failedPayload?.every((byte) => byte === 0)).toBe(true);
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
