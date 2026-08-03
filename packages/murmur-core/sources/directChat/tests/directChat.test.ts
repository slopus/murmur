import { describe, expect, it } from "vitest";
import { MurmurClient } from "../../client/index.js";
import { generateIdentityKeyPair, type IdentityKeyPair } from "../../crypto/index.js";
import { FriendBook, pairwiseTopic } from "../../identity/index.js";
import {
    createPrivateMessage,
    encodeEncryptedPrivateMessage,
    encryptPrivateMessageForContact,
    privateMessageListElementId,
} from "../../messaging/index.js";
import { MemoryMurmurStore, type MurmurStore } from "../../storage/index.js";
import {
    createRelayEvent,
    type EventPage,
    type ListElement,
    type ListPage,
    type PublishOutcome,
    type RelayBlob,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicState,
} from "../../transport/index.js";
import { utf8Encode } from "../../utils/index.js";
import { DirectChat, type DirectChatCallbacks } from "../index.js";

class ChatTransport implements RelayTransport {
    readonly events = new Map<string, SignedRelayEvent[]>();
    readonly lists = new Map<string, ListElement[]>();
    readonly blobs = new Map<string, RelayBlob>();
    offline = false;
    reset = false;

    constructor(readonly id: string) {}

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        if (this.offline) {
            throw new Error(`${this.id} offline`);
        }
        const events = this.events.get(event.topic) ?? [];
        const duplicate = events.findIndex((candidate) => candidate.id === event.id);
        if (duplicate >= 0) {
            return { seq: BigInt(duplicate + 1), duplicate: true };
        }
        events.push(event);
        this.events.set(event.topic, events);
        const elements = this.lists.get(event.topic) ?? [];
        for (const operation of event.list ?? []) {
            if (
                operation.op === "append" &&
                !elements.some((element) => element.id === operation.id)
            ) {
                elements.push({
                    id: operation.id,
                    version: 1n,
                    bytes: operation.bytes.slice(),
                });
            }
        }
        this.lists.set(event.topic, elements);
        return { seq: BigInt(events.length), duplicate: false };
    }

    async readState(topic: string): Promise<TopicState | undefined> {
        const events = this.events.get(topic);
        if (events === undefined) {
            return undefined;
        }
        return {
            seq: BigInt(events.length),
            snapshot: null,
            list: {
                elements: (this.lists.get(topic) ?? []).map((element) => ({
                    ...element,
                    bytes: element.bytes.slice(),
                })),
                nextCursor: null,
            },
        };
    }

    async readList(): Promise<ListPage | undefined> {
        return { elements: [], nextCursor: null };
    }

    async readEvents(topic: string, since: bigint): Promise<EventPage | undefined> {
        const events = this.events.get(topic);
        if (events === undefined) {
            return undefined;
        }
        return {
            events: events
                .map((event, index) => ({ seq: BigInt(index + 1), event }))
                .filter((retained) => retained.seq > since),
            reset: this.reset,
            seq: BigInt(events.length),
        };
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        this.blobs.set(blob.id, blob);
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        return this.blobs.get(id);
    }
}

function callbacks(storePrefix: string = "application"): DirectChatCallbacks {
    return {
        persistMessage: async (transaction, surfaced) => {
            await transaction.set(
                `${storePrefix}/${surfaced.direction}/${surfaced.message.id}`,
                utf8Encode(
                    JSON.stringify({
                        text: surfaced.message.text,
                        friend: surfaced.ordering.senderId,
                        ordering: surfaced.ordering,
                    }),
                ),
            );
        },
        messagePublished: async (transaction, surfaced) => {
            await transaction.set(
                `${storePrefix}/published/${surfaced.message.id}`,
                utf8Encode("published"),
            );
        },
    };
}

async function addFriends(
    left: IdentityKeyPair,
    leftStore: MurmurStore,
    right: IdentityKeyPair,
    rightStore: MurmurStore,
): Promise<{ readonly left: FriendBook; readonly right: FriendBook }> {
    const leftFriends = new FriendBook(left, leftStore);
    const rightFriends = new FriendBook(right, rightStore);
    await leftFriends.save({ identity: right, profile: { name: "Right" } }, 1);
    await rightFriends.save({ identity: left, profile: { name: "Left" } }, 1);
    return { left: leftFriends, right: rightFriends };
}

function chat(
    identity: IdentityKeyPair,
    store: MurmurStore,
    friends: FriendBook,
    transports: readonly RelayTransport[],
    applicationCallbacks: DirectChatCallbacks = callbacks(),
): DirectChat {
    return new DirectChat({
        identity,
        store,
        friends,
        client: new MurmurClient({ identity, store, transports }),
        callbacks: applicationCallbacks,
        now: () => 1_000,
    });
}

describe("DirectChat", () => {
    it("publishes separated self/recipient copies and retries one caller ID exactly once", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);
        const bobChat = chat(bob, bobStore, friends.right, [relay]);
        const id = "A".repeat(32);

        const first = await aliceChat.sendText(bob, "hello", { id, sentAt: 42 });
        const retry = await aliceChat.sendText(bob, "hello", { id });
        const received = await bobChat.sync();
        const topic = pairwiseTopic(alice, bob);
        const elements = relay.lists.get(topic) ?? [];

        expect(first.message.id).toBe(id);
        expect(retry.message).toEqual(first.message);
        expect(elements).toHaveLength(2);
        expect(elements.map((element) => element.id)).toEqual([
            expect.stringMatching(/^message:/),
            expect.stringMatching(/^self-message:/),
        ]);
        expect(received.status).toBe("events");
        if (received.status === "events") {
            expect(received.opened.map((message) => message.message.id)).toEqual([id]);
            expect(received.opened[0]?.ordering).toEqual({
                sentAt: 42,
                senderId: expect.any(String),
                messageId: id,
            });
        }
        expect(await aliceStore.list("application/outgoing/")).toHaveLength(1);
        expect(await bobStore.list("application/incoming/")).toHaveLength(1);
        await expect(aliceChat.sendText(bob, "collision", { id })).rejects.toThrow("ID collision");
        await expect(aliceChat.sendText(bob, "x", { attachments: [] } as never)).rejects.toThrow(
            "options",
        );
    });

    it("reconstructs fresh two-party sent and received history exactly once", async () => {
        const firstRelay = new ChatTransport("first");
        const secondRelay = new ChatTransport("second");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [firstRelay, secondRelay]);
        const bobChat = chat(bob, bobStore, friends.right, [firstRelay, secondRelay]);

        await aliceChat.sendText(bob, "A to B", { id: "A".repeat(32), sentAt: 10 });
        await bobChat.sendText(alice, "B to A", { id: "B".repeat(32), sentAt: 20 });

        const freshAliceStore = new MemoryMurmurStore();
        const freshBobStore = new MemoryMurmurStore();
        const freshFriends = await addFriends(alice, freshAliceStore, bob, freshBobStore);
        const freshAlice = chat(alice, freshAliceStore, freshFriends.left, [
            firstRelay,
            secondRelay,
        ]);
        const freshBob = chat(bob, freshBobStore, freshFriends.right, [firstRelay, secondRelay]);

        const aliceFirst = await freshAlice.loadHistory(bob, "first");
        const aliceSecond = await freshAlice.loadHistory(bob, "second");
        const bobFirst = await freshBob.loadHistory(alice, "first");
        const bobSecond = await freshBob.loadHistory(alice, "second");

        expect(aliceFirst.opened.map((value) => [value.direction, value.message.text])).toEqual([
            ["outgoing", "A to B"],
            ["incoming", "B to A"],
        ]);
        expect(bobFirst.opened.map((value) => [value.direction, value.message.text])).toEqual([
            ["incoming", "A to B"],
            ["outgoing", "B to A"],
        ]);
        expect(aliceSecond.opened).toEqual([]);
        expect(bobSecond.opened).toEqual([]);
        expect(await freshAliceStore.list("application/")).toHaveLength(2);
        expect(await freshBobStore.list("application/")).toHaveLength(2);
    });

    it("recovers a retained outbox after restart and keeps consumer persistence atomic", async () => {
        const relay = new ChatTransport("relay");
        relay.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const id = "C".repeat(32);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);

        await expect(
            aliceChat.sendText(bob, "survive restart", { id, sentAt: 30 }),
        ).rejects.toThrow("rejected");
        expect(await aliceStore.list("application/outgoing/")).toHaveLength(1);
        relay.offline = false;

        const restarted = chat(alice, aliceStore, friends.left, [relay]);
        expect((await restarted.retryPending()).published).toBe(1);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(0);
        const bobChat = chat(bob, bobStore, friends.right, [relay]);
        const received = await bobChat.sync();
        expect(received.status === "events" ? received.opened[0]?.message.id : undefined).toBe(id);

        const failingStore = new MemoryMurmurStore();
        const failingFriends = new FriendBook(bob, failingStore);
        await failingFriends.save({ identity: alice, profile: { name: "Alice" } }, 1);
        const failing = chat(bob, failingStore, failingFriends, [relay], {
            persistMessage: async (transaction, surfaced) => {
                await transaction.set(
                    "application/will-roll-back",
                    utf8Encode(surfaced.message.id),
                );
                throw new Error("consumer crash");
            },
        });
        await expect(failing.loadHistory(alice)).rejects.toThrow("consumer crash");
        expect(await failingStore.get("application/will-roll-back")).toBeUndefined();

        const recovered = chat(bob, failingStore, failingFriends, [relay]);
        expect((await recovered.loadHistory(alice)).opened).toHaveLength(1);
    });

    it("quarantines wrong-topic senders and authenticated ID collisions without cursor gaps", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);
        const bobClient = new MurmurClient({ identity: bob, store: bobStore, transports: [relay] });
        const eveClient = new MurmurClient({
            identity: eve,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });
        const topic = pairwiseTopic(alice, bob);
        const id = "D".repeat(32);
        const original = createPrivateMessage("original", [], 40, id);
        const collision = { ...original, text: "collision" };
        const originalBytes = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(bob, alice, original),
        );
        const collisionBytes = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(bob, alice, collision),
        );
        const wrongBytes = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(eve, alice, createPrivateMessage("wrong", [], 1)),
        );
        await bobClient.publishEvent(
            createRelayEvent(bob, topic, originalBytes, {
                list: [
                    {
                        op: "append",
                        id: privateMessageListElementId(bob, original),
                        bytes: originalBytes,
                    },
                ],
            }),
        );
        await bobClient.publishEvent(createRelayEvent(bob, topic, collisionBytes));
        await eveClient.publishEvent(createRelayEvent(eve, topic, wrongBytes));

        const result = await aliceChat.sync();

        expect(result.status).toBe("events");
        if (result.status === "events") {
            expect(result.opened.map((value) => value.message.text)).toEqual(["original"]);
            expect(result.quarantined).toBe(2);
        }
        expect(await aliceStore.list("application/incoming/")).toHaveLength(1);
        expect(await aliceStore.list("direct-chat/v1/quarantine/")).toHaveLength(2);
        expect(await aliceChat.sync()).toMatchObject({
            status: "events",
            opened: [],
        });

        const freshStore = new MemoryMurmurStore();
        const freshFriends = new FriendBook(alice, freshStore);
        await freshFriends.save({ identity: bob, profile: { name: "Bob" } }, 1);
        const legacyHistory = await chat(alice, freshStore, freshFriends, [relay]).loadHistory(bob);
        expect(legacyHistory.opened.map((value) => value.message.text)).toEqual(["original"]);
    });

    it("handles removed-friend traffic gaplessly and resumes only future delivery", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);
        const bobChat = chat(bob, bobStore, friends.right, [relay]);

        await friends.right.remove(alice, 2);
        await aliceChat.sendText(bob, "while removed", { id: "E".repeat(32), sentAt: 3 });
        const removed = await bobChat.sync();
        expect(removed.status === "events" ? removed.quarantined : 0).toBe(1);
        expect(await bobStore.list("application/incoming/")).toHaveLength(0);

        const active = await friends.right.save(
            { identity: alice, profile: { name: "Alice again" } },
            4,
        );
        await bobChat.subscribeFriend(active);
        await aliceChat.sendText(bob, "after re-add", { id: "F".repeat(32), sentAt: 5 });
        const resumed = await bobChat.sync();
        expect(
            resumed.status === "events" ? resumed.opened.map((value) => value.message.text) : [],
        ).toEqual(["after re-add"]);
    });

    it("surfaces reset recovery through permanent history", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        await chat(alice, aliceStore, friends.left, [relay]).sendText(bob, "retained", {
            id: "G".repeat(32),
            sentAt: 7,
        });
        relay.reset = true;
        const bobChat = chat(bob, bobStore, friends.right, [relay]);
        const reset = await bobChat.sync();
        expect(reset.status).toBe("reset");
        if (reset.status !== "reset" || reset.resets[0] === undefined) {
            throw new Error("Expected direct-chat reset");
        }
        const recovered = await bobChat.recoverReset(reset.resets[0]);
        expect(recovered.opened.map((value) => value.message.text)).toEqual(["retained"]);
        relay.reset = false;
        expect(await bobChat.sync()).toMatchObject({ status: "events", opened: [] });
    });
});
