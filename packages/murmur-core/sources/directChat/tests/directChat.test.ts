import { describe, expect, it } from "vitest";
import { MurmurClient } from "../../client/index.js";
import { generateIdentityKeyPair, type IdentityKeyPair } from "../../crypto/index.js";
import { FriendBook, pairwiseTopic } from "../../identity/index.js";
import {
    createPrivateMessage,
    encodeEncryptedPrivateMessage,
    encryptFile,
    encryptPrivateMessageForContact,
    MAX_FILE_BYTES,
    privateMessageListElementId,
    privateMessageSelfListElementId,
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
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    DirectChat,
    DirectChatAttachmentIntegrityError,
    DirectChatAttachmentPolicyError,
    MAX_DIRECT_CHAT_ATTACHMENT_BYTES,
    MAX_DIRECT_CHAT_ATTACHMENTS,
    MAX_DIRECT_CHAT_DOCUMENT_BYTES,
    type DirectChatCallbacks,
} from "../index.js";

class ChatTransport implements RelayTransport {
    readonly events = new Map<string, SignedRelayEvent[]>();
    readonly lists = new Map<string, ListElement[]>();
    readonly blobs = new Map<string, RelayBlob>();
    readonly operations: string[] = [];
    offline = false;
    reset = false;
    now = 1_000;
    enforceFreshness = false;
    loseNextResponse = false;
    loseNextBlobResponse = false;

    constructor(readonly id: string) {}

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        if (this.offline) {
            throw new Error(`${this.id} offline`);
        }
        this.operations.push(`event:${event.id}`);
        const events = this.events.get(event.topic) ?? [];
        const duplicate = events.findIndex((candidate) => candidate.id === event.id);
        if (duplicate >= 0) {
            return { seq: BigInt(duplicate + 1), duplicate: true };
        }
        if (
            this.enforceFreshness &&
            (event.createdAt < this.now - 5 * 60 * 1_000 ||
                event.createdAt > this.now + 5 * 60 * 1_000)
        ) {
            throw new Error(`${this.id} rejected an expired event`);
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
        if (this.loseNextResponse) {
            this.loseNextResponse = false;
            throw new Error(`${this.id} lost its accepted response`);
        }
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
        if (this.offline) {
            throw new Error(`${this.id} offline`);
        }
        this.operations.push(`blob:${blob.id}`);
        this.blobs.set(blob.id, { id: blob.id, bytes: blob.bytes.slice() });
        if (this.loseNextBlobResponse) {
            this.loseNextBlobResponse = false;
            throw new Error(`${this.id} lost its accepted blob response`);
        }
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        const blob = this.blobs.get(id);
        return blob === undefined ? undefined : { id: blob.id, bytes: blob.bytes.slice() };
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
    now: () => number = () => 1_000,
): DirectChat {
    return new DirectChat({
        identity,
        store,
        friends,
        client: new MurmurClient({ identity, store, transports }),
        callbacks: applicationCallbacks,
        now,
    });
}

describe("DirectChat", () => {
    it("sends, downloads, retries, and backfills photo and document attachments", async () => {
        const first = new ChatTransport("first");
        const second = new ChatTransport("second");
        second.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [first, second]);
        const bobChat = chat(bob, bobStore, friends.right, [first, second]);
        const id = "L".repeat(32);

        const sent = await aliceChat.sendMessage(
            bob,
            {
                text: "two files",
                attachments: [
                    {
                        name: "photo.jpg",
                        mediaType: "image/jpeg",
                        bytes: utf8Encode("photo"),
                    },
                    {
                        name: "notes.txt",
                        mediaType: "text/plain",
                        bytes: utf8Encode("document"),
                    },
                ],
            },
            { id, sentAt: 50 },
        );

        expect(sent.message.attachments.map((value) => value.mediaType)).toEqual([
            "image/jpeg",
            "text/plain",
        ]);
        expect(first.operations.slice(-1)[0]).toMatch(/^event:/);
        expect(first.operations.slice(0, 2)).toEqual([
            `blob:${sent.message.attachments[0]?.blobId}`,
            `blob:${sent.message.attachments[1]?.blobId}`,
        ]);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(1);
        expect(await aliceStore.list("client/")).toHaveLength(0);
        const genericRetry = await new MurmurClient({
            identity: alice,
            store: aliceStore,
            transports: [first, second],
        }).retryOutboundSettled();
        expect(genericRetry.results).toHaveLength(0);
        expect(second.operations).toEqual([]);
        const received = await bobChat.sync();
        if (received.status !== "events" || received.opened[0] === undefined) {
            throw new Error("Expected attachment message");
        }
        expect(
            utf8Decode(await bobChat.fetchAttachment(received.opened[0].message.attachments[0]!)),
        ).toBe("photo");
        expect(
            utf8Decode(await bobChat.fetchAttachment(received.opened[0].message.attachments[1]!)),
        ).toBe("document");
        await expect(
            aliceChat.sendMessage(
                bob,
                {
                    text: "two files",
                    attachments: [
                        {
                            name: "photo.jpg",
                            mediaType: "image/jpeg",
                            bytes: utf8Encode("changed"),
                        },
                        {
                            name: "notes.txt",
                            mediaType: "text/plain",
                            bytes: utf8Encode("document"),
                        },
                    ],
                },
                { id },
            ),
        ).rejects.toThrow("ID collision");

        second.offline = false;
        expect((await aliceChat.retryPending()).failures).toEqual([]);
        expect(second.operations.slice(-1)[0]).toMatch(/^event:/);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(0);
        expect(await aliceStore.list("direct-chat/v2/outbox-blob/")).toHaveLength(0);

        const freshStore = new MemoryMurmurStore();
        const freshFriends = new FriendBook(alice, freshStore);
        await freshFriends.save({ identity: bob, profile: { name: "Bob" } }, 1);
        const recovered = await chat(alice, freshStore, freshFriends, [first]).loadHistory(bob);
        expect(recovered.opened).toHaveLength(1);
        expect(recovered.opened[0]?.direction).toBe("outgoing");
        expect(recovered.opened[0]?.message.attachments).toEqual(sent.message.attachments);
    });

    it("enforces exact document, photo, aggregate, count, filename, and MIME boundaries", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);

        await expect(
            aliceChat.sendMessage(bob, {
                text: "",
                attachments: [
                    {
                        name: "too-large.pdf",
                        mediaType: "application/pdf",
                        bytes: new Uint8Array(MAX_DIRECT_CHAT_DOCUMENT_BYTES + 1),
                    },
                ],
            }),
        ).rejects.toBeInstanceOf(DirectChatAttachmentPolicyError);
        await expect(
            aliceChat.sendMessage(bob, {
                text: "",
                attachments: [
                    {
                        name: "bad/name",
                        mediaType: "text/plain",
                        bytes: new Uint8Array(),
                    },
                ],
            }),
        ).rejects.toThrow("descriptor");
        await expect(
            aliceChat.sendMessage(bob, {
                text: "",
                attachments: [
                    {
                        name: "name",
                        mediaType: "not a mime",
                        bytes: new Uint8Array(),
                    },
                ],
            }),
        ).rejects.toThrow("descriptor");
        await expect(
            aliceChat.sendMessage(bob, {
                text: "",
                attachments: Array.from(
                    { length: MAX_DIRECT_CHAT_ATTACHMENTS + 1 },
                    (_, index) => ({
                        name: `empty-${index}`,
                        mediaType: "image/png",
                        bytes: new Uint8Array(),
                    }),
                ),
            }),
        ).rejects.toThrow("message input");
        await expect(
            aliceChat.sendMessage(bob, {
                text: "",
                attachments: [
                    {
                        name: "left.png",
                        mediaType: "image/png",
                        bytes: new Uint8Array(MAX_DIRECT_CHAT_ATTACHMENT_BYTES / 2),
                    },
                    {
                        name: "right.png",
                        mediaType: "image/png",
                        bytes: new Uint8Array(MAX_DIRECT_CHAT_ATTACHMENT_BYTES / 2 + 1),
                    },
                ],
            }),
        ).rejects.toBeInstanceOf(DirectChatAttachmentPolicyError);

        const exactDocument = await aliceChat.sendMessage(bob, {
            text: "",
            attachments: [
                {
                    name: "exact.pdf",
                    mediaType: "application/pdf",
                    bytes: new Uint8Array(MAX_DIRECT_CHAT_DOCUMENT_BYTES),
                },
            ],
        });
        expect(exactDocument.message.attachments[0]?.plaintextBytes).toBe(
            MAX_DIRECT_CHAT_DOCUMENT_BYTES,
        );
        const exactPhoto = await aliceChat.sendMessage(bob, {
            text: "",
            attachments: [
                {
                    name: "maximum.jpg",
                    mediaType: "image/jpeg",
                    bytes: new Uint8Array(MAX_FILE_BYTES),
                },
            ],
        });
        expect(exactPhoto.message.attachments[0]?.plaintextBytes).toBe(MAX_FILE_BYTES);
        const exactCount = await aliceChat.sendMessage(bob, {
            text: "",
            attachments: Array.from({ length: MAX_DIRECT_CHAT_ATTACHMENTS }, (_, index) => ({
                name: `empty-${index}`,
                mediaType: "image/png",
                bytes: new Uint8Array(),
            })),
        });
        expect(exactCount.message.attachments).toHaveLength(MAX_DIRECT_CHAT_ATTACHMENTS);
    }, 30_000);

    it("accepts oversize authenticated document metadata but refuses policy and tamper fetches", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);
        const bobClient = new MurmurClient({ identity: bob, store: bobStore, transports: [relay] });
        const oversized = {
            version: 1 as const,
            blobId: "A".repeat(43),
            key: new Uint8Array(32),
            nonce: new Uint8Array(12),
            name: "oversize.pdf",
            mediaType: "application/pdf",
            plaintextBytes: MAX_DIRECT_CHAT_DOCUMENT_BYTES + 1,
        };
        const message = createPrivateMessage("oversize metadata", [oversized], 1);
        const payload = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(bob, alice, message),
        );
        await bobClient.publishEvent(
            createRelayEvent(bob, pairwiseTopic(alice, bob), payload, {
                list: [
                    {
                        op: "append",
                        id: privateMessageListElementId(bob, message),
                        bytes: payload,
                    },
                ],
            }),
        );

        const received = await aliceChat.sync();
        const descriptor =
            received.status === "events" ? received.opened[0]?.message.attachments[0] : undefined;
        expect(descriptor).toBeDefined();
        expect(aliceChat.attachmentPolicy(descriptor!)).toMatchObject({
            status: "blocked",
            reason: "document-too-large",
        });
        await expect(aliceChat.fetchAttachment(descriptor!)).rejects.toBeInstanceOf(
            DirectChatAttachmentPolicyError,
        );

        const encrypted = encryptFile(utf8Encode("authentic"), {
            name: "tamper.txt",
            mediaType: "text/plain",
        });
        relay.blobs.set(encrypted.blob.id, {
            id: encrypted.blob.id,
            bytes: utf8Encode("tampered"),
        });
        await expect(aliceChat.fetchAttachment(encrypted.descriptor)).rejects.toBeInstanceOf(
            DirectChatAttachmentIntegrityError,
        );
    });

    it("retries an ambiguously accepted blob idempotently before publishing its event", async () => {
        const relay = new ChatTransport("relay");
        relay.loseNextBlobResponse = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const id = "M".repeat(32);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);

        await expect(
            aliceChat.sendMessage(
                bob,
                {
                    text: "ambiguous blob",
                    attachments: [
                        {
                            name: "note.txt",
                            mediaType: "text/plain",
                            bytes: utf8Encode("once"),
                        },
                    ],
                },
                { id, sentAt: 60 },
            ),
        ).rejects.toThrow("lost its accepted blob response");
        expect(relay.blobs).toHaveLength(1);
        expect(relay.events.size).toBe(0);

        const restarted = chat(alice, aliceStore, friends.left, [relay]);
        expect((await restarted.retryPending()).failures).toEqual([]);
        expect(relay.blobs).toHaveLength(1);
        expect(relay.operations.filter((operation) => operation.startsWith("blob:"))).toHaveLength(
            2,
        );
        expect(relay.operations.slice(-1)[0]).toMatch(/^event:/);
    });

    it("keeps a corrupt attachment outbox poisoned without exposing its event", async () => {
        const relay = new ChatTransport("relay");
        relay.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);

        await expect(
            aliceChat.sendMessage(bob, {
                text: "poison",
                attachments: [
                    {
                        name: "note.txt",
                        mediaType: "text/plain",
                        bytes: utf8Encode("durable"),
                    },
                ],
            }),
        ).rejects.toThrow("offline");
        const blobs = await aliceStore.list("direct-chat/v2/outbox-blob/");
        const blobKey = [...blobs.keys()][0];
        if (blobKey === undefined) {
            throw new Error("Expected retained direct-chat blob");
        }
        await aliceStore.set(blobKey, utf8Encode("corrupt"));
        relay.offline = false;

        const report = await aliceChat.retryPending();
        expect(report.failures[0]?.message).toContain("failed validation");
        expect(relay.events.size).toBe(0);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(1);
    });

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
        relay.enforceFreshness = true;
        relay.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const id = "C".repeat(32);
        let now = 1_000;
        const aliceChat = chat(alice, aliceStore, friends.left, [relay], callbacks(), () => now);

        await expect(
            aliceChat.sendText(bob, "survive restart", { id, sentAt: 30 }),
        ).rejects.toThrow("rejected");
        expect(await aliceStore.list("application/outgoing/")).toHaveLength(1);
        now += 6 * 60 * 1_000;
        relay.now = now;
        relay.offline = false;

        const restarted = chat(alice, aliceStore, friends.left, [relay], callbacks(), () => now);
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

    it("retains partial multi-relay sends until a fresh event reaches every relay", async () => {
        const first = new ChatTransport("first");
        const second = new ChatTransport("second");
        first.enforceFreshness = true;
        second.enforceFreshness = true;
        second.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        let now = 1_000;
        const aliceChat = chat(
            alice,
            aliceStore,
            friends.left,
            [first, second],
            callbacks(),
            () => now,
        );

        await aliceChat.sendText(bob, "both relays", {
            id: "H".repeat(32),
            sentAt: 8,
        });
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(1);
        expect(await aliceStore.list("application/published/")).toHaveLength(1);

        now += 6 * 60 * 1_000;
        first.now = now;
        second.now = now;
        second.offline = false;
        expect((await aliceChat.retryPending()).failures).toEqual([]);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(0);
        expect(first.events.get(pairwiseTopic(alice, bob))).toHaveLength(1);
        expect(second.events.get(pairwiseTopic(alice, bob))).toHaveLength(1);

        const bobChat = chat(bob, bobStore, friends.right, [first, second], callbacks(), () => now);
        const synced = await bobChat.sync();
        expect(synced.status === "events" ? synced.opened : []).toHaveLength(1);
        expect(await bobStore.list("application/incoming/")).toHaveLength(1);
    });

    it("recovers an ambiguous accepted receipt before refreshing a stale event", async () => {
        const relay = new ChatTransport("relay");
        relay.enforceFreshness = true;
        relay.loseNextResponse = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        let now = 1_000;
        const aliceChat = chat(alice, aliceStore, friends.left, [relay], callbacks(), () => now);

        await expect(
            aliceChat.sendText(bob, "ambiguous", {
                id: "J".repeat(32),
                sentAt: 10,
            }),
        ).rejects.toThrow("rejected");
        now += 6 * 60 * 1_000;
        relay.now = now;

        expect((await aliceChat.retryPending()).failures).toEqual([]);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(0);
        expect(relay.events.get(pairwiseTopic(alice, bob))).toHaveLength(1);
    });

    it("keeps refreshing an unaccepted event across multiple offline windows", async () => {
        const relay = new ChatTransport("relay");
        relay.enforceFreshness = true;
        relay.offline = true;
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        let now = 1_000;
        const aliceChat = chat(alice, aliceStore, friends.left, [relay], callbacks(), () => now);

        await expect(
            aliceChat.sendText(bob, "long offline", {
                id: "K".repeat(32),
                sentAt: 11,
            }),
        ).rejects.toThrow("rejected");
        for (let window = 0; window < 2; window += 1) {
            now += 6 * 60 * 1_000;
            relay.now = now;
            expect((await aliceChat.retryPending()).failures).toHaveLength(1);
        }
        relay.offline = false;
        expect((await aliceChat.retryPending()).failures).toEqual([]);
        expect(await aliceStore.list("direct-chat/v1/outbox/")).toHaveLength(0);
        expect(relay.events.get(pairwiseTopic(alice, bob))).toHaveLength(1);
    });

    it("rejects text larger than the default relay list element before persistence", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const aliceChat = chat(alice, aliceStore, friends.left, [relay]);

        await expect(aliceChat.sendText(bob, "x".repeat(300_000))).rejects.toThrow(
            "list-element limit",
        );
        expect(await aliceStore.list("application/")).toHaveLength(0);
        expect(await aliceStore.list("direct-chat/v1/")).toHaveLength(0);
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

    it("opens the valid self copy when an earlier self-prefixed element is bogus", async () => {
        const relay = new ChatTransport("relay");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const friends = await addFriends(alice, aliceStore, bob, bobStore);
        const message = createPrivateMessage("recover self", [], 9, "I".repeat(32));
        const recipientBytes = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(alice, bob, message),
        );
        const selfBytes = encodeEncryptedPrivateMessage(
            encryptPrivateMessageForContact(alice, alice, message),
        );
        const client = new MurmurClient({
            identity: alice,
            store: aliceStore,
            transports: [relay],
        });
        await client.publishEvent(
            createRelayEvent(alice, pairwiseTopic(alice, bob), recipientBytes, {
                list: [
                    {
                        op: "append",
                        id: "self-message:bogus",
                        bytes: utf8Encode("bogus"),
                    },
                    {
                        op: "append",
                        id: privateMessageSelfListElementId(alice, bob, message),
                        bytes: selfBytes,
                    },
                ],
            }),
        );

        const result = await chat(alice, aliceStore, friends.left, [relay]).sync();
        expect(
            result.status === "events"
                ? result.opened.map((value) => [value.direction, value.message.text])
                : [],
        ).toEqual([["outgoing", "recover self"]]);
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
