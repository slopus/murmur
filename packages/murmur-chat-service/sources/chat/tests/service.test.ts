import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import { MemoryMurmurStore, Murmur, type MurmurStore, type RelayFetch } from "@slopus/murmur";
import { afterEach, describe, expect, it } from "vitest";
import { ChatFrameTooLargeError } from "../errors.js";
import { ChatService } from "../index.js";
import type { AttachmentSource } from "../types.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function inProcessFetch(relay: RelayService): RelayFetch {
    const handler = createRelayFetchHandler(relay);
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function convergeMurmur(peers: readonly Murmur[], rounds: number = 8): Promise<void> {
    for (let round = 0; round < rounds; round += 1) {
        for (const peer of peers) await peer.sync();
    }
}

async function makeFriends(owner: Murmur, peer: Murmur): Promise<void> {
    await owner.friends.request(peer.identityKey);
    await convergeMurmur([owner, peer], 2);
    await peer.friends.accept(owner.identityKey);
    await convergeMurmur([peer, owner], 6);
}

function openChat(murmur: Murmur, store: MurmurStore): Promise<ChatService<string, string>> {
    return ChatService.open({
        murmur,
        store,
        blobStore: new (class {
            readonly values = new Map<string, Uint8Array>();
            async put(
                blobId: Uint8Array,
                _byteLength: number,
                bytes: AsyncIterable<Uint8Array>,
                _signal: AbortSignal,
            ): Promise<void> {
                const chunks: Uint8Array[] = [];
                for await (const chunk of bytes) chunks.push(chunk);
                const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
                const result = new Uint8Array(length);
                let offset = 0;
                for (const chunk of chunks) {
                    result.set(chunk, offset);
                    offset += chunk.length;
                }
                this.values.set(key(blobId), result);
            }
            async head(
                blobId: Uint8Array,
                _signal: AbortSignal,
            ): Promise<{ byteLength: number } | undefined> {
                const bytes = this.values.get(key(blobId));
                return bytes === undefined ? undefined : { byteLength: bytes.length };
            }
            async get(
                blobId: Uint8Array,
                offset: number,
                byteLength: number,
                _signal: AbortSignal,
            ): Promise<Uint8Array> {
                const bytes = this.values.get(key(blobId));
                if (bytes === undefined) throw new Error("missing");
                return bytes.slice(offset, offset + byteLength);
            }
        })(),
        encodeMessage: (message) => textEncoder.encode(message),
        decodeMessage: (bytes) => textDecoder.decode(bytes),
        encodeAttachmentMetadata: (metadata) => textEncoder.encode(metadata),
        decodeAttachmentMetadata: (bytes) => textDecoder.decode(bytes),
        resolveAttachmentSource: async (sourceId): Promise<AttachmentSource> => {
            throw new Error(`Unexpected source ${sourceId}`);
        },
        idlePollMilliseconds: 30_000,
    });
}

function key(bytes: Uint8Array): string {
    return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

describe("ChatService", () => {
    const closers: (() => Promise<void>)[] = [];

    afterEach(async () => {
        for (const close of closers.reverse()) await close();
        closers.length = 0;
    });

    async function openPeers(count: number): Promise<{
        relay: RelayService;
        murmurs: Murmur[];
        stores: MemoryMurmurStore[];
        chats: ChatService<string, string>[];
    }> {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        closers.push(async () => relay.close());
        const fetch = inProcessFetch(relay);
        const stores: MemoryMurmurStore[] = [];
        const murmurs: Murmur[] = [];
        const chats: ChatService<string, string>[] = [];
        for (let index = 0; index < count; index += 1) {
            const store = new MemoryMurmurStore();
            const murmur = await Murmur.open({
                relay: "https://relay.test",
                store,
                initialProfile: { name: `Peer ${index}` },
                fetch,
            });
            const chat = await openChat(murmur, store);
            stores.push(store);
            murmurs.push(murmur);
            chats.push(chat);
        }
        closers.push(async () => {
            for (const chat of chats) await chat.close();
            for (const murmur of murmurs) await murmur.close();
        });
        return { relay, murmurs, stores, chats };
    }

    it("roundtrips typed messages in relay order and converges concurrent sends", async () => {
        const { murmurs, chats } = await openPeers(3);
        const [alice, bob, carol] = murmurs;
        const [aliceChat, bobChat, carolChat] = chats;
        await makeFriends(alice!, bob!);
        await makeFriends(alice!, carol!);
        const conversationId = await aliceChat!.createConversation([
            bob!.identityKey,
            carol!.identityKey,
        ]);
        await convergeMurmur(murmurs, 12);

        await Promise.all([
            aliceChat!.send(conversationId, { message: "from Alice" }),
            bobChat!.send(conversationId, { message: "from Bob" }),
            carolChat!.send(conversationId, { message: "from Carol" }),
        ]);
        for (let round = 0; round < 8; round += 1) {
            for (const chat of chats) await chat.sync();
        }
        const histories = await Promise.all(chats.map((chat) => chat.history(conversationId)));
        expect(
            histories.map((history) => history.messages.map((message) => message.message)),
        ).toEqual(
            Array.from({ length: 3 }, () =>
                histories[0]!.messages.map((message) => message.message),
            ),
        );
        expect(histories[0]!.messages).toHaveLength(3);
        expect(histories[0]!.messages.map((message) => message.sequence)).toEqual(
            histories[0]!.messages.map((message) => message.sequence).sort(),
        );
        for (const chat of chats) expect(await chat.outbox()).toEqual([]);
    }, 90_000);

    it("rebuilds projection from Murmur events after cache deletion", async () => {
        const { murmurs, stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.send(conversationId, { message: "rebuild me" });
        await chats[0]!.sync();
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);
        await chats[0]!.close();

        const cache = await stores[0]!.list("chat/v1/");
        for (const keyName of cache.keys()) {
            if (!keyName.startsWith("chat/v1/outbox/")) await stores[0]!.delete(keyName);
        }
        const reopened = await openChat(murmurs[0]!, stores[0]!);
        chats[0] = reopened;
        await reopened.sync();
        expect((await reopened.history(conversationId)).messages[0]?.message).toBe("rebuild me");
    }, 30_000);

    it("recovers exact outbox state and projects ambiguous handoff duplicates once", async () => {
        const { murmurs, stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.send(conversationId, { message: "crash boundary" });
        await chats[0]!.close();
        const pending = await stores[0]!.list("chat/v1/outbox/");
        expect(pending.size).toBe(1);
        const [outboxKey, outboxValue] = [...pending][0]!;

        chats[0] = await openChat(murmurs[0]!, stores[0]!);
        await chats[0]!.sync();
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);

        await chats[0]!.close();
        await stores[0]!.set(outboxKey, outboxValue);
        chats[0] = await openChat(murmurs[0]!, stores[0]!);
        await chats[0]!.sync();
        expect((await murmurs[0]!.groups.get(conversationId, { limit: 10 }))?.events).toHaveLength(
            2,
        );
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);
        expect(await chats[0]!.outbox()).toEqual([]);
    }, 30_000);

    it("rejects oversized frames before leaving outbox residue", async () => {
        const { stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await expect(
            chats[0]!.send(conversationId, {
                message: "x".repeat(256 * 1024),
            }),
        ).rejects.toBeInstanceOf(ChatFrameTooLargeError);
        expect(await stores[0]!.list("chat/v1/outbox/")).toEqual(new Map());
    }, 30_000);

    it("recovers five hundred offline sends after restart without projection loss", async () => {
        const { murmurs, stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!);
        for (let index = 0; index < 500; index += 1) {
            await chats[0]!.send(conversationId, { message: `offline-${index}` });
        }
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!);
        await chats[0]!.sync();
        const messages = (await chats[0]!.history(conversationId, { limit: 1_000 })).messages;
        expect(messages).toHaveLength(500);
        expect(new Set(messages.map((message) => key(message.messageId))).size).toBe(500);
        expect(await chats[0]!.outbox()).toEqual([]);
    }, 120_000);

    it("ignores non-chat groups while Murmur continues syncing them", async () => {
        const { murmurs, chats } = await openPeers(1);
        const groupId = await murmurs[0]!.groups.create(textEncoder.encode("other protocol"));
        await murmurs[0]!.groups.send(groupId, new Uint8Array([1, 2, 3]));
        await chats[0]!.sync();
        expect(await chats[0]!.listConversations()).toEqual([]);
        expect((await murmurs[0]!.groups.get(groupId))?.events).toHaveLength(1);
    }, 30_000);

    it("does not give an added member old message history", async () => {
        const { murmurs, chats } = await openPeers(3);
        const [alice, bob, carol] = murmurs;
        const [aliceChat, bobChat, carolChat] = chats;
        await makeFriends(alice!, bob!);
        await makeFriends(alice!, carol!);
        const conversationId = await aliceChat!.createConversation([bob!.identityKey]);
        await convergeMurmur([alice!, bob!], 10);
        await aliceChat!.send(conversationId, { message: "before add" });
        for (let round = 0; round < 4; round += 1) {
            await aliceChat!.sync();
            await bobChat!.sync();
        }
        await aliceChat!.addMember(conversationId, carol!.identityKey);
        await convergeMurmur(murmurs, 12);
        await carolChat!.sync();
        expect((await carolChat!.history(conversationId)).messages).toEqual([]);
        await bobChat!.send(conversationId, { message: "after add" });
        for (let round = 0; round < 6; round += 1) {
            for (const chat of chats) await chat.sync();
        }
        expect(
            (await carolChat!.history(conversationId)).messages.map((entry) => entry.message),
        ).toEqual(["after add"]);
    }, 120_000);
});
