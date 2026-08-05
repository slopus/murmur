import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import {
    MemoryMurmurStore,
    Murmur,
    type MurmurStore,
    type RelayFetch,
    type StoreScanOptions,
    type StoreTransaction,
} from "@slopus/murmur";
import { afterEach, describe, expect, it } from "vitest";
import {
    ChatAlreadyOpenError,
    ChatClosedError,
    ChatFrameTooLargeError,
    ChatValidationError,
} from "../errors.js";
import { encodeFrame } from "../impl/codec.js";
import { decodeOutbox, encodeOutbox } from "../impl/codec.js";
import { ChatService, MemoryBlobStore, destroyAttachment } from "../index.js";
import type { AttachmentSource, BlobStore, ChatHistoryItem, ChatMessage } from "../types.js";

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

class TestSource implements AttachmentSource {
    readonly sourceId: string;
    bytes: Uint8Array;
    reads = 0;

    constructor(sourceId: string, bytes: Uint8Array) {
        this.sourceId = sourceId;
        this.bytes = bytes;
    }

    get byteLength(): number {
        return this.bytes.length;
    }

    async read(offset: number, byteLength: number, signal: AbortSignal): Promise<Uint8Array> {
        if (signal.aborted) throw signal.reason;
        this.reads += 1;
        return this.bytes.subarray(offset, offset + byteLength);
    }
}

class SwitchingSource implements AttachmentSource {
    readonly sourceId: string;
    readonly byteLength: number;
    readonly initial: Uint8Array;
    readonly changed: Uint8Array;
    reads = 0;

    constructor(sourceId: string, initial: Uint8Array, changed: Uint8Array) {
        this.sourceId = sourceId;
        this.initial = initial;
        this.changed = changed;
        this.byteLength = initial.length;
    }

    async read(offset: number, byteLength: number): Promise<Uint8Array> {
        this.reads += 1;
        const value = this.reads === 1 ? this.initial : this.changed;
        return value.subarray(offset, offset + byteLength);
    }
}

class OneFailureBlobStore implements BlobStore {
    readonly inner = new MemoryBlobStore();
    failures = 1;

    async put(
        blobId: Uint8Array,
        byteLength: number,
        bytes: AsyncIterable<Uint8Array>,
        signal: AbortSignal,
    ): Promise<void> {
        await this.inner.put(blobId, byteLength, bytes, signal);
        if (this.failures > 0) {
            this.failures -= 1;
            throw new Error("ambiguous upload response");
        }
    }

    head(blobId: Uint8Array, signal: AbortSignal): Promise<{ byteLength: number } | undefined> {
        return this.inner.head(blobId, signal);
    }

    get(
        blobId: Uint8Array,
        offset: number,
        byteLength: number,
        signal: AbortSignal,
    ): Promise<Uint8Array> {
        return this.inner.get(blobId, offset, byteLength, signal);
    }
}

class TimeoutThenBlobStore implements BlobStore {
    readonly inner = new MemoryBlobStore();
    attempts = 0;

    async put(
        blobId: Uint8Array,
        byteLength: number,
        bytes: AsyncIterable<Uint8Array>,
        signal: AbortSignal,
    ): Promise<void> {
        this.attempts += 1;
        if (this.attempts === 1) {
            await new Promise<void>((_resolve, reject) => {
                signal.addEventListener("abort", () => reject(signal.reason), { once: true });
            });
            return;
        }
        await this.inner.put(blobId, byteLength, bytes, signal);
    }

    head(blobId: Uint8Array, signal: AbortSignal): Promise<{ byteLength: number } | undefined> {
        return this.inner.head(blobId, signal);
    }

    get(
        blobId: Uint8Array,
        offset: number,
        byteLength: number,
        signal: AbortSignal,
    ): Promise<Uint8Array> {
        return this.inner.get(blobId, offset, byteLength, signal);
    }
}

class DelegatingStore implements MurmurStore {
    readonly inner: MurmurStore;

    constructor(inner: MurmurStore) {
        this.inner = inner;
    }

    get(key: string): Promise<Uint8Array | undefined> {
        return this.inner.get(key);
    }
    set(key: string, value: Uint8Array): Promise<void> {
        return this.inner.set(key, value);
    }
    delete(key: string): Promise<void> {
        return this.inner.delete(key);
    }
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.inner.list(prefix);
    }
    scan(prefix: string, options: StoreScanOptions): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.inner.scan(prefix, options);
    }
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.inner.transaction(operation);
    }
}

class ReplayTransactionStore extends DelegatingStore {
    replayNext = false;

    override transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        if (!this.replayNext) return this.inner.transaction(operation);
        this.replayNext = false;
        return this.inner.transaction(async (transaction) => {
            const snapshot = await transaction.list("");
            await operation(transaction);
            const changed = await transaction.list("");
            for (const key of changed.keys()) await transaction.delete(key);
            for (const [key, value] of snapshot) await transaction.set(key, value);
            return operation(transaction);
        });
    }
}

class ProjectionFailureStore extends DelegatingStore {
    failProjection = false;

    override transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.inner.transaction((transaction) =>
            operation({
                ...transaction,
                set: async (key, value): Promise<void> => {
                    if (this.failProjection && key.startsWith("chat/v1/projection/")) {
                        throw new Error("injected projection quota failure");
                    }
                    await transaction.set(key, value);
                },
            }),
        );
    }
}

function openChat(
    murmur: Murmur,
    store: MurmurStore,
    configuration: {
        readonly blobStore?: BlobStore;
        readonly sources?: ReadonlyMap<string, AttachmentSource>;
        readonly operationTimeoutMilliseconds?: number;
        readonly sourceTimeoutMilliseconds?: number;
        readonly networkTimeoutMilliseconds?: number;
        readonly rejectDecodedMessages?: boolean;
    } = {},
): Promise<ChatService<string, string>> {
    return ChatService.open({
        murmur,
        store,
        blobStore: configuration.blobStore ?? new MemoryBlobStore(),
        encodeMessage: (message) => textEncoder.encode(message),
        decodeMessage: (bytes) => {
            if (configuration.rejectDecodedMessages === true) {
                throw new Error("new codec rejects old frame");
            }
            return textDecoder.decode(bytes);
        },
        encodeAttachmentMetadata: (metadata) => textEncoder.encode(metadata),
        decodeAttachmentMetadata: (bytes) => textDecoder.decode(bytes),
        resolveAttachmentSource: async (sourceId): Promise<AttachmentSource> => {
            const source = configuration.sources?.get(sourceId);
            if (source === undefined) throw new Error(`Unexpected source ${sourceId}`);
            return source;
        },
        idlePollMilliseconds: 30_000,
        ...(configuration.operationTimeoutMilliseconds === undefined
            ? {}
            : { operationTimeoutMilliseconds: configuration.operationTimeoutMilliseconds }),
        ...(configuration.sourceTimeoutMilliseconds === undefined
            ? {}
            : { sourceTimeoutMilliseconds: configuration.sourceTimeoutMilliseconds }),
        ...(configuration.networkTimeoutMilliseconds === undefined
            ? {}
            : { networkTimeoutMilliseconds: configuration.networkTimeoutMilliseconds }),
    });
}

function key(bytes: Uint8Array): string {
    return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function known(
    items: readonly ChatHistoryItem<string, string>[],
): readonly ChatMessage<string, string>[] {
    return items.filter((item): item is ChatMessage<string, string> => item.kind === "message");
}

describe("ChatService", () => {
    const closers: (() => Promise<void>)[] = [];

    afterEach(async () => {
        for (const close of closers.reverse()) await close();
        closers.length = 0;
    });

    async function openPeers(
        count: number,
        blobStore: BlobStore = new MemoryBlobStore(),
        suppliedStores?: readonly MurmurStore[],
    ): Promise<{
        relay: RelayService;
        murmurs: Murmur[];
        stores: MurmurStore[];
        chats: ChatService<string, string>[];
        blobStore: BlobStore;
        sources: Map<string, AttachmentSource>;
    }> {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        closers.push(async () => relay.close());
        const fetch = inProcessFetch(relay);
        const stores: MurmurStore[] = [];
        const murmurs: Murmur[] = [];
        const chats: ChatService<string, string>[] = [];
        const sources = new Map<string, AttachmentSource>();
        for (let index = 0; index < count; index += 1) {
            const store = suppliedStores?.[index] ?? new MemoryMurmurStore();
            const murmur = await Murmur.open({
                relay: "https://relay.test",
                store,
                initialProfile: { name: `Peer ${index}` },
                fetch,
            });
            const chat = await openChat(murmur, store, { blobStore, sources });
            stores.push(store);
            murmurs.push(murmur);
            chats.push(chat);
        }
        closers.push(async () => {
            for (const chat of chats) await chat.close();
            for (const murmur of murmurs) await murmur.close();
        });
        return { relay, murmurs, stores, chats, blobStore, sources };
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
            histories.map((history) => known(history.messages).map((message) => message.message)),
        ).toEqual(
            Array.from({ length: 3 }, () =>
                known(histories[0]!.messages).map((message) => message.message),
            ),
        );
        expect(histories[0]!.messages).toHaveLength(3);
        expect(histories[0]!.messages.map((message) => message.sequence)).toEqual(
            histories[0]!.messages.map((message) => message.sequence).sort(),
        );
        for (const chat of chats) expect((await chat.outbox()).entries).toEqual([]);
    }, 90_000);

    it("rebuilds projection with surviving cursor/dedupe and resumes marked resets", async () => {
        const { stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.send(conversationId, { message: "rebuild me" });
        await chats[0]!.sync();
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);

        let projection = await stores[0]!.list("chat/v1/projection/");
        const projectionKey = [...projection.keys()][0]!;
        const projectionPrefix = projectionKey.slice(0, projectionKey.lastIndexOf("/") + 1);
        await stores[0]!.set(`${projectionPrefix}!`, new Uint8Array([7]));
        expect((await chats[0]!.history(conversationId)).messages[0]?.kind).toBe("unknown");
        await chats[0]!.sync();
        await stores[0]!.set(projectionKey, new Uint8Array([1, 2, 3]));
        expect((await chats[0]!.history(conversationId)).messages[0]?.kind).toBe("unknown");
        await chats[0]!.sync();
        expect(known((await chats[0]!.history(conversationId)).messages)[0]?.message).toBe(
            "rebuild me",
        );

        projection = await stores[0]!.list("chat/v1/projection/");
        for (const keyName of projection.keys()) await stores[0]!.delete(keyName);
        await chats[0]!.sync();
        expect(known((await chats[0]!.history(conversationId)).messages)[0]?.message).toBe(
            "rebuild me",
        );

        for (const keyName of (await stores[0]!.list("chat/v1/projection/")).keys()) {
            await stores[0]!.delete(keyName);
        }
        for (const keyName of (await stores[0]!.list("chat/v1/cursor/")).keys()) {
            await stores[0]!.delete(keyName);
        }
        expect((await stores[0]!.list("chat/v1/dedupe/")).size).toBeGreaterThan(0);
        await chats[0]!.sync();
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);

        await chats[0]!.rebuild(conversationId);
        expect((await chats[0]!.history(conversationId)).messages).toHaveLength(1);
        expect((await stores[0]!.list("chat/v1/delivered/")).size).toBe(0);
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
        expect((await chats[0]!.outbox()).entries).toEqual([]);
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
        const pending: bigint[] = [];
        let outboxAfter: string | undefined;
        for (;;) {
            const page = await chats[0]!.outbox({
                ...(outboxAfter === undefined ? {} : { after: outboxAfter }),
                limit: 100,
            });
            pending.push(...page.entries.map((entry) => entry.enqueueSequence));
            if (page.nextAfter === undefined) break;
            outboxAfter = page.nextAfter;
        }
        expect(pending).toEqual(Array.from({ length: 500 }, (_unused, index) => BigInt(index + 1)));
        await chats[0]!.sync();
        const messages: ChatMessage<string, string>[] = [];
        let after: bigint | undefined;
        for (;;) {
            const page = await chats[0]!.history(conversationId, {
                ...(after === undefined ? {} : { after }),
                limit: 100,
            });
            messages.push(...known(page.messages));
            if (page.nextAfter === undefined) break;
            after = page.nextAfter;
        }
        expect(messages).toHaveLength(500);
        expect(new Set(messages.map((message) => key(message.messageId))).size).toBe(500);
        expect(messages.map((message) => message.message)).toEqual(
            Array.from({ length: 500 }, (_unused, index) => `offline-${index}`),
        );
        expect((await chats[0]!.outbox()).entries).toEqual([]);
    }, 120_000);

    it("survives a replayed send transaction without zeroing attachment intent secrets", async () => {
        const base = new MemoryMurmurStore();
        const replay = new ReplayTransactionStore(base);
        const blobs = new MemoryBlobStore();
        const { murmurs, chats, sources } = await openPeers(1, blobs, [replay]);
        const conversationId = await chats[0]!.createConversation();
        const source = new TestSource("replayed", new Uint8Array(20_000).fill(6));
        sources.set(source.sourceId, source);
        replay.replayNext = true;
        await chats[0]!.send(conversationId, {
            message: "replayed transaction",
            attachments: [{ sourceId: source.sourceId, metadata: "replayed" }],
        });
        await chats[0]!.close();
        const persisted = [...(await base.list("chat/v1/outbox/")).values()];
        expect(persisted).toHaveLength(1);
        const record = decodeOutbox(persisted[0]!);
        expect(record.attachments[0]!.fileId.some((value) => value !== 0)).toBe(true);
        expect(record.attachments[0]!.fileKey.some((value) => value !== 0)).toBe(true);
        expect(record.attachments[0]!.sourceHash.some((value) => value !== 0)).toBe(true);
        record.attachments[0]!.fileId.fill(0);
        record.attachments[0]!.fileKey.fill(0);
        record.attachments[0]!.sourceHash.fill(0);

        chats[0] = await openChat(murmurs[0]!, replay, { blobStore: blobs, sources });
        await chats[0]!.sync();
        const message = known((await chats[0]!.history(conversationId)).messages)[0]!;
        expect(await chats[0]!.downloadAttachment(message.attachments[0]!)).toEqual(source.bytes);
    }, 30_000);

    it("repairs a corrupt enqueue counter from retained outbox order", async () => {
        const { murmurs, stores, chats, blobStore, sources } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.send(conversationId, { message: "first retained" });
        const retained = await stores[0]!.list("chat/v1/outbox/");
        await chats[0]!.close();
        for (const [key, value] of retained) await stores[0]!.set(key, value);
        await stores[0]!.set("chat/v1/meta/enqueue-sequence", new Uint8Array([255]));
        chats[0] = await openChat(murmurs[0]!, stores[0]!, { blobStore, sources });
        await chats[0]!.send(conversationId, { message: "second retained" });
        const page = await chats[0]!.outbox({ limit: 10 });
        expect(page.entries.map((entry) => entry.enqueueSequence)).toEqual([1n, 2n]);
    }, 30_000);

    it("surfaces projection storage failure and retries the atomic cursor fold", async () => {
        const base = new MemoryMurmurStore();
        const failureStore = new ProjectionFailureStore(base);
        const { murmurs, chats } = await openPeers(1, new MemoryBlobStore(), [failureStore]);
        const conversationId = await chats[0]!.createConversation();
        await murmurs[0]!.groups.send(
            conversationId,
            encodeFrame({
                messageId: new Uint8Array(16).fill(10),
                claimedAt: 10,
                body: textEncoder.encode("quota retry"),
                attachments: [],
            }),
        );
        const changes: string[] = [];
        chats[0]!.onChange((change) => changes.push(change.kind));
        failureStore.failProjection = true;
        await expect(chats[0]!.sync()).rejects.toThrow("injected projection quota failure");
        expect(chats[0]!.convergenceError?.message).toContain("projection quota");
        expect(changes).toContain("error");
        expect((await base.list("chat/v1/cursor/")).size).toBe(0);
        failureStore.failProjection = false;
        await chats[0]!.sync();
        expect(known((await chats[0]!.history(conversationId)).messages)[0]?.message).toBe(
            "quota retry",
        );
    }, 30_000);

    it("pages and removes orphan staging across a 100 MiB-equivalent chunk set", async () => {
        const { murmurs, stores, chats, blobStore, sources } = await openPeers(1);
        await chats[0]!.close();
        for (let index = 0; index < 400; index += 1) {
            await stores[0]!.set(
                `chat/v1/staging/${"f".repeat(16)}/${"A".repeat(22)}/00/${index
                    .toString(16)
                    .padStart(8, "0")}`,
                new Uint8Array([index & 0xff]),
            );
        }
        chats[0] = await openChat(murmurs[0]!, stores[0]!, { blobStore, sources });
        expect((await stores[0]!.list("chat/v1/staging/")).size).toBe(0);
    }, 30_000);

    it("collects staged residue after a crash with an uploaded durable marker", async () => {
        const blobs = new OneFailureBlobStore();
        const { murmurs, stores, chats, sources } = await openPeers(1, blobs);
        const conversationId = await chats[0]!.createConversation();
        const source = new TestSource("uploaded-marker", new Uint8Array(1024 * 1024).fill(18));
        sources.set(source.sourceId, source);
        await chats[0]!.send(conversationId, {
            message: "uploaded marker",
            attachments: [{ sourceId: source.sourceId, metadata: "residue" }],
        });
        await chats[0]!.sync();
        expect((await stores[0]!.list("chat/v1/staging/")).size).toBeGreaterThan(0);
        await chats[0]!.close();

        const [outboxKey, encoded] = [...(await stores[0]!.list("chat/v1/outbox/"))][0]!;
        const record = decodeOutbox(encoded);
        record.attachments[0]!.stageState = "uploaded";
        const uploaded = encodeOutbox(record);
        await stores[0]!.set(outboxKey, uploaded);
        uploaded.fill(0);
        record.attachments[0]!.fileId.fill(0);
        record.attachments[0]!.fileKey.fill(0);
        record.attachments[0]!.sourceHash.fill(0);

        chats[0] = await openChat(murmurs[0]!, stores[0]!, {
            blobStore: blobs,
            sources,
        });
        expect((await stores[0]!.list("chat/v1/staging/")).size).toBe(0);
    }, 30_000);

    it("runs the public attachment send/upload/history/download path including empty files", async () => {
        const sharedBlobs = new MemoryBlobStore();
        const { murmurs, chats, sources } = await openPeers(2, sharedBlobs);
        await makeFriends(murmurs[0]!, murmurs[1]!);
        const conversationId = await chats[0]!.createConversation([murmurs[1]!.identityKey]);
        await convergeMurmur(murmurs, 10);
        const source = new TestSource("document", textEncoder.encode("secret document"));
        const empty = new TestSource("empty", new Uint8Array());
        sources.set(source.sourceId, source);
        sources.set(empty.sourceId, empty);
        await chats[0]!.send(conversationId, {
            message: "with files",
            attachments: [
                { sourceId: source.sourceId, metadata: "document" },
                { sourceId: empty.sourceId, metadata: "empty" },
            ],
        });
        for (let round = 0; round < 5; round += 1) {
            for (const chat of chats) await chat.sync();
        }
        const received = known((await chats[1]!.history(conversationId)).messages)[0]!;
        const streamed: Uint8Array[] = [];
        for await (const chunk of chats[1]!.openAttachment(received.attachments[0]!)) {
            streamed.push(chunk);
        }
        expect(streamed).toHaveLength(1);
        expect(streamed[0]).toEqual(source.bytes);
        expect(await chats[1]!.downloadAttachment(received.attachments[0]!)).toEqual(source.bytes);
        expect(await chats[1]!.downloadAttachment(received.attachments[1]!)).toEqual(
            new Uint8Array(),
        );
        expect(received.attachments[1]!.chunkCount).toBe(1);
        expect(
            (await sharedBlobs.head(received.attachments[1]!.blobId, new AbortController().signal))
                ?.byteLength,
        ).toBe(16);
        const caller = new AbortController();
        const held = chats[1]!
            .openAttachment(received.attachments[0]!, {
                signal: caller.signal,
            })
            [Symbol.asyncIterator]();
        expect((await held.next()).done).toBe(false);
        await chats[1]!.close();
        expect((await held.next()).done).toBe(true);
        await expect(chats[1]!.listConversations()).rejects.toBeInstanceOf(ChatClosedError);
        destroyAttachment(received.attachments[0]!);
        expect(received.attachments[0]!.fileKey.every((value) => value === 0)).toBe(true);
    }, 90_000);

    it("persists upload failure, lets unrelated traffic converge, and retries exact staging", async () => {
        const blobs = new OneFailureBlobStore();
        const { murmurs, stores, chats, sources } = await openPeers(2, blobs);
        await makeFriends(murmurs[0]!, murmurs[1]!);
        const conversationId = await chats[0]!.createConversation([murmurs[1]!.identityKey]);
        await convergeMurmur(murmurs, 10);
        const source = new TestSource("flaky", new Uint8Array(70_000).fill(4));
        sources.set(source.sourceId, source);
        const failedId = await chats[0]!.send(conversationId, {
            message: "attachment eventually",
            attachments: [{ sourceId: source.sourceId, metadata: "binary" }],
        });
        await chats[0]!.sync();
        expect((await chats[0]!.outbox()).entries[0]).toMatchObject({
            status: "failed",
            lastError: { code: "operation-failed" },
        });

        await chats[0]!.send(conversationId, { message: "unrelated" });
        for (let round = 0; round < 4; round += 1) {
            for (const chat of chats) await chat.sync();
        }
        expect(
            known((await chats[1]!.history(conversationId)).messages).map(
                (message) => message.message,
            ),
        ).toEqual(["unrelated"]);

        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!, {
            blobStore: blobs,
            sources,
        });
        expect((await chats[0]!.outbox()).entries[0]?.lastError?.message).toContain(
            "ambiguous upload",
        );
        await chats[0]!.retry(failedId);
        for (let round = 0; round < 4; round += 1) {
            for (const chat of chats) await chat.sync();
        }
        const messages = known((await chats[1]!.history(conversationId)).messages);
        expect(messages.map((message) => message.message)).toEqual([
            "unrelated",
            "attachment eventually",
        ]);
        expect(await chats[1]!.downloadAttachment(messages[1]!.attachments[0]!)).toEqual(
            source.bytes,
        );
    }, 90_000);

    it("terminally isolates a changed source until explicit fresh-key retry", async () => {
        const { murmurs, stores, chats, sources, blobStore } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        const source = new SwitchingSource(
            "mutable",
            new Uint8Array(10).fill(1),
            new Uint8Array(10).fill(2),
        );
        sources.set(source.sourceId, source);
        const messageId = await chats[0]!.send(conversationId, {
            message: "mutable attachment",
            attachments: [{ sourceId: source.sourceId, metadata: "mutable" }],
        });
        await chats[0]!.sync();
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!, { sources, blobStore });
        expect((await chats[0]!.outbox()).entries[0]?.lastError?.code).toBe("source-changed");
        await chats[0]!.retry(messageId);
        await chats[0]!.sync();
        expect((await chats[0]!.outbox()).entries).toEqual([]);
        const attachment = known((await chats[0]!.history(conversationId)).messages)[0]!
            .attachments[0]!;
        expect(await chats[0]!.downloadAttachment(attachment)).toEqual(source.changed);
    }, 30_000);

    it("isolates corrupt durable records and ignores future namespace keys", async () => {
        const { murmurs, stores, chats, blobStore, sources } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await stores[0]!.set("chat/v1/outbox/ffffffffffffffff/corrupt", new Uint8Array([1, 2, 3]));
        await stores[0]!.set("chat/v1/future/record", new Uint8Array([9]));
        await chats[0]!.send(conversationId, { message: "still converges" });
        await chats[0]!.sync();
        expect(known((await chats[0]!.history(conversationId)).messages)[0]?.message).toBe(
            "still converges",
        );
        expect(await stores[0]!.get("chat/v1/outbox/ffffffffffffffff/corrupt")).toBeUndefined();
        expect((await stores[0]!.list("chat/v1/diagnostics/outbox/")).size).toBe(1);
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!, { blobStore, sources });
        expect(await stores[0]!.get("chat/v1/future/record")).toEqual(new Uint8Array([9]));
    }, 30_000);

    it("uses sequence event identity while applying the exact retry dedupe rule", async () => {
        const { murmurs, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        const messageId = new Uint8Array(16).fill(7);
        const identical = encodeFrame({
            messageId,
            claimedAt: 1,
            body: textEncoder.encode("same"),
            attachments: [],
        });
        const changed = encodeFrame({
            messageId,
            claimedAt: 1,
            body: textEncoder.encode("different"),
            attachments: [],
        });
        await murmurs[0]!.groups.send(conversationId, identical);
        await murmurs[0]!.groups.send(conversationId, identical);
        await murmurs[0]!.groups.send(conversationId, changed);
        await chats[0]!.sync();
        const messages = known((await chats[0]!.history(conversationId)).messages);
        expect(messages.map((message) => message.message)).toEqual(["same", "different"]);
        expect(new Set(messages.map((message) => message.eventId)).size).toBe(2);
        expect(messages[0]!.messageId).toEqual(messages[1]!.messageId);
    }, 30_000);

    it("quarantines malformed chat frames, advances, and emits later changes", async () => {
        const { murmurs, stores, chats } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        const changes: string[] = [];
        const unsubscribe = chats[0]!.onChange((change) => changes.push(change.kind));
        await murmurs[0]!.groups.send(conversationId, new Uint8Array([1, 2, 3]));
        await murmurs[0]!.groups.send(
            conversationId,
            encodeFrame({
                messageId: new Uint8Array(16).fill(8),
                claimedAt: 2,
                body: textEncoder.encode("after malformed"),
                attachments: [],
            }),
        );
        await chats[0]!.sync();
        expect(
            known((await chats[0]!.history(conversationId)).messages).map(
                (message) => message.message,
            ),
        ).toEqual(["after malformed"]);
        expect((await stores[0]!.list("chat/v1/quarantine/")).size).toBe(1);
        expect(changes).toContain("message");
        unsubscribe();
    }, 30_000);

    it("detects duplicate instances and guards direct runtime construction", async () => {
        const { murmurs, stores, chats } = await openPeers(1);
        await expect(openChat(murmurs[0]!, stores[0]!)).rejects.toBeInstanceOf(
            ChatAlreadyOpenError,
        );
        await expect(openChat(murmurs[0]!, new DelegatingStore(stores[0]!))).rejects.toBeInstanceOf(
            ChatAlreadyOpenError,
        );
        expect(() => Reflect.construct(ChatService, [])).toThrow(ChatValidationError);
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!);
    });

    it("times out a stalled blob without blocking reads and close cancellation", async () => {
        const { murmurs, stores, chats, sources } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.close();
        const source = new TestSource("stall", new Uint8Array(100).fill(2));
        sources.set(source.sourceId, source);
        const stalled: BlobStore = {
            put: async () => new Promise<void>(() => undefined),
            head: async () => undefined,
            get: async () => new Promise<Uint8Array>(() => undefined),
        };
        chats[0] = await openChat(murmurs[0]!, stores[0]!, {
            blobStore: stalled,
            sources,
            operationTimeoutMilliseconds: 25,
        });
        const stalledId = await chats[0]!.send(conversationId, {
            message: "will timeout",
            attachments: [{ sourceId: source.sourceId, metadata: "stall" }],
        });
        const syncing = chats[0]!.sync();
        const readable = await Promise.race([
            chats[0]!.listConversations().then(() => true),
            new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 100)),
        ]);
        expect(readable).toBe(true);
        await syncing;
        expect((await chats[0]!.outbox()).entries[0]?.lastError?.code).toBe("network-timeout");
        expect(await chats[0]!.cancel(stalledId)).toEqual({ status: "cancelled" });
        expect((await chats[0]!.outbox()).entries).toEqual([]);
        expect(await chats[0]!.drop(stalledId)).toEqual({
            status: "may-have-delivered",
        });
        await chats[0]!.close();
    }, 30_000);

    it("retains exact staged ciphertext and keys across a network timeout retry", async () => {
        const blobs = new TimeoutThenBlobStore();
        const { murmurs, stores, chats, sources } = await openPeers(1, blobs);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!, {
            blobStore: blobs,
            sources,
            sourceTimeoutMilliseconds: 30_000,
            networkTimeoutMilliseconds: 25,
        });
        const source = new TestSource("timeout-retry", new Uint8Array(70_000).fill(14));
        sources.set(source.sourceId, source);
        const messageId = await chats[0]!.send(conversationId, {
            message: "timeout retry",
            attachments: [{ sourceId: source.sourceId, metadata: "timeout" }],
        });
        await chats[0]!.sync();
        expect((await chats[0]!.outbox()).entries[0]?.lastError?.code).toBe("network-timeout");
        const persisted = [...(await stores[0]!.list("chat/v1/outbox/")).values()][0]!;
        const staged = decodeOutbox(persisted);
        expect(staged.attachments[0]?.stageState).toBe("staged");
        const stagedKey = staged.attachments[0]!.fileKey.slice();
        const stagedBlobId = staged.attachments[0]!.manifest!.blobId.slice();
        const readsBeforeRetry = source.reads;
        await chats[0]!.retry(messageId);
        await chats[0]!.sync();
        expect(source.reads).toBe(readsBeforeRetry);
        const message = known((await chats[0]!.history(conversationId)).messages)[0]!;
        expect(message.attachments[0]!.fileKey).toEqual(stagedKey);
        expect(message.attachments[0]!.blobId).toEqual(stagedBlobId);
        expect(await chats[0]!.downloadAttachment(message.attachments[0]!)).toEqual(source.bytes);
    }, 30_000);

    it("returns unknown history when a later application codec rejects an old frame", async () => {
        const { murmurs, stores, chats, blobStore, sources } = await openPeers(1);
        const conversationId = await chats[0]!.createConversation();
        await chats[0]!.send(conversationId, { message: "old codec" });
        await chats[0]!.sync();
        const exactFrame = (await murmurs[0]!.groups.get(conversationId))?.events[0]!.bytes;
        await chats[0]!.close();
        chats[0] = await openChat(murmurs[0]!, stores[0]!, {
            blobStore,
            sources,
            rejectDecodedMessages: true,
        });
        const history = await chats[0]!.history(conversationId);
        expect(history.messages[0]).toMatchObject({
            kind: "unknown",
            reason: expect.stringContaining("new codec rejects old frame"),
        });
        expect(history.messages[0]!.kind === "unknown" && history.messages[0]!.rawFrame).toEqual(
            exactFrame,
        );
        expect(history.nextAfter).toBeUndefined();
    }, 30_000);

    it("ignores non-chat groups while Murmur continues syncing them", async () => {
        const { murmurs, chats } = await openPeers(1);
        const groupId = await murmurs[0]!.groups.create(textEncoder.encode("other protocol"));
        await murmurs[0]!.groups.send(groupId, new Uint8Array([1, 2, 3]));
        await chats[0]!.sync();
        expect(await chats[0]!.listConversations()).toEqual([]);
        expect((await murmurs[0]!.groups.get(groupId))?.events).toHaveLength(1);
    }, 30_000);

    it("rejects send and membership mutations after local removal", async () => {
        const { murmurs, chats } = await openPeers(2);
        await makeFriends(murmurs[0]!, murmurs[1]!);
        const conversationId = await chats[0]!.createConversation([murmurs[1]!.identityKey]);
        await convergeMurmur(murmurs, 10);
        await chats[1]!.removeMember(conversationId, murmurs[0]!.identityKey);
        await convergeMurmur(murmurs, 10);
        expect((await chats[0]!.getConversation(conversationId))?.status).toBe("removed");
        await expect(
            chats[0]!.send(conversationId, { message: "forbidden" }),
        ).rejects.toBeInstanceOf(ChatValidationError);
        await expect(
            chats[0]!.addMember(conversationId, murmurs[1]!.identityKey),
        ).rejects.toBeInstanceOf(ChatValidationError);
        await expect(
            chats[0]!.removeMember(conversationId, murmurs[1]!.identityKey),
        ).rejects.toBeInstanceOf(ChatValidationError);
    }, 90_000);

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
            known((await carolChat!.history(conversationId)).messages).map(
                (entry) => entry.message,
            ),
        ).toEqual(["after add"]);
    }, 120_000);
});
