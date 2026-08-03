import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
    InProcessWakeSource,
    LocalBlobBackend,
    RelayService,
    SqliteRelayStore,
    createRelayFetchHandler,
} from "@murmur/relay";
import {
    HttpRelayTransport,
    MAX_DIRECT_CHAT_DOCUMENT_BYTES,
    utf8Decode,
    utf8Encode,
} from "@slopus/murmur";
import { afterEach, describe, expect, it } from "vitest";
import { MurmurCliRuntime } from "../index.js";
import { SqliteMurmurStore } from "../../storage/index.js";

describe("CLI runtime over the fixed relay protocol", () => {
    const closeables: { close(): Promise<void> }[] = [];
    const runtimes: MurmurCliRuntime[] = [];

    afterEach(async () => {
        for (const runtime of runtimes.splice(0)) {
            runtime.destroy();
        }
        for (const closeable of closeables.splice(0).reverse()) {
            await closeable.close();
        }
    });

    it("exchanges profiles, direct files, groups, removal, and a convergent document", async () => {
        const relayStore = new SqliteRelayStore(":memory:");
        let relayNow = Date.now();
        const service = new RelayService(
            relayStore,
            { eventRetentionMilliseconds: 1 },
            new InProcessWakeSource(),
            () => relayNow,
        );
        closeables.push(service);
        const blobRoot = await mkdtemp(join(tmpdir(), "murmur-cli-blobs-"));
        const blobBackend = new LocalBlobBackend({
            rootDirectory: blobRoot,
            secret: new Uint8Array(32).fill(17),
        });
        closeables.push({
            close: async () => {
                await blobBackend.close();
                await rm(blobRoot, { recursive: true, force: true });
            },
        });
        const handler = createRelayFetchHandler(service, { blobBackend });
        const fetchRelay = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => handler(new Request(input, init));
        let aliceOnline = true;
        const fetchForAlice = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => {
            if (!aliceOnline) {
                throw new Error("Alice relay connection is offline");
            }
            return fetchRelay(input, init);
        };
        let bobOnline = true;
        let tamperNextBobBlob = false;
        const fetchForBob = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => {
            if (!bobOnline) {
                throw new Error("Bob relay connection is offline");
            }
            const request = new Request(input, init);
            const response = await fetchRelay(request);
            if (
                tamperNextBobBlob &&
                request.method === "GET" &&
                /^\/v1\/blobs\/[^/]+$/.test(new URL(request.url).pathname)
            ) {
                tamperNextBobBlob = false;
                const bytes = new Uint8Array(await response.arrayBuffer());
                return new Response(new Uint8Array(bytes.length).fill(1), {
                    status: response.status,
                    headers: { "content-length": String(bytes.length) },
                });
            }
            return response;
        };

        const aliceStore = new SqliteMurmurStore(":memory:");
        const bobStore = new SqliteMurmurStore(":memory:");
        closeables.push(aliceStore, bobStore);
        let alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchForAlice)],
        });
        const bob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchForBob)],
        });
        runtimes.push(alice, bob);

        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();
        expect((await alice.contacts()).map((contact) => contact.profile.name)).toEqual(["Bob"]);
        expect((await bob.contacts()).map((contact) => contact.profile.name)).toEqual(["Alice"]);

        bobOnline = false;
        const messageId = await alice.send(
            bobIdentity.id,
            "with photo and document",
            [
                {
                    name: "photo.png",
                    mediaType: "image/png",
                    bytes: new Uint8Array([137, 80, 78, 71]),
                },
                { name: "note.txt", mediaType: "text/plain", bytes: utf8Encode("secret") },
            ],
            100,
        );
        expect((await aliceStore.list("cli/outbound/v1/")).size).toBe(0);
        expect((await aliceStore.list("cli/outbound-blobs/v1/")).size).toBe(0);
        bobOnline = true;
        await bob.sync();
        expect((await bob.messages(aliceIdentity.id))[0]?.message.id).toBe(messageId);
        expect(await bob.attachment(messageId, "photo.png")).toEqual(
            new Uint8Array([137, 80, 78, 71]),
        );
        expect(utf8Decode(await bob.attachment(messageId, "note.txt"))).toBe("secret");
        tamperNextBobBlob = true;
        await expect(bob.attachment(messageId, "photo.png")).rejects.toThrow("integrity");
        await expect(
            alice.send(bobIdentity.id, "oversize", [
                {
                    name: "oversize.pdf",
                    mediaType: "application/pdf",
                    bytes: new Uint8Array(MAX_DIRECT_CHAT_DOCUMENT_BYTES + 1),
                },
            ]),
        ).rejects.toThrow("document exceeds");

        aliceOnline = false;
        await expect(
            alice.send(
                bobIdentity.id,
                "pending across restart",
                [{ name: "pending.txt", mediaType: "text/plain", bytes: utf8Encode("pending") }],
                110,
            ),
        ).rejects.toThrow("offline");
        const pendingId = (await alice.messages(bobIdentity.id)).find(
            (stored) => stored.message.text === "pending across restart",
        )?.message.id;
        expect(pendingId).toBeDefined();
        runtimes.splice(runtimes.indexOf(alice), 1);
        alice.destroy();
        aliceOnline = true;
        alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchForAlice)],
        });
        runtimes.push(alice);
        await alice.sync();
        await bob.sync();
        expect(
            (await bob.messages(aliceIdentity.id)).filter(
                (stored) => stored.message.id === pendingId,
            ),
        ).toHaveLength(1);
        expect(utf8Decode(await bob.attachment(pendingId!, "pending.txt"))).toBe("pending");

        const replyId = await bob.send(aliceIdentity.id, "reply while Alice is offline", [], 120);
        await alice.sync();
        expect(
            (await alice.messages(bobIdentity.id)).filter(
                (stored) => stored.message.id === replyId,
            ),
        ).toHaveLength(1);

        relayNow += 10;
        expect((await service.prune()).events).toBeGreaterThan(0);
        const freshAliceStore = new SqliteMurmurStore(":memory:");
        const freshBobStore = new SqliteMurmurStore(":memory:");
        closeables.push(freshAliceStore, freshBobStore);
        for (const [source, target] of [
            [aliceStore, freshAliceStore],
            [bobStore, freshBobStore],
        ] as const) {
            for (const [key, value] of await source.list("")) {
                if (
                    key === "cli/account/v1" ||
                    key.startsWith("identity/") ||
                    (key.startsWith("client/") && key.includes("/identity:"))
                ) {
                    await target.set(key, value);
                }
            }
        }
        const freshAlice = await MurmurCliRuntime.open({
            store: freshAliceStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchRelay)],
        });
        const freshBob = await MurmurCliRuntime.open({
            store: freshBobStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchRelay)],
        });
        runtimes.push(freshAlice, freshBob);
        await freshAlice.sync();
        await freshBob.sync();
        expect(
            (await freshAlice.messages(bobIdentity.id))
                .find((stored) => stored.message.id === messageId)
                ?.message.attachments.map((attachment) => attachment.name),
        ).toEqual(["photo.png", "note.txt"]);
        expect(await freshAlice.attachment(messageId, "photo.png")).toEqual(
            new Uint8Array([137, 80, 78, 71]),
        );
        expect(utf8Decode(await freshBob.attachment(messageId, "note.txt"))).toBe("secret");
        expect(
            (await freshAlice.messages(bobIdentity.id))
                .filter((stored) => stored.message.attachments.length === 0)
                .map((stored) => [stored.direction, stored.status, stored.message.text]),
        ).toEqual([["incoming", "received", "reply while Alice is offline"]]);
        expect(
            (await freshBob.messages(aliceIdentity.id))
                .filter((stored) => stored.message.attachments.length === 0)
                .map((stored) => [stored.direction, stored.status, stored.message.text]),
        ).toEqual([["outgoing", "sent", "reply while Alice is offline"]]);
        relayNow = Date.now();

        const groupId = await alice.createGroup("room");
        await alice.inviteToGroup(groupId, bobIdentity.id);
        await bob.sync();
        expect(bob.groups().map((group) => group.id)).toContain(groupId);

        await alice.sendToGroup(groupId, "hello group", 200);
        await bob.sync();
        expect((await bob.groupMessages(groupId))[0]?.message.text).toBe("hello group");

        const documentId = await alice.createDocument(groupId, "notes");
        await bob.sync();
        await bob.insertDocument(documentId, "shared");
        await alice.sync();
        expect((await alice.documents(groupId))[0]?.text).toBe("shared");
        expect((await bob.documents(groupId))[0]?.text).toBe("shared");

        await alice.removeFromGroup(groupId, bobIdentity.id);
        await bob.sync();
        expect(bob.groups()).toHaveLength(0);
    });
});
