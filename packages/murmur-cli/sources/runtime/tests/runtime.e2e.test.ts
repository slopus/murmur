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
import { HttpRelayTransport, utf8Decode, utf8Encode } from "@slopus/murmur";
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
        const service = new RelayService(relayStore, {}, new InProcessWakeSource());
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

        const aliceStore = new SqliteMurmurStore(":memory:");
        const bobStore = new SqliteMurmurStore(":memory:");
        closeables.push(aliceStore, bobStore);
        const alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchRelay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new HttpRelayTransport("shared", "https://relay.test", fetchRelay)],
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

        const messageId = await alice.send(
            bobIdentity.id,
            "with attachment",
            [{ name: "note.txt", mediaType: "text/plain", bytes: utf8Encode("secret") }],
            100,
        );
        await bob.sync();
        expect((await bob.messages(aliceIdentity.id))[0]?.message.id).toBe(messageId);
        expect(utf8Decode(await bob.attachment(messageId, "note.txt"))).toBe("secret");

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
