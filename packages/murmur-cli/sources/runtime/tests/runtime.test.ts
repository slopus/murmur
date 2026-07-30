import {
    MemoryMurmurStore,
    createRelayEvent,
    generateIdentityKeyPair,
    utf8Decode,
    utf8Encode,
    type RelayBlob,
    type RelayEvent,
} from "@murmur/core";
import { EmbeddedRelayTransport, MemoryRelayStore, RelayService } from "@murmur/relay";
import { describe, expect, it } from "vitest";
import { MurmurCliRuntime, cliDirectMessageTopic, encodeCliIdentityToken } from "../index.js";

class ControlledTransport extends EmbeddedRelayTransport {
    rejectPublish = false;
    rejectBlob = false;

    override async publish(event: RelayEvent): Promise<void> {
        if (this.rejectPublish) {
            throw new Error(`Relay ${this.id} rejects events`);
        }
        await super.publish(event);
    }

    override async putBlob(blob: RelayBlob): Promise<void> {
        if (this.rejectBlob) {
            throw new Error(`Relay ${this.id} rejects blobs`);
        }
        await super.putBlob(blob);
    }
}

describe("MurmurCliRuntime", () => {
    it("exchanges profiles, offline messages, and encrypted attachments", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [new EmbeddedRelayTransport("relay", relay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("relay", relay)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });

        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        expect((await alice.sync()).profiles).toBe(1);
        expect((await bob.sync()).profiles).toBe(1);
        expect((await alice.contacts())[0]?.profile.name).toBe("Bob");
        expect((await bob.contacts())[0]?.profile.name).toBe("Alice");

        const firstId = await alice.send(bobIdentity.id, "first", [], 10);
        const secondId = await alice.send(
            bobIdentity.id,
            "second",
            [
                {
                    name: "note.txt",
                    mediaType: "text/plain",
                    bytes: utf8Encode("private attachment"),
                },
            ],
            20,
        );

        const synchronized = await bob.sync();
        expect(synchronized.messages).toBe(2);
        expect((await bob.sync()).messages).toBe(0);
        const received = await bob.messages(aliceIdentity.id);
        expect(received.map((stored) => stored.message.id)).toEqual([firstId, secondId]);
        expect(received.map((stored) => stored.message.text)).toEqual(["first", "second"]);
        expect(utf8Decode(await bob.attachment(secondId, "note.txt"))).toBe("private attachment");

        for (let index = 0; index < 20; index += 1) {
            await alice.send(bobIdentity.id, `bulk ${index}`, [], 100 + index);
        }
        expect((await bob.sync()).messages).toBe(20);
        expect((await bob.messages(aliceIdentity.id, 20)).map((item) => item.message.text)).toEqual(
            Array.from({ length: 20 }, (_, index) => `bulk ${index}`),
        );

        const reopenedBob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("relay-reopened", relay)],
        });
        expect(
            (await reopenedBob.messages(aliceIdentity.id)).map((item) => item.message.text),
        ).toEqual([
            "first",
            "second",
            ...Array.from({ length: 20 }, (_, index) => `bulk ${index}`),
        ]);
        alice.destroy();
        bob.destroy();
        reopenedBob.destroy();
    });

    it("quarantines poison pages without starving later valid messages", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("alice-relay", relay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("bob-relay", relay)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();

        const attacker = generateIdentityKeyPair();
        for (let index = 0; index < 20; index += 1) {
            await relay.publish(
                createRelayEvent(
                    attacker,
                    cliDirectMessageTopic(bobIdentity.identity),
                    utf8Encode("{}"),
                    [bobIdentity.identity],
                    index,
                ),
            );
        }
        await alice.send(bobIdentity.id, "after poison", [], 30);

        const result = await bob.sync();
        expect(result.quarantined).toBe(20);
        expect(result.messages).toBe(1);
        expect((await bob.messages())[0]?.message.text).toBe("after poison");
        alice.destroy();
        bob.destroy();
    });

    it("retains blobs and reconciles pending status across partial relay success", async () => {
        const relayA = new RelayService(new MemoryRelayStore());
        const relayB = new RelayService(new MemoryRelayStore());
        const aliceA = new ControlledTransport("alice-a", relayA);
        const aliceB = new ControlledTransport("alice-b", relayB);
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [aliceA, aliceB],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("bob-b", relayB)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();

        aliceA.rejectPublish = true;
        aliceB.rejectBlob = true;
        await expect(
            alice.send(
                bobIdentity.id,
                "event waits for every blob",
                [{ name: "note.txt", bytes: utf8Encode("durable ciphertext") }],
                40,
            ),
        ).rejects.toThrow("rejects blobs");
        expect((await alice.messages())[0]?.status).toBe("pending");

        aliceB.rejectBlob = false;
        await alice.sync();
        expect((await alice.messages())[0]?.status).toBe("sent");
        expect((await bob.sync()).messages).toBe(1);
        const received = (await bob.messages())[0];
        expect(utf8Decode(await bob.attachment(received?.message.id ?? "", "note.txt"))).toBe(
            "durable ciphertext",
        );
        alice.destroy();
        bob.destroy();
    });

    it("continues inbound sync when a retained outbound event still fails", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const bobTransport = new ControlledTransport("bob-relay", relay);
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("alice-relay", relay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [bobTransport],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();

        bobTransport.rejectPublish = true;
        await expect(
            bob.shareProfile(encodeCliIdentityToken(generateIdentityKeyPair())),
        ).rejects.toThrow("Every transport rejected");
        await alice.send(bobIdentity.id, "pull still works", [], 50);

        const result = await bob.sync();
        expect(result.retryFailures).toBeGreaterThan(0);
        expect(result.messages).toBe(1);
        alice.destroy();
        bob.destroy();
    });

    it("orders global history by local delivery sequence rather than sender clocks", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const transport = (id: string): EmbeddedRelayTransport =>
            new EmbeddedRelayTransport(id, relay);
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("alice")],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("bob")],
        });
        const carol = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("carol")],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        const carolIdentity = await carol.signIn({ name: "Carol" });
        await alice.shareProfile(bobIdentity.token);
        await carol.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await bob.shareProfile(carolIdentity.token);
        await alice.sync();
        await carol.sync();
        await bob.sync();

        await alice.send(bobIdentity.id, "published first", [], 9_999);
        await carol.send(bobIdentity.id, "published second", [], 1);
        await bob.sync();

        expect((await bob.messages()).map((stored) => stored.message.text)).toEqual([
            "published first",
            "published second",
        ]);
        alice.destroy();
        bob.destroy();
        carol.destroy();
    });

    it("creates, welcomes, persists, and messages an RFC MLS group", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [new EmbeddedRelayTransport("alice-relay", relay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("bob-relay", relay)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();

        const groupId = await alice.createGroup("Protocol team");
        await alice.inviteToGroup(groupId, bobIdentity.id);
        const joined = await bob.sync();

        expect(joined.invitations).toBe(1);
        expect(bob.groups()).toEqual([
            {
                id: groupId,
                name: "Protocol team",
                epoch: 1n,
                members: [aliceIdentity.id, bobIdentity.id],
            },
        ]);
        expect(alice.groups()[0]?.epoch).toBe(1n);

        const first = await alice.sendToGroup(groupId, "hello group", 100);
        expect((await bob.sync()).groupMessages).toBe(1);
        expect(await bob.groupMessages(groupId)).toEqual([
            {
                sequence: 1,
                groupId,
                direction: "incoming",
                status: "received",
                sender: 0,
                message: {
                    id: first,
                    sentAt: 100,
                    text: "hello group",
                },
            },
        ]);

        const reply = await bob.sendToGroup(groupId, "durable reply", 200);
        expect((await alice.sync()).groupMessages).toBe(1);
        expect((await alice.groupMessages(groupId)).at(-1)?.message.id).toBe(reply);

        bob.destroy();
        const reopenedBob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("bob-reopened", relay)],
        });
        expect(reopenedBob.groups()[0]?.epoch).toBe(1n);
        await alice.sendToGroup(groupId, "after restart", 300);
        expect((await reopenedBob.sync()).groupMessages).toBe(1);
        expect(
            (await reopenedBob.groupMessages(groupId)).map((stored) => stored.message.text),
        ).toEqual(["hello group", "durable reply", "after restart"]);

        alice.destroy();
        reopenedBob.destroy();
    });

    it("retires a removed member and drains later ciphertext without decrypting it", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const bobStore = new MemoryMurmurStore();
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("alice-relay", relay)],
        });
        const bob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("bob-relay", relay)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();
        const groupId = await alice.createGroup("Removal");
        await alice.inviteToGroup(groupId, bobIdentity.id);
        await bob.sync();

        await alice.removeFromGroup(groupId, bobIdentity.id);
        const removed = await bob.sync();
        expect(removed.groupCommits).toBe(1);
        expect(bob.groups()).toEqual([]);
        expect(alice.groups()[0]?.members).toEqual([aliceIdentity.id]);

        bob.destroy();
        const reopenedBob = await MurmurCliRuntime.open({
            store: bobStore,
            transports: [new EmbeddedRelayTransport("bob-reopened", relay)],
        });
        expect(reopenedBob.groups()).toEqual([]);
        await alice.sendToGroup(groupId, "not for Bob", 400);
        const drained = await reopenedBob.sync();
        expect(drained.groupMessages).toBe(0);
        expect(drained.quarantined).toBe(0);

        alice.destroy();
        reopenedBob.destroy();
    });

    it("recovers ordered Welcome then Commit publication after relay failure", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const aliceTransport = new ControlledTransport("alice-relay", relay);
        const aliceStore = new MemoryMurmurStore();
        const alice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [aliceTransport],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("bob-relay", relay)],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        await alice.shareProfile(bobIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();
        const groupId = await alice.createGroup("Recovered invite");

        aliceTransport.rejectPublish = true;
        await expect(alice.inviteToGroup(groupId, bobIdentity.id)).rejects.toThrow(
            "Every transport rejected",
        );
        await expect(alice.sendToGroup(groupId, "must wait")).rejects.toThrow(
            "unresolved durable publication",
        );

        alice.destroy();
        const reopenedAlice = await MurmurCliRuntime.open({
            store: aliceStore,
            transports: [aliceTransport],
        });
        aliceTransport.rejectPublish = false;
        expect((await reopenedAlice.sync()).retryFailures).toBe(0);
        expect((await bob.sync()).invitations).toBe(1);
        expect(bob.groups()[0]?.id).toBe(groupId);

        reopenedAlice.destroy();
        bob.destroy();
    });

    it("retries a future-epoch application after its delayed Commit arrives", async () => {
        const relayA = new RelayService(new MemoryRelayStore());
        const relayB = new RelayService(new MemoryRelayStore());
        const aliceA = new ControlledTransport("alice-a", relayA);
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [aliceA, new EmbeddedRelayTransport("alice-b", relayB)],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [new EmbeddedRelayTransport("bob-a", relayA)],
        });
        const carol = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [
                new EmbeddedRelayTransport("carol-a", relayA),
                new EmbeddedRelayTransport("carol-b", relayB),
            ],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        const carolIdentity = await carol.signIn({ name: "Carol" });
        await alice.shareProfile(bobIdentity.token);
        await alice.shareProfile(carolIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await carol.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();
        await carol.sync();
        const groupId = await alice.createGroup("Delayed epoch");
        await alice.inviteToGroup(groupId, bobIdentity.id);
        await bob.sync();

        aliceA.rejectPublish = true;
        await alice.inviteToGroup(groupId, carolIdentity.id);
        await carol.sync();
        await carol.sendToGroup(groupId, "future epoch", 500);

        const beforeCommit = await bob.sync();
        expect(beforeCommit.groupMessages).toBe(0);
        expect(beforeCommit.deferred).toBeGreaterThan(0);

        aliceA.rejectPublish = false;
        await alice.sync();
        const afterCommit = await bob.sync();
        expect(afterCommit.groupCommits).toBe(1);
        expect(afterCommit.groupMessages).toBe(1);
        expect((await bob.groupMessages(groupId)).at(-1)?.message.text).toBe("future epoch");

        alice.destroy();
        bob.destroy();
        carol.destroy();
    });

    it("converges a shared document across a three-member MLS group", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const transport = (id: string): EmbeddedRelayTransport =>
            new EmbeddedRelayTransport(id, relay);
        const alice = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("alice")],
        });
        const bob = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("bob")],
        });
        const carol = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [transport("carol")],
        });
        const aliceIdentity = await alice.signIn({ name: "Alice" });
        const bobIdentity = await bob.signIn({ name: "Bob" });
        const carolIdentity = await carol.signIn({ name: "Carol" });
        await alice.shareProfile(bobIdentity.token);
        await alice.shareProfile(carolIdentity.token);
        await bob.shareProfile(aliceIdentity.token);
        await carol.shareProfile(aliceIdentity.token);
        await alice.sync();
        await bob.sync();
        await carol.sync();

        const groupId = await alice.createGroup("Writers");
        await alice.inviteToGroup(groupId, bobIdentity.id);
        await bob.sync();
        await alice.inviteToGroup(groupId, carolIdentity.id);
        await bob.sync();
        await carol.sync();
        expect(alice.groups()[0]?.members.filter(Boolean)).toHaveLength(3);
        expect(bob.groups()[0]?.members.filter(Boolean)).toHaveLength(3);
        expect(carol.groups()[0]?.members.filter(Boolean)).toHaveLength(3);

        const documentId = await alice.createDocument(groupId, "Draft");
        await bob.sync();
        await carol.sync();
        const aliceInsert = await alice.insertDocument(documentId, "A");
        await bob.insertDocument(documentId, "B");

        await alice.sync();
        await bob.sync();
        await carol.sync();
        const concurrent = [
            (await alice.documents(groupId))[0]?.text,
            (await bob.documents(groupId))[0]?.text,
            (await carol.documents(groupId))[0]?.text,
        ];
        expect(new Set(concurrent).size).toBe(1);
        expect(concurrent[0]).toHaveLength(2);

        await carol.deleteDocument(documentId, aliceInsert);
        await alice.sync();
        await bob.sync();
        const afterDelete = [
            (await alice.documents(groupId))[0]?.text,
            (await bob.documents(groupId))[0]?.text,
            (await carol.documents(groupId))[0]?.text,
        ];
        expect(afterDelete).toEqual(["B", "B", "B"]);

        await alice.removeFromGroup(groupId, bobIdentity.id);
        await bob.sync();
        await carol.sync();
        expect(alice.groups()[0]?.members.filter(Boolean)).toHaveLength(2);
        expect(carol.groups()[0]?.members.filter(Boolean)).toHaveLength(2);
        expect(bob.groups()).toEqual([]);

        alice.destroy();
        bob.destroy();
        carol.destroy();
    });
});
