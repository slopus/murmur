import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair, randomBytes } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    createRelayEvent,
    type EventPage,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicAccess,
} from "../../transport/index.js";
import { MurmurClient } from "../index.js";

class OrderedTransport implements RelayTransport {
    readonly reads: bigint[] = [];
    readonly published: SignedRelayEvent[] = [];
    readonly #pages: EventPage[];

    constructor(pages: EventPage[]) {
        this.#pages = pages;
    }

    queue(page: EventPage): void {
        this.#pages.push(page);
    }

    async publish(_event: SignedRelayEvent): Promise<{ seq: bigint; duplicate: boolean }> {
        this.published.push(_event);
        return { seq: BigInt(this.published.length), duplicate: false };
    }

    async readEvents(_access: TopicAccess, since: bigint): Promise<EventPage> {
        this.reads.push(since);
        return this.#pages.shift() ?? { events: [], head: since, exhausted: true };
    }
}

describe("single-relay stateful client", () => {
    test("advances durable cursors across legal sequence holes", async () => {
        const identity = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "group",
            writeKey: identity.signingKey,
        };
        const firstEvent = createRelayEvent(identity, topic, new Uint8Array([1]), {}, 1);
        const secondEvent = createRelayEvent(identity, topic, new Uint8Array([2]), {}, 2);
        const transport = new OrderedTransport([
            {
                events: [
                    { seq: 2n, event: firstEvent },
                    { seq: 4n, event: secondEvent },
                ],
                head: 4n,
                exhausted: true,
            },
            { events: [], head: 4n, exhausted: true },
        ]);
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity, store, transport });
        client.subscribe({ topic });
        const first = await client.sync();
        expect(first.events.map(({ seq }) => seq)).toEqual([2n, 4n]);
        await expect(
            store.transaction((transaction) => first.events[1]!.advanceCursor(transaction)),
        ).rejects.toThrow("Cannot skip");
        await store.transaction((transaction) => first.events[0]!.advanceCursor(transaction));
        await store.transaction((transaction) => first.events[1]!.advanceCursor(transaction));
        expect((await client.sync()).events).toEqual([]);
        expect(transport.reads).toEqual([0n, 4n]);
    });

    test("publishes once through exactly one transport", async () => {
        const identity = generateIdentityKeyPair();
        const transport = new OrderedTransport([]);
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transport,
        });
        const result = await client.publish(
            {
                topic: { type: "write", name: "out", writeKey: identity.signingKey },
                writeSecretKey: identity.signingSecretKey,
            },
            new Uint8Array([9]),
        );
        expect(result.outcome).toEqual({ seq: 1n, duplicate: false });
    });

    test("uses a shared non-identity write capability for multiple clients", async () => {
        const firstIdentity = generateIdentityKeyPair();
        const secondIdentity = generateIdentityKeyPair();
        const writeSecretKey = randomBytes(32);
        const readSecretKey = randomBytes(32);
        const access = {
            topic: {
                type: "read-write" as const,
                name: "shared",
                readKey: ed25519.getPublicKey(readSecretKey),
                writeKey: ed25519.getPublicKey(writeSecretKey),
            },
            readSecretKey,
            writeSecretKey,
        };
        const transport = new OrderedTransport([]);
        const first = new MurmurClient({
            identity: firstIdentity,
            store: new MemoryMurmurStore(),
            transport,
        });
        const second = new MurmurClient({
            identity: secondIdentity,
            store: new MemoryMurmurStore(),
            transport,
        });
        await first.publish(access, new Uint8Array([1]));
        await second.publish(access, new Uint8Array([2]));
        expect(transport.published.map((event) => event.author.signingKey)).toEqual([
            access.topic.writeKey,
            access.topic.writeKey,
        ]);
        expect(transport.published[0]!.author.signingKey).not.toEqual(firstIdentity.signingKey);
        const sharedPage = {
            events: transport.published.map((event, index) => ({
                seq: BigInt(index + 1),
                event,
            })),
            head: 2n,
            exhausted: true,
        };
        transport.queue(sharedPage);
        transport.queue(sharedPage);
        first.subscribe(access);
        second.subscribe(access);
        expect((await first.sync()).events.map(({ seq }) => seq)).toEqual([1n, 2n]);
        expect((await second.sync()).events.map(({ seq }) => seq)).toEqual([1n, 2n]);
        await expect(
            first.publish({ ...access, writeSecretKey: randomBytes(32) }, new Uint8Array([3])),
        ).rejects.toThrow("Write secret key does not match");
    });

    test("does not advance to head until a byte-truncated page is exhausted", async () => {
        const identity = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "paged",
            writeKey: identity.signingKey,
        };
        const firstEvent = createRelayEvent(identity, topic, new Uint8Array([1]), {}, 1);
        const secondEvent = createRelayEvent(identity, topic, new Uint8Array([2]), {}, 2);
        const transport = new OrderedTransport([
            { events: [{ seq: 1n, event: firstEvent }], head: 2n, exhausted: false },
            { events: [{ seq: 2n, event: secondEvent }], head: 2n, exhausted: true },
        ]);
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity, store, transport });
        client.subscribe({ topic });
        const firstPage = await client.sync();
        await store.transaction((transaction) => firstPage.events[0]!.advanceCursor(transaction));
        const secondPage = await client.sync();
        expect(transport.reads).toEqual([0n, 1n]);
        expect(secondPage.events.map(({ seq }) => seq)).toEqual([2n]);
    });
});
