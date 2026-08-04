import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair, randomBytes } from "../../crypto/index.js";
import { identityId } from "../../identity/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    createRelayEvent,
    type EventPage,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicAccess,
    relayTopicId,
} from "../../transport/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

class OrderedTransport implements RelayTransport {
    readonly reads: bigint[] = [];
    readonly published: SignedRelayEvent[] = [];
    beforeRead?: () => Promise<void>;
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
        await this.beforeRead?.();
        return this.#pages.shift() ?? { events: [], head: since, exhausted: true };
    }
}

class PerTopicTransport implements RelayTransport {
    readonly pages = new Map<string, EventPage>();

    async publish(_event: SignedRelayEvent): Promise<{ seq: bigint; duplicate: boolean }> {
        return { seq: 1n, duplicate: false };
    }

    async readEvents(access: TopicAccess): Promise<EventPage> {
        return (
            this.pages.get(relayTopicId(access.topic)) ?? {
                events: [],
                head: 0n,
                exhausted: true,
            }
        );
    }
}

describe("single-relay stateful client", () => {
    test("advances durable cursors across legal sequence holes", async () => {
        const identity = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "group",
            writeKey: identity.publicKey,
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
                topic: { type: "write", name: "out", writeKey: identity.publicKey },
                writeSecretKey: identity.secretKey,
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
        expect(transport.published[0]!.author.signingKey).not.toEqual(firstIdentity.publicKey);
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
            writeKey: identity.publicKey,
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

    test("serializes concurrent sync and rejects a stale delivery advance", async () => {
        const identity = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "concurrent",
            writeKey: identity.publicKey,
        };
        const event = createRelayEvent(identity, topic, new Uint8Array([1]), {}, 1);
        const transport = new OrderedTransport([
            { events: [{ seq: 1n, event }], head: 1n, exhausted: true },
        ]);
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity, store, transport });
        client.subscribe({ topic });
        const results = await Promise.all([client.sync(), client.sync()]);
        expect(results.flatMap(({ events }) => events)).toHaveLength(1);
        const delivery = results.flatMap(({ events }) => events)[0]!;
        await store.transaction((transaction) => delivery.advanceCursor(transaction));
        await expect(
            store.transaction((transaction) => delivery.advanceCursor(transaction)),
        ).rejects.toThrow("Cannot skip");
    });

    test("never lowers an empty-page cursor advanced by a concurrent transaction", async () => {
        const identity = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "monotonic",
            writeKey: identity.publicKey,
        };
        const store = new MemoryMurmurStore();
        const cursorKey = `client/${identityId(identity)}/cursor/${relayTopicId(topic)}`;
        const transport = new OrderedTransport([{ events: [], head: 3n, exhausted: true }]);
        transport.beforeRead = async () => store.set(cursorKey, utf8Encode("5"));
        const client = new MurmurClient({ identity, store, transport });
        client.subscribe({ topic });
        await client.sync();
        expect(utf8Decode((await store.get(cursorKey))!)).toBe("5");
    });

    test("rejects a validly signed event from an unauthorized write author", async () => {
        const owner = generateIdentityKeyPair();
        const attacker = generateIdentityKeyPair();
        const topic = {
            type: "write" as const,
            name: "adversarial",
            writeKey: owner.publicKey,
        };
        const malicious = createRelayEvent(attacker, topic, new Uint8Array([1]), {}, 1);
        const client = new MurmurClient({
            identity: owner,
            store: new MemoryMurmurStore(),
            transport: new OrderedTransport([
                { events: [{ seq: 1n, event: malicious }], head: 1n, exhausted: true },
            ]),
        });
        client.subscribe({ topic });
        await expect(client.sync()).rejects.toThrow("invalid ordered event page");
    });

    test("does not strand an earlier valid topic when a later page is malicious", async () => {
        const identity = generateIdentityKeyPair();
        const attacker = generateIdentityKeyPair();
        const firstTopic = {
            type: "write" as const,
            name: "first-valid",
            writeKey: identity.publicKey,
        };
        const secondTopic = {
            type: "write" as const,
            name: "second-malicious",
            writeKey: identity.publicKey,
        };
        const firstEvent = createRelayEvent(identity, firstTopic, new Uint8Array([1]), {}, 1);
        const malicious = createRelayEvent(attacker, secondTopic, new Uint8Array([2]), {}, 1);
        const transport = new PerTopicTransport();
        transport.pages.set(relayTopicId(firstTopic), {
            events: [{ seq: 1n, event: firstEvent }],
            head: 1n,
            exhausted: true,
        });
        transport.pages.set(relayTopicId(secondTopic), {
            events: [{ seq: 1n, event: malicious }],
            head: 1n,
            exhausted: true,
        });
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transport,
        });
        client.subscribe({ topic: firstTopic });
        client.subscribe({ topic: secondTopic });
        await expect(client.sync()).rejects.toThrow("invalid ordered event page");

        const corrected = createRelayEvent(identity, secondTopic, new Uint8Array([2]), {}, 1);
        transport.pages.set(relayTopicId(secondTopic), {
            events: [{ seq: 1n, event: corrected }],
            head: 1n,
            exhausted: true,
        });
        const recovered = await client.sync();
        expect(recovered.events.map(({ event }) => event.topic.name).sort()).toEqual([
            "first-valid",
            "second-malicious",
        ]);
    });
});
