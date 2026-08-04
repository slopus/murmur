import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
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
    readonly #pages: EventPage[];

    constructor(pages: EventPage[]) {
        this.#pages = pages;
    }

    async publish(_event: SignedRelayEvent): Promise<{ seq: bigint; duplicate: boolean }> {
        return { seq: 1n, duplicate: false };
    }

    async readEvents(_access: TopicAccess, since: bigint): Promise<EventPage> {
        this.reads.push(since);
        return this.#pages.shift() ?? { events: [], head: since };
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
            },
            { events: [], head: 4n },
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
            { type: "write", name: "out", writeKey: identity.signingKey },
            new Uint8Array([9]),
        );
        expect(result.outcome).toEqual({ seq: 1n, duplicate: false });
    });
});
