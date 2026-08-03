import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    createRelayEvent,
    type EventPage,
    type ListPage,
    type PublishOutcome,
    type RelayBlob,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicState,
} from "../../transport/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

class TestTransport implements RelayTransport {
    readonly blobs = new Map<string, RelayBlob>();
    readonly events = new Map<string, SignedRelayEvent[]>();
    reset = false;

    constructor(readonly id: string) {}

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        const existing = this.events.get(event.topic) ?? [];
        const duplicateIndex = existing.findIndex((candidate) => candidate.id === event.id);
        if (duplicateIndex >= 0) {
            return { seq: BigInt(duplicateIndex + 1), duplicate: true };
        }
        existing.push(event);
        this.events.set(event.topic, existing);
        return { seq: BigInt(existing.length), duplicate: false };
    }

    async readState(topic: string): Promise<TopicState | undefined> {
        const events = this.events.get(topic);
        if (events === undefined) {
            return undefined;
        }
        const elements = events.flatMap((event) =>
            (event.list ?? [])
                .filter((operation) => operation.op === "append")
                .map((operation, index) => ({
                    id: operation.id,
                    version: 1n,
                    bytes: operation.bytes,
                    index,
                })),
        );
        return {
            seq: BigInt(events.length),
            snapshot: null,
            list: {
                elements: elements.map(({ index: _index, ...element }) => element),
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

class RejectingTransport extends TestTransport {
    override async publish(): Promise<PublishOutcome> {
        throw new Error(`Relay ${this.id} is offline`);
    }
}

describe("MurmurClient", () => {
    it("commits application state and cursor atomically", async () => {
        const alice = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity: alice, store, transports: [relay] });
        await client.subscribe("room");
        await client.publish("room", utf8Encode("hello"));

        const first = await client.sync();
        expect(first.status).toBe("events");
        if (first.status !== "events") {
            throw new Error("Expected events");
        }
        const delivery = first.events[0];
        if (delivery === undefined) {
            throw new Error("Expected one event");
        }
        await expect(
            store.transaction(async (transaction) => {
                await transaction.set("application/message", delivery.event.payload);
                await delivery.advanceCursor(transaction);
                throw new Error("simulated crash");
            }),
        ).rejects.toThrow("simulated crash");
        expect(await store.get("application/message")).toBeUndefined();
        expect((await client.sync()).status).toBe("events");

        await store.transaction(async (transaction) => {
            await transaction.set("application/message", delivery.event.payload);
            await delivery.advanceCursor(transaction);
        });
        const caughtUp = await client.sync();
        expect(caughtUp).toEqual({ status: "events", events: [] });
        expect(utf8Decode((await store.get("application/message")) ?? new Uint8Array())).toBe(
            "hello",
        );
    });

    it("surfaces reset as a mandatory discriminated result", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });
        await client.subscribe("room");
        await client.publish("room", utf8Encode("retained"));
        relay.reset = true;

        const result = await client.sync();

        expect(result.status).toBe("reset");
        if (result.status === "reset") {
            expect(result.resets).toEqual([
                {
                    kind: "reset",
                    relayId: "relay",
                    topic: "room",
                    requestedSince: 0n,
                    head: 1n,
                },
            ]);
        }
    });

    it("loads permanent list history and installs its head cursor atomically", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity, store, transports: [relay] });
        await client.subscribe("chat");
        await client.publish("chat", utf8Encode("event"), {
            list: [{ op: "append", id: "message:stable", bytes: utf8Encode("ciphertext") }],
        });

        await client.loadTopic("chat", async (transaction, state) => {
            expect(state.elements.map((element) => element.id)).toEqual(["message:stable"]);
            await transaction.set(
                "application/history",
                state.elements[0]?.bytes ?? new Uint8Array(),
            );
        });

        expect(await client.sync()).toEqual({ status: "events", events: [] });
        expect(utf8Decode((await store.get("application/history")) ?? new Uint8Array())).toBe(
            "ciphertext",
        );
    });

    it("uses relay idempotency outcomes and retains failed multi-relay publication", async () => {
        const identity = generateIdentityKeyPair();
        const healthy = new TestTransport("healthy");
        const offline = new RejectingTransport("offline");
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transports: [offline, healthy],
        });

        const first = await client.publish("room", utf8Encode("hello"));
        const duplicate = await healthy.publish(first.event);
        const retry = await client.retryOutboundSettled();

        expect(first.publishedRelayIds).toEqual(["healthy"]);
        expect(first.publications[0]?.outcome.duplicate).toBe(false);
        expect(duplicate).toEqual({ seq: 1n, duplicate: true });
        expect(retry.results).toHaveLength(1);
        expect(retry.failures).toHaveLength(0);
    });

    it("atomically replaces a stale outbound event with equivalent fresh content", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const store = new MemoryMurmurStore();
        const client = new MurmurClient({ identity, store, transports: [relay] });
        const previous = createRelayEvent(
            identity,
            "room",
            utf8Encode("hello"),
            {
                list: [{ op: "append", id: "message:stable", bytes: utf8Encode("ciphertext") }],
            },
            1,
        );
        const replacement = createRelayEvent(
            identity,
            "room",
            previous.payload,
            {
                list: previous.list ?? [],
            },
            400_000,
        );

        await client.publishEvent(previous);
        await client.replaceOutboundEvent(previous, replacement);

        expect(relay.events.get("room")).toHaveLength(1);
        expect((await client.retryOutboundSettled()).failures).toEqual([]);
        await expect(
            client.replaceOutboundEvent(
                previous,
                createRelayEvent(identity, "different", previous.payload, {}, 400_001),
            ),
        ).rejects.toThrow("does not match");
    });

    it("uses a one-use relay author for public first-contact traffic", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });

        const result = await client.publishUnlinkable(
            "identity:public",
            utf8Encode("self-authenticating ciphertext"),
        );

        expect(result.event.author.signingKey).not.toEqual(identity.signingKey);
        expect(result.publishedRelayIds).toEqual(["relay"]);
    });

    it("uploads and validates ciphertext blobs", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });

        const uploaded = await client.putBlob(utf8Encode("ciphertext"));
        expect((await client.getBlob(uploaded.id))?.bytes).toEqual(utf8Encode("ciphertext"));
    });
});
