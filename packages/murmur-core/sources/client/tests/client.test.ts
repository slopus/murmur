import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair, signBytes } from "../../crypto/index.js";
import { identityId } from "../../identity/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    createRelayEvent,
    relayEventSignaturePayload,
    type QueueAcknowledgeRequest,
    type QueueReadRequest,
    type RelayBlob,
    type RelayDelivery,
    type RelayEvent,
    type RelayTransport,
    type TopicSubscription,
} from "../../transport/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

class TestTransport implements RelayTransport {
    readonly queue = new Map<string, RelayDelivery[]>();
    readonly blobs = new Map<string, RelayBlob>();
    readonly subscriptions = new Map<string, Set<string>>();
    readonly published: RelayEvent[] = [];

    constructor(readonly id: string) {}

    async publish(event: RelayEvent): Promise<void> {
        this.published.push(event);
        const recipients =
            event.recipients.length > 0
                ? event.recipients
                : [...(this.subscriptions.get(event.topic) ?? [])];
        for (const recipient of recipients) {
            const deliveries = this.queue.get(recipient) ?? [];
            deliveries.push({
                deliveryId: `${this.id}:${recipient}:${event.id}`,
                event,
            });
            this.queue.set(recipient, deliveries);
        }
    }

    async subscribe(subscription: TopicSubscription): Promise<void> {
        const subscribers = this.subscriptions.get(subscription.topic) ?? new Set<string>();
        subscribers.add(identityId(subscription.subscriber));
        this.subscriptions.set(subscription.topic, subscribers);
    }

    async pull(request: QueueReadRequest): Promise<readonly RelayDelivery[]> {
        const recipientId = identityId(request.recipient);
        return [...(this.queue.get(recipientId) ?? [])];
    }

    async acknowledge(request: QueueAcknowledgeRequest): Promise<void> {
        const recipientId = identityId(request.recipient);
        this.queue.set(
            recipientId,
            (this.queue.get(recipientId) ?? []).filter(
                (delivery) => delivery.deliveryId !== request.deliveryId,
            ),
        );
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        this.blobs.set(blob.id, blob);
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        return this.blobs.get(id);
    }
}

class RejectingTransport extends TestTransport {
    override async publish(): Promise<void> {
        throw new Error(`Relay ${this.id} is offline`);
    }
}

describe("MurmurClient", () => {
    it("merges duplicate relay deliveries and acknowledges every copy", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const relayA = new TestTransport("a");
        const relayB = new TestTransport("b");
        const aliceClient = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [relayA, relayB],
        });
        const bobClient = new MurmurClient({
            identity: bob,
            store: new MemoryMurmurStore(),
            transports: [relayA, relayB],
        });

        await bobClient.subscribe("room");
        await aliceClient.publish("room", utf8Encode("hello"));
        const received = await bobClient.sync();

        expect(received).toHaveLength(1);
        expect(utf8Decode(received[0]?.event.payload ?? new Uint8Array())).toBe("hello");
        expect(await bobClient.sync()).toHaveLength(0);
        await received[0]?.acknowledge();
        expect(relayA.queue.get(identityId(bob))).toHaveLength(0);
        expect(relayB.queue.get(identityId(bob))).toHaveLength(0);
    });

    it("redelivers unacknowledged events after restart and suppresses acknowledged ones", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const store = new MemoryMurmurStore();
        const aliceClient = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });
        const firstBobClient = new MurmurClient({
            identity: bob,
            store,
            transports: [relay],
        });

        await aliceClient.publish("direct", utf8Encode("one"), [bob]);
        expect(await firstBobClient.sync()).toHaveLength(1);

        const restartedBobClient = new MurmurClient({
            identity: bob,
            store,
            transports: [relay],
        });
        const redelivered = await restartedBobClient.sync();
        expect(redelivered).toHaveLength(1);
        await redelivered[0]?.acknowledge();
        expect(await restartedBobClient.sync()).toHaveLength(0);
    });

    it("uploads and validates ciphertext blobs across relays", async () => {
        const identity = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const client = new MurmurClient({
            identity,
            store: new MemoryMurmurStore(),
            transports: [relay],
        });

        const uploaded = await client.putBlob(utf8Encode("ciphertext"));
        const downloaded = await client.getBlob(uploaded.id);

        expect(downloaded?.bytes).toEqual(utf8Encode("ciphertext"));
    });

    it("continues healthy relay processing after a poison delivery", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const poisonRelay = new TestTransport("poison");
        const healthyRelay = new TestTransport("healthy");
        const poison = createRelayEvent(alice, "direct", utf8Encode("poison"), [bob]);
        poisonRelay.queue.set(identityId(bob), [
            {
                deliveryId: "poison-delivery",
                event: { ...poison, payload: utf8Encode("tampered") },
            },
        ]);
        await healthyRelay.publish(createRelayEvent(alice, "direct", utf8Encode("healthy"), [bob]));
        const client = new MurmurClient({
            identity: bob,
            store: new MemoryMurmurStore(),
            transports: [poisonRelay, healthyRelay],
        });

        const received = await client.sync();

        expect(received).toHaveLength(1);
        expect(utf8Decode(received[0]?.event.payload ?? new Uint8Array())).toBe("healthy");
        expect(poisonRelay.queue.get(identityId(bob))).toHaveLength(0);
    });

    it("binds deduplication to the full signed event rather than publisher IDs", async () => {
        const alice = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const relayA = new TestTransport("a");
        const relayB = new TestTransport("b");
        const first = createRelayEvent(alice, "direct", utf8Encode("first"), [bob]);
        const originalSecond = createRelayEvent(carol, "direct", utf8Encode("second"), [bob]);
        const unsignedSecond = {
            ...originalSecond,
            id: first.id,
        };
        const second: RelayEvent = {
            ...unsignedSecond,
            signature: signBytes(carol, relayEventSignaturePayload(unsignedSecond)),
        };
        await relayA.publish(first);
        await relayB.publish(second);
        const client = new MurmurClient({
            identity: bob,
            store: new MemoryMurmurStore(),
            transports: [relayA, relayB],
        });

        const received = await client.sync();

        expect(received.map((item) => utf8Decode(item.event.payload)).sort()).toEqual([
            "first",
            "second",
        ]);
    });

    it("namespaces acknowledgement state when identities share one store", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const sender = generateIdentityKeyPair();
        const relay = new TestTransport("relay");
        const sharedStore = new MemoryMurmurStore();
        await relay.publish(createRelayEvent(sender, "direct", utf8Encode("both"), [alice, bob]));
        const aliceClient = new MurmurClient({
            identity: alice,
            store: sharedStore,
            transports: [relay],
        });
        const bobClient = new MurmurClient({
            identity: bob,
            store: sharedStore,
            transports: [relay],
        });

        const aliceDelivery = await aliceClient.sync();
        await aliceDelivery[0]?.acknowledge();

        expect(await bobClient.sync()).toHaveLength(1);
    });

    it("publishes prepared events and isolates retained retry failures", async () => {
        const alice = generateIdentityKeyPair();
        const healthy = new TestTransport("healthy");
        const offline = new RejectingTransport("offline");
        const client = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [offline, healthy],
        });
        const prepared = createRelayEvent(alice, "direct", utf8Encode("prepared"));

        const published = await client.publishEvent(prepared);
        const retried = await client.retryOutboundSettled();

        expect(published.event.id).toBe(prepared.id);
        expect(retried.results).toHaveLength(1);
        expect(retried.failures).toHaveLength(0);

        const unavailable = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [offline],
        });
        await expect(unavailable.publish("direct", utf8Encode("pending"))).rejects.toThrow();
        const report = await unavailable.retryOutboundSettled();
        expect(report.results).toHaveLength(0);
        expect(report.failures).toHaveLength(1);
    });

    it("never prunes events still pending on one relay", async () => {
        const alice = generateIdentityKeyPair();
        const healthy = new TestTransport("healthy");
        const offline = new RejectingTransport("offline");
        const client = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [healthy, offline],
            outboundHistoryLimit: 1,
        });

        await client.publish("direct", utf8Encode("first"));
        await client.publish("direct", utf8Encode("second"));

        expect((await client.retryOutboundSettled()).results).toHaveLength(2);
    });
});
