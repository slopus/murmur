import {
    MurmurClient,
    MemoryMurmurStore,
    createQueueAcknowledgeRequest,
    createQueueReadRequest,
    createRelayBlob,
    createRelayEvent,
    createTopicSubscription,
    generateIdentityKeyPair,
    utf8Decode,
    utf8Encode,
    type IdentityKeyPair,
    type RelayEvent,
    type TopicSubscription,
} from "@murmur/core";
import { describe, expect, it } from "vitest";
import { RelayService } from "../index.js";
import { MemoryRelayStore } from "../../storage/index.js";
import { EmbeddedRelayTransport } from "../../transport/index.js";

function pull(
    relay: RelayService,
    identity: IdentityKeyPair,
    waitMilliseconds: number = 0,
    now: number = Date.now(),
    signal?: AbortSignal,
) {
    return relay.pull(createQueueReadRequest(identity, now), waitMilliseconds, signal);
}

class RecordingStore extends MemoryRelayStore {
    recordedEvent: RelayEvent | undefined;
    recordedSubscription: TopicSubscription | undefined;

    override async publish(event: RelayEvent, observedAt: number) {
        this.recordedEvent = event;
        return super.publish(event, observedAt);
    }

    override async addSubscription(
        subscription: TopicSubscription,
        observedAt: number,
    ): Promise<number> {
        this.recordedSubscription = subscription;
        return super.addSubscription(subscription, observedAt);
    }
}

describe("RelayService", () => {
    it("fans out one opaque event into per-recipient queues", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        await relay.subscribe(createTopicSubscription(bob, "room"));
        await relay.subscribe(createTopicSubscription(carol, "room"));

        const event = createRelayEvent(alice, "room", utf8Encode("ciphertext"));
        await relay.publish(event);
        await relay.publish(event);

        expect(await pull(relay, bob)).toHaveLength(1);
        expect(await pull(relay, carol)).toHaveLength(1);
        expect(await pull(relay, alice)).toHaveLength(0);
    });

    it("wakes a long poll and preserves the event until ack", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const pendingPull = pull(relay, bob, 1_000);

        await relay.publish(createRelayEvent(alice, "direct", utf8Encode("x"), [bob]));
        const deliveries = await pendingPull;
        expect(deliveries).toHaveLength(1);
        expect(await pull(relay, bob)).toHaveLength(1);

        const deliveryId = deliveries[0]?.deliveryId;
        expect(deliveryId).toBeDefined();
        await relay.acknowledge(createQueueAcknowledgeRequest(bob, deliveryId ?? ""));
        expect(await pull(relay, bob)).toHaveLength(0);
    });

    it("rejects corrupt blobs", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const blob = createRelayBlob(utf8Encode("ciphertext"));

        await relay.putBlob(blob);
        await expect(relay.putBlob({ ...blob, bytes: utf8Encode("tampered") })).rejects.toThrow(
            "does not match",
        );
    });

    it("expires inactive topics using relay-observed time", async () => {
        let now = 100;
        const relay = new RelayService(
            new MemoryRelayStore(),
            { topicInactivityMilliseconds: 10 },
            () => now,
        );
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        await relay.subscribe(createTopicSubscription(bob, "room", now));
        await relay.publish(createRelayEvent(alice, "room", utf8Encode("x"), [], 999_999));

        now = 111;
        expect(await relay.pruneInactiveTopics()).toEqual({ topics: 1, deliveries: 1 });
        expect(await pull(relay, bob, 0, now)).toHaveLength(0);
    });

    it("integrates with multi-relay Murmur clients", async () => {
        const service = new RelayService(new MemoryRelayStore());
        const transport = new EmbeddedRelayTransport("embedded", service);
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceClient = new MurmurClient({
            identity: alice,
            store: new MemoryMurmurStore(),
            transports: [transport],
        });
        const bobClient = new MurmurClient({
            identity: bob,
            store: new MemoryMurmurStore(),
            transports: [transport],
        });

        await bobClient.subscribe("room");
        await aliceClient.publish("room", utf8Encode("opaque"));
        const received = await bobClient.sync();

        expect(utf8Decode(received[0]?.event.payload ?? new Uint8Array())).toBe("opaque");
        await received[0]?.acknowledge();
        expect(await bobClient.sync()).toHaveLength(0);
    });

    it("stops the client event stream when a long poll is aborted", async () => {
        const service = new RelayService(new MemoryRelayStore());
        const transport = new EmbeddedRelayTransport("embedded", service);
        const client = new MurmurClient({
            identity: generateIdentityKeyPair(),
            store: new MemoryMurmurStore(),
            transports: [transport],
        });
        const controller = new AbortController();
        const iterator = client.events(controller.signal, 1_000)[Symbol.asyncIterator]();
        const next = iterator.next();

        controller.abort();

        await expect(next).resolves.toEqual({ done: true, value: undefined });
    });

    it("requires recipient signatures and rejects replayed queue requests", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        await relay.publish(createRelayEvent(alice, "direct", utf8Encode("secret"), [bob]));
        const readRequest = createQueueReadRequest(bob);
        const deliveries = await relay.pull(readRequest);
        const deliveryId = deliveries[0]?.deliveryId ?? "";
        const forged = {
            ...createQueueAcknowledgeRequest(eve, deliveryId),
            recipient: {
                signingKey: bob.signingKey,
                encryptionKey: bob.encryptionKey,
            },
        };

        await expect(relay.acknowledge(forged)).rejects.toThrow("Invalid queue request");
        expect(await pull(relay, bob)).toHaveLength(1);
        await expect(relay.pull(readRequest)).rejects.toThrow("Replayed queue request");
    });

    it("retains future-skewed replay IDs for their entire validity window", async () => {
        let now = 1_000;
        const relay = new RelayService(new MemoryRelayStore(), {}, () => now);
        const bob = generateIdentityKeyPair();
        const futureRequest = createQueueReadRequest(bob, now + 5 * 60 * 1_000);

        await relay.pull(futureRequest);
        now += 1;

        await expect(relay.pull(futureRequest)).rejects.toThrow("Replayed queue request");
    });

    it("rejects stale topic subscriptions", async () => {
        const now = 10 * 60 * 1_000;
        const relay = new RelayService(new MemoryRelayStore(), {}, () => now);
        const bob = generateIdentityKeyPair();

        await expect(
            relay.subscribe(createTopicSubscription(bob, "room", now - 5 * 60 * 1_000 - 1)),
        ).rejects.toThrow("Expired topic subscription");
    });

    it("replays retained broadcast history to a late subscriber", async () => {
        const relay = new RelayService(new MemoryRelayStore());
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        await relay.publish(createRelayEvent(alice, "room", utf8Encode("before")));

        await relay.subscribe(createTopicSubscription(bob, "room"));

        const deliveries = await pull(relay, bob);
        expect(deliveries).toHaveLength(1);
        expect(utf8Decode(deliveries[0]?.event.payload ?? new Uint8Array())).toBe("before");
    });

    it("bounds recipient fan-out and cancels long polls", async () => {
        const relay = new RelayService(new MemoryRelayStore(), {
            maximumRecipients: 1,
        });
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        await expect(
            relay.publish(createRelayEvent(alice, "room", utf8Encode("x"), [bob, carol])),
        ).rejects.toThrow("recipients");

        const controller = new AbortController();
        const pending = pull(relay, bob, 1_000, Date.now(), controller.signal);
        controller.abort(new Error("disconnected"));

        await expect(pending).rejects.toThrow("disconnected");
    });

    it("strips structural secret-key extras before custom storage", async () => {
        const store = new RecordingStore();
        const relay = new RelayService(store);
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "room", utf8Encode("x"));
        const subscription = createTopicSubscription(alice, "room");

        await relay.subscribe({ ...subscription, subscriber: alice });
        await relay.publish({ ...event, sender: alice });

        expect("signingSecretKey" in (store.recordedEvent?.sender ?? {})).toBe(false);
        expect("encryptionSecretKey" in (store.recordedSubscription?.subscriber ?? {})).toBe(false);
    });
});
