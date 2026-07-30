import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
    createQueueAcknowledgeRequest,
    createQueueReadRequest,
    createRelayBlob,
    createRelayEvent,
    createTopicSubscription,
    generateIdentityKeyPair,
    utf8Decode,
    utf8Encode,
} from "@murmur/core";
import { RelayService } from "@murmur/relay";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteRelayStore } from "../index.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { recursive: true, force: true });
    }
});

describe("SqliteRelayStore", () => {
    it("survives closing and reopening a database file", async () => {
        const directory = mkdtempSync(join(tmpdir(), "murmur-relay-"));
        temporaryDirectories.push(directory);
        const path = join(directory, "relay.sqlite");
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const blob = createRelayBlob(utf8Encode("durable ciphertext"));
        const firstStore = new SqliteRelayStore(path);
        const firstRelay = new RelayService(firstStore);
        await firstRelay.subscribe(createTopicSubscription(bob, "room"));
        await firstRelay.publish(createRelayEvent(alice, "room", utf8Encode("durable event")));
        await firstRelay.putBlob(blob);
        firstStore.close();

        const secondStore = new SqliteRelayStore(path);
        const secondRelay = new RelayService(secondStore);
        const deliveries = await secondRelay.pull(createQueueReadRequest(bob));

        expect(utf8Decode(deliveries[0]?.event.payload ?? new Uint8Array())).toBe("durable event");
        expect(await secondRelay.getBlob(blob.id)).toEqual(blob);
        secondStore.close();
    });

    it("persists offline queues, replay, acknowledgements, and blobs", async () => {
        const store = new SqliteRelayStore(":memory:");
        const relay = new RelayService(store);
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        await relay.publish(createRelayEvent(alice, "room", utf8Encode("before")));
        await relay.subscribe(createTopicSubscription(bob, "room"));

        const request = createQueueReadRequest(bob);
        const deliveries = await relay.pull(request);
        expect(utf8Decode(deliveries[0]?.event.payload ?? new Uint8Array())).toBe("before");
        await expect(relay.pull(request)).rejects.toThrow("Replayed");
        const identifier = deliveries[0]?.deliveryId ?? "";
        await relay.acknowledge(createQueueAcknowledgeRequest(bob, identifier));
        expect(await relay.pull(createQueueReadRequest(bob))).toHaveLength(0);

        const blob = createRelayBlob(utf8Encode("ciphertext"));
        await relay.putBlob(blob);
        expect(await relay.getBlob(blob.id)).toEqual(blob);
        store.close();
    });

    it("keeps publication idempotence and pruning atomic", async () => {
        let now = 10;
        const store = new SqliteRelayStore(":memory:");
        const relay = new RelayService(store, { topicInactivityMilliseconds: 5 }, () => now);
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        await relay.subscribe(createTopicSubscription(bob, "room", now));
        const event = createRelayEvent(alice, "room", utf8Encode("one"), [], now);
        await relay.publish(event);
        await relay.publish(event);
        expect(await relay.pull(createQueueReadRequest(bob, now))).toHaveLength(1);

        now = 16;
        expect(await relay.pruneInactiveTopics()).toEqual({
            topics: 1,
            deliveries: 1,
        });
        store.close();
    });

    it("preserves publication order across bounded queue pages", async () => {
        const store = new SqliteRelayStore(":memory:");
        const relay = new RelayService(store);
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        for (let index = 0; index < 20; index += 1) {
            await relay.publish(
                createRelayEvent(alice, "ordered", utf8Encode(String(index).padStart(2, "0"))),
            );
        }
        await relay.subscribe(createTopicSubscription(bob, "ordered"));

        const firstPage = await relay.pull(createQueueReadRequest(bob));
        expect(firstPage).toHaveLength(16);
        for (const delivery of firstPage) {
            await relay.acknowledge(createQueueAcknowledgeRequest(bob, delivery.deliveryId));
        }
        const secondPage = await relay.pull(createQueueReadRequest(bob));

        expect(
            [...firstPage, ...secondPage].map((delivery) => utf8Decode(delivery.event.payload)),
        ).toEqual(Array.from({ length: 20 }, (_, index) => String(index).padStart(2, "0")));
        store.close();
    });

    it("prunes more topics than SQLite's variable limit", async () => {
        const store = new SqliteRelayStore(":memory:");
        const bob = generateIdentityKeyPair();
        for (let index = 0; index < 1_100; index += 1) {
            await store.addSubscription(createTopicSubscription(bob, `topic-${index}`, 0), 0);
        }

        expect(await store.pruneInactiveTopics(1)).toEqual({
            topics: 1_100,
            deliveries: 0,
        });
        store.close();
    });
});
