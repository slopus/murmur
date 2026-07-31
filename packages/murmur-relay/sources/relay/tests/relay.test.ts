import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { relayEventSigningBytes, type SignedRelayEvent } from "../../protocol/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import type { PublishConstraints, RelayStore } from "../../storage/types.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { RelayService } from "../index.js";

const now = 1_000_000;
const privateKey = new Uint8Array(32).fill(9);
const signingKey = ed25519.getPublicKey(privateKey);
const encoder = new TextEncoder();

function resign(event: SignedRelayEvent): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        ...event,
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), privateKey),
    };
}

function event(id: string, createdAt: number = now): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode(id))),
        topic: "long-poll",
        author: { signingKey },
        createdAt,
        payload: encoder.encode(id),
        signature: new Uint8Array(64),
    };
    return resign(unsigned);
}

describe("RelayService", () => {
    let service: RelayService | undefined;

    afterEach(async () => {
        await service?.close();
    });

    it("wakes a parked event read and re-reads the committed event", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        await service.publish(event("first"));
        const pending = service.readEvents("long-poll", 1n, 10, 1_000);
        await new Promise<void>((resolve) => setImmediate(resolve));
        await service.publish(event("second"));

        const page = await pending;
        expect(page?.events.map((retained) => retained.seq)).toEqual([2n]);
    });

    it("uses the post-registration recheck to close the park/arrive race", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        await service.publish(event("first"));
        const pending = service.readEvents("long-poll", 1n, 10, 1_000);
        await service.publish(event("racing"));

        await expect(pending).resolves.toMatchObject({
            reset: false,
            seq: 2n,
        });
    });

    it("returns the original outcome for an authenticated retry regardless of age", async () => {
        let clock = now;
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => clock);
        const original = event("durable-retry", clock);
        await expect(service.publish(original)).resolves.toEqual({
            seq: 1n,
            duplicate: false,
        });

        clock += 300_001;
        await expect(service.publish(original)).resolves.toEqual({
            seq: 1n,
            duplicate: true,
        });
        await expect(
            service.publish(
                resign({
                    ...original,
                    payload: encoder.encode("different"),
                }),
            ),
        ).rejects.toMatchObject({
            status: 409,
            body: { error: "id_collision" },
        });
        await expect(service.publish(event("genuinely-new", now))).rejects.toMatchObject({
            status: 401,
            body: { error: "unauthorized" },
        });
    });

    it("rejects timestamp, signature, size, and waiter overload failures", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                maximumEventPayloadBytes: 3,
                maximumConcurrentLongPolls: 1,
            },
            undefined,
            () => now,
        );
        await expect(service.publish(event("expired", now - 300_001))).rejects.toMatchObject({
            status: 413,
        });
        await expect(
            service.publish(
                resign({
                    ...event("x", now - 300_001),
                    payload: new Uint8Array(),
                }),
            ),
        ).rejects.toMatchObject({ status: 401 });
        const small = event("ok");
        const badSignature = {
            ...small,
            payload: new Uint8Array([1]),
            signature: new Uint8Array(64),
        };
        await expect(service.publish(badSignature)).rejects.toMatchObject({ status: 401 });

        const validSmallUnsigned: SignedRelayEvent = {
            ...small,
            payload: new Uint8Array(),
            signature: new Uint8Array(64),
        };
        const validSmall: SignedRelayEvent = {
            ...validSmallUnsigned,
            signature: ed25519.sign(relayEventSigningBytes(validSmallUnsigned), privateKey),
        };
        await service.publish(validSmall);
        const firstWaiter = service.readEvents("long-poll", 1n, 10, 1_000);
        await new Promise<void>((resolve) => setImmediate(resolve));
        await expect(service.readEvents("long-poll", 1n, 10, 1_000)).rejects.toMatchObject({
            status: 503,
        });
        await service.publish(
            resign({
                ...event("wake"),
                payload: new Uint8Array(),
            }),
        );
        await firstWaiter;
    });

    it("passes list capacity explicitly to a custom store publish", async () => {
        const backingStore = new SqliteRelayStore(":memory:");
        let receivedConstraints: PublishConstraints | undefined;
        const customStore: RelayStore = {
            readPublishReceipt: (topic, id) => backingStore.readPublishReceipt(topic, id),
            publish: (published, observedAt, constraints) => {
                receivedConstraints = constraints;
                return backingStore.publish(published, observedAt, constraints);
            },
            readState: (topic, limit, constraints) =>
                backingStore.readState(topic, limit, constraints),
            readList: (topic, cursor, limit, constraints) =>
                backingStore.readList(topic, cursor, limit, constraints),
            readEvents: (topic, since, limit, constraints) =>
                backingStore.readEvents(topic, since, limit, constraints),
            putBlob: (blob) => backingStore.putBlob(blob),
            getBlob: (id) => backingStore.getBlob(id),
            pruneEvents: (olderThan) => backingStore.pruneEvents(olderThan),
            pruneInactiveTopics: (olderThan) => backingStore.pruneInactiveTopics(olderThan),
            health: () => backingStore.health(),
            close: () => backingStore.close(),
        };
        service = new RelayService(
            customStore,
            { maximumElementsPerTopic: 1 },
            undefined,
            () => now,
        );
        await service.publish(
            resign({
                ...event("capacity-1"),
                topic: "capacity",
                list: [{ op: "append", id: "a", bytes: new Uint8Array() }],
            }),
        );
        await expect(
            service.publish(
                resign({
                    ...event("capacity-2"),
                    topic: "capacity",
                    list: [{ op: "append", id: "b", bytes: new Uint8Array() }],
                }),
            ),
        ).rejects.toMatchObject({ status: 413 });
        expect(receivedConstraints).toEqual({ maximumElementsPerTopic: 1 });
        expect((await service.readState("capacity"))?.seq).toBe(1n);
    });
});
