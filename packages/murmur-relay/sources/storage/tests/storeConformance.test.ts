import { PGlite } from "@electric-sql/pglite";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
    RelayConflictError,
    RelayError,
    relayEventSigningBytes,
    type ListOperation,
    type SignedRelayEvent,
    type SnapshotMutation,
} from "../../protocol/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { PGliteDatabase, PostgresRelayStore } from "../postgres/index.js";
import { SqliteRelayStore } from "../sqlite/index.js";
import type {
    EventPage,
    ListPage,
    PageReadConstraints,
    PublishOutcome,
    RelayStore,
    TopicState,
} from "../types.js";

const privateKey = new Uint8Array(32).fill(7);
const signingKey = ed25519.getPublicKey(privateKey);
const textEncoder = new TextEncoder();

function bytes(value: string): Uint8Array {
    return textEncoder.encode(value);
}

function eventId(value: string): string {
    return encodeBase64Url(sha256(bytes(value)));
}

function signedEvent(options: {
    readonly id: string;
    readonly topic: string;
    readonly payload?: string;
    readonly createdAt?: number;
    readonly snapshot?: SnapshotMutation;
    readonly list?: readonly ListOperation[];
}): SignedRelayEvent {
    const event: {
        version: 1;
        id: string;
        topic: string;
        author: { signingKey: Uint8Array };
        createdAt: number;
        payload: Uint8Array;
        snapshot?: SnapshotMutation;
        list?: readonly ListOperation[];
        signature: Uint8Array;
    } = {
        version: 1,
        id: eventId(options.id),
        topic: options.topic,
        author: { signingKey },
        createdAt: options.createdAt ?? 1_000,
        payload: bytes(options.payload ?? options.id),
        signature: new Uint8Array(64),
    };
    if (options.snapshot !== undefined) {
        event.snapshot = options.snapshot;
    }
    if (options.list !== undefined) {
        event.list = options.list;
    }
    event.signature = ed25519.sign(relayEventSigningBytes(event), privateKey);
    return event;
}

interface StoreBackend {
    readonly name: string;
    readonly create: () => Promise<RelayStore>;
}

const backends: readonly StoreBackend[] = [
    {
        name: "SQLite",
        create: async () => new SqliteRelayStore(":memory:"),
    },
    {
        name: "Postgres/PGlite",
        create: async () => PostgresRelayStore.create(new PGliteDatabase(new PGlite())),
    },
];

describe.each(backends)("$name RelayStore conformance", ({ create }) => {
    let store: RelayStore;
    let maximumElementsPerTopic: number;
    const pageReadConstraints: PageReadConstraints = {
        maximumEncodedBytes: Number.MAX_SAFE_INTEGER,
    };

    beforeEach(async () => {
        store = await create();
        maximumElementsPerTopic = 100_000;
    });

    afterEach(async () => {
        await store.close();
    });

    function publish(event: SignedRelayEvent, now: number): Promise<PublishOutcome> {
        return store.publish(event, now, { maximumElementsPerTopic });
    }

    function readState(topic: string, limit: number): Promise<TopicState | undefined> {
        return store.readState(topic, limit, pageReadConstraints);
    }

    function readList(
        topic: string,
        cursor: string | undefined,
        limit: number,
    ): Promise<ListPage | undefined> {
        return store.readList(topic, cursor, limit, pageReadConstraints);
    }

    function readEvents(
        topic: string,
        since: bigint,
        limit: number,
    ): Promise<EventPage | undefined> {
        return store.readEvents(topic, since, limit, pageReadConstraints);
    }

    it("preserves append order across replace and delete", async () => {
        await publish(
            signedEvent({
                id: "order-1",
                topic: "ordered",
                list: [
                    { op: "append", id: "a", bytes: bytes("A1") },
                    { op: "append", id: "b", bytes: bytes("B1") },
                ],
            }),
            100,
        );
        await publish(
            signedEvent({
                id: "order-2",
                topic: "ordered",
                list: [
                    {
                        op: "replace",
                        id: "a",
                        expectedVersion: 1,
                        bytes: bytes("A2"),
                    },
                    { op: "delete", id: "b", expectedVersion: 1 },
                    { op: "append", id: "c", bytes: bytes("C1") },
                ],
            }),
            200,
        );

        const state = await readState("ordered", 10);
        expect(state?.seq).toBe(2n);
        expect(
            state?.list.elements.map((element) => ({
                id: element.id,
                version: element.version,
                position: element.position,
                bytes: new TextDecoder().decode(element.bytes),
            })),
        ).toEqual([
            { id: "a", version: 2n, position: 1n, bytes: "A2" },
            { id: "c", version: 1n, position: 3n, bytes: "C1" },
        ]);
    });

    it("recreates an absent snapshot without reusing its generation", async () => {
        const first = await publish(
            signedEvent({
                id: "snapshot-1",
                topic: "snapshot",
                snapshot: { expectedVersion: 0, bytes: bytes("one") },
            }),
            100,
        );
        const second = await publish(
            signedEvent({
                id: "snapshot-2",
                topic: "snapshot",
                snapshot: { expectedVersion: 1, bytes: bytes("two") },
            }),
            200,
        );
        const deleted = await publish(
            signedEvent({
                id: "snapshot-3",
                topic: "snapshot",
                snapshot: { expectedVersion: 2 },
            }),
            300,
        );

        expect(first.snapshotVersion).toBe(1n);
        expect(second.snapshotVersion).toBe(2n);
        expect(deleted.snapshotVersion).toBe(3n);
        expect((await readState("snapshot", 10))?.snapshot).toBeNull();

        const recreated = await publish(
            signedEvent({
                id: "snapshot-4",
                topic: "snapshot",
                snapshot: { expectedVersion: 0, bytes: bytes("three") },
            }),
            400,
        );
        expect(recreated.snapshotVersion).toBe(4n);
        expect((await readState("snapshot", 10))?.snapshot?.version).toBe(4n);

        await expect(
            publish(
                signedEvent({
                    id: "snapshot-stale",
                    topic: "snapshot",
                    snapshot: { expectedVersion: 0, bytes: bytes("stale") },
                }),
                500,
            ),
        ).rejects.toMatchObject({
            status: 409,
            snapshotVersion: 4n,
        });
    });

    it("rolls back snapshot, list, event, and seq on one failing operation", async () => {
        await publish(
            signedEvent({
                id: "atomic-1",
                topic: "atomic",
                snapshot: { expectedVersion: 0, bytes: bytes("before") },
                list: [{ op: "append", id: "a", bytes: bytes("before") }],
            }),
            100,
        );

        const failure = publish(
            signedEvent({
                id: "atomic-2",
                topic: "atomic",
                snapshot: { expectedVersion: 1, bytes: bytes("after") },
                list: [
                    {
                        op: "replace",
                        id: "a",
                        expectedVersion: 99,
                        bytes: bytes("after"),
                    },
                ],
            }),
            200,
        );
        await expect(failure).rejects.toBeInstanceOf(RelayConflictError);
        await expect(failure).rejects.toMatchObject({
            snapshotVersion: 1n,
            elements: { a: 1n },
        });

        const state = await readState("atomic", 10);
        expect(state?.seq).toBe(1n);
        expect(new TextDecoder().decode(state?.snapshot?.bytes)).toBe("before");
        expect(state?.list.elements[0]?.version).toBe(1n);
        expect(new TextDecoder().decode(state?.list.elements[0]?.bytes)).toBe("before");
        expect((await readEvents("atomic", 0n, 10))?.events).toHaveLength(1);
    });

    it("does not leak a receipt when publish rolls back", async () => {
        const retry = signedEvent({
            id: "retry-after-failure",
            topic: "receipt-rollback",
            snapshot: { expectedVersion: 1, bytes: bytes("second") },
        });
        await expect(publish(retry, 100)).rejects.toBeInstanceOf(RelayConflictError);
        expect(await store.readPublishReceipt(retry.topic, retry.id)).toBeUndefined();

        await publish(
            signedEvent({
                id: "receipt-setup",
                topic: "receipt-rollback",
                snapshot: { expectedVersion: 0, bytes: bytes("first") },
            }),
            200,
        );
        await expect(publish(retry, 300)).resolves.toEqual({
            seq: 2n,
            duplicate: false,
            snapshotVersion: 2n,
        });
    });

    it("returns the original outcome for retries and rejects id collisions", async () => {
        const original = signedEvent({
            id: "same-id",
            topic: "idempotent",
            snapshot: { expectedVersion: 0, bytes: bytes("one") },
        });
        const first = await publish(original, 100);
        await publish(
            signedEvent({
                id: "later",
                topic: "idempotent",
                snapshot: { expectedVersion: 1, bytes: bytes("two") },
            }),
            200,
        );
        const duplicate = await publish(original, 300);

        expect(first).toEqual({
            seq: 1n,
            duplicate: false,
            snapshotVersion: 1n,
        });
        expect(duplicate).toEqual({
            seq: 1n,
            duplicate: true,
            snapshotVersion: 1n,
        });
        await expect(
            publish(
                signedEvent({
                    id: "same-id",
                    topic: "idempotent",
                    payload: "different",
                }),
                400,
            ),
        ).rejects.toMatchObject({
            status: 409,
            body: { error: "id_collision" },
        });
    });

    it("allocates monotonic gapless sequences under concurrent calls", async () => {
        const outcomes = await Promise.all(
            Array.from({ length: 12 }, (_, index) =>
                publish(
                    signedEvent({
                        id: `sequence-${index}`,
                        topic: "sequence",
                    }),
                    100 + index,
                ),
            ),
        );
        expect(
            outcomes.map((outcome) => outcome.seq).sort((left, right) => (left < right ? -1 : 1)),
        ).toEqual(Array.from({ length: 12 }, (_, index) => BigInt(index + 1)));
        expect((await readEvents("sequence", 0n, 20))?.seq).toBe(12n);
    });

    it("advances the reset watermark when retained events are pruned", async () => {
        const first = signedEvent({
            id: "retention-1",
            topic: "retention",
            list: [{ op: "append", id: "permanent", bytes: bytes("kept") }],
        });
        await publish(first, 100);
        await publish(signedEvent({ id: "retention-2", topic: "retention" }), 200);
        await publish(signedEvent({ id: "retention-3", topic: "retention" }), 300);

        expect(await store.pruneEvents(250)).toBe(2);
        expect(await readEvents("retention", 0n, 10)).toEqual({
            events: [],
            reset: true,
            seq: 3n,
        });
        const available = await readEvents("retention", 2n, 10);
        expect(available?.reset).toBe(false);
        expect(available?.events.map((event) => event.seq)).toEqual([3n]);
        expect((await readState("retention", 10))?.list.elements[0]?.id).toBe("permanent");
        expect(await publish(first, 400)).toEqual({
            seq: 1n,
            duplicate: true,
        });
        expect((await readState("retention", 10))?.seq).toBe(3n);
    });

    it("returns no reset page for a topic that has never existed", async () => {
        expect(await readEvents("empty", 0n, 10)).toBeUndefined();
    });

    it("requires reset when all retained events have been pruned", async () => {
        await publish(signedEvent({ id: "all-pruned-1", topic: "all-pruned" }), 100);
        await publish(signedEvent({ id: "all-pruned-2", topic: "all-pruned" }), 200);

        expect(await store.pruneEvents(300)).toBe(2);
        expect(await readEvents("all-pruned", 0n, 10)).toEqual({
            events: [],
            reset: true,
            seq: 2n,
        });
        expect(await readEvents("all-pruned", 2n, 10)).toEqual({
            events: [],
            reset: false,
            seq: 2n,
        });
    });

    it("requires reset for a cursor beyond the topic head", async () => {
        await publish(signedEvent({ id: "future-cursor", topic: "future-cursor" }), 100);

        expect(await readEvents("future-cursor", 2n, 10)).toEqual({
            events: [],
            reset: true,
            seq: 1n,
        });
    });

    it("paginates the permanent list without changing relay order", async () => {
        await publish(
            signedEvent({
                id: "page",
                topic: "pages",
                list: Array.from({ length: 5 }, (_, index) => ({
                    op: "append" as const,
                    id: `item-${index}`,
                    bytes: bytes(`${index}`),
                })),
            }),
            100,
        );

        const first = await readState("pages", 2);
        expect(first?.list.elements.map((element) => element.id)).toEqual(["item-0", "item-1"]);
        expect(first?.list.nextCursor).not.toBeNull();
        const second = await readList("pages", first?.list.nextCursor ?? undefined, 2);
        expect(second?.elements.map((element) => element.id)).toEqual(["item-2", "item-3"]);
        const third = await readList("pages", second?.nextCursor ?? undefined, 2);
        expect(third?.elements.map((element) => element.id)).toEqual(["item-4"]);
        expect(third?.nextCursor).toBeNull();
    });

    it("bounds materialized pages while preserving list and event continuation", async () => {
        await publish(
            signedEvent({
                id: "byte-page-1",
                topic: "byte-pages",
                payload: "x".repeat(512),
                list: ["a", "b", "c"].map((id) => ({
                    op: "append" as const,
                    id,
                    bytes: bytes("x".repeat(512)),
                })),
            }),
            100,
        );
        await publish(
            signedEvent({
                id: "byte-page-2",
                topic: "byte-pages",
                payload: "y".repeat(512),
            }),
            200,
        );
        const oneItem: PageReadConstraints = { maximumEncodedBytes: 1 };

        const state = await store.readState("byte-pages", 10, oneItem);
        expect(state?.list.elements.map((element) => element.id)).toEqual(["a"]);
        expect(state?.list.nextCursor).not.toBeNull();
        const nextList = await store.readList(
            "byte-pages",
            state?.list.nextCursor ?? undefined,
            10,
            oneItem,
        );
        expect(nextList?.elements.map((element) => element.id)).toEqual(["b"]);
        expect(nextList?.nextCursor).not.toBeNull();

        const events = await store.readEvents("byte-pages", 0n, 10, oneItem);
        expect(events?.events.map((retained) => retained.seq)).toEqual([1n]);
        expect(events?.seq).toBe(2n);
        expect(
            (
                await store.readEvents("byte-pages", events?.events[0]?.seq ?? 0n, 10, oneItem)
            )?.events.map((retained) => retained.seq),
        ).toEqual([2n]);
    });

    it("drops only inactive topics and leaves blobs permanent", async () => {
        await publish(signedEvent({ id: "old", topic: "old" }), 100);
        await publish(signedEvent({ id: "new", topic: "new" }), 300);
        const blobBytes = bytes("permanent blob");
        const blobId = encodeBase64Url(sha256(blobBytes));
        await store.putBlob({ id: blobId, bytes: blobBytes });

        expect(await store.pruneInactiveTopics(200)).toEqual({ topics: 1 });
        expect(await readState("old", 10)).toBeUndefined();
        expect(await readState("new", 10)).toBeDefined();
        expect((await store.getBlob(blobId))?.bytes).toEqual(blobBytes);
    });

    it("round-trips content-addressed blobs and rejects a hash mismatch", async () => {
        const blobBytes = bytes("ciphertext");
        const id = encodeBase64Url(sha256(blobBytes));
        await store.putBlob({ id, bytes: blobBytes });
        await store.putBlob({ id, bytes: blobBytes });

        expect(await store.getBlob(id)).toEqual({ id, bytes: blobBytes });
        await expect(
            store.putBlob({
                id,
                bytes: bytes("tampered"),
            }),
        ).rejects.toMatchObject({
            status: 400,
            body: { error: "hash_mismatch" },
        });
    });

    it("enforces the configured live element capacity atomically", async () => {
        await store.close();
        store = await create();
        maximumElementsPerTopic = 1;
        await publish(
            signedEvent({
                id: "capacity-1",
                topic: "capacity",
                list: [{ op: "append", id: "a", bytes: bytes("a") }],
            }),
            100,
        );
        await expect(
            publish(
                signedEvent({
                    id: "capacity-2",
                    topic: "capacity",
                    list: [{ op: "append", id: "b", bytes: bytes("b") }],
                }),
                200,
            ),
        ).rejects.toBeInstanceOf(RelayError);
        expect((await readState("capacity", 10))?.seq).toBe(1n);
    });
});
