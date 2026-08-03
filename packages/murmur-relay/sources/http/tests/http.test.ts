import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import {
    relayEventSigningBytes,
    signedRelayEventToJson,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { createRelayFetchHandler } from "../index.js";

const now = 2_000_000;
const privateKey = new Uint8Array(32).fill(11);
const signingKey = ed25519.getPublicKey(privateKey);
const encoder = new TextEncoder();

interface EventOptions {
    readonly payload?: Uint8Array;
    readonly list?: readonly {
        readonly op: "append";
        readonly id: string;
        readonly bytes: Uint8Array;
    }[];
}

function event(id: string, expectedVersion: number, options: EventOptions = {}): SignedRelayEvent {
    const unsigned: {
        version: 1;
        id: string;
        topic: string;
        author: { signingKey: Uint8Array };
        createdAt: number;
        payload: Uint8Array;
        snapshot: {
            expectedVersion: number;
            bytes: Uint8Array;
        };
        list?: readonly {
            readonly op: "append";
            readonly id: string;
            readonly bytes: Uint8Array;
        }[];
        signature: Uint8Array;
    } = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode(id))),
        topic: "http",
        author: { signingKey },
        createdAt: now,
        payload: options.payload ?? encoder.encode("opaque"),
        snapshot: {
            expectedVersion,
            bytes: encoder.encode(`snapshot-${id}`),
        },
        signature: new Uint8Array(64),
    };
    if (options.list !== undefined) {
        unsigned.list = options.list;
    } else if (expectedVersion === 0) {
        unsigned.list = [{ op: "append", id: "element", bytes: encoder.encode("element") }];
    }
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), privateKey),
    };
}

describe("relay Fetch handler", () => {
    let service: RelayService | undefined;

    afterEach(async () => {
        await service?.close();
    });

    it("publishes and reads state and retained events as string bigints", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const publication = await handler(
            new Request("https://relay.test/v1/topics/http/events", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(signedRelayEventToJson(event("first", 0))),
            }),
        );
        expect(publication.status).toBe(200);
        expect(await publication.json()).toEqual({
            seq: "1",
            duplicate: false,
            snapshotVersion: "1",
        });

        const state = await handler(new Request("https://relay.test/v1/topics/http/state?limit=1"));
        expect(await state.json()).toMatchObject({
            seq: "1",
            snapshot: { version: "1" },
            list: {
                elements: [{ id: "element", version: "1" }],
                nextCursor: null,
            },
        });
        const events = await handler(
            new Request("https://relay.test/v1/topics/http/events?since=0"),
        );
        expect(await events.json()).toMatchObject({
            reset: false,
            seq: "1",
            events: [{ seq: "1", topic: "http" }],
        });
    });

    it("returns machine-readable conflicts and keeps CORS on failures", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        await handler(
            new Request("https://relay.test/v1/topics/http/events", {
                method: "POST",
                body: JSON.stringify(signedRelayEventToJson(event("first", 0))),
            }),
        );
        const conflict = await handler(
            new Request("https://relay.test/v1/topics/http/events", {
                method: "POST",
                headers: { origin: "https://app.test" },
                body: JSON.stringify(signedRelayEventToJson(event("stale", 0))),
            }),
        );
        expect(conflict.status).toBe(409);
        expect(conflict.headers.get("access-control-allow-origin")).toBe("*");
        expect(await conflict.json()).toEqual({
            error: "conflict",
            snapshotVersion: "1",
            elements: { element: "1" },
        });
    });

    it("truncates encoded event and list pages without hiding continuation", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const opaque = new Uint8Array(512).fill(3);
        await service.publish(
            event("large-first", 0, {
                payload: opaque,
                list: ["a", "b", "c"].map((id) => ({
                    op: "append" as const,
                    id,
                    bytes: opaque,
                })),
            }),
        );
        await service.publish(event("large-second", 1, { payload: opaque }));

        const oneItemHandler = createRelayFetchHandler(service, {
            maximumPageResponseBytes: 1,
        });
        const eventProbe = await oneItemHandler(
            new Request("https://relay.test/v1/topics/http/events?since=0"),
        );
        const eventBudget = Buffer.byteLength(await eventProbe.text());
        const boundedHandler = createRelayFetchHandler(service, {
            maximumPageResponseBytes: eventBudget,
        });
        const eventResponse = await boundedHandler(
            new Request("https://relay.test/v1/topics/http/events?since=0"),
        );
        const eventText = await eventResponse.text();
        const eventPage = JSON.parse(eventText) as {
            readonly events: readonly { readonly seq: string }[];
            readonly seq: string;
        };
        expect(Buffer.byteLength(eventText)).toBeLessThanOrEqual(eventBudget);
        expect(eventPage.events.map((retained) => retained.seq)).toEqual(["1"]);
        expect(eventPage.seq).toBe("2");
        const eventContinuation = await boundedHandler(
            new Request("https://relay.test/v1/topics/http/events?since=1"),
        );
        await expect(eventContinuation.json()).resolves.toMatchObject({
            events: [{ seq: "2" }],
            seq: "2",
        });

        const listProbe = await oneItemHandler(
            new Request("https://relay.test/v1/topics/http/list"),
        );
        const listBudget = Buffer.byteLength(await listProbe.text());
        const boundedListHandler = createRelayFetchHandler(service, {
            maximumPageResponseBytes: listBudget,
        });
        const listResponse = await boundedListHandler(
            new Request("https://relay.test/v1/topics/http/list"),
        );
        const listText = await listResponse.text();
        const listPage = JSON.parse(listText) as {
            readonly elements: readonly { readonly id: string }[];
            readonly nextCursor: string | null;
        };
        expect(Buffer.byteLength(listText)).toBeLessThanOrEqual(listBudget);
        expect(listPage.elements.map((element) => element.id)).toEqual(["a"]);
        expect(listPage.nextCursor).not.toBeNull();

        const continuation = await boundedListHandler(
            new Request(
                `https://relay.test/v1/topics/http/list?cursor=${encodeURIComponent(
                    listPage.nextCursor ?? "",
                )}`,
            ),
        );
        await expect(continuation.json()).resolves.toMatchObject({
            elements: [{ id: "b" }],
        });
    });

    it("reports health, malformed bodies, missing routes, and unsigned blob transfers", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const blob = encoder.encode("ciphertext");
        const id = encodeBase64Url(sha256(blob));
        const unsignedUpload = await handler(
            new Request(`https://relay.test/v1/blobs/${id}`, {
                method: "PUT",
                body: blob,
            }),
        );
        expect(unsignedUpload.status).toBe(404);

        const root = await handler(new Request("https://relay.test/"));
        expect(root.status).toBe(200);
        expect(root.headers.get("content-type")).toBe("text/plain; charset=utf-8");
        await expect(root.text()).resolves.toBe("Welcome to Murmur Relay!");
        const health = await handler(new Request("https://relay.test/health"));
        expect(await health.json()).toEqual({ ok: true });
        const malformed = await handler(
            new Request("https://relay.test/v1/topics/http/events", {
                method: "POST",
                body: "{",
            }),
        );
        expect(malformed.status).toBe(400);
        const missing = await handler(new Request("https://relay.test/nope"));
        expect(missing.status).toBe(404);
    });

    it("logs safe route summaries while suppressing successful health probes", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const messages: string[] = [];
        const handler = createRelayFetchHandler(service, {
            logger: {
                info: (message) => messages.push(`info ${message}`),
                warn: (message) => messages.push(`warn ${message}`),
                error: (message) => messages.push(`error ${message}`),
            },
        });
        await handler(new Request("https://relay.test/"));
        await handler(new Request("https://relay.test/health"));
        await handler(new Request("https://relay.test/v1/topics/private-topic/state"));

        expect(messages).toHaveLength(2);
        expect(messages[0]).toMatch(
            /^info http:request method=GET route=root status=200 durationMs=\d+$/,
        );
        expect(messages[1]).toMatch(
            /^warn http:request method=GET route=topic-state status=404 durationMs=\d+$/,
        );
        expect(messages.join("\n")).not.toContain("private-topic");
    });
});
