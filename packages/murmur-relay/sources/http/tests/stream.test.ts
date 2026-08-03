import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { relayEventSigningBytes, type SignedRelayEvent } from "../../protocol/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { createRelayFetchHandler } from "../index.js";

const now = 2_000_000;
const privateKey = new Uint8Array(32).fill(7);
const signingKey = ed25519.getPublicKey(privateKey);
const encoder = new TextEncoder();

interface SseEvent {
    readonly event: string | undefined;
    readonly data: string | undefined;
    readonly comment: string | undefined;
}

function parseBlock(raw: string): SseEvent {
    let event: string | undefined;
    let data: string | undefined;
    let comment: string | undefined;
    for (const line of raw.split("\n")) {
        if (line.startsWith(":")) {
            comment = line.slice(1).trimStart();
        } else if (line.startsWith("event:")) {
            event = line.slice("event:".length).trimStart();
        } else if (line.startsWith("data:")) {
            data = line.slice("data:".length).trimStart();
        }
    }
    return { event, data, comment };
}

/** Minimal incremental parser for the named SSE events under test. */
class SseReader {
    readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
    readonly #decoder = new TextDecoder();
    #buffer = "";
    readonly #queue: SseEvent[] = [];

    constructor(body: ReadableStream<Uint8Array>) {
        this.#reader = body.getReader();
    }

    async next(): Promise<SseEvent> {
        while (this.#queue.length === 0) {
            const result = await this.#reader.read();
            if (result.done) {
                throw new Error("SSE stream ended unexpectedly");
            }
            this.#buffer += this.#decoder.decode(result.value, { stream: true });
            let boundary = this.#buffer.indexOf("\n\n");
            while (boundary !== -1) {
                this.#queue.push(parseBlock(this.#buffer.slice(0, boundary)));
                this.#buffer = this.#buffer.slice(boundary + 2);
                boundary = this.#buffer.indexOf("\n\n");
            }
        }
        const next = this.#queue.shift();
        if (next === undefined) {
            throw new Error("unreachable empty SSE queue");
        }
        return next;
    }

    async cancel(): Promise<void> {
        await this.#reader.cancel().catch(() => undefined);
    }
}

function bodyOf(response: Response): ReadableStream<Uint8Array> {
    const body = response.body;
    if (body === null) {
        throw new Error("expected a streaming body");
    }
    return body;
}

function signedEvent(topic: string, id: string): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode(id))),
        topic,
        author: { signingKey },
        createdAt: now,
        payload: encoder.encode(id),
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), privateKey),
    };
}

function streamRequest(topic: string, signal: AbortSignal): Request {
    return new Request(`https://relay.test/v1/topics/${topic}/stream`, { signal });
}

function ephemeralRequest(topic: string, frame: Uint8Array): Request {
    return new Request(`https://relay.test/v1/topics/${topic}/ephemeral`, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: frame,
    });
}

/** An ephemeral POST whose `content-type` is wrong on purpose. */
function untypedEphemeralRequest(topic: string, frame: Uint8Array): Request {
    return new Request(`https://relay.test/v1/topics/${topic}/ephemeral`, {
        method: "POST",
        headers: { "content-type": "text/plain;charset=UTF-8" },
        body: frame,
    });
}

async function tick(): Promise<void> {
    await new Promise<void>((resolve) => setImmediate(resolve));
}

describe("relay ephemeral stream handler", () => {
    let service: RelayService | undefined;

    afterEach(async () => {
        await service?.close();
    });

    it("delivers a frame posted after the stream connected", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
        expect(response.headers.get("cache-control")).toBe("no-cache");
        expect(response.headers.get("x-accel-buffering")).toBe("no");
        expect(response.headers.get("access-control-allow-origin")).toBe("*");

        const sse = new SseReader(bodyOf(response));
        const ready = await sse.next();
        expect(ready.event).toBe("ready");
        expect(JSON.parse(ready.data ?? "")).toEqual({ topic: "room" });

        const post = await handler(ephemeralRequest("room", new Uint8Array([1, 2, 3])));
        expect(post.status).toBe(200);
        expect(await post.json()).toEqual({ delivered: 1 });

        const frame = await sse.next();
        expect(frame.event).toBe("frame");
        expect(decodeBase64Url(frame.data ?? "")).toEqual(new Uint8Array([1, 2, 3]));

        controller.abort();
        await sse.cancel();
    });

    it("never persists an ephemeral frame", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        const sse = new SseReader(bodyOf(response));
        await sse.next();

        expect(await handler(ephemeralRequest("room", new Uint8Array([9, 9, 9])))).toMatchObject({
            status: 200,
        });
        await sse.next();

        const state = await handler(new Request("https://relay.test/v1/topics/room/state"));
        expect(state.status).toBe(404);
        const list = await handler(new Request("https://relay.test/v1/topics/room/list"));
        expect(list.status).toBe(404);
        const events = await handler(
            new Request("https://relay.test/v1/topics/room/events?since=0"),
        );
        expect(events.status).toBe(404);

        controller.abort();
        await sse.cancel();
    });

    it("drops the oldest frames for a stalled consumer and reports the count", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumStreamQueueFrames: 2, maximumStreamQueueBytes: 1_000_000 },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        // The stream is constructed (emitting `ready`) but never read until every
        // frame is posted, so no pull runs and the bounded queue must drop.
        const response = await handler(streamRequest("room", controller.signal));
        for (let index = 0; index < 6; index += 1) {
            const post = await handler(ephemeralRequest("room", new Uint8Array([index])));
            expect(await post.json()).toEqual({ delivered: 1 });
        }

        const sse = new SseReader(bodyOf(response));
        expect((await sse.next()).event).toBe("ready");
        let framesReceived = 0;
        let dropped: number | undefined;
        for (let guard = 0; guard < 10 && dropped === undefined; guard += 1) {
            const message = await sse.next();
            if (message.event === "frame") {
                framesReceived += 1;
            } else if (message.event === "drop") {
                dropped = (JSON.parse(message.data ?? "") as { frames: number }).frames;
            }
        }
        expect(framesReceived).toBe(2);
        expect(dropped).toBe(4);

        controller.abort();
        await sse.cancel();
    });

    it("bounds retained frame bytes across streams, not just per stream", async () => {
        // Each stream may queue 64 bytes, but the process may retain only 64 in
        // total, so a second stalled stream cannot add another 64.
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                maximumEphemeralFrameBytes: 64,
                maximumStreamQueueBytes: 64,
                maximumTotalStreamQueueBytes: 64,
            },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const first = new AbortController();
        const second = new AbortController();
        // Neither body is read until every frame is posted, so nothing drains.
        const stalled = await handler(streamRequest("room", first.signal));
        const later = await handler(streamRequest("lobby", second.signal));

        expect(await (await handler(ephemeralRequest("room", new Uint8Array(40)))).json()).toEqual({
            delivered: 1,
        });
        expect(await (await handler(ephemeralRequest("lobby", new Uint8Array(40)))).json()).toEqual(
            { delivered: 1 },
        );

        // The longest-backlogged reader gives up its frame and is told so.
        const stalledSse = new SseReader(bodyOf(stalled));
        expect((await stalledSse.next()).event).toBe("ready");
        const dropped = await stalledSse.next();
        expect(dropped.event).toBe("drop");
        expect(JSON.parse(dropped.data ?? "")).toEqual({ frames: 1 });

        // The reader that arrived later keeps what it was sent.
        const laterSse = new SseReader(bodyOf(later));
        expect((await laterSse.next()).event).toBe("ready");
        expect((await laterSse.next()).event).toBe("frame");

        first.abort();
        second.abort();
        await stalledSse.cancel();
        await laterSse.cancel();
    });

    it("rejects an over-sized ephemeral frame with 413", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumEphemeralFrameBytes: 8 },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const response = await handler(ephemeralRequest("room", new Uint8Array(9)));
        expect(response.status).toBe(413);
        expect(await response.json()).toEqual({ error: "limit" });
    });

    it("returns 503 once the concurrent-stream cap is reached", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumConcurrentStreams: 1 },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const first = new AbortController();
        const second = new AbortController();
        const opened = await handler(streamRequest("room", first.signal));
        expect(opened.status).toBe(200);
        const rejected = await handler(streamRequest("room", second.signal));
        expect(rejected.status).toBe(503);
        expect(await rejected.json()).toEqual({ error: "overloaded" });

        first.abort();
        second.abort();
        await bodyOf(opened)
            .cancel()
            .catch(() => undefined);
    });

    it("returns 503 once one topic reaches the per-topic stream cap", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumConcurrentStreams: 100, maximumStreamsPerTopic: 1 },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const first = new AbortController();
        const second = new AbortController();
        const third = new AbortController();
        const opened = await handler(streamRequest("room", first.signal));
        expect(opened.status).toBe(200);
        const rejected = await handler(streamRequest("room", second.signal));
        expect(rejected.status).toBe(503);
        expect(await rejected.json()).toEqual({ error: "overloaded" });
        // The process-wide cap is untouched, so another topic still opens.
        const other = await handler(streamRequest("lobby", third.signal));
        expect(other.status).toBe(200);

        first.abort();
        second.abort();
        third.abort();
        await bodyOf(opened)
            .cancel()
            .catch(() => undefined);
        await bodyOf(other)
            .cancel()
            .catch(() => undefined);
    });

    it("charges an ephemeral publish for the fan-out it causes", async () => {
        // Capacity 10 with a frozen clock: no refill, so every token spent is
        // visible. Opening a stream costs `read` (1); an ephemeral POST costs
        // `ephemeral` (1) plus one per subscriber it is about to reach.
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                rateLimit: {
                    capacity: 10,
                    refillTokensPerSecond: 1,
                    costs: { publish: 1, upload: 1, read: 1, ephemeral: 1 },
                },
            },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service, { now: () => now });
        const controllers = [new AbortController(), new AbortController()];
        const streams: Response[] = [];
        for (const controller of controllers) {
            const response = await handler(streamRequest("room", controller.signal));
            expect(response.status).toBe(200);
            streams.push(response);
        }
        expect(service.ephemeralSubscriberCountForTopic("room")).toBe(2);

        // 10 - 2 reads = 8 tokens. Each POST now costs 1 + 2 = 3.
        const first = await handler(ephemeralRequest("room", new Uint8Array([1])));
        expect(first.status).toBe(200);
        expect(await first.json()).toEqual({ delivered: 2 });
        const second = await handler(ephemeralRequest("room", new Uint8Array([2])));
        expect(second.status).toBe(200);

        // Two tokens left and the third POST needs three: flat pricing would
        // have spent only three tokens in total and still allowed this.
        const third = await handler(ephemeralRequest("room", new Uint8Array([3])));
        expect(third.status).toBe(429);
        expect(await third.json()).toMatchObject({ error: "rate_limited" });

        for (const controller of controllers) {
            controller.abort();
        }
        for (const stream of streams) {
            await bodyOf(stream)
                .cancel()
                .catch(() => undefined);
        }
    });

    it("charges only the flat cost when a topic has no subscribers", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                rateLimit: {
                    capacity: 4,
                    refillTokensPerSecond: 1,
                    costs: { publish: 1, upload: 1, read: 1, ephemeral: 1 },
                },
            },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service, { now: () => now });
        for (let index = 0; index < 4; index += 1) {
            const response = await handler(ephemeralRequest("room", new Uint8Array([index])));
            expect(response.status).toBe(200);
            expect(await response.json()).toEqual({ delivered: 0 });
        }
        expect((await handler(ephemeralRequest("room", new Uint8Array([9])))).status).toBe(429);
    });

    it("accepts an ephemeral frame whatever the content-type claims", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        const sse = new SseReader(bodyOf(response));
        expect((await sse.next()).event).toBe("ready");

        const post = await handler(untypedEphemeralRequest("room", new Uint8Array([4, 5])));
        expect(post.status).toBe(200);
        expect(await post.json()).toEqual({ delivered: 1 });
        const frame = await sse.next();
        expect(decodeBase64Url(frame.data ?? "")).toEqual(new Uint8Array([4, 5]));

        controller.abort();
        await sse.cancel();
    });

    it("emits a wake promptly on a durable publish", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        const sse = new SseReader(bodyOf(response));
        expect((await sse.next()).event).toBe("ready");

        await service.publish(signedEvent("room", "durable"));
        const wake = await sse.next();
        expect(wake.event).toBe("wake");
        expect(JSON.parse(wake.data ?? "")).toEqual({});

        controller.abort();
        await sse.cancel();
    });

    it("cleans up the subscriber when the request aborts", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        const sse = new SseReader(bodyOf(response));
        await sse.next();
        expect(service.ephemeralSubscriberCount).toBe(1);

        controller.abort();
        await tick();
        expect(service.ephemeralSubscriberCount).toBe(0);
        await sse.cancel();
    });

    it("writes periodic keepalive comments on an idle stream", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            { streamKeepAliveMilliseconds: 20 },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service);
        const controller = new AbortController();
        const response = await handler(streamRequest("room", controller.signal));
        const sse = new SseReader(bodyOf(response));
        expect((await sse.next()).event).toBe("ready");
        const keepalive = await sse.next();
        expect(keepalive.comment).toBe("keepalive");

        controller.abort();
        await sse.cancel();
    });
});
