import { describe, expect, it } from "vitest";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import { HttpRelayTransport, MAX_RELAY_EPHEMERAL_FRAME_BYTES } from "../index.js";
import type { RelayStreamHandlers } from "../index.js";

/** A relay `text/event-stream` response driven byte-by-byte from the test. */
function eventStreamResponse(): {
    readonly response: Response;
    push(text: string): void;
    pushBytes(bytes: Uint8Array): void;
    close(): void;
    readonly cancelled: boolean;
} {
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
        start(streamController): void {
            controller = streamController;
        },
        cancel(): void {
            cancelled = true;
        },
    });
    return {
        response: new Response(stream, {
            headers: { "content-type": "text/event-stream; charset=utf-8" },
        }),
        push: (text: string): void => controller.enqueue(utf8Encode(text)),
        pushBytes: (bytes: Uint8Array): void => controller.enqueue(bytes),
        close: (): void => controller.close(),
        get cancelled(): boolean {
            return cancelled;
        },
    };
}

function streamingTransport(source: { readonly response: Response }): HttpRelayTransport {
    return new HttpRelayTransport("stream", "https://relay.test", async () => source.response);
}

describe("ephemeral relay transport", () => {
    it("exports the frozen ephemeral frame bound", () => {
        expect(MAX_RELAY_EPHEMERAL_FRAME_BYTES).toBe(128 * 1024);
    });

    it("reassembles named events split across chunk boundaries", async () => {
        const source = eventStreamResponse();
        const controller = new AbortController();
        const seen: Array<string | { frame: string } | { drop: number }> = [];
        const handlers: RelayStreamHandlers = {
            onReady: () => seen.push("ready"),
            onFrame: (bytes) => seen.push({ frame: utf8Decode(bytes) }),
            onWake: () => seen.push("wake"),
            onDrop: (frames) => seen.push({ drop: frames }),
        };
        const promise = streamingTransport(source).openStream("room", handlers, controller.signal);

        source.push("event: ready\n");
        source.push('data: {"topic":"room"}\n\n');
        // Split the event name and the base64url data across chunks.
        source.push("event: fr");
        source.push("ame\ndata: ");
        source.push(`${encodeBase64Url(utf8Encode("hello"))}\n\n`);
        // A CRLF-framed wake event.
        source.push("event: wake\r\ndata: {}\r\n\r\n");
        source.push('event: drop\ndata: {"frames":4}\n\n');
        source.close();
        await promise;

        expect(seen).toEqual(["ready", { frame: "hello" }, "wake", { drop: 4 }]);
    });

    it("ignores comments, keepalives, and unknown event names", async () => {
        const source = eventStreamResponse();
        const controller = new AbortController();
        const seen: string[] = [];
        const promise = streamingTransport(source).openStream(
            "room",
            {
                onReady: () => seen.push("ready"),
                onFrame: () => seen.push("frame"),
            },
            controller.signal,
        );

        source.push(": keepalive\n");
        source.push("\n");
        source.push('event: mystery\ndata: {"ignored":true}\n\n');
        source.push("event: ready\ndata: {}\n\n");
        source.close();
        await promise;

        expect(seen).toEqual(["ready"]);
    });

    it("fails the stream when one event exceeds the hard cap", async () => {
        const source = eventStreamResponse();
        const controller = new AbortController();
        const promise = streamingTransport(source).openStream("room", {}, controller.signal);

        // A single unterminated data line that grows past the 256 KiB cap.
        source.push(`data: ${"A".repeat(300 * 1024)}`);

        await expect(promise).rejects.toThrow("maximum size");
        expect(source.cancelled).toBe(true);
    });

    it("stops promptly and cancels the reader when aborted", async () => {
        const source = eventStreamResponse();
        const controller = new AbortController();
        let frames = 0;
        const promise = streamingTransport(source).openStream(
            "room",
            {
                onReady: () => controller.abort(),
                onFrame: () => {
                    frames += 1;
                },
            },
            controller.signal,
        );

        source.push("event: ready\ndata: {}\n\n");
        // This frame arrives after the abort and must not be delivered.
        source.push(`event: frame\ndata: ${encodeBase64Url(utf8Encode("late"))}\n\n`);

        await expect(promise).resolves.toBeUndefined();
        expect(source.cancelled).toBe(true);
        expect(frames).toBe(0);
    });

    it("returns the delivered count and posts raw octet-stream bytes", async () => {
        const requests: Array<{ method: string; path: string; contentType: string; body: string }> =
            [];
        const transport = new HttpRelayTransport(
            "stream",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                requests.push({
                    method: request.method,
                    path: new URL(request.url).pathname,
                    contentType: request.headers.get("content-type") ?? "",
                    body: utf8Decode(new Uint8Array(await request.arrayBuffer())),
                });
                return Response.json({ delivered: 3 });
            },
        );

        await expect(transport.publishEphemeral("room", utf8Encode("frame"))).resolves.toBe(3);
        expect(requests).toEqual([
            {
                method: "POST",
                path: "/v1/topics/room/ephemeral",
                contentType: "application/octet-stream",
                body: "frame",
            },
        ]);
    });

    it("surfaces HTTP errors from ephemeral publish", async () => {
        const transport = new HttpRelayTransport(
            "stream",
            "https://relay.test",
            async () => new Response(JSON.stringify({ error: "limit" }), { status: 413 }),
        );

        await expect(transport.publishEphemeral("room", utf8Encode("x"))).rejects.toThrow(
            "HTTP 413",
        );
    });

    it("rejects an oversized frame before any request", async () => {
        let called = false;
        const transport = new HttpRelayTransport("stream", "https://relay.test", async () => {
            called = true;
            return Response.json({ delivered: 0 });
        });

        await expect(
            transport.publishEphemeral("room", new Uint8Array(MAX_RELAY_EPHEMERAL_FRAME_BYTES + 1)),
        ).rejects.toThrow("exceeds");
        expect(called).toBe(false);
    });
});
