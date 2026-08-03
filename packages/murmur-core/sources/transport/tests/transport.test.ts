import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    createRelayBlob,
    createRelayEvent,
    DEFAULT_RELAY_URL,
    decodeSignedRelayEventWire,
    deriveNestedTopic,
    encodeSignedRelayEventWire,
    HttpRelayTransport,
    RelayBlobIntegrityError,
    relayEventSigningBytes,
    verifyRelayBlob,
    verifyRelayEvent,
} from "../index.js";

describe("relay protocol", () => {
    it("exports the canonical public relay URL", () => {
        expect(DEFAULT_RELAY_URL).toBe("https://murmur.cluster-fluster.com");
    });

    it("signs the relay's exact canonical event preimage", async () => {
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(
            alice,
            "topic",
            utf8Encode("opaque"),
            {
                snapshot: { expectedVersion: 0, bytes: utf8Encode("snapshot") },
                list: [{ op: "append", id: "message:one", bytes: utf8Encode("ciphertext") }],
            },
            42,
        );
        // This cross-package import is intentionally test-only: the published
        // browser library does not depend on the Node relay implementation.
        const relayProtocolPath = "../../../../murmur-relay/sources/protocol/index.js";
        const relayProtocol = (await import(relayProtocolPath)) as {
            verifyRelayEventSignature(value: typeof event): boolean;
            relayEventSigningBytes(value: typeof event): Uint8Array;
        };

        expect(relayProtocol.verifyRelayEventSignature(event)).toBe(true);
        expect(relayProtocol.relayEventSigningBytes(event)).toEqual(relayEventSigningBytes(event));
        expect(verifyRelayEvent({ ...event, payload: utf8Encode("changed") })).toBe(false);
        expect("signingSecretKey" in event.author).toBe(false);
    });

    it("round trips the fixed signed event wire shape", () => {
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), {}, 42);

        expect(decodeSignedRelayEventWire(encodeSignedRelayEventWire(event))).toEqual(event);
        expect(utf8Decode(encodeSignedRelayEventWire(event))).not.toContain("encryptionKey");
    });

    it("content-addresses ciphertext blobs", () => {
        const blob = createRelayBlob(utf8Encode("ciphertext"));

        expect(verifyRelayBlob(blob)).toBe(true);
        expect(verifyRelayBlob({ ...blob, bytes: utf8Encode("changed") })).toBe(false);
    });

    it("derives opaque nested topics without a depth limit", () => {
        const document = deriveNestedTopic("group", utf8Encode("document"));
        const comments = deriveNestedTopic(document, utf8Encode("comments"));

        expect(document).toMatch(/^topic:[A-Za-z0-9_-]{43}$/);
        expect(comments).not.toBe(document);
        expect(deriveNestedTopic("group", utf8Encode("document"))).toBe(document);
    });

    it("implements every topic HTTP route with injected fetch", async () => {
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), {}, 42);
        const requests: Request[] = [];
        const transport = new HttpRelayTransport(
            "in-process",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                requests.push(request);
                const url = new URL(request.url);
                if (request.method === "POST") {
                    return Response.json({ seq: "1", duplicate: false });
                }
                if (url.pathname.endsWith("/state")) {
                    return Response.json({
                        seq: "1",
                        snapshot: null,
                        list: {
                            elements: [
                                { id: "message:one", version: "1", bytes: "Y2lwaGVydGV4dA" },
                            ],
                            nextCursor: null,
                        },
                    });
                }
                if (url.pathname.endsWith("/list")) {
                    return Response.json({ elements: [], nextCursor: null });
                }
                return Response.json({
                    events: [
                        {
                            seq: "1",
                            ...JSON.parse(utf8Decode(encodeSignedRelayEventWire(event))),
                        },
                    ],
                    reset: false,
                    seq: "1",
                });
            },
        );

        await expect(transport.publish(event)).resolves.toEqual({
            seq: 1n,
            duplicate: false,
        });
        await expect(transport.readState("topic")).resolves.toMatchObject({ seq: 1n });
        await expect(transport.readList("topic", "cursor", 10)).resolves.toEqual({
            elements: [],
            nextCursor: null,
        });
        await expect(transport.readEvents("topic", 0n, 10, 25)).resolves.toMatchObject({
            reset: false,
            seq: 1n,
        });

        expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
            "/v1/topics/topic/events",
            "/v1/topics/topic/state",
            "/v1/topics/topic/list",
            "/v1/topics/topic/events",
        ]);
    });

    it("rejects oversized and corrupt HTTP responses", async () => {
        const blob = createRelayBlob(utf8Encode("expected"));
        const oversized = new HttpRelayTransport(
            "hostile",
            "https://relay.test",
            async () =>
                new Response("{}", {
                    headers: { "content-length": String(33 * 1024 * 1024) },
                }),
        );
        const corrupt = new HttpRelayTransport(
            "hostile",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                if (new URL(request.url).pathname.endsWith("/download-link")) {
                    return Response.json({
                        url: "/objects/corrupt",
                        method: "GET",
                        expiresAt: Date.now() + 1_000,
                    });
                }
                return new Response(utf8Encode("tampered").slice().buffer as ArrayBuffer);
            },
        );

        await expect(oversized.readEvents("topic", 0n)).rejects.toThrow("too large");
        await expect(corrupt.getBlob(blob.id)).rejects.toThrow("content-address");
    });

    it("streams blobs within their exact expected ciphertext length", async () => {
        const blob = createRelayBlob(utf8Encode("chunked ciphertext"));
        const transport = new HttpRelayTransport(
            "chunked",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                if (new URL(request.url).pathname.endsWith("/download-link")) {
                    return Response.json({
                        url: "/objects/chunked",
                        method: "GET",
                        expiresAt: Date.now() + 1_000,
                    });
                }
                return new Response(
                    new ReadableStream<Uint8Array>({
                        start(controller): void {
                            controller.enqueue(blob.bytes.slice(0, 5));
                            controller.enqueue(blob.bytes.slice(5));
                            controller.close();
                        },
                    }),
                );
            },
        );

        await expect(transport.getBlob(blob.id, blob.bytes.length)).resolves.toEqual(blob);
        await expect(transport.getBlob(blob.id, blob.bytes.length - 1)).rejects.toBeInstanceOf(
            RelayBlobIntegrityError,
        );
    });

    it("cancels an oversized blob stream before concatenating it", async () => {
        const blob = createRelayBlob(utf8Encode("oversized stream"));
        let cancelled = false;
        const transport = new HttpRelayTransport(
            "hostile",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                if (new URL(request.url).pathname.endsWith("/download-link")) {
                    return Response.json({
                        url: "/objects/oversized",
                        method: "GET",
                        expiresAt: Date.now() + 1_000,
                    });
                }
                return new Response(
                    new ReadableStream<Uint8Array>({
                        start(controller): void {
                            controller.enqueue(utf8Encode("first"));
                            controller.enqueue(utf8Encode("second"));
                        },
                        cancel(): void {
                            cancelled = true;
                        },
                    }),
                );
            },
        );

        await expect(transport.getBlob(blob.id, 8)).rejects.toBeInstanceOf(RelayBlobIntegrityError);
        expect(cancelled).toBe(true);
    });

    it("requests blob links before direct upload and download transfers", async () => {
        const blob = createRelayBlob(utf8Encode("linked ciphertext"));
        const requests: Request[] = [];
        let stored = new Uint8Array();
        const transport = new HttpRelayTransport(
            "linked",
            "https://relay.test",
            async (input, init) => {
                const request = new Request(input, init);
                requests.push(request);
                const path = new URL(request.url).pathname;
                if (path.endsWith("/upload-link")) {
                    return Response.json({
                        url: "https://objects.test/blob",
                        method: "PUT",
                        expiresAt: Date.now() + 1_000,
                        headers: { "x-transfer-token": "upload" },
                    });
                }
                if (path.endsWith("/download-link")) {
                    return Response.json({
                        url: "https://objects.test/blob",
                        method: "GET",
                        expiresAt: Date.now() + 1_000,
                    });
                }
                if (request.method === "PUT") {
                    expect(request.headers.get("x-transfer-token")).toBe("upload");
                    stored = new Uint8Array(await request.arrayBuffer());
                    return new Response(null, { status: 204 });
                }
                return new Response(stored.slice().buffer as ArrayBuffer);
            },
        );

        await transport.putBlob(blob);
        await expect(transport.getBlob(blob.id)).resolves.toEqual(blob);
        expect(
            requests.map((request) => ({
                method: request.method,
                path: new URL(request.url).pathname,
            })),
        ).toEqual([
            { method: "POST", path: `/v1/blobs/${blob.id}/upload-link` },
            { method: "PUT", path: "/blob" },
            { method: "POST", path: `/v1/blobs/${blob.id}/download-link` },
            { method: "GET", path: "/blob" },
        ]);
    });

    it("rejects credentialed, insecure, and explicit private-network external blob links", async () => {
        const blob = createRelayBlob(utf8Encode("ciphertext"));
        for (const url of [
            "https://user:secret@objects.test/blob",
            "http://objects.test/blob",
            "https://127.0.0.1/blob",
        ]) {
            const transport = new HttpRelayTransport("hostile", "https://relay.test", async () =>
                Response.json({
                    url,
                    method: "GET",
                    expiresAt: Date.now() + 1_000,
                }),
            );
            await expect(transport.getBlob(blob.id)).rejects.toThrow("unsafe blob link");
        }
    });
});
