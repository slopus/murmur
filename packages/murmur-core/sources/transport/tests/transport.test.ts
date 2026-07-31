import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    createRelayBlob,
    createRelayEvent,
    decodeSignedRelayEventWire,
    deriveNestedTopic,
    encodeSignedRelayEventWire,
    HttpRelayTransport,
    relayEventSigningBytes,
    verifyRelayBlob,
    verifyRelayEvent,
} from "../index.js";

describe("relay protocol", () => {
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
            async () => new Response(utf8Encode("tampered").slice().buffer as ArrayBuffer),
        );

        await expect(oversized.readEvents("topic", 0n)).rejects.toThrow("too large");
        await expect(corrupt.getBlob(blob.id)).rejects.toThrow("content-address");
    });
});
