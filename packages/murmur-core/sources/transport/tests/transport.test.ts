import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "vitest";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Encode,
} from "../../utils/index.js";
import { HttpRelayTransport, decodeEventPageWire, decodeSignedRelayEventWire } from "../index.js";
import { relayTopicToJson } from "../impl/wireCodec.js";

describe("HTTP relay transport", () => {
    test("requires canonical decimal event page heads and sequences", () => {
        const page = (head: string): Uint8Array =>
            utf8Encode(
                JSON.stringify({
                    events: [],
                    head,
                    exhausted: true,
                }),
            );
        expect(decodeEventPageWire(page("0"))).toEqual({
            events: [],
            head: 0n,
            exhausted: true,
        });
        for (const invalid of ["", "+1", "-1", "01", " 1", "1 ", "1.0", "1e0"]) {
            expect(() => decodeEventPageWire(page(invalid))).toThrow("Invalid event page head");
        }
        expect(() => decodeEventPageWire(page("10000000000000000000"))).toThrow(
            "Invalid event page head",
        );
        const retainedPage = (seq: string): Uint8Array =>
            utf8Encode(
                JSON.stringify({
                    events: [{ seq, event: null }],
                    head: "1",
                    exhausted: true,
                }),
            );
        for (const invalid of ["", "+1", "-1", "0", "01", " 1", "1.0", "1e0"]) {
            expect(() => decodeEventPageWire(retainedPage(invalid))).toThrow(
                "Invalid event sequence",
            );
        }
    });

    test("rejects descriptor fields and names rejected by the relay codec", () => {
        const key = encodeBase64Url(new Uint8Array(32));
        const base = {
            version: 1,
            id: encodeBase64Url(new Uint8Array(32)),
            topic: { type: "write", name: "ok", writeKey: key },
            author: { signingKey: key },
            createdAt: 0,
            payload: "",
            signature: encodeBase64Url(new Uint8Array(64)),
        };
        expect(() =>
            decodeSignedRelayEventWire(
                utf8Encode(JSON.stringify({ ...base, topic: { ...base.topic, extra: true } })),
            ),
        ).toThrow("Invalid topic");
        expect(() =>
            decodeSignedRelayEventWire(
                utf8Encode(JSON.stringify({ ...base, topic: { ...base.topic, name: "é" } })),
            ),
        ).toThrow("Invalid topic");
    });

    test("acquires and signs a read challenge for exact request parameters", async () => {
        const secretKey = new Uint8Array(32).fill(7);
        const topic = {
            type: "read" as const,
            name: "inbox",
            readKey: ed25519.getPublicKey(secretKey),
        };
        const nonce = new Uint8Array(32).fill(4);
        let readBody: Record<string, unknown> | undefined;
        const relayFetch = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => {
            const url = String(input);
            if (url.endsWith("/v1/read-challenges")) {
                return Response.json({
                    id: "challenge",
                    nonce: encodeBase64Url(nonce),
                    expiresAt: 10_000,
                });
            }
            readBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
            return Response.json({ events: [], head: "0", exhausted: true });
        };
        const transport = new HttpRelayTransport("https://relay.test", relayFetch);
        await transport.readEvents({ topic, readSecretKey: secretKey }, 0n, 10, 25);
        const proof = readBody?.proof as Record<string, unknown>;
        expect(proof.challengeId).toBe("challenge");
        expect(
            ed25519.verify(
                decodeBase64Url(String(proof.signature)),
                canonicalJsonBytes({
                    challengeId: "challenge",
                    nonce: encodeBase64Url(nonce),
                    topic: relayTopicToJson(topic),
                    since: "0",
                    limit: 10,
                    waitMilliseconds: 25,
                }),
                topic.readKey,
                { zip215: false },
            ),
        ).toBe(true);
    });
});
