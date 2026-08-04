import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "vitest";
import { canonicalJsonBytes, decodeBase64Url, encodeBase64Url } from "../../utils/index.js";
import { HttpRelayTransport } from "../index.js";
import { relayTopicToJson } from "../impl/wireCodec.js";

describe("HTTP relay transport", () => {
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
