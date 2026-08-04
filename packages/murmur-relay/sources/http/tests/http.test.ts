import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "vitest";
import {
    readProofSigningBytes,
    relayTopicToJson,
    type ReadChallenge,
} from "../../protocol/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { createRelayFetchHandler } from "../index.js";

describe("relay HTTP read authorization", () => {
    test("issues and consumes a challenge without receiving a secret key", async () => {
        const secretKey = new Uint8Array(32).fill(9);
        const topic = {
            type: "read" as const,
            name: "friends",
            readKey: ed25519.getPublicKey(secretKey),
        };
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        try {
            const challengeResponse = await handler(
                new Request("https://relay.test/v1/read-challenges", {
                    method: "POST",
                    body: JSON.stringify({ topic: relayTopicToJson(topic) }),
                }),
            );
            expect(challengeResponse.status).toBe(200);
            const challengeJson = (await challengeResponse.json()) as {
                id: string;
                nonce: string;
                expiresAt: number;
            };
            const challenge: ReadChallenge = {
                id: challengeJson.id,
                nonce: decodeBase64Url(challengeJson.nonce),
                expiresAt: challengeJson.expiresAt,
            };
            const response = await handler(
                new Request("https://relay.test/v1/events/read", {
                    method: "POST",
                    body: JSON.stringify({
                        topic: relayTopicToJson(topic),
                        since: "0",
                        limit: 10,
                        waitMilliseconds: 0,
                        proof: {
                            challengeId: challenge.id,
                            signature: encodeBase64Url(
                                ed25519.sign(
                                    readProofSigningBytes(challenge, topic, 0n, 10, 0),
                                    secretKey,
                                ),
                            ),
                        },
                    }),
                }),
            );
            expect(response.status).toBe(200);
            await expect(response.json()).resolves.toEqual({ events: [], head: "0" });
        } finally {
            await relay.close();
        }
    });
});
