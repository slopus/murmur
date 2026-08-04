import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { describe, expect, test } from "vitest";
import {
    readProofSigningBytes,
    relayEventSigningBytes,
    relayTopicToJson,
    signedRelayEventToJson,
    type ReadChallenge,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { createRelayFetchHandler } from "../index.js";

describe("relay HTTP read authorization", () => {
    test("issues and consumes a challenge without receiving a secret key", async () => {
        const readSecretKey = new Uint8Array(32).fill(9);
        const writeSecretKey = new Uint8Array(32).fill(8);
        const topic = {
            type: "read-write" as const,
            name: "shared",
            readKey: ed25519.getPublicKey(readSecretKey),
            writeKey: ed25519.getPublicKey(writeSecretKey),
        };
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay);
        try {
            for (const payload of ["first", "second"]) {
                const unsigned: SignedRelayEvent = {
                    version: 1,
                    id: encodeBase64Url(randomBytes(32)),
                    topic,
                    author: { signingKey: topic.writeKey },
                    createdAt: Date.now(),
                    payload: new TextEncoder().encode(payload),
                    signature: new Uint8Array(64),
                };
                const event = {
                    ...unsigned,
                    signature: ed25519.sign(relayEventSigningBytes(unsigned), writeSecretKey),
                };
                const publishResponse = await handler(
                    new Request("https://relay.test/v1/events", {
                        method: "POST",
                        body: JSON.stringify(signedRelayEventToJson(event)),
                    }),
                );
                expect(publishResponse.status).toBe(200);
            }
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
                                    readSecretKey,
                                ),
                            ),
                        },
                    }),
                }),
            );
            expect(response.status).toBe(200);
            await expect(response.json()).resolves.toEqual({
                events: expect.arrayContaining([
                    expect.objectContaining({ seq: "1" }),
                    expect.objectContaining({ seq: "2" }),
                ]),
                head: "2",
                exhausted: true,
            });
        } finally {
            await relay.close();
        }
    });
});
