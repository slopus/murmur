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
import { SqliteRelayStore, type EventPage, type PageReadConstraints } from "../../storage/index.js";
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

    test("rejects oversized cursors before storage and reflects CORS with Vary", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            allowedOrigins: ["https://app.test"],
        });
        try {
            const health = await handler(
                new Request("https://relay.test/health", {
                    headers: { origin: "https://app.test" },
                }),
            );
            expect(health.headers.get("vary")).toBe("Origin");
            const key = ed25519.getPublicKey(new Uint8Array(32).fill(3));
            const response = await handler(
                new Request("https://relay.test/v1/events/read", {
                    method: "POST",
                    body: JSON.stringify({
                        topic: {
                            type: "write",
                            name: "cursor",
                            writeKey: encodeBase64Url(key),
                        },
                        since: "9223372036854775808",
                        limit: 1,
                        waitMilliseconds: 0,
                    }),
                }),
            );
            expect(response.status).toBe(400);
        } finally {
            await relay.close();
        }
    });

    test("enforces the actual encoded event-page response budget", async () => {
        const secretKey = new Uint8Array(32).fill(6);
        const topic = {
            type: "write" as const,
            name: "bounded",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        class OversizedPageStore extends SqliteRelayStore {
            override async readEvents(
                topicId: string,
                since: bigint,
                limit: number,
                now: number,
                constraints: PageReadConstraints,
            ): Promise<EventPage> {
                const page = await super.readEvents(topicId, since, limit, now, constraints);
                const retained = page.events[0];
                if (limit === 1 || retained === undefined) return page;
                return {
                    ...page,
                    events: Array.from({ length: 20 }, () => retained),
                };
            }
        }
        const relay = new RelayService(new OversizedPageStore(":memory:"), {
            maximumEventPayloadBytes: 64,
            maximumCollapseKeyBytes: 1,
            maximumJsonBodyBytes: 4_188,
        });
        const handler = createRelayFetchHandler(relay);
        try {
            const unsigned: SignedRelayEvent = {
                version: 1,
                id: encodeBase64Url(randomBytes(32)),
                topic,
                author: { signingKey: topic.writeKey },
                createdAt: Date.now(),
                payload: new Uint8Array(64),
                signature: new Uint8Array(64),
            };
            await relay.publish({
                ...unsigned,
                signature: ed25519.sign(relayEventSigningBytes(unsigned), secretKey),
            });
            const request = (limit: number): Request =>
                new Request("https://relay.test/v1/events/read", {
                    method: "POST",
                    body: JSON.stringify({
                        topic: relayTopicToJson(topic),
                        since: "0",
                        limit,
                        waitMilliseconds: 0,
                    }),
                });
            expect((await handler(request(256))).status).toBe(413);
            const single = await handler(request(1));
            expect(single.status).toBe(200);
            expect(((await single.json()) as { exhausted: boolean }).exhausted).toBe(true);
        } finally {
            await relay.close();
        }
    });
});
