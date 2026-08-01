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

const encoder = new TextEncoder();
const now = 50_000;

function event(label: string, privateKey: Uint8Array): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode(label))),
        topic: "rate-limit",
        author: { signingKey: ed25519.getPublicKey(privateKey) },
        createdAt: now,
        payload: encoder.encode(label),
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), privateKey),
    };
}

function publishRequest(value: SignedRelayEvent): Request {
    return new Request("https://relay.test/v1/topics/rate-limit/events", {
        method: "POST",
        body: JSON.stringify(signedRelayEventToJson(value)),
    });
}

describe("relay HTTP rate limiting", () => {
    let service: RelayService | undefined;

    afterEach(async () => {
        await service?.close();
    });

    it("allows under limit and returns machine-readable 429 with Retry-After", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                rateLimit: {
                    capacity: 2,
                    refillTokensPerSecond: 1,
                    maximumBuckets: 10,
                    costs: { publish: 2, upload: 2, read: 1 },
                },
            },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service, { now: () => now });
        const context = { remoteAddress: "192.0.2.10" };

        expect((await handler(new Request("https://relay.test/health"), context)).status).toBe(200);
        expect((await handler(new Request("https://relay.test/health"), context)).status).toBe(200);
        const denied = await handler(new Request("https://relay.test/health"), context);

        expect(denied.status).toBe(429);
        expect(denied.headers.get("retry-after")).toBe("1");
        await expect(denied.json()).resolves.toEqual({
            error: "rate_limited",
            retryAfterMilliseconds: 1_000,
        });
    });

    it("enforces independent per-IP and authenticated-author buckets", async () => {
        service = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                rateLimit: {
                    capacity: 2,
                    refillTokensPerSecond: 1,
                    maximumBuckets: 20,
                    costs: { publish: 2, upload: 2, read: 1 },
                },
            },
            undefined,
            () => now,
        );
        const handler = createRelayFetchHandler(service, { now: () => now });
        const firstAuthor = new Uint8Array(32).fill(3);
        const secondAuthor = new Uint8Array(32).fill(4);

        expect(
            (
                await handler(publishRequest(event("first", firstAuthor)), {
                    remoteAddress: "192.0.2.1",
                })
            ).status,
        ).toBe(200);
        expect(
            (
                await handler(new Request("https://relay.test/health"), {
                    remoteAddress: "192.0.2.1",
                })
            ).status,
        ).toBe(429);

        expect(
            (
                await handler(publishRequest(event("same-author", firstAuthor)), {
                    remoteAddress: "192.0.2.2",
                })
            ).status,
        ).toBe(429);
        expect(
            (
                await handler(publishRequest(event("other-author", secondAuthor)), {
                    remoteAddress: "192.0.2.3",
                })
            ).status,
        ).toBe(200);
    });

    it("ignores spoofed X-Forwarded-For when no proxies are trusted", async () => {
        service = new RelayService(new SqliteRelayStore(":memory:"), {
            rateLimit: {
                capacity: 1,
                refillTokensPerSecond: 1,
                maximumBuckets: 10,
                costs: { publish: 1, upload: 1, read: 1 },
            },
        });
        const handler = createRelayFetchHandler(service, { now: () => now });
        const context = { remoteAddress: "198.51.100.8" };
        const first = new Request("https://relay.test/health", {
            headers: { "x-forwarded-for": "203.0.113.1" },
        });
        const second = new Request("https://relay.test/health", {
            headers: { "x-forwarded-for": "203.0.113.2" },
        });

        expect((await handler(first, context)).status).toBe(200);
        expect((await handler(second, context)).status).toBe(429);
    });
});
