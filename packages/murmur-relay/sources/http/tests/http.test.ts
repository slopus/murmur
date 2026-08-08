import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, test } from "vitest";
import {
    signedDeliveryToJson,
    signedQueueAckToJson,
    signedQueueReadToJson,
} from "../../protocol/index.js";
import {
    identity,
    recipients,
    secret,
    signedAck,
    signedDelivery,
    signedRead,
} from "../../protocol/tests/helpers.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { createRelayFetchHandler, parseRelayAllowedOrigins } from "../index.js";

const NOW = 10_000;

function post(path: string, body: unknown, origin?: string): Request {
    return new Request(`https://relay.example${path}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            ...(origin === undefined ? {} : { origin }),
        },
        body: JSON.stringify(body),
    });
}

function invitation(createdAt: number, expiresAt: number, value = "public"): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ createdAt, expiresAt, value }));
}

describe("identity queue HTTP API", () => {
    test("uploads and downloads a five-minute invitation by its exact digest", async () => {
        let now = NOW;
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const handler = createRelayFetchHandler(relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "invitation-tests",
        });
        const bundle = invitation(NOW, NOW + 5 * 60_000);
        const digest = encodeBase64Url(sha256(bundle));
        const upload = (): Promise<Response> =>
            handler(
                new Request("https://relay.example/v1/invitations", {
                    method: "POST",
                    headers: {
                        "content-type": "application/vnd.slopus.murmur-discovery+json",
                    },
                    body: bundle.slice(),
                }),
            );
        try {
            const excessiveLifetime = await handler(
                new Request("https://relay.example/v1/invitations", {
                    method: "POST",
                    body: invitation(NOW, NOW + 5 * 60_000 + 1),
                }),
            );
            expect(excessiveLifetime.status).toBe(400);
            expect(await excessiveLifetime.json()).toEqual({ error: "malformed" });

            const first = await upload();
            expect(first.status).toBe(200);
            expect(await first.json()).toEqual({
                digest,
                expiresAt: NOW + 5 * 60_000,
                duplicate: false,
            });
            now += 1;
            expect(await (await upload()).json()).toEqual({
                digest,
                expiresAt: NOW + 5 * 60_000,
                duplicate: true,
            });
            const downloaded = await handler(
                new Request(`https://relay.example/v1/invitations/${digest}`),
            );
            expect(downloaded.status).toBe(200);
            expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(bundle);
            expect(downloaded.headers.get("cache-control")).toBe("no-store");

            now = NOW + 5 * 60_000;
            const expired = await handler(
                new Request(`https://relay.example/v1/invitations/${digest}`),
            );
            expect(expired.status).toBe(404);
            expect(await expired.json()).toEqual({ error: "invitation_not_found" });

            const malformedDigest = await handler(
                new Request("https://relay.example/v1/invitations/not-a-digest"),
            );
            expect(malformedDigest.status).toBe(400);
            expect(await malformedDigest.json()).toEqual({ error: "malformed" });
        } finally {
            await relay.close();
        }
    });

    test("publishes, reads, and acknowledges", async () => {
        const aliceSecret = secret(1);
        const bobSecret = secret(2);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const handler = createRelayFetchHandler(relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "http-tests",
        });
        try {
            const delivery = signedDelivery(
                aliceSecret,
                recipients(identity(aliceSecret), identity(bobSecret)),
                { now: NOW },
            );
            const published = await handler(post("/v1/deliveries", signedDeliveryToJson(delivery)));
            const publishBody = (await published.json()) as {
                readonly eventId: string;
                readonly duplicate: boolean;
            };
            expect(publishBody.duplicate).toBe(false);

            const read = await handler(
                post("/v1/queue/read", signedQueueReadToJson(signedRead(bobSecret))),
            );
            expect(read.status).toBe(200);
            expect(await read.json()).toMatchObject({
                head: publishBody.eventId,
                acknowledgedThrough: null,
                exhausted: true,
                deliveries: [{ eventId: publishBody.eventId }],
            });

            const acknowledged = await handler(
                post(
                    "/v1/queue/ack",
                    signedQueueAckToJson(signedAck(bobSecret, publishBody.eventId)),
                ),
            );
            expect(await acknowledged.json()).toEqual({ removed: 1 });
        } finally {
            await relay.close();
        }
    });

    test("enforces exact CORS origins and bounded JSON", async () => {
        expect(parseRelayAllowedOrigins("https://app.example")).toEqual(["https://app.example"]);
        expect(() => parseRelayAllowedOrigins("https://app.example/")).toThrow("invalid origin");
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumCiphertextBytes: 1, maximumRecipients: 1, maximumJsonBodyBytes: 5_000 },
            undefined,
            () => NOW,
        );
        const handler = createRelayFetchHandler(relay, {
            allowedOrigins: ["https://app.example"],
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "http-tests",
        });
        try {
            const health = await handler(
                new Request("https://relay.example/health", {
                    headers: { origin: "https://app.example" },
                }),
            );
            expect(health.headers.get("access-control-allow-origin")).toBe("https://app.example");
            const oversized = await handler(
                new Request("https://relay.example/v1/deliveries", {
                    method: "POST",
                    headers: { "content-length": "5001" },
                    body: "{}",
                }),
            );
            expect(oversized.status).toBe(413);
        } finally {
            await relay.close();
        }
    });

    test("returns skip metadata for a delivery above the current response budget", async () => {
        const aliceSecret = secret(5);
        const bobSecret = secret(6);
        const store = new SqliteRelayStore(":memory:");
        const publisher = new RelayService(
            store,
            {
                maximumCiphertextBytes: 4_000,
                maximumRecipients: 1,
                maximumJsonBodyBytes: 10_000,
            },
            undefined,
            () => NOW,
        );
        const reader = new RelayService(
            store,
            {
                maximumCiphertextBytes: 1,
                maximumRecipients: 1,
                maximumJsonBodyBytes: 5_000,
            },
            undefined,
            () => NOW,
        );
        const handler = createRelayFetchHandler(reader, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "http-tests",
        });
        try {
            const published = await publisher.publish(
                signedDelivery(aliceSecret, recipients(identity(bobSecret)), {
                    now: NOW,
                    ciphertext: new Uint8Array(4_000),
                }),
                "http-tests",
            );
            const response = await handler(
                post("/v1/queue/read", signedQueueReadToJson(signedRead(bobSecret, { now: NOW }))),
            );
            expect(response.status).toBe(413);
            expect(await response.json()).toEqual({
                error: "delivery_too_large",
                eventId: published.eventId,
                head: published.eventId,
                acknowledgedThrough: null,
            });
        } finally {
            await reader.close();
            await publisher.close();
        }
    });

    test("rate limits POST requests per remote address", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const handler = createRelayFetchHandler(relay, {
            maximumRequestsPerMinutePerAddress: 1,
        });
        try {
            expect(() => createRelayFetchHandler(relay, { requireRemoteAddress: false })).toThrow(
                "explicit default admission principal",
            );
            const context = { remoteAddress: "203.0.113.10" };
            const missingHealthContext = await handler(new Request("https://relay.example/health"));
            expect(missingHealthContext.status).toBe(503);
            const missingContext = await handler(post("/v1/deliveries", {}));
            expect(missingContext.status).toBe(503);
            expect(await missingContext.json()).toEqual({
                error: "admission_context_required",
            });
            expect((await handler(post("/v1/deliveries", {}), context)).status).toBe(400);
            const limited = await handler(post("/v1/deliveries", {}), context);
            expect(limited.status).toBe(429);
            expect(await limited.json()).toEqual({ error: "rate_limited" });

            const proxyHandler = createRelayFetchHandler(relay, {
                maximumRequestsPerMinutePerAddress: 1,
                remoteAddressHeader: "x-real-ip",
            });
            const proxied = (): Request =>
                new Request("https://relay.example/v1/deliveries", {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        "x-real-ip": "198.51.100.7",
                    },
                    body: "{}",
                });
            expect((await proxyHandler(proxied())).status).toBe(400);
            expect((await proxyHandler(proxied())).status).toBe(429);
        } finally {
            await relay.close();
        }
    });

    test("bounds outstanding fanout by the trusted ingress principal", async () => {
        const firstSender = secret(31);
        const secondSender = secret(32);
        const recipient = identity(secret(33));
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            { maximumAdmissionReferences: 1 },
            undefined,
            () => NOW,
        );
        const handler = createRelayFetchHandler(relay);
        const principal = { remoteAddress: "account:example" };
        try {
            expect(
                (
                    await handler(
                        post(
                            "/v1/deliveries",
                            signedDeliveryToJson(
                                signedDelivery(firstSender, recipients(recipient), {
                                    id: 34,
                                    now: NOW,
                                }),
                            ),
                        ),
                        principal,
                    )
                ).status,
            ).toBe(200);
            const blocked = await handler(
                post(
                    "/v1/deliveries",
                    signedDeliveryToJson(
                        signedDelivery(secondSender, recipients(recipient), {
                            id: 35,
                            now: NOW,
                        }),
                    ),
                ),
                principal,
            );
            expect(blocked.status).toBe(429);
            expect(await blocked.json()).toEqual({ error: "admission_full" });
        } finally {
            await relay.close();
        }
    });
});
