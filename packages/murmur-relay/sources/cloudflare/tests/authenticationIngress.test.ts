import {
    createSignedRelaySessionRequest,
    generateIdentityKeyPair,
    signedRelaySessionRequestToJson,
} from "@slopus/murmur";
import { describe, expect, test } from "vitest";
import { LocalDirectoryTicketIssuer } from "../../directory/index.js";
import { verifyRelaySessionToken } from "../../session/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { createMurmurCloudflareWorker } from "../main.js";
import { deriveCloudflareDirectoryTicketSecret } from "../impl/cloudflareCodec.js";
import type {
    DurableObjectIdLike,
    DurableObjectNamespaceLike,
    DurableObjectStubLike,
    MurmurCloudflareEnvironment,
} from "../types.js";

class TestId implements DurableObjectIdLike {
    constructor(readonly value: string) {}

    toString(): string {
        return this.value;
    }
}

const unusedNamespace: DurableObjectNamespaceLike = {
    idFromName: (name) => new TestId(name),
    get: (_id): DurableObjectStubLike => ({
        fetch: async () => Response.json({ error: "unused" }, { status: 500 }),
    }),
};

const authorizedDirectoryNamespace: DurableObjectNamespaceLike = {
    idFromName: (name) => new TestId(name),
    get: (_id): DurableObjectStubLike => ({
        fetch: async () => Response.json({ authorized: true }),
    }),
};

const tokenSecret = new Uint8Array(32).fill(23);
const encodedTokenSecret = encodeBase64Url(tokenSecret);
const environment: MurmurCloudflareEnvironment = {
    MURMUR_FANOUT: authorizedDirectoryNamespace,
    MURMUR_INBOXES: unusedNamespace,
    MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
    MURMUR_RELAY_TOKEN_SECRET: encodedTokenSecret,
    WORKOS_CLIENT_ID: "client_test",
};

function authorizedRequest(path: string, body?: unknown): Request {
    return new Request(`https://relay.test${path}`, {
        method: "POST",
        headers: {
            authorization: "Bearer valid-access-token",
            ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
}

describe("Cloudflare authentication ingress", () => {
    test("rejects ticket issuance without a WorkOS access token", async () => {
        const worker = createMurmurCloudflareWorker({
            authenticateAccessToken: async () => ({ userId: "user_test" }),
        });

        const response = await worker.fetch(
            new Request("https://relay.test/v2/session", { method: "POST" }),
            environment,
        );

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toEqual({ error: "unauthorized" });
    });

    test("binds a negotiated session ticket to the signed device and WorkOS user", async () => {
        const worker = createMurmurCloudflareWorker({
            authenticateAccessToken: async (accessToken) => {
                expect(accessToken).toBe("valid-access-token");
                return { userId: "user_test" };
            },
        });
        const identity = generateIdentityKeyPair();
        const proof = createSignedRelaySessionRequest(identity, Date.now());

        const response = await worker.fetch(
            authorizedRequest("/v2/session", signedRelaySessionRequestToJson(proof)),
            environment,
        );

        expect(response.status).toBe(200);
        const ticket = (await response.json()) as {
            endpoint: string;
            expiresAt: number;
            protocol: "murmur-websocket-v1";
            token: string;
            version: 1;
        };
        expect(ticket).toMatchObject({
            endpoint: environment.MURMUR_RELAY_ENDPOINT,
            protocol: "murmur-websocket-v1",
            version: 1,
        });
        const claims = verifyRelaySessionToken(tokenSecret, ticket.token, {
            expectedEndpoint: environment.MURMUR_RELAY_ENDPOINT,
        });
        expect(claims.device).toEqual(identity.publicKey);
        expect(claims.admissionPrincipal).toBe("user_test");
    });

    test("issues a short-lived directory claim ticket to an authenticated user", async () => {
        const worker = createMurmurCloudflareWorker({
            authenticateAccessToken: async () => ({ userId: "user_test" }),
        });

        const response = await worker.fetch(authorizedRequest("/v2/directory-ticket"), environment);

        expect(response.status).toBe(200);
        const body = (await response.json()) as {
            expiresAt: number;
            ticket: string;
            version: 1;
        };
        expect(body.version).toBe(1);
        const issuer = new LocalDirectoryTicketIssuer({
            issuer: "murmur-cloudflare-directory",
            secretKey: deriveCloudflareDirectoryTicketSecret(encodedTokenSecret),
        });
        expect(issuer.verify(decodeBase64Url(body.ticket), Date.now())).toMatchObject({
            claimBudget: 8,
            expiresAt: body.expiresAt,
            issuer: "murmur-cloudflare-directory",
        });
    });

    test("passes durable directory-ticket throttling back to the authenticated caller", async () => {
        const worker = createMurmurCloudflareWorker({
            authenticateAccessToken: async () => ({ userId: "user_test" }),
        });
        const throttledEnvironment: MurmurCloudflareEnvironment = {
            ...environment,
            MURMUR_FANOUT: {
                idFromName: (name) => new TestId(name),
                get: (_id): DurableObjectStubLike => ({
                    fetch: async () =>
                        Response.json(
                            { error: "rate_limited", retryAfterMilliseconds: 1_000 },
                            { status: 429 },
                        ),
                }),
            },
        };

        const response = await worker.fetch(
            authorizedRequest("/v2/directory-ticket"),
            throttledEnvironment,
        );

        expect(response.status).toBe(429);
        await expect(response.json()).resolves.toEqual({
            error: "rate_limited",
            retryAfterMilliseconds: 1_000,
        });
    });
});
