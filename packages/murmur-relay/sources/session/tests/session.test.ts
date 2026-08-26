import { ed25519 } from "@noble/curves/ed25519";
import {
    WebSocketDeliveryTransport,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    destroyIdentity,
    generateIdentityKeyPair,
    type DeliveryWebSocket,
    type DeliveryWebSocketCloseEvent,
    type DeliveryWebSocketMessageEvent,
    type RelaySessionProvider,
} from "@slopus/murmur";
import { describe, expect, test } from "vitest";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { RelayWebSocketSession, type RelayWebSocketPeer } from "../../websocket/index.js";
import {
    identity,
    recipients,
    secret,
    signedDelivery,
    signedRead,
} from "../../protocol/tests/helpers.js";
import {
    createRelaySessionFetchHandler,
    createRelaySessionToken,
    verifyRelaySessionToken,
} from "../index.js";

const NOW = 1_720_000_000_000;
const ENDPOINT = "wss://relay.test/v2/connect";
const TOKEN_SECRET = new Uint8Array(32).fill(19);
const textEncoder = new TextEncoder();

function sessionProof(secretKey: Uint8Array): Record<string, unknown> {
    const unsigned = {
        version: 1 as const,
        device: encodeBase64Url(identity(secretKey)),
        createdAt: NOW,
        nonce: encodeBase64Url(new Uint8Array(24).fill(8)),
    };
    const prefix = textEncoder.encode("murmur.relay.session.v1\0");
    const body = canonicalJson(unsigned);
    const signingBytes = new Uint8Array(prefix.length + body.length);
    signingBytes.set(prefix);
    signingBytes.set(body, prefix.length);
    return {
        ...unsigned,
        signature: encodeBase64Url(ed25519.sign(signingBytes, secretKey)),
    };
}

class CapturingPeer implements RelayWebSocketPeer {
    readonly messages: string[] = [];
    closed = false;

    send(message: string): void {
        this.messages.push(message);
    }

    close(): void {
        this.closed = true;
    }
}

class RelaySessionWebSocket implements DeliveryWebSocket {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null = null;
    readonly #session: RelayWebSocketSession;

    constructor(relay: RelayService, claims: ReturnType<typeof verifyRelaySessionToken>) {
        const peer: RelayWebSocketPeer = {
            send: (message) => {
                queueMicrotask(() => this.onmessage?.({ data: message }));
            },
            close: (code = 1000, reason = "") => {
                if (this.readyState === 3) return;
                this.readyState = 3;
                queueMicrotask(() => this.onclose?.({ code, reason, wasClean: code === 1000 }));
            },
        };
        this.#session = new RelayWebSocketSession({ relay, claims, peer });
        queueMicrotask(() => {
            if (this.readyState !== 0) return;
            this.readyState = 1;
            this.onopen?.();
        });
    }

    send(data: string): void {
        void this.#session.receive(data).catch(() => this.onerror?.());
    }

    close(code: number = 1000, reason: string = ""): void {
        this.#session.close(code, reason);
    }
}

describe("negotiated relay sessions", () => {
    test("rejects duplicate JSON keys before authorization", async () => {
        const aliceSecret = secret(1);
        let authorizations = 0;
        const handler = createRelaySessionFetchHandler({
            tokenSecret: TOKEN_SECRET,
            now: () => NOW,
            authorize: async () => {
                authorizations += 1;
                return { endpoint: ENDPOINT, admissionPrincipal: "account-42" };
            },
        });
        const canonical = JSON.stringify(sessionProof(aliceSecret));
        const response = await handler(
            new Request("https://app.test/v2/murmur-session", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: canonical.replace("{", '{"version":2,'),
            }),
        );
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({ error: "duplicate_json_key" });
        expect(authorizations).toBe(0);
    });

    test("lets the application authorize a device and issues an endpoint-bound token", async () => {
        const aliceSecret = secret(1);
        const handler = createRelaySessionFetchHandler({
            tokenSecret: TOKEN_SECRET,
            now: () => NOW,
            authorize: async (request, proof) =>
                request.headers.get("authorization") === "Bearer user-session" &&
                proof.device.every((byte, index) => byte === identity(aliceSecret)[index])
                    ? { endpoint: ENDPOINT, admissionPrincipal: "account-42" }
                    : undefined,
        });
        const response = await handler(
            new Request("https://app.test/v2/murmur-session", {
                method: "POST",
                headers: {
                    authorization: "Bearer user-session",
                    "content-type": "application/json",
                },
                body: JSON.stringify(sessionProof(aliceSecret)),
            }),
        );
        expect(response.status).toBe(200);
        const ticket = (await response.json()) as {
            readonly token: string;
            readonly expiresAt: number;
        };
        const claims = verifyRelaySessionToken(TOKEN_SECRET, ticket.token, {
            now: NOW,
            expectedEndpoint: ENDPOINT,
        });
        expect(claims.device).toEqual(identity(aliceSecret));
        expect(claims.admissionPrincipal).toBe("account-42");
        expect(ticket.expiresAt).toBe(NOW + 5 * 60 * 1_000);
        const tampered = `${ticket.token.startsWith("A") ? "B" : "A"}${ticket.token.slice(1)}`;
        expect(() =>
            verifyRelaySessionToken(TOKEN_SECRET, tampered, {
                now: NOW,
            }),
        ).toThrow("Invalid relay-session token");
    });

    test("binds every WebSocket operation to the ticket device", async () => {
        const aliceSecret = secret(1);
        const bobSecret = secret(2);
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        try {
            const token = createRelaySessionToken(TOKEN_SECRET, {
                device: identity(aliceSecret),
                endpoint: ENDPOINT,
                admissionPrincipal: "account-42",
                issuedAt: NOW,
                expiresAt: NOW + 60_000,
                nonce: new Uint8Array(24).fill(3),
            });
            const claims = verifyRelaySessionToken(TOKEN_SECRET, token, { now: NOW });
            const peer = new CapturingPeer();
            const session = new RelayWebSocketSession({ relay, claims, peer });
            const delivery = signedDelivery(aliceSecret, recipients(identity(bobSecret)), {
                now: NOW,
                expiresAt: NOW + 60_000,
            });
            await session.receive(
                JSON.stringify({
                    version: 1,
                    id: "AAAAAAAAAAAAAAAAAAAAAAAA",
                    operation: "publish",
                    body: {
                        version: delivery.version,
                        id: delivery.id,
                        sender: encodeBase64Url(delivery.sender),
                        recipients: delivery.recipients.map(encodeBase64Url),
                        createdAt: delivery.createdAt,
                        expiresAt: delivery.expiresAt,
                        ciphertext: encodeBase64Url(delivery.ciphertext),
                        signature: encodeBase64Url(delivery.signature),
                    },
                }),
            );
            expect(JSON.parse(peer.messages[0]!) as unknown).toMatchObject({
                status: 200,
                body: { duplicate: false },
            });

            const unauthorizedPeer = new CapturingPeer();
            const unauthorized = new RelayWebSocketSession({
                relay,
                claims,
                peer: unauthorizedPeer,
            });
            const read = signedRead(bobSecret, { now: NOW });
            await unauthorized.receive(
                JSON.stringify({
                    version: 1,
                    id: "BBBBBBBBBBBBBBBBBBBBBBBB",
                    operation: "read",
                    body: {
                        version: read.version,
                        recipient: encodeBase64Url(read.recipient),
                        after: read.after,
                        limit: read.limit,
                        waitMilliseconds: read.waitMilliseconds,
                        createdAt: read.createdAt,
                        signature: encodeBase64Url(read.signature),
                    },
                }),
            );
            expect(JSON.parse(unauthorizedPeer.messages[0]!) as unknown).toMatchObject({
                status: 403,
                body: { error: "forbidden" },
            });
        } finally {
            await relay.close();
        }
    });

    test("roundtrips continuity acknowledgement through the production WebSocket client", async () => {
        const identityKeyPair = generateIdentityKeyPair();
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const token = createRelaySessionToken(TOKEN_SECRET, {
            device: identityKeyPair.publicKey,
            endpoint: ENDPOINT,
            admissionPrincipal: "account-42",
            issuedAt: NOW,
            expiresAt: NOW + 60_000,
            nonce: new Uint8Array(24).fill(9),
        });
        const claims = verifyRelaySessionToken(TOKEN_SECRET, token, { now: NOW });
        const provider: RelaySessionProvider = {
            issue: async () => ({
                version: 1,
                protocol: "murmur-websocket-v1",
                endpoint: ENDPOINT,
                token,
                expiresAt: NOW + 60_000,
            }),
        };
        const transport = new WebSocketDeliveryTransport(identityKeyPair, provider, {
            now: () => NOW,
            webSocketFactory: () => new RelaySessionWebSocket(relay, claims),
        });
        try {
            const delivery = createSignedDelivery(
                identityKeyPair,
                [identityKeyPair.publicKey],
                new Uint8Array([2]),
                { createdAt: NOW, expiresAt: NOW + 60_000 },
            );
            const published = await transport.publish(delivery);
            const page = await transport.read(
                createSignedInboxRead(identityKeyPair, { createdAt: NOW }),
            );
            expect(page.deliveries).toHaveLength(1);
            const acknowledgement = await transport.acknowledge(
                createSignedInboxAck(identityKeyPair, published.eventId, NOW),
            );
            expect(acknowledgement).toEqual({
                removed: 1,
                sequence: 1,
                generation: page.generation,
            });
            await expect(
                transport.read(
                    createSignedInboxRead(identityKeyPair, {
                        after: published.eventId,
                        createdAt: NOW,
                    }),
                ),
            ).resolves.toMatchObject({ deliveries: [] });
        } finally {
            destroyIdentity(identityKeyPair);
            await relay.close();
        }
    });
});
