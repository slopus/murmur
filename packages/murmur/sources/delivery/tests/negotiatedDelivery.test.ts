import {
    parseSignedRelaySessionRequest as parseServerSessionRequest,
    verifyRelaySessionRequest,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { utf8Encode } from "../../utils/index.js";
import {
    HttpRelaySessionProvider,
    WebSocketDeliveryTransport,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    createSignedRelaySessionRequest,
    parseSignedRelaySessionRequest,
    signedRelaySessionRequestToJson,
    signedDeliveryToJson,
    verifySignedRelaySessionRequest,
    type DeliveryWebSocket,
    type DeliveryWebSocketCloseEvent,
    type DeliveryWebSocketMessageEvent,
    type RelaySessionProvider,
    type SignedRelaySessionRequest,
} from "../index.js";

const NOW = 1_720_000_000_000;
const EVENT_ID = "0190b2e0-8000-7000-8000-000000000001";

interface RequestFrame {
    readonly version: 1;
    readonly id: string;
    readonly operation: "publish" | "read" | "acknowledge" | "stream";
    readonly body: unknown;
}

class FakeWebSocket implements DeliveryWebSocket {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null = null;
    readonly #handler: (frame: RequestFrame, socket: FakeWebSocket) => void;

    constructor(handler: (frame: RequestFrame, socket: FakeWebSocket) => void) {
        this.#handler = handler;
        queueMicrotask(() => {
            this.readyState = 1;
            this.onopen?.();
        });
    }

    send(data: string): void {
        this.#handler(JSON.parse(data) as RequestFrame, this);
    }

    close(): void {
        this.readyState = 3;
    }

    receive(value: unknown): void {
        this.onmessage?.({ data: JSON.stringify(value) });
    }
}

describe("negotiated WebSocket delivery", () => {
    test("roundtrips and verifies the device proof through the HTTP issuer", async () => {
        const identity = generateIdentityKeyPair();
        let captured: SignedRelaySessionRequest | undefined;
        const provider = new HttpRelaySessionProvider("https://app.test/v2/murmur-session", {
            fetch: async (_input, initialization) => {
                captured = parseSignedRelaySessionRequest(
                    JSON.parse(String(initialization?.body)) as unknown,
                );
                return Response.json({
                    version: 1,
                    protocol: "murmur-websocket-v1",
                    endpoint: "wss://relay.test/v2/connect",
                    token: "claims.signature",
                    expiresAt: NOW + 60_000,
                });
            },
        });
        const proof = createSignedRelaySessionRequest(identity, NOW, new Uint8Array(24).fill(7));
        const ticket = await provider.issue(proof);

        expect(ticket.endpoint).toBe("wss://relay.test/v2/connect");
        expect(captured).toBeDefined();
        expect(verifySignedRelaySessionRequest(captured!)).toBe(true);
        const serverProof = parseServerSessionRequest(signedRelaySessionRequestToJson(proof));
        expect(verifyRelaySessionRequest(serverProof)).toBe(true);
        expect(captured!.device).toEqual(identity.publicKey);
    });

    test("uses one cached ticket for signed publish, read, ack, and stream operations", async () => {
        const identity = generateIdentityKeyPair();
        const delivery = createSignedDelivery(
            identity,
            [identity.publicKey],
            utf8Encode("ciphertext"),
            { createdAt: NOW, expiresAt: NOW + 60_000 },
        );
        const issued: SignedRelaySessionRequest[] = [];
        const provider: RelaySessionProvider = {
            issue: (request) => {
                issued.push(request);
                return Promise.resolve({
                    version: 1,
                    protocol: "murmur-websocket-v1",
                    endpoint: "wss://relay.test/v2/connect",
                    token: "claims.signature",
                    expiresAt: NOW + 60_000,
                });
            },
        };
        const protocols: (readonly string[])[] = [];
        const transport = new WebSocketDeliveryTransport(identity, provider, {
            now: () => NOW,
            webSocketFactory: (_url, offered) => {
                protocols.push(offered);
                return new FakeWebSocket((frame, socket) => {
                    if (frame.operation === "publish") {
                        socket.receive({
                            version: 1,
                            id: frame.id,
                            type: "response",
                            status: 200,
                            body: { eventId: EVENT_ID, duplicate: false },
                        });
                    } else if (frame.operation === "read") {
                        socket.receive({
                            version: 1,
                            id: frame.id,
                            type: "response",
                            status: 200,
                            body: {
                                deliveries: [],
                                head: EVENT_ID,
                                acknowledgedThrough: null,
                                exhausted: true,
                            },
                        });
                    } else if (frame.operation === "acknowledge") {
                        socket.receive({
                            version: 1,
                            id: frame.id,
                            type: "response",
                            status: 200,
                            body: { removed: 1 },
                        });
                    } else {
                        socket.receive({
                            version: 1,
                            id: frame.id,
                            type: "response",
                            status: 200,
                            body: { connected: true },
                        });
                        queueMicrotask(() =>
                            socket.receive({
                                version: 1,
                                id: frame.id,
                                type: "delivery",
                                body: {
                                    eventId: EVENT_ID,
                                    delivery: signedDeliveryToJson(delivery),
                                },
                            }),
                        );
                    }
                });
            },
        });

        await expect(transport.publish(delivery)).resolves.toEqual({
            eventId: EVENT_ID,
            duplicate: false,
        });
        await expect(
            transport.read(createSignedInboxRead(identity, { createdAt: NOW, limit: 1 })),
        ).resolves.toMatchObject({ head: EVENT_ID, deliveries: [] });
        await expect(
            transport.acknowledge(createSignedInboxAck(identity, EVENT_ID, NOW)),
        ).resolves.toEqual({ removed: 1 });

        const controller = new AbortController();
        const events = transport.stream(
            createSignedInboxRead(identity, { createdAt: NOW, limit: 1 }),
            controller.signal,
        );
        const streamed = await events[Symbol.asyncIterator]().next();
        controller.abort();
        expect(streamed.value?.eventId).toBe(EVENT_ID);

        expect(issued).toHaveLength(1);
        expect(verifySignedRelaySessionRequest(issued[0]!)).toBe(true);
        expect(protocols).toEqual(
            Array.from({ length: 4 }, () => [
                "murmur-websocket-v1",
                "murmur-ticket.claims.signature",
            ]),
        );
    });
});
