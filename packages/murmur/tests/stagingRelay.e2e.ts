import { createRelaySessionToken } from "@slopus/murmur-relay";
import { afterAll, describe, expect, test } from "vitest";
import {
    WebSocketDeliveryTransport,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    destroyIdentity,
    generateIdentityKeyPair,
    type IdentityKeyPair,
    type RelaySessionProvider,
    type RelaySessionTicket,
    type SignedRelaySessionRequest,
} from "../sources/index.js";
import {
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../sources/utils/index.js";

const STAGING_ORIGIN = "https://murmur-relay-staging.bulka-llc.workers.dev";
const STAGING_ENDPOINT = "wss://murmur-relay-staging.bulka-llc.workers.dev/v2/connect";
const TICKET_TTL_MILLISECONDS = 60_000;
const DELIVERY_TTL_MILLISECONDS = 90_000;
const REQUEST_TIMEOUT_MILLISECONDS = 20_000;

const encodedSecret = process.env.MURMUR_RELAY_STAGING_TOKEN_SECRET;
const tokenSecret = encodedSecret === undefined ? undefined : decodeBase64Url(encodedSecret);

function requireTokenSecret(): Uint8Array {
    if (tokenSecret === undefined || tokenSecret.length < 32) {
        throw new Error("MURMUR_RELAY_STAGING_TOKEN_SECRET must contain canonical base64url");
    }
    return tokenSecret;
}

function sessionProvider(
    secret: Uint8Array,
    admissionPrincipal: string,
    deviceOverride?: Uint8Array,
): RelaySessionProvider {
    return {
        issue(request: SignedRelaySessionRequest): Promise<RelaySessionTicket> {
            const issuedAt = Date.now();
            const expiresAt = issuedAt + TICKET_TTL_MILLISECONDS;
            const device = deviceOverride ?? request.device;
            return Promise.resolve({
                version: 1,
                protocol: "murmur-websocket-v1",
                endpoint: STAGING_ENDPOINT,
                token: createRelaySessionToken(secret, {
                    device,
                    endpoint: STAGING_ENDPOINT,
                    admissionPrincipal,
                    issuedAt,
                    expiresAt,
                }),
                expiresAt,
            });
        },
    };
}

function transport(
    identity: IdentityKeyPair,
    secret: Uint8Array,
    admissionPrincipal: string,
): WebSocketDeliveryTransport {
    return new WebSocketDeliveryTransport(identity, sessionProvider(secret, admissionPrincipal), {
        requestTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
        streamHeartbeatTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
    });
}

function rejectUnauthenticatedWebSocket(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        const socket = new WebSocket(STAGING_ENDPOINT, [
            "murmur-websocket-v1",
            "murmur-ticket.invalid.invalid",
        ]);
        let settled = false;
        const finish = (error?: Error): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            socket.close();
            if (error === undefined) resolve();
            else reject(error);
        };
        const timeout = setTimeout(
            () => finish(new Error("Staging relay did not reject an invalid ticket")),
            REQUEST_TIMEOUT_MILLISECONDS,
        );
        socket.onopen = () => finish(new Error("Staging relay accepted an invalid ticket"));
        socket.onerror = () => finish();
        socket.onclose = () => finish();
    });
}

async function within<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            promise,
            new Promise<T>((_resolve, reject) => {
                timer = setTimeout(
                    () => reject(new Error("Staging relay operation timed out")),
                    milliseconds,
                );
            }),
        ]);
    } finally {
        if (timer !== undefined) clearTimeout(timer);
    }
}

afterAll(() => {
    if (tokenSecret !== undefined) zeroBytes(tokenSecret);
});

describe("deployed Cloudflare staging relay", () => {
    test("reports health and rejects an invalid WebSocket ticket", async () => {
        const response = await fetch(`${STAGING_ORIGIN}/health`);
        expect(response.status).toBe(200);
        expect(response.headers.get("cache-control")).toBe("no-store");
        await expect(response.json()).resolves.toEqual({ ok: true });
        await rejectUnauthenticatedWebSocket();
    });

    test("authenticates devices and preserves multicast, order, ack, and reconnect semantics", async () => {
        const secret = requireTokenSecret();
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const principal = `staging-e2e-${encodeBase64Url(alice.publicKey)}`;
        const aliceTransport = transport(alice, secret, principal);
        const bobTransport = transport(bob, secret, principal);
        let latestEventId: string | undefined;
        let stage = "create deliveries";
        try {
            const now = Date.now();
            const first = createSignedDelivery(
                alice,
                [alice.publicKey, bob.publicKey],
                utf8Encode("staging-first"),
                { createdAt: now, expiresAt: now + DELIVERY_TTL_MILLISECONDS },
            );
            const second = createSignedDelivery(
                alice,
                [alice.publicKey, bob.publicKey],
                utf8Encode("staging-second"),
                { createdAt: now + 1, expiresAt: now + DELIVERY_TTL_MILLISECONDS },
            );

            stage = "publish first delivery";
            const firstOutcome = await aliceTransport.publish(first);
            stage = "deduplicate first delivery";
            await expect(aliceTransport.publish(first)).resolves.toEqual({
                eventId: firstOutcome.eventId,
                duplicate: true,
            });
            stage = "publish second delivery";
            const secondOutcome = await aliceTransport.publish(second);
            expect(firstOutcome.eventId < secondOutcome.eventId).toBe(true);
            latestEventId = secondOutcome.eventId;

            stage = "read Bob's multicast inbox";
            const bobPage = await bobTransport.read(
                createSignedInboxRead(bob, { createdAt: Date.now(), limit: 10 }),
            );
            expect(bobPage.deliveries.map((delivery) => delivery.eventId)).toEqual([
                firstOutcome.eventId,
                secondOutcome.eventId,
            ]);
            expect(
                bobPage.deliveries.map((delivery) => utf8Decode(delivery.delivery.ciphertext)),
            ).toEqual(["staging-first", "staging-second"]);
            stage = "read Alice's multicast inbox";
            const alicePage = await aliceTransport.read(
                createSignedInboxRead(alice, { createdAt: Date.now(), limit: 10 }),
            );
            expect(alicePage.deliveries.map((delivery) => delivery.eventId)).toEqual([
                firstOutcome.eventId,
                secondOutcome.eventId,
            ]);

            const misboundTransport = new WebSocketDeliveryTransport(
                alice,
                sessionProvider(secret, principal, bob.publicKey),
                { requestTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS },
            );
            stage = "reject a misbound device ticket";
            await expect(misboundTransport.publish(second)).rejects.toMatchObject({
                status: 403,
                code: "forbidden",
            });

            stage = "acknowledge Bob's initial inbox";
            await expect(
                bobTransport.acknowledge(
                    createSignedInboxAck(bob, secondOutcome.eventId, Date.now()),
                ),
            ).resolves.toEqual({ removed: 2 });
            stage = "acknowledge Alice's initial inbox";
            await expect(
                aliceTransport.acknowledge(
                    createSignedInboxAck(alice, secondOutcome.eventId, Date.now()),
                ),
            ).resolves.toEqual({ removed: 2 });

            const streamAbort = new AbortController();
            let markConnected: (() => void) | undefined;
            let rejectConnection: ((error: unknown) => void) | undefined;
            const connected = new Promise<void>((resolve, reject) => {
                markConnected = resolve;
                rejectConnection = reject;
            });
            const stream = bobTransport.stream(
                createSignedInboxRead(bob, {
                    after: secondOutcome.eventId,
                    createdAt: Date.now(),
                    limit: 1,
                    waitMilliseconds: 0,
                }),
                streamAbort.signal,
                { onConnected: () => markConnected?.() },
            );
            const nextDelivery = stream.next();
            void nextDelivery.catch((error: unknown) => rejectConnection?.(error));
            stage = "connect Bob's delivery stream";
            await within(connected, REQUEST_TIMEOUT_MILLISECONDS);

            const thirdCreatedAt = Date.now();
            const third = createSignedDelivery(
                alice,
                [alice.publicKey, bob.publicKey],
                utf8Encode("staging-reconnect"),
                {
                    createdAt: thirdCreatedAt,
                    expiresAt: thirdCreatedAt + DELIVERY_TTL_MILLISECONDS,
                },
            );
            stage = "publish to Bob's connected stream";
            const thirdOutcome = await aliceTransport.publish(third);
            latestEventId = thirdOutcome.eventId;
            stage = "receive Bob's streamed delivery";
            const streamed = await within(nextDelivery, REQUEST_TIMEOUT_MILLISECONDS);
            expect(streamed.done).toBe(false);
            expect(streamed.value?.eventId).toBe(thirdOutcome.eventId);
            expect(utf8Decode(streamed.value!.delivery.ciphertext)).toBe("staging-reconnect");
            streamAbort.abort();
            await stream.return(undefined);

            stage = "read Bob's unacknowledged delivery after reconnect";
            const reconnectedBob = transport(bob, secret, principal);
            const redelivered = await reconnectedBob.read(
                createSignedInboxRead(bob, {
                    after: secondOutcome.eventId,
                    createdAt: Date.now(),
                    limit: 10,
                }),
            );
            expect(redelivered.deliveries.map((delivery) => delivery.eventId)).toEqual([
                thirdOutcome.eventId,
            ]);

            stage = "acknowledge Bob's reconnected inbox";
            await bobTransport.acknowledge(
                createSignedInboxAck(bob, thirdOutcome.eventId, Date.now()),
            );
            stage = "acknowledge Alice's streamed delivery";
            await aliceTransport.acknowledge(
                createSignedInboxAck(alice, thirdOutcome.eventId, Date.now()),
            );
            stage = "verify Bob's acknowledged inbox is empty";
            const empty = await reconnectedBob.read(
                createSignedInboxRead(bob, {
                    after: thirdOutcome.eventId,
                    createdAt: Date.now(),
                    limit: 10,
                }),
            );
            expect(empty.deliveries).toEqual([]);
            expect(empty.acknowledgedThrough).toBe(thirdOutcome.eventId);
        } catch (error: unknown) {
            throw new Error(`Staging relay failed to ${stage}`, { cause: error });
        } finally {
            if (latestEventId !== undefined) {
                await Promise.allSettled([
                    bobTransport.acknowledge(createSignedInboxAck(bob, latestEventId, Date.now())),
                    aliceTransport.acknowledge(
                        createSignedInboxAck(alice, latestEventId, Date.now()),
                    ),
                ]);
            }
            destroyIdentity(alice);
            destroyIdentity(bob);
        }
    }, 60_000);
});
