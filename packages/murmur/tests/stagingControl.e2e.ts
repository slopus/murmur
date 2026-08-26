import {
    LocalDirectoryTicketIssuer,
    createRelaySessionToken,
    deriveCloudflareDirectoryTicketSecret,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    MemoryMurmurStore,
    MurmurClient,
    createAccountSecret,
    generateIdentityKeyPair,
    unlockAccountSecret,
    type IdentityKeyPair,
    type RelaySessionProvider,
    type RelaySessionTicket,
    type SignedRelaySessionRequest,
} from "../sources/index.js";
import { decodeBase64Url, utf8Decode, utf8Encode } from "../sources/utils/index.js";

const STAGING_ENDPOINT = "wss://murmur-relay-staging.bulka-llc.workers.dev/v2/connect";
const TICKET_TTL_MILLISECONDS = 60_000;
const REQUEST_TIMEOUT_MILLISECONDS = 20_000;
const SYNCHRONIZE_ROUNDS = 8;

const encodedSecret = process.env.MURMUR_RELAY_STAGING_TOKEN_SECRET;
const tokenSecret = encodedSecret === undefined ? undefined : decodeBase64Url(encodedSecret);

function requireTokenSecret(): Uint8Array {
    if (tokenSecret === undefined || tokenSecret.length < 32) {
        throw new Error("MURMUR_RELAY_STAGING_TOKEN_SECRET must contain canonical base64url");
    }
    return tokenSecret;
}

function sessionProvider(secret: Uint8Array, admissionPrincipal: string): RelaySessionProvider {
    return {
        issue(request: SignedRelaySessionRequest): Promise<RelaySessionTicket> {
            const issuedAt = Date.now();
            const expiresAt = issuedAt + TICKET_TTL_MILLISECONDS;
            return Promise.resolve({
                version: 1,
                protocol: "murmur-websocket-v1",
                endpoint: STAGING_ENDPOINT,
                token: createRelaySessionToken(secret, {
                    device: request.device,
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

function openClient(
    identity: IdentityKeyPair,
    secret: Uint8Array,
    admissionPrincipal: string,
): Promise<MurmurClient> {
    // Murmur builds the socket with its own generated device key, so the
    // negotiated token must bind that device rather than the account identity.
    return MurmurClient.open({
        identity,
        sessionProvider: sessionProvider(secret, admissionPrincipal),
        webSocket: {
            requestTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
            streamHeartbeatTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
        },
        store: new MemoryMurmurStore(),
    });
}

async function settle(clients: readonly MurmurClient[]): Promise<void> {
    for (let round = 0; round < SYNCHRONIZE_ROUNDS; round += 1) {
        for (const client of clients) await client.synchronize({ waitMilliseconds: 0 });
    }
}

describe.runIf(tokenSecret !== undefined)("deployed Cloudflare staging control plane", () => {
    test("claims directory prekeys and runs a role-managed session end to end", async () => {
        const secret = requireTokenSecret();
        const principal = `control-e2e-${Date.now()}`;
        const ticketIssuer = new LocalDirectoryTicketIssuer({
            issuer: "murmur-cloudflare-directory",
            secretKey: deriveCloudflareDirectoryTicketSecret(encodedSecret!),
        });

        // The account secret is the whole multidevice story: wrap a fresh root,
        // then restore it exactly as a second device would.
        const created = await createAccountSecret(generateIdentityKeyPair(), "staging-password");
        const alice = await unlockAccountSecret(
            created.blob,
            created.generatedSecret,
            "staging-password",
        );
        const bob = generateIdentityKeyPair();

        const aliceClient = await openClient(alice, secret, principal);
        const bobClient = await openClient(bob, secret, principal);
        try {
            // Devices self-register and publish directory prekeys on open.
            await settle([aliceClient, bobClient]);

            const claim = await aliceClient.claimAccount(
                bob.publicKey,
                ticketIssuer.issue({
                    expiresAt: Date.now() + TICKET_TTL_MILLISECONDS,
                    claimBudget: 8,
                }),
            );
            expect(claim.members.length).toBeGreaterThan(0);

            const session = await aliceClient.createSession({
                descriptor: utf8Encode("staging-control-session"),
                members: [claim],
                sendPolicy: "admins",
            });
            await settle([aliceClient, bobClient]);

            if ((await bobClient.session(session.id))?.status === "pending") {
                await bobClient.activateSession(session.id);
            }
            expect((await bobClient.session(session.id))?.status).toBe("active");

            // The relay derives fanout from its own session and roster state;
            // the sender never names a recipient device.
            await aliceClient.send(session.id, utf8Encode("relay-derived-fanout"));
            const received: string[] = [];
            for (let round = 0; round < SYNCHRONIZE_ROUNDS; round += 1) {
                // Sends persist locally first; Alice's own synchronize is what
                // publishes her outbox to the relay.
                await aliceClient.synchronize({ waitMilliseconds: 0 });
                await bobClient.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: (updates) => {
                            for (const update of updates) received.push(utf8Decode(update.bytes));
                        },
                    },
                );
                if (received.length > 0) break;
            }
            expect(received).toContain("relay-derived-fanout");

            // Bob is not an admin, so the admins-only send policy rejects him
            // locally before anything is encrypted.
            await expect(bobClient.send(session.id, utf8Encode("denied"))).rejects.toThrow();

            // The owner deletes the session and the account cascade removes the
            // remaining control state.
            await aliceClient.deleteSession(session.id);
            await settle([aliceClient, bobClient]);
            expect(await aliceClient.session(session.id)).toBeUndefined();

            await aliceClient.deleteAccount();
        } finally {
            await aliceClient.close();
            await bobClient.close();
        }
    }, 120_000);
});
