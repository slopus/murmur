import {
    LocalDirectoryTicketIssuer,
    RelayService,
    SqliteRelayStore,
    createRelayFetchHandler,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { ACCOUNT_PEER_ROSTER_PREFIX, serializeDeviceRoster } from "../index.js";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { HttpDeliveryTransport } from "../../delivery/index.js";
import { MurmurClient } from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

describe("restored-account device registration", () => {
    test("self-registers a second device and removes it", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        const account = generateIdentityKeyPair();
        const first = await MurmurClient.open({
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const peer = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const session = await first.createSession({
            descriptor: utf8Encode("device-roster-convergence"),
            members: [await peer.createKeyPackage()],
        });
        for (let round = 0; round < 4; round += 1) {
            await first.synchronize({ waitMilliseconds: 0 });
            await peer.synchronize({ waitMilliseconds: 0 });
        }
        if ((await peer.session(session.id))?.status === "pending") {
            await peer.activateSession(session.id);
        }
        const second = await MurmurClient.open({
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const firstNotification = await first.synchronize({ waitMilliseconds: 0 });
            const secondNotification = await second.synchronize({ waitMilliseconds: 0 });
            expect(firstNotification.inbox.processed).toBeGreaterThan(0);
            expect(secondNotification.inbox.processed).toBeGreaterThan(0);
            for (let round = 0; round < 8; round += 1) {
                await first.synchronize({ waitMilliseconds: 0 });
                await peer.synchronize({ waitMilliseconds: 0 });
                await second.synchronize({ waitMilliseconds: 0 });
            }
            expect((await second.session(session.id))?.status).toBe("pending");
            await second.activateSession(session.id);
            expect((await second.session(session.id))?.status).toBe("active");
            expect(await first.devices()).toHaveLength(2);
            await first.removeDevice(second.deviceKey);
            expect(await first.devices()).toHaveLength(1);
        } finally {
            first.close();
            second.close();
            peer.close();
            await relay.close();
        }
    });

    test("consumes a stale-roster response and retries a session delivery to a new device", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const relayFetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        let trackSenderPublications = false;
        const staleResponses: unknown[] = [];
        const successfulPublications: Record<string, unknown>[] = [];
        const senderFetch = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => {
            const request = new Request(input, init);
            const requestCopy = request.clone();
            const response = await handler(request);
            if (trackSenderPublications && new URL(request.url).pathname === "/v1/deliveries") {
                const body = (await requestCopy.json()) as Record<string, unknown>;
                if (response.status === 409) {
                    staleResponses.push(await response.clone().json());
                } else if (response.ok) {
                    successfulPublications.push(body);
                }
            }
            return response;
        };
        const senderStore = new MemoryMurmurStore();
        const sender = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch: senderFetch }),
            store: senderStore,
        });
        const targetAccount = generateIdentityKeyPair();
        const firstTarget = await MurmurClient.open({
            identity: targetAccount,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch }),
            store: new MemoryMurmurStore(),
        });
        let secondTarget: MurmurClient | undefined;
        try {
            const session = await firstTarget.createSession({
                descriptor: utf8Encode("stale-roster-retry"),
                members: [await sender.createKeyPackage()],
            });
            for (let round = 0; round < 4; round += 1) {
                await firstTarget.synchronize({ waitMilliseconds: 0 });
                await sender.synchronize({ waitMilliseconds: 0 });
            }
            if ((await sender.session(session.id))?.status === "pending") {
                await sender.activateSession(session.id);
            }
            const staleRoster = await new HttpDeliveryTransport("https://relay.test", {
                fetch: relayFetch,
            }).readDeviceRoster(targetAccount.publicKey);
            if (staleRoster === undefined) throw new Error("Target roster was not registered");

            secondTarget = await MurmurClient.open({
                identity: targetAccount,
                transport: new HttpDeliveryTransport("https://relay.test", {
                    fetch: relayFetch,
                }),
                store: new MemoryMurmurStore(),
            });
            for (let round = 0; round < 12; round += 1) {
                await firstTarget.synchronize({ waitMilliseconds: 0 });
                await sender.synchronize({ waitMilliseconds: 0 });
                await secondTarget.synchronize({ waitMilliseconds: 0 });
            }
            expect((await secondTarget.session(session.id))?.status).toBe("pending");
            await secondTarget.activateSession(session.id);
            await senderStore.set(
                `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(targetAccount.publicKey)}`,
                serializeDeviceRoster(staleRoster),
            );

            trackSenderPublications = true;
            await sender.send(session.id, utf8Encode("expanded roster delivery"));
            await expect(sender.synchronize({ waitMilliseconds: 0 })).resolves.toMatchObject({
                transientPublicationFailures: 1,
                terminalPublicationFailures: 0,
            });
            const retried = await sender.synchronize({ waitMilliseconds: 0 });
            expect(retried.published).toBeGreaterThanOrEqual(1);
            expect(retried).toMatchObject({
                transientPublicationFailures: 0,
                terminalPublicationFailures: 0,
            });

            expect(staleResponses).toEqual([expect.objectContaining({ error: "stale_roster" })]);
            expect(successfulPublications).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        recipients: expect.arrayContaining([
                            encodeBase64Url(secondTarget.deviceKey),
                        ]),
                        targetAccounts: expect.arrayContaining([
                            {
                                accountKey: encodeBase64Url(targetAccount.publicKey),
                                rosterRevision: 2,
                            },
                        ]),
                    }),
                ]),
            );

            const received: string[] = [];
            for (let round = 0; round < 4; round += 1) {
                await secondTarget.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: (updates) => {
                            received.push(...updates.map((update) => utf8Decode(update.bytes)));
                        },
                    },
                );
            }
            expect(received).toContain("expanded roster delivery");
        } finally {
            sender.close();
            firstTarget.close();
            secondTarget?.close();
            await relay.close();
        }
    });
});

describe("identity directory", () => {
    test("automatically publishes, replenishes, and rotates one-use prekeys", async () => {
        const issuer = new LocalDirectoryTicketIssuer();
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {},
            undefined,
            Date.now,
            issuer,
        );
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        const owner = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const claimant = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const ticket = issuer.issue({
                expiresAt: Date.now() + 60_000,
                claimBudget: 8,
            });
            for (let index = 0; index < 4; index += 1) {
                const claim = await claimant.claimAccount(owner.identity, ticket);
                expect(claim.members).toHaveLength(1);
                expect(claim.members[0]?.source).toBe("one_time");
            }
            const replenished = await owner.synchronize({ waitMilliseconds: 0 });
            expect(replenished.inbox.processed).toBeGreaterThanOrEqual(4);
            expect((await claimant.claimAccount(owner.identity, ticket)).members[0]?.source).toBe(
                "one_time",
            );

            await owner.rotate();
            const afterRotation = await claimant.claimAccount(
                owner.identity,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 1 }),
            );
            expect(afterRotation.members[0]?.source).toBe("one_time");
        } finally {
            owner.close();
            claimant.close();
            await relay.close();
        }
    });

    test("accepts two independent Welcomes from one last-resort prekey and passes claims to Add", async () => {
        const issuer = new LocalDirectoryTicketIssuer();
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {},
            undefined,
            Date.now,
            issuer,
        );
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        const target = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const firstClaimant = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const secondClaimant = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const ticket = issuer.issue({
                expiresAt: Date.now() + 60_000,
                claimBudget: 8,
            });
            for (let index = 0; index < 4; index += 1) {
                await firstClaimant.claimAccount(target.identity, ticket);
            }
            const firstClaim = await firstClaimant.claimAccount(target.identity, ticket);
            const secondClaim = await secondClaimant.claimAccount(target.identity, ticket);
            expect(firstClaim.members[0]?.source).toBe("last_resort");
            expect(secondClaim.members[0]?.source).toBe("last_resort");
            expect(firstClaim.members[0]?.keyPackage).toEqual(secondClaim.members[0]?.keyPackage);

            const firstSession = await firstClaimant.createSession({
                descriptor: utf8Encode("first-last-resort-session"),
                members: [firstClaim],
            });
            const secondSession = await secondClaimant.createSession({
                descriptor: utf8Encode("second-last-resort-session"),
                members: [secondClaim],
            });
            for (let round = 0; round < 8; round += 1) {
                await firstClaimant.synchronize({ waitMilliseconds: 0 });
                await secondClaimant.synchronize({ waitMilliseconds: 0 });
                await target.synchronize({ waitMilliseconds: 0 });
            }
            expect((await target.session(firstSession.id))?.status).toBe("pending");
            expect((await target.session(secondSession.id))?.status).toBe("pending");
            await target.activateSession(firstSession.id);
            await target.activateSession(secondSession.id);

            const secondAccountClaim = await firstClaimant.claimAccount(
                secondClaimant.identity,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 1 }),
            );
            await firstClaimant.addMember(firstSession.id, secondAccountClaim);
            for (let round = 0; round < 8; round += 1) {
                await firstClaimant.synchronize({ waitMilliseconds: 0 });
                await target.synchronize({ waitMilliseconds: 0 });
                await secondClaimant.synchronize({ waitMilliseconds: 0 });
            }
            expect((await secondClaimant.session(firstSession.id))?.status).toBe("pending");
        } finally {
            target.close();
            firstClaimant.close();
            secondClaimant.close();
            await relay.close();
        }
    });
});
