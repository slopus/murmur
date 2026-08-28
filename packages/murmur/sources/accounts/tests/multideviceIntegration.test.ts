import { createRootContext } from "@steve.kite/stdlib";
import {
    LocalDirectoryTicketIssuer,
    RelayService,
    SqliteRelayStore,
    createRelayFetchHandler,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { ACCOUNT_PEER_ROSTER_PREFIX, serializeDeviceRoster } from "../index.js";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { HttpDeliveryTransport, type DeliveryFetch } from "../../delivery/index.js";
import { MurmurClient } from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

const ctx = createRootContext().named("test");

describe("restored-account device registration", () => {
    test("registers sibling devices and updates owner-encrypted metadata in place", async () => {
        const issuer = new LocalDirectoryTicketIssuer();
        const relayStore = new SqliteRelayStore(":memory:");
        const relay = new RelayService(relayStore, {}, undefined, Date.now, issuer);
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch: DeliveryFetch = (_ctx, input, init): Promise<Response> =>
            handler(new Request(input, init));
        const transport = (): HttpDeliveryTransport =>
            new HttpDeliveryTransport("https://relay.test", { fetch });
        const account = generateIdentityKeyPair();
        const firstStore = new MemoryMurmurStore();
        const secondStore = new MemoryMurmurStore();
        let first: MurmurClient | undefined;
        let second: MurmurClient | undefined;
        let reopened: MurmurClient | undefined;
        let claimant: MurmurClient | undefined;
        let firstMetadataDevice: Uint8Array | undefined;
        let secondMetadataDevice: Uint8Array | undefined;
        try {
            first = await MurmurClient.open(ctx, {
                identity: account,
                transport: transport(),
                store: firstStore,
                encryptDeviceMetadata: (_ctx, deviceKey) => {
                    firstMetadataDevice = deviceKey.slice();
                    return new Uint8Array([1]);
                },
            });
            second = await MurmurClient.open(ctx, {
                identity: account,
                transport: transport(),
                store: secondStore,
                encryptDeviceMetadata: async (_ctx, deviceKey) => {
                    secondMetadataDevice = deviceKey.slice();
                    return new Uint8Array([2]);
                },
            });
            expect(firstMetadataDevice).toEqual(first.deviceKey);
            expect(secondMetadataDevice).toEqual(second.deviceKey);

            const registered = await transport().readDeviceRoster(ctx, account.publicKey);
            expect(registered?.devices).toHaveLength(2);
            expect(registered?.devices.map((entry) => entry.encryptedMetadata[0]).sort()).toEqual([
                1, 2,
            ]);
            const firstRegistered = registered?.devices.find(
                (entry) => encodeBase64Url(entry.deviceKey) === encodeBase64Url(first!.deviceKey),
            );
            expect(firstRegistered?.lastAccessedAt).toEqual(expect.any(Number));
            await relay.recordDeviceAccess(
                first.deviceKey,
                firstRegistered!.lastAccessedAt + 1_000,
            );
            const refreshed = await first.devices(ctx);
            expect(
                refreshed.find(
                    (entry) =>
                        encodeBase64Url(entry.deviceKey) === encodeBase64Url(first!.deviceKey),
                )?.lastAccessedAt,
            ).toBe(firstRegistered!.lastAccessedAt + 1_000);
            expect((await transport().readDeviceRoster(ctx, account.publicKey))?.revision).toBe(
                registered?.revision,
            );
            const secondGeneration = registered?.devices.find(
                (entry) => encodeBase64Url(entry.deviceKey) === encodeBase64Url(second!.deviceKey),
            )?.resetGeneration;

            claimant = await MurmurClient.open(ctx, {
                transport: transport(),
                store: new MemoryMurmurStore(),
            });
            const beforeUpdate = await claimant.claimAccount(
                ctx,
                account.publicKey,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 2 }),
            );
            expect(beforeUpdate.members).toHaveLength(2);

            const secondDeviceKey = second.deviceKey;
            second.close(ctx);
            second = undefined;
            reopened = await MurmurClient.open(ctx, {
                identity: account,
                transport: transport(),
                store: secondStore,
                encryptDeviceMetadata: (_ctx, deviceKey) => {
                    expect(deviceKey).toEqual(secondDeviceKey);
                    return new Uint8Array([3]);
                },
            });

            const updated = await transport().readDeviceRoster(ctx, account.publicKey);
            const updatedSecond = updated?.devices.find(
                (entry) => encodeBase64Url(entry.deviceKey) === encodeBase64Url(secondDeviceKey),
            );
            expect(updatedSecond).toMatchObject({
                resetGeneration: secondGeneration,
                encryptedMetadata: new Uint8Array([3]),
            });
            expect(updated?.devices).toHaveLength(2);

            const afterUpdate = await claimant.claimAccount(
                ctx,
                account.publicKey,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 2 }),
            );
            expect(afterUpdate.members).toHaveLength(2);
        } finally {
            first?.close(ctx);
            second?.close(ctx);
            reopened?.close(ctx);
            claimant?.close(ctx);
            await relay.close();
        }
    });

    test("self-registers a second device and removes it", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch: DeliveryFetch = (_ctx, input, init): Promise<Response> =>
            handler(new Request(input, init));
        const account = generateIdentityKeyPair();
        const first = await MurmurClient.open(ctx, {
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const peer = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const session = await first.createSession(ctx, {
            descriptor: utf8Encode("device-roster-convergence"),
            members: [await peer.createKeyPackage(ctx)],
        });
        for (let round = 0; round < 4; round += 1) {
            await first.synchronize(ctx, { waitMilliseconds: 0 });
            await peer.synchronize(ctx, { waitMilliseconds: 0 });
        }
        if ((await peer.session(ctx, session.id))?.status === "pending") {
            await peer.activateSession(ctx, session.id);
        }
        const second = await MurmurClient.open(ctx, {
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const firstNotification = await first.synchronize(ctx, { waitMilliseconds: 0 });
            const secondNotification = await second.synchronize(ctx, { waitMilliseconds: 0 });
            expect(firstNotification.inbox.processed).toBeGreaterThan(0);
            expect(secondNotification.inbox.processed).toBeGreaterThan(0);
            for (let round = 0; round < 8; round += 1) {
                await first.synchronize(ctx, { waitMilliseconds: 0 });
                await peer.synchronize(ctx, { waitMilliseconds: 0 });
                await second.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect((await second.session(ctx, session.id))?.status).toBe("pending");
            await second.activateSession(ctx, session.id);
            expect((await second.session(ctx, session.id))?.status).toBe("active");
            expect(await first.devices(ctx)).toHaveLength(2);
            await first.removeDevice(ctx, second.deviceKey);
            expect(await first.devices(ctx)).toHaveLength(1);
        } finally {
            first.close(ctx);
            second.close(ctx);
            peer.close(ctx);
            await relay.close();
        }
    });

    test("consumes stale epoch coverage and retries a session delivery to a new device", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const relayFetch: DeliveryFetch = (_ctx, input, init): Promise<Response> =>
            handler(new Request(input, init));
        let trackSenderPublications = false;
        const staleResponses: unknown[] = [];
        const successfulPublications: Record<string, unknown>[] = [];
        const senderFetch: DeliveryFetch = async (
            _ctx,
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
        const sender = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch: senderFetch }),
            store: senderStore,
        });
        const targetAccount = generateIdentityKeyPair();
        const firstTarget = await MurmurClient.open(ctx, {
            identity: targetAccount,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch }),
            store: new MemoryMurmurStore(),
        });
        let secondTarget: MurmurClient | undefined;
        try {
            const session = await firstTarget.createSession(ctx, {
                descriptor: utf8Encode("stale-roster-retry"),
                members: [await sender.createKeyPackage(ctx)],
            });
            for (let round = 0; round < 4; round += 1) {
                await firstTarget.synchronize(ctx, { waitMilliseconds: 0 });
                await sender.synchronize(ctx, { waitMilliseconds: 0 });
            }
            if ((await sender.session(ctx, session.id))?.status === "pending") {
                await sender.activateSession(ctx, session.id);
            }
            const staleRoster = await new HttpDeliveryTransport("https://relay.test", {
                fetch: relayFetch,
            }).readDeviceRoster(ctx, targetAccount.publicKey);
            if (staleRoster === undefined) throw new Error("Target roster was not registered");

            const secondStore = new MemoryMurmurStore();
            secondTarget = await MurmurClient.open(ctx, {
                identity: targetAccount,
                transport: new HttpDeliveryTransport("https://relay.test", {
                    fetch: relayFetch,
                }),
                store: secondStore,
            });
            await senderStore.set(
                ctx,
                `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(targetAccount.publicKey)}`,
                serializeDeviceRoster(staleRoster),
            );

            trackSenderPublications = true;
            await sender.send(ctx, session.id, utf8Encode("expanded roster delivery"));
            await expect(sender.synchronize(ctx, { waitMilliseconds: 0 })).resolves.toMatchObject({
                transientPublicationFailures: 1,
                terminalPublicationFailures: 0,
            });
            let retriedPublications = 0;
            for (let round = 0; round < 12; round += 1) {
                const retried = await sender.synchronize(ctx, { waitMilliseconds: 0 });
                retriedPublications += retried.published;
                expect(retried).toMatchObject({
                    transientPublicationFailures: 0,
                    terminalPublicationFailures: 0,
                });
                await firstTarget.synchronize(ctx, { waitMilliseconds: 0 });
                await secondTarget.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect(retriedPublications).toBeGreaterThanOrEqual(2);
            expect(await secondTarget.session(ctx, session.id)).toMatchObject({
                status: "pending",
            });
            expect(await secondTarget.issues(ctx)).toEqual([]);
            await secondTarget.activateSession(ctx, session.id);

            expect(staleResponses).toEqual([
                expect.objectContaining({ error: "stale_epoch_coverage" }),
            ]);
            expect(successfulPublications).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        recipients: [],
                        targetAccounts: [],
                        sessionControl: expect.objectContaining({
                            type: "commit",
                            coveredDevices: expect.arrayContaining([
                                encodeBase64Url(secondTarget.deviceKey),
                            ]),
                        }),
                    }),
                ]),
            );

            const received: string[] = [];
            for (let round = 0; round < 4; round += 1) {
                await secondTarget.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: (_ctx, updates) => {
                            received.push(...updates.map((update) => utf8Decode(update.bytes)));
                        },
                    },
                );
            }
            expect(received).toContain("expanded roster delivery");
        } finally {
            sender.close(ctx);
            firstTarget.close(ctx);
            secondTarget?.close(ctx);
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
        const fetch: DeliveryFetch = (_ctx, input, init): Promise<Response> =>
            handler(new Request(input, init));
        const owner = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const claimant = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const ticket = issuer.issue({
                expiresAt: Date.now() + 60_000,
                claimBudget: 8,
            });
            for (let index = 0; index < 4; index += 1) {
                const claim = await claimant.claimAccount(ctx, owner.identity, ticket);
                expect(claim.members).toHaveLength(1);
                expect(claim.members[0]?.source).toBe("one_time");
            }
            const replenished = await owner.synchronize(ctx, { waitMilliseconds: 0 });
            expect(replenished.inbox.processed).toBeGreaterThanOrEqual(4);
            expect(
                (await claimant.claimAccount(ctx, owner.identity, ticket)).members[0]?.source,
            ).toBe("one_time");

            await owner.rotate(ctx);
            const afterRotation = await claimant.claimAccount(
                ctx,
                owner.identity,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 1 }),
            );
            expect(afterRotation.members[0]?.source).toBe("one_time");
        } finally {
            owner.close(ctx);
            claimant.close(ctx);
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
        const fetch: DeliveryFetch = (_ctx, input, init): Promise<Response> =>
            handler(new Request(input, init));
        const target = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const firstClaimant = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const secondClaimant = await MurmurClient.open(ctx, {
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const ticket = issuer.issue({
                expiresAt: Date.now() + 60_000,
                claimBudget: 8,
            });
            for (let index = 0; index < 4; index += 1) {
                await firstClaimant.claimAccount(ctx, target.identity, ticket);
            }
            const firstClaim = await firstClaimant.claimAccount(ctx, target.identity, ticket);
            const secondClaim = await secondClaimant.claimAccount(ctx, target.identity, ticket);
            expect(firstClaim.members[0]?.source).toBe("last_resort");
            expect(secondClaim.members[0]?.source).toBe("last_resort");
            expect(firstClaim.members[0]?.keyPackage).toEqual(secondClaim.members[0]?.keyPackage);

            const firstSession = await firstClaimant.createSession(ctx, {
                descriptor: utf8Encode("first-last-resort-session"),
                members: [firstClaim],
            });
            const secondSession = await secondClaimant.createSession(ctx, {
                descriptor: utf8Encode("second-last-resort-session"),
                members: [secondClaim],
            });
            for (let round = 0; round < 8; round += 1) {
                await firstClaimant.synchronize(ctx, { waitMilliseconds: 0 });
                await secondClaimant.synchronize(ctx, { waitMilliseconds: 0 });
                await target.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect((await target.session(ctx, firstSession.id))?.status).toBe("pending");
            expect((await target.session(ctx, secondSession.id))?.status).toBe("pending");
            await target.activateSession(ctx, firstSession.id);
            await target.activateSession(ctx, secondSession.id);

            const secondAccountClaim = await firstClaimant.claimAccount(
                ctx,
                secondClaimant.identity,
                issuer.issue({ expiresAt: Date.now() + 60_000, claimBudget: 1 }),
            );
            await firstClaimant.addMember(ctx, firstSession.id, secondAccountClaim);
            for (let round = 0; round < 8; round += 1) {
                await firstClaimant.synchronize(ctx, { waitMilliseconds: 0 });
                await target.synchronize(ctx, { waitMilliseconds: 0 });
                await secondClaimant.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect((await secondClaimant.session(ctx, firstSession.id))?.status).toBe("pending");
        } finally {
            target.close(ctx);
            firstClaimant.close(ctx);
            secondClaimant.close(ctx);
            await relay.close();
        }
    });
});
