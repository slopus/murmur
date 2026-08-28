import { createRootContext } from "@steve.kite/stdlib";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurService } from "../index.js";
import type { MurmurSessionChangedEvent } from "../../sessions/index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;

function relayEventId(sequence: number): string {
    const timestamp = NOW.toString(16).padStart(12, "0");
    return `${timestamp.slice(0, 8)}-${timestamp.slice(8)}-7000-8000-${sequence
        .toString(16)
        .padStart(12, "0")}`;
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "service-routing-tests",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

describe("typed session services", () => {
    test("claims once, routes through the global batch, and restores ownership", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const bobUpdates: string[] = [];
        let claims = 0;
        const bobService: MurmurService = {
            onNewSession: async (_ctx, session) => {
                claims += 1;
                return utf8Decode(session.descriptor) === "notes-v1";
            },
            onUpdate: async (_ctx, update) => {
                bobUpdates.push(utf8Decode(update.bytes));
            },
        };
        const noop: MurmurService = {
            onNewSession: async (_ctx) => true,
            onUpdate: async (_ctx) => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: noop }],
        });
        let bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "notes", service: bobService }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("notes-v1"),
                members: [await bob.createKeyPackage(ctx)],
                service: "notes",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toMatchObject({ status: "active" });
            expect(claims).toBe(1);

            await alice.send(ctx, session.id, utf8Encode("first"));
            await alice.synchronize(ctx);
            const global: string[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        global.push(
                            ...updates.map(
                                (update) => `${update.service}:${utf8Decode(update.bytes)}`,
                            ),
                        );
                    },
                },
            );
            expect(bobUpdates).toEqual(["first"]);
            expect(global).toEqual(["notes:first"]);

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [{ id: "notes", service: bobService }],
            });
            await alice.send(ctx, session.id, utf8Encode("second"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(claims).toBe(1);
            expect(bobUpdates).toEqual(["first", "second"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("preserves bootstrap, update, and pending Commit effects through routing", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const order: string[] = [];
        let claims = 0;
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        let bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("deferred activation"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });

            await alice.send(ctx, session.id, utf8Encode("before commit"));
            await alice.synchronize(ctx);
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.synchronize(ctx);
            await bob.synchronize(ctx, { limit: 256, waitMilliseconds: 0 });

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [
                    {
                        id: "crdt.loro",
                        service: {
                            onNewSession: async () => {
                                claims += 1;
                                order.push("route");
                                return true;
                            },
                            onUpdate: async (_ctx, update) => {
                                order.push(`update:${utf8Decode(update.bytes)}`);
                            },
                        },
                    },
                ],
            });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        order.push(
                            ...events.map(
                                (event) => `session:${String(event.policies.adminsAssignAdmins)}`,
                            ),
                        );
                    },
                },
            );
            expect(claims).toBe(1);
            expect(order).toEqual([
                "route",
                "session:false",
                "update:before commit",
                "session:true",
            ]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("durably ignores a session declined by every registered service", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "declines",
                    service: {
                        onNewSession: async (_ctx) => false,
                        onUpdate: async (_ctx) => {
                            throw new Error("Declined service received an update");
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("unknown-v1"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
            await bob.synchronize(ctx);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("retries the same service update when any batch callback throws", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        let attempts = 0;
        const seen: string[] = [];
        const receiver: MurmurService = {
            onNewSession: async (_ctx) => true,
            onUpdate: async (_ctx, update) => {
                attempts += 1;
                seen.push(update.id);
                if (attempts === 1) throw new Error("retry this service batch");
            },
        };
        const sender: MurmurService = {
            onNewSession: async (_ctx) => true,
            onUpdate: async (_ctx) => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "retry", service: sender }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "retry", service: receiver }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("retry"),
                members: [await bob.createKeyPackage(ctx)],
                service: "retry",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("stable"));
            await alice.synchronize(ctx);
            await expect(bob.synchronize(ctx)).rejects.toThrow("retry this service batch");
            expect(await bob.session(ctx, session.id)).toMatchObject({ bufferedEvents: 1 });
            await bob.synchronize(ctx);
            expect(seen).toHaveLength(2);
            expect(seen[0]).toBe(seen[1]);
            expect(await bob.session(ctx, session.id)).toMatchObject({ bufferedEvents: 0 });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("retries one final typed service event after owner deletion destroys local state", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const ownerEvents: string[] = [];
        const memberEvents: string[] = [];
        let memberAttempts = 0;
        const ownerService: MurmurService = {
            onNewSession: async (_ctx) => true,
            onUpdate: async (_ctx) => {},
            onSessionDeleted: async (_ctx, event) => {
                ownerEvents.push(event.id);
            },
        };
        const memberService: MurmurService = {
            onNewSession: async (_ctx) => true,
            onUpdate: async (_ctx) => {},
            onSessionDeleted: async (_ctx, event) => {
                memberAttempts += 1;
                memberEvents.push(event.id);
                if (memberAttempts === 1) throw new Error("retry deletion event");
            },
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: ownerService }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: memberService }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("delete-service"),
                members: [await bob.createKeyPackage(ctx)],
                service: "notes",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await alice.synchronize(ctx);

            const deletionId = await alice.deleteSession(ctx, session.id);
            await alice.synchronize(ctx);
            expect(ownerEvents).toEqual([deletionId]);
            await expect(bob.synchronize(ctx)).rejects.toThrow("retry deletion event");
            await expect(bob.session(ctx, session.id)).resolves.toBeUndefined();
            await bob.synchronize(ctx);
            expect(memberEvents).toEqual([deletionId, deletionId]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("durably reports complete service session snapshots for activation and Commits", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        let bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("loro descriptor"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            const activated: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        activated.push(...events);
                    },
                },
            );
            expect(activated).toHaveLength(1);
            expect(activated[0]).toMatchObject({
                service: "crdt.loro",
                status: "active",
                descriptor: utf8Encode("loro descriptor"),
                members: expect.arrayContaining([alice.identity, bob.identity]),
                owner: alice.identity,
                admins: [alice.identity],
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                    sendPolicy: "everyone",
                },
            });

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
                sendPolicy: "admins",
            });
            await alice.synchronize(ctx);

            const attempts: string[] = [];
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async (_ctx, events) => {
                            const changed = events.find(
                                (event) => event.policies.sendPolicy === "admins",
                            );
                            if (changed === undefined) return;
                            attempts.push(changed.id);
                            throw new Error("retry session lifecycle");
                        },
                    },
                ),
            ).rejects.toThrow("retry session lifecycle");

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [{ id: "crdt.loro", service: noop }],
            });
            const retried: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        retried.push(...events);
                    },
                },
            );
            expect(retried).toHaveLength(2);
            expect(retried[0]).toMatchObject({
                id: attempts[0],
                service: "crdt.loro",
                status: "active",
                policies: {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                    sendPolicy: "admins",
                },
            });
            expect(retried[1]).toMatchObject({
                service: "crdt.loro",
                status: "active",
                policies: {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                    sendPolicy: "everyone",
                },
            });

            await bob.leave(ctx, session.id);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const removed: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        removed.push(...events);
                    },
                },
            );
            expect(removed).toHaveLength(1);
            expect(removed[0]).toMatchObject({
                service: "crdt.loro",
                status: "removed",
                descriptor: utf8Encode("loro descriptor"),
                members: [alice.identity],
                owner: alice.identity,
            });
            expect(await bob.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("reports the creator's echoed bootstrap and local policy Commit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const snapshots: MurmurSessionChangedEvent[] = [];
        const lifecycle = {
            onSessionsChanged: async (
                _ctx: typeof ctx,
                events: readonly MurmurSessionChangedEvent[],
            ) => {
                snapshots.push(...events);
            },
        };
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("creator lifecycle"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            expect(snapshots).toHaveLength(1);
            expect(snapshots[0]).toMatchObject({ status: "active", service: "crdt.loro" });

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            await alice.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            expect(snapshots).toHaveLength(2);
            expect(snapshots[1]!.policies.adminsAssignAdmins).toBe(true);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("reports confirmed membership and admin-role Commits", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const carol = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("membership and roles"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const membership: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        membership.push(...events);
                    },
                },
            );
            expect(membership).toHaveLength(1);
            expect(membership[0]!.members).toEqual(
                expect.arrayContaining([alice.identity, bob.identity, carol.identity]),
            );

            await alice.grantAdmin(ctx, session.id, bob.identity);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const roles: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        roles.push(...events);
                    },
                },
            );
            expect(roles).toHaveLength(1);
            expect(roles[0]!.admins).toEqual(
                expect.arrayContaining([alice.identity, bob.identity]),
            );
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("delivers a buffered update before the Commit that removes the local account", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const order: string[] = [];
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async (_ctx, update) => {
                            order.push(`update:${utf8Decode(update.bytes)}`);
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("update before removal"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.send(ctx, session.id, utf8Encode("last visible update"));
            await alice.removeMember(ctx, session.id, bob.identity);
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        order.push(
                            `session:${events[0]!.status}:${String(events[0]!.policies.adminsAssignAdmins)}`,
                        );
                    },
                },
            );
            expect(order).toEqual([
                "session:active:true",
                "update:last visible update",
                "session:removed:true",
            ]);
            expect(await bob.session(ctx, session.id)).toBeUndefined();
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("propagates re-admission provenance into the activation snapshot", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("re-admitted service"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bobStore.set(
                ctx,
                `murmur/reset/v1/re-admissions/${encodeBase64Url(session.id)}`,
                session.descriptor,
            );
            const snapshots: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        snapshots.push(...events);
                    },
                },
            );
            expect(snapshots).toHaveLength(1);
            expect(snapshots[0]).toMatchObject({ reAdmission: true, status: "active" });
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("reports an account-device-only convergence Commit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobAccount = generateIdentityKeyPair();
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            identity: bobAccount,
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        let second: MurmurClient | undefined;
        try {
            await alice.createSession(ctx, {
                descriptor: utf8Encode("device convergence"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            second = await MurmurClient.open(ctx, {
                identity: bobAccount,
                relay: "https://relay.test",
                fetch,
                store: new MemoryMurmurStore(),
                now: () => NOW,
                services: [{ id: "crdt.loro", service: noop }],
            });
            const snapshots: MurmurSessionChangedEvent[] = [];
            for (let round = 0; round < 8 && snapshots.length === 0; round += 1) {
                await bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async (_ctx, events) => {
                            snapshots.push(...events);
                        },
                    },
                );
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await second.synchronize(ctx, { waitMilliseconds: 0 });
            }
            expect(snapshots).toHaveLength(1);
            expect(snapshots[0]!.members).toEqual(
                expect.arrayContaining([alice.identity, bob.accountKey]),
            );
            expect(snapshots[0]!.members).toHaveLength(2);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            second?.close(ctx);
            destroyIdentity(bobAccount);
            await relay.close();
        }
    });

    test("orders Commit snapshots before later updates and suppresses snapshots after deletion", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const order: string[] = [];
        const ownerService: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const memberService: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async (_ctx, update) => {
                order.push(`update:${utf8Decode(update.bytes)}`);
            },
            onSessionDeleted: async () => {
                order.push("deleted");
            },
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: ownerService }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: memberService }],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("ordered lifecycle"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("after commit"));
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        order.push(`session:${String(events[0]!.policies.adminsAssignAdmins)}`);
                    },
                },
            );
            expect(order).toEqual(["session:true", "update:after commit"]);

            order.length = 0;
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.synchronize(ctx);
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async () => {
                            throw new Error("retain stale session snapshot");
                        },
                    },
                ),
            ).rejects.toThrow("retain stale session snapshot");
            await alice.deleteSession(ctx, session.id);
            await alice.synchronize(ctx);
            order.length = 0;
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async () => {
                        order.push("stale-session");
                    },
                },
            );
            expect(order).toEqual(["deleted"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("globally blocks later lifecycle behind an unresolved application update", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        let bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
        });
        try {
            const applicationSession = await alice.createSession(ctx, {
                descriptor: utf8Encode("application owned"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.activateSession(ctx, applicationSession.id);
            await alice.send(ctx, applicationSession.id, utf8Encode("deferred application update"));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [
                    {
                        id: "crdt.loro",
                        service: {
                            onNewSession: async (_ctx, session) =>
                                utf8Decode(session.descriptor) === "service owned",
                            onUpdate: async () => {},
                        },
                    },
                ],
            });
            const serviceSession = await alice.createSession(ctx, {
                descriptor: utf8Encode("service owned"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const snapshots: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        snapshots.push(...events);
                    },
                },
            );
            expect(snapshots).toEqual([]);
            const rawUpdates: string[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        rawUpdates.push(...updates.map((update) => utf8Decode(update.bytes)));
                    },
                    onSessionsChanged: async (_ctx, events) => {
                        snapshots.push(...events);
                    },
                },
            );
            expect(rawUpdates).toEqual(["deferred application update"]);
            expect(snapshots).toHaveLength(1);
            expect(snapshots[0]!.sessionId).toEqual(serviceSession.id);
            expect(await bob.session(ctx, applicationSession.id)).toMatchObject({
                bufferedEvents: 0,
            });
            expect(
                (
                    await bobStore.scan(ctx, "murmur/session-changed-event-index/", {
                        limit: 1,
                    })
                ).size,
            ).toBe(0);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("lets an unresolved route globally block later cross-session effects", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const order: string[] = [];
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const receiverService: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async (_ctx, update) => {
                order.push(`update:${utf8Decode(update.bytes)}`);
            },
        };
        let bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "crdt.loro", service: receiverService }],
        });
        try {
            const existing = await alice.createSession(ctx, {
                descriptor: utf8Encode("existing service"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
            });
            const pending = await alice.createSession(ctx, {
                descriptor: utf8Encode("pending service"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.send(ctx, pending.id, utf8Encode("before existing lifecycle"));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.setPolicies(ctx, existing.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.setPolicies(ctx, pending.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async () => {
                            throw new Error("later lifecycle must stay blocked");
                        },
                    },
                ),
            ).resolves.toBeDefined();
            expect(order).toEqual([]);

            bob.close(ctx);
            bob = await MurmurClient.open(ctx, {
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [{ id: "crdt.loro", service: receiverService }],
            });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        const event = events[0]!;
                        order.push(
                            encodeBase64Url(event.sessionId) === encodeBase64Url(existing.id)
                                ? "session:existing"
                                : "session:pending",
                        );
                    },
                },
            );
            expect(order).toEqual([
                "session:pending",
                "update:before existing lifecycle",
                "session:existing",
                "session:pending",
            ]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("suppresses a lifecycle snapshot destroyed after preparation", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        let releaseUpdate!: () => void;
        const updateReleased = new Promise<void>((resolve) => {
            releaseUpdate = resolve;
        });
        let enterUpdate!: () => void;
        const updateEntered = new Promise<void>((resolve) => {
            enterUpdate = resolve;
        });
        let blockUpdate = false;
        const snapshots: MurmurSessionChangedEvent[] = [];
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async () => {
                            if (!blockUpdate) return;
                            enterUpdate();
                            await updateReleased;
                        },
                    },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const carol = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        let synchronization: Promise<unknown> | undefined;
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("prepare destruction race"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.activateSession(ctx, session.id);

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });

            blockUpdate = true;
            await bob.send(ctx, session.id, utf8Encode("before destruction"));
            await bob.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            synchronization = alice.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        snapshots.push(...events);
                    },
                },
            );
            await updateEntered;
            await alice.deleteSession(ctx, session.id);
            releaseUpdate();
            await synchronization;
            synchronization = undefined;
            expect(snapshots).toEqual([]);
        } finally {
            releaseUpdate();
            await synchronization?.catch(() => {});
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("quarantines an incoming Commit above the receiver member limit", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            limits: { maximumMembersPerSession: 2 },
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const carol = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("receiver member limit"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const withinLimit: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        withinLimit.push(...events);
                    },
                },
            );
            expect(withinLimit).toHaveLength(1);

            await alice.addMember(ctx, session.id, await carol.createKeyPackage(ctx));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            const issues: string[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onIssues: async (_ctx, current) => {
                        issues.push(...current.map((issue) => issue.code));
                    },
                },
            );
            expect(issues).toContain("session_member_capacity");
            const retained = (await bob.session(ctx, session.id))!;
            expect(retained.members).toEqual(
                expect.arrayContaining([alice.identity, bob.identity]),
            );
            expect(retained.members).toHaveLength(2);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            carol.close(ctx);
            await relay.close();
        }
    });

    test("defers the exact relay event when the identity effect queue is full", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "crdt.loro", service: noop }],
        });
        try {
            await alice.createSession(ctx, {
                descriptor: utf8Encode("identity effect capacity"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });

            for (let index = 0; index < 1_000; index += 1) {
                await bobStore.set(
                    ctx,
                    `murmur/application-updates/${relayEventId(index)}`,
                    new Uint8Array(32),
                );
            }
            const deferred = await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(deferred.inbox).toMatchObject({
                rejected: 0,
                exhausted: false,
            });
            expect(deferred.inbox.processed).toBeGreaterThan(0);
            expect(deferred.inbox.cursor).not.toBeNull();
            expect(utf8Decode((await bobStore.get(ctx, "murmur/delivery/cursor"))!)).toBe(
                deferred.inbox.cursor,
            );
            expect(
                JSON.parse(utf8Decode((await bobStore.get(ctx, "murmur/delivery/continuity"))!)),
            ).toMatchObject({ sequence: deferred.inbox.processed });
            expect(
                (
                    await bobStore.scan(ctx, "murmur/delivery/replay/entries/", {
                        limit: 1_000,
                    })
                ).size,
            ).toBe(deferred.inbox.processed);

            const retained = await bobStore.scan(ctx, "murmur/application-updates/", {
                limit: 1_000,
            });
            for (const [key, value] of retained) {
                await bobStore.delete(ctx, key);
                value.fill(0);
            }
            const snapshots: MurmurSessionChangedEvent[] = [];
            const retried = await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onSessionsChanged: async (_ctx, events) => {
                        snapshots.push(...events);
                    },
                },
            );
            expect(retried.inbox.processed).toBeGreaterThan(0);
            expect(snapshots).toHaveLength(1);
            expect(snapshots[0]!.id > deferred.inbox.cursor!).toBe(true);
            expect(snapshots[0]!.id <= retried.inbox.cursor!).toBe(true);
            expect(retried.inbox.cursor).not.toBe(deferred.inbox.cursor);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("preserves every lifecycle snapshot between alternating Commits and updates", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const serviceOrder: string[] = [];
        const globalOrder: string[] = [];
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async (_ctx, update) => {
                            serviceOrder.push(`update:${utf8Decode(update.bytes)}`);
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("alternating lifecycle"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("one"));
            await alice.synchronize(ctx);
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("two"));
            await alice.synchronize(ctx);

            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        globalOrder.push(
                            ...updates.map((update) => `update:${utf8Decode(update.bytes)}`),
                        );
                    },
                    onSessionsChanged: async (_ctx, events) => {
                        const label = `session:${String(events[0]!.policies.adminsAssignAdmins)}`;
                        serviceOrder.push(label);
                        globalOrder.push(label);
                    },
                },
            );
            expect(serviceOrder).toEqual([
                "session:true",
                "update:one",
                "session:false",
                "update:two",
            ]);
            expect(globalOrder).toEqual(serviceOrder);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("keeps lifecycle snapshots ordered after a full application-update page", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const order: string[] = [];
        const globalOrder: string[] = [];
        let blockDelivery = false;
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async (_ctx, update) => {
                            if (blockDelivery) throw new Error("hold ordered page");
                            order.push(utf8Decode(update.bytes));
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("paged lifecycle"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            for (let index = 0; index < 257; index += 1) {
                await alice.send(ctx, session.id, utf8Encode(`update-${String(index)}`));
            }
            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            for (let attempt = 0; attempt < 8; attempt += 1) {
                const result = await alice.synchronize(ctx, { waitMilliseconds: 0 });
                if (result.pendingOutboxes === 0) break;
            }

            blockDelivery = true;
            await expect(bob.synchronize(ctx, { limit: 256, waitMilliseconds: 0 })).rejects.toThrow(
                "hold ordered page",
            );
            await expect(bob.synchronize(ctx, { limit: 256, waitMilliseconds: 0 })).rejects.toThrow(
                "hold ordered page",
            );

            blockDelivery = false;
            await bob.synchronize(
                ctx,
                { limit: 256, waitMilliseconds: 0 },
                {
                    onUpdates: async (_ctx, updates) => {
                        globalOrder.push(...updates.map((update) => utf8Decode(update.bytes)));
                    },
                    onSessionsChanged: async (_ctx, events) => {
                        if (events.some((event) => event.policies.adminsAssignAdmins)) {
                            order.push("session-change");
                            globalOrder.push("session-change");
                        }
                    },
                },
            );
            expect(order).toHaveLength(258);
            expect(order.slice(0, 257)).toEqual(
                Array.from({ length: 257 }, (_, index) => `update-${String(index)}`),
            );
            expect(order[257]).toBe("session-change");
            expect(globalOrder).toEqual(order);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    }, 120_000);

    test("quarantines one corrupt lifecycle record without discarding a newer snapshot", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const received: string[] = [];
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async (_ctx, update) => {
                            received.push(utf8Decode(update.bytes));
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("corrupt lifecycle"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx);
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await alice.send(ctx, session.id, utf8Encode("ordered update"));
            await alice.synchronize(ctx);

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx);
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async () => {
                            throw new Error("retain lifecycle snapshot");
                        },
                    },
                ),
            ).rejects.toThrow("retain lifecycle snapshot");

            const retained = await bobStore.scan(ctx, "murmur/session-changed-events/", {
                limit: 3,
            });
            const retainedKeys = [...retained.keys()].sort();
            expect(retainedKeys).toHaveLength(2);
            await bobStore.set(ctx, retainedKeys[0]!, utf8Encode("{"));
            const corruptIndexKey =
                "murmur/session-changed-event-index/not-a-relay-event/not-a-session";
            await bobStore.set(ctx, corruptIndexKey, new Uint8Array([1]));
            const corruptPageKeys = Array.from(
                { length: 257 },
                (_, index) =>
                    `murmur/session-changed-event-index/${relayEventId(index)}/bad-${String(index)}`,
            );
            for (const key of corruptPageKeys) {
                await bobStore.set(ctx, key, new Uint8Array([1]));
            }
            const mismatchedEventId = relayEventId(500);
            const encodedSessionId = encodeBase64Url(session.id);
            const mismatchedRecordKey = `murmur/session-changed-events/${encodedSessionId}/${mismatchedEventId}`;
            const mismatchedIndexKey = `murmur/session-changed-event-index/${mismatchedEventId}/${encodedSessionId}`;
            const wrongSessionId = session.id.slice();
            wrongSessionId[0] = (wrongSessionId[0] ?? 0) ^ 1;
            await bobStore.set(ctx, mismatchedRecordKey, utf8Encode("orphan"));
            await bobStore.set(ctx, mismatchedIndexKey, wrongSessionId);
            const issueCodes: string[] = [];
            let issueCallbacks = 0;
            const recoveredSnapshots: MurmurSessionChangedEvent[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onIssues: async (_ctx, issues) => {
                        issueCallbacks += 1;
                        issueCodes.push(...issues.map((issue) => issue.code));
                    },
                    onSessionsChanged: async (_ctx, events) => {
                        recoveredSnapshots.push(...events);
                    },
                },
            );
            expect(issueCodes).toContain("corrupt_session_changed_event");
            expect(issueCodes).toContain("corrupt_session_changed_event_index");
            expect(await bobStore.get(ctx, corruptIndexKey)).toBeUndefined();
            expect(await bobStore.get(ctx, corruptPageKeys[0]!)).toBeUndefined();
            expect(await bobStore.get(ctx, corruptPageKeys.at(-1)!)).toBeUndefined();
            expect(await bobStore.get(ctx, mismatchedIndexKey)).toBeUndefined();
            expect(await bobStore.get(ctx, mismatchedRecordKey)).toBeUndefined();
            expect(recoveredSnapshots).toHaveLength(1);
            expect(recoveredSnapshots[0]!.policies.adminsAssignAdmins).toBe(false);
            expect(issueCallbacks).toBe(1);

            await alice.setPolicies(ctx, session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onSessionsChanged: async () => {
                            throw new Error("retain repeated corrupt snapshot");
                        },
                    },
                ),
            ).rejects.toThrow("retain repeated corrupt snapshot");
            const repeated = await bobStore.scan(ctx, "murmur/session-changed-events/", {
                limit: 2,
            });
            expect(repeated.size).toBe(1);
            await bobStore.set(ctx, [...repeated.keys()][0]!, utf8Encode("{"));
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onIssues: async (_ctx, issues) => {
                        issueCallbacks += 1;
                        issueCodes.push(...issues.map((issue) => issue.code));
                    },
                    onSessionsChanged: async () => {},
                },
            );
            expect(issueCallbacks).toBe(1);

            await alice.send(ctx, session.id, utf8Encode("healthy update"));
            await alice.synchronize(ctx);
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(received).toEqual(["ordered update", "healthy update"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("repairs buffered accounting after quarantining a corrupt application effect", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const received: string[] = [];
        let retainUpdate = false;
        const alice = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: { onNewSession: async () => true, onUpdate: async () => {} },
                },
            ],
        });
        const bob = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [
                {
                    id: "crdt.loro",
                    service: {
                        onNewSession: async () => true,
                        onUpdate: async (_ctx, update) => {
                            if (retainUpdate) throw new Error("retain corruptible update");
                            received.push(utf8Decode(update.bytes));
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("corrupt application accounting"),
                members: [await bob.createKeyPackage(ctx)],
                service: "crdt.loro",
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                { onSessionsChanged: async () => {} },
            );

            await alice.send(ctx, session.id, utf8Encode("corrupt me"));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            retainUpdate = true;
            await expect(bob.synchronize(ctx, { waitMilliseconds: 0 })).rejects.toThrow(
                "retain corruptible update",
            );
            const bufferPrefix = `murmur/session-data/${encodeBase64Url(session.id)}/buffer/`;
            const buffered = await bobStore.scan(ctx, bufferPrefix, { limit: 1 });
            expect(buffered.size).toBe(1);
            await bobStore.set(ctx, [...buffered.keys()][0]!, utf8Encode("{"));

            retainUpdate = false;
            const issues: string[] = [];
            await bob.synchronize(
                ctx,
                { waitMilliseconds: 0 },
                {
                    onIssues: async (_ctx, current) => {
                        issues.push(...current.map((issue) => issue.code));
                    },
                },
            );
            expect(issues).toContain("corrupt_application_update");
            expect(await bob.session(ctx, session.id)).toMatchObject({
                bufferedEvents: 0,
            });

            await alice.send(ctx, session.id, utf8Encode("healthy"));
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            expect(received).toEqual(["healthy"]);
        } finally {
            alice.close(ctx);
            bob.close(ctx);
            await relay.close();
        }
    });

    test("reports bounded durable session issues through synchronization", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const store = new MemoryMurmurStore();
        const murmur = await MurmurClient.open(ctx, {
            relay: "https://relay.test",
            fetch: relayFetch(relay),
            store,
            now: () => NOW,
        });
        try {
            await store.set(ctx, "murmur/session-quarantine/corrupt", utf8Encode("{"));
            await store.set(ctx, `murmur/session-intents/${"A".repeat(32)}`, utf8Encode("{"));
            const issues: string[] = [];
            let callbacks = 0;
            const lifecycle = {
                onIssues: async (
                    _ctx: typeof ctx,
                    current: readonly { readonly code: string }[],
                ) => {
                    callbacks += 1;
                    expect(Object.isFrozen(current)).toBe(true);
                    expect(current.every((issue) => Object.isFrozen(issue))).toBe(true);
                    expect(current.length).toBeLessThanOrEqual(256);
                    issues.push(...current.map(({ code }) => code));
                },
            };
            await murmur.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            expect(issues).toContain("corrupt_session_intent");
            expect(await store.get(ctx, "murmur/session-quarantine/corrupt")).toBeUndefined();
            await murmur.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            expect(callbacks).toBe(1);
            await store.set(ctx, `murmur/session-intents/${"A".repeat(32)}`, utf8Encode("{"));
            await murmur.synchronize(ctx, { waitMilliseconds: 0 }, lifecycle);
            expect(callbacks).toBe(1);
        } finally {
            murmur.close(ctx);
            await relay.close();
        }
    });
});
