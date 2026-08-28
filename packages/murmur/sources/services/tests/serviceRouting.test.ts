import { createRootContext } from "@steve.kite/stdlib";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurService } from "../index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;

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
});
