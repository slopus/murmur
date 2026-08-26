import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurService } from "../index.js";

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "service-routing-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

describe("typed session services", () => {
    test("claims once, routes through the global batch, and restores ownership", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const bobUpdates: string[] = [];
        let claims = 0;
        const bobService: MurmurService = {
            onNewSession: async (session) => {
                claims += 1;
                return utf8Decode(session.descriptor) === "notes-v1";
            },
            onUpdate: async (update) => {
                bobUpdates.push(utf8Decode(update.bytes));
            },
        };
        const noop: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: noop }],
        });
        let bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "notes", service: bobService }],
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("notes-v1"),
                members: [await bob.createKeyPackage()],
                service: "notes",
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.synchronize();
            expect(await bob.session(session.id)).toMatchObject({ status: "active" });
            expect(claims).toBe(1);

            await alice.send(session.id, utf8Encode("first"));
            await alice.synchronize();
            const global: string[] = [];
            await bob.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (updates) => {
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

            bob.close();
            bob = await MurmurClient.open({
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [{ id: "notes", service: bobService }],
            });
            await alice.send(session.id, utf8Encode("second"));
            await alice.synchronize();
            await bob.synchronize();
            expect(claims).toBe(1);
            expect(bobUpdates).toEqual(["first", "second"]);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("durably ignores a session declined by every registered service", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [
                {
                    id: "declines",
                    service: {
                        onNewSession: async () => false,
                        onUpdate: async () => {
                            throw new Error("Declined service received an update");
                        },
                    },
                },
            ],
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("unknown-v1"),
                members: [await bob.createKeyPackage()],
            });
            await alice.synchronize();
            await bob.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
            await bob.synchronize();
            expect(await bob.session(session.id)).toBeUndefined();
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("retries the same service update when any batch callback throws", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        let attempts = 0;
        const seen: string[] = [];
        const receiver: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async (update) => {
                attempts += 1;
                seen.push(update.id);
                if (attempts === 1) throw new Error("retry this service batch");
            },
        };
        const sender: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
        };
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "retry", service: sender }],
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "retry", service: receiver }],
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("retry"),
                members: [await bob.createKeyPackage()],
                service: "retry",
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.synchronize();
            await alice.send(session.id, utf8Encode("stable"));
            await alice.synchronize();
            await expect(bob.synchronize()).rejects.toThrow("retry this service batch");
            expect(await bob.session(session.id)).toMatchObject({ bufferedEvents: 1 });
            await bob.synchronize();
            expect(seen).toHaveLength(2);
            expect(seen[0]).toBe(seen[1]);
            expect(await bob.session(session.id)).toMatchObject({ bufferedEvents: 0 });
        } finally {
            alice.close();
            bob.close();
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
            onNewSession: async () => true,
            onUpdate: async () => {},
            onSessionDeleted: async (event) => {
                ownerEvents.push(event.id);
            },
        };
        const memberService: MurmurService = {
            onNewSession: async () => true,
            onUpdate: async () => {},
            onSessionDeleted: async (event) => {
                memberAttempts += 1;
                memberEvents.push(event.id);
                if (memberAttempts === 1) throw new Error("retry deletion event");
            },
        };
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: ownerService }],
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "notes", service: memberService }],
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("delete-service"),
                members: [await bob.createKeyPackage()],
                service: "notes",
            });
            await alice.synchronize();
            await bob.synchronize();
            await alice.synchronize();

            const deletionId = await alice.deleteSession(session.id);
            await alice.synchronize();
            expect(ownerEvents).toEqual([deletionId]);
            await expect(bob.synchronize()).rejects.toThrow("retry deletion event");
            await expect(bob.session(session.id)).resolves.toBeUndefined();
            await bob.synchronize();
            expect(memberEvents).toEqual([deletionId, deletionId]);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });
});
