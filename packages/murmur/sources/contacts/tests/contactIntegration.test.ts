import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurContactAdded, MurmurContactRemoved, MurmurContactRequested } from "../index.js";

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "contact-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function establishContact(
    invited: MurmurClient,
    requester: MurmurClient,
    invitedName: string,
    requesterName: string,
): Promise<void> {
    const session = await requester.requestContact(await invited.createInvitation(), {
        name: requesterName,
    });
    let accepted = false;
    for (let index = 0; index < 8; index += 1) {
        await requester.synchronize({ waitMilliseconds: 0 });
        await invited.synchronize(
            { waitMilliseconds: 0 },
            {
                onContactRequested: async (events) => {
                    if (!accepted && events.length > 0) {
                        await invited.acceptContact(session.id, { name: invitedName });
                        accepted = true;
                    }
                },
            },
        );
        if (
            (await invited.contact(requester.identity)) !== undefined &&
            (await requester.contact(invited.identity)) !== undefined
        ) {
            return;
        }
    }
    throw new Error("Contact did not converge");
}

describe("built-in contacts", () => {
    test("creates an N-person service group from contacts and exchanges messages", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const received = new Map<string, string[]>();
        const open = async (name: string): Promise<MurmurClient> =>
            MurmurClient.open({
                relay: "https://relay.test",
                fetch,
                store: new MemoryMurmurStore(),
                now: () => NOW,
                services: [
                    {
                        id: "chat",
                        service: {
                            onNewSession: async (session) =>
                                new TextDecoder().decode(session.descriptor) === "chat-v1",
                            onUpdate: async (update) => {
                                const messages = received.get(name) ?? [];
                                messages.push(new TextDecoder().decode(update.bytes));
                                received.set(name, messages);
                            },
                        },
                    },
                ],
            });
        const alice = await open("Alice");
        const bob = await open("Bob");
        const carol = await open("Carol");
        try {
            await establishContact(alice, bob, "Alice", "Bob");
            await establishContact(alice, carol, "Alice", "Carol");

            const group = await alice.createSession({
                descriptor: new TextEncoder().encode("chat-v1"),
                contacts: [bob.identity, carol.identity],
                service: "chat",
            });
            for (let index = 0; index < 8; index += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                await carol.synchronize({ waitMilliseconds: 0 });
                if (
                    (await bob.session(group.id))?.status === "active" &&
                    (await carol.session(group.id))?.status === "active"
                ) {
                    break;
                }
            }

            await alice.send(group.id, new TextEncoder().encode("hello group"));
            for (let index = 0; index < 17; index += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                await carol.synchronize({ waitMilliseconds: 0 });
                if (
                    received.get("Alice")?.includes("hello group") === true &&
                    received.get("Bob")?.includes("hello group") === true &&
                    received.get("Carol")?.includes("hello group") === true
                ) {
                    break;
                }
            }
            expect(received.get("Alice")).toContain("hello group");
            expect(received.get("Bob")).toContain("hello group");
            expect(received.get("Carol")).toContain("hello group");
        } finally {
            alice.close();
            bob.close();
            carol.close();
            await relay.close();
        }
    });

    test("creates groups while a contact is offline, reuses fallback, and refills", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const bobStore = new MemoryMurmurStore();
        const service = {
            onNewSession: async (): Promise<boolean> => true,
            onUpdate: async (): Promise<void> => {},
        };
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
            services: [{ id: "chat", service }],
        });
        let bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => NOW,
            services: [{ id: "chat", service }],
        });
        try {
            const contactSession = await bob.requestContact(await alice.createInvitation(), {
                name: "Bob",
            });
            let accepted = false;
            for (let index = 0; index < 8; index += 1) {
                await bob.synchronize();
                await alice.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onContactRequested: async (events) => {
                            if (!accepted && events.length > 0) {
                                await alice.acceptContact(contactSession.id, {
                                    name: "Alice",
                                });
                                accepted = true;
                            }
                        },
                    },
                );
                if ((await alice.contacts()).length === 1 && (await bob.contacts()).length === 1) {
                    break;
                }
            }
            expect(await alice.contacts()).toHaveLength(1);
            expect(await bob.contacts()).toHaveLength(1);

            const bobIdentity = bob.identity;
            bob.close();

            const groups = [];
            for (let index = 0; index < 6; index += 1) {
                groups.push(
                    await alice.createSession({
                        descriptor: new TextEncoder().encode(`chat-${String(index)}`),
                        contacts: [bobIdentity],
                        service: "chat",
                    }),
                );
            }
            await alice.synchronize();

            bob = await MurmurClient.open({
                relay: "https://relay.test",
                fetch,
                store: bobStore,
                now: () => NOW,
                services: [{ id: "chat", service }],
            });
            for (let index = 0; index < 12; index += 1) {
                await bob.synchronize({ waitMilliseconds: 0 });
                await alice.synchronize({ waitMilliseconds: 0 });
                if (
                    (await Promise.all(groups.map((group) => bob.session(group.id)))).every(
                        (session) => session?.status === "active",
                    )
                ) {
                    break;
                }
            }
            for (const group of groups) {
                expect(await bob.session(group.id)).toMatchObject({ status: "active" });
            }

            for (let index = 0; index < 6; index += 1) {
                await bob.synchronize({ waitMilliseconds: 0 });
                await alice.synchronize({ waitMilliseconds: 0 });
            }
            const afterRefill = await alice.createSession({
                descriptor: new TextEncoder().encode("chat-after-refill"),
                contacts: [bobIdentity],
                service: "chat",
            });
            for (let index = 0; index < 6; index += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                if ((await bob.session(afterRefill.id))?.status === "active") break;
            }
            expect(await bob.session(afterRefill.id)).toMatchObject({ status: "active" });
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("establishes mutual proof, restores offline, and removes the contact", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const fetch = relayFetch(relay);
        const aliceStore = new MemoryMurmurStore();
        let alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const requests: MurmurContactRequested[] = [];
        const aliceAdded: MurmurContactAdded[] = [];
        const bobAdded: MurmurContactAdded[] = [];
        const removed: MurmurContactRemoved[] = [];
        try {
            const invitation = await alice.createInvitation();
            const session = await bob.requestContact(invitation, {
                name: "Bob",
                capabilities: ["notes"],
            });

            for (let index = 0; index < 4 && requests.length === 0; index += 1) {
                await bob.synchronize();
                await alice.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onContactRequested: async (events) => {
                            requests.push(...events);
                        },
                    },
                );
            }
            expect(requests).toHaveLength(1);
            expect(requests[0]).toMatchObject({
                sessionId: session.id,
                profile: { name: "Bob", capabilities: ["notes"] },
            });
            expect(await alice.session(session.id)).toMatchObject({ status: "pending" });

            await alice.acceptContact(session.id, { name: "Alice" });
            for (let index = 0; index < 5; index += 1) {
                await alice.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onContactAdded: async (events) => {
                            aliceAdded.push(...events);
                        },
                    },
                );
                await bob.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onContactAdded: async (events) => {
                            bobAdded.push(...events);
                        },
                    },
                );
                if ((await alice.contacts()).length === 1 && (await bob.contacts()).length === 1) {
                    break;
                }
            }
            expect(aliceAdded).toHaveLength(1);
            expect(bobAdded).toHaveLength(1);
            expect(await alice.contact(bob.identity)).toMatchObject({
                status: "active",
                profile: { name: "Bob", capabilities: ["notes"] },
                localProfile: { name: "Alice" },
            });
            expect(await bob.contact(alice.identity)).toMatchObject({
                status: "active",
                profile: { name: "Alice" },
                localProfile: { name: "Bob", capabilities: ["notes"] },
            });

            const aliceIdentity = alice.identity;
            alice.close();
            alice = await MurmurClient.open({
                relay: "https://relay.test",
                fetch,
                store: aliceStore,
                now: () => NOW,
            });
            expect(alice.identity).toEqual(aliceIdentity);
            expect(await alice.contact(bob.identity)).toMatchObject({ status: "active" });

            await bob.removeContact(alice.identity);
            for (let index = 0; index < 4; index += 1) {
                await bob.synchronize({
                    waitMilliseconds: 0,
                });
                await alice.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onContactRemoved: async (events) => {
                            removed.push(...events);
                        },
                    },
                );
                if ((await alice.contacts()).length === 0) break;
            }
            expect(removed).toHaveLength(1);
            expect(await alice.contacts()).toEqual([]);
            expect(await bob.contacts()).toEqual([]);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });

    test("retries a requested callback and explicitly rejects the pending session", async () => {
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
        });
        try {
            const session = await bob.requestContact(await alice.createInvitation(), {
                name: "Bob",
            });
            let firstId: string | undefined;
            let attempted = false;
            for (let index = 0; index < 4 && !attempted; index += 1) {
                await bob.synchronize();
                try {
                    await alice.synchronize(
                        { waitMilliseconds: 0 },
                        {
                            onContactRequested: async (events) => {
                                attempted = true;
                                firstId = events[0]!.id;
                                throw new Error("contact decision failed");
                            },
                        },
                    );
                } catch (error: unknown) {
                    expect(error).toMatchObject({ message: "contact decision failed" });
                }
            }
            expect(firstId).toBeDefined();
            expect(await alice.contactRequests()).toHaveLength(1);
            let retryId: string | undefined;
            await alice.synchronize(
                { waitMilliseconds: 0 },
                {
                    onContactRequested: async (events) => {
                        retryId = events[0]!.id;
                    },
                },
            );
            expect(retryId).toBe(firstId);
            await alice.rejectContact(session.id);
            expect(await alice.session(session.id)).toBeUndefined();
            expect(await alice.contactRequests()).toEqual([]);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    });
});
