import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { MurmurClient } from "../../sessions/index.js";
import type { MurmurSyncOptions, MurmurUpdate } from "../../sessions/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

const NOW = 1_700_000_000_000;
const CHAT_DESCRIPTOR = utf8Encode('{"protocol":"messenger.chat","version":1}');

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "multidevice-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

/**
 * One minimal messenger built only on the public Murmur API.
 *
 * It knows nothing about devices: it opens a client, activates incoming chat
 * sessions, collects decrypted messages, and records lifecycle callbacks.
 * Multidevice behavior must stay entirely inside Murmur.
 */
class Messenger {
    readonly client: MurmurClient;
    readonly messages: { sender: string; text: string }[] = [];
    readonly deviceAdded: string[] = [];
    readonly deviceRevoked: string[] = [];
    readonly contactRosterChanges: { account: string; change: string }[] = [];

    constructor(client: MurmurClient) {
        this.client = client;
    }

    #lifecycle(): MurmurSyncOptions {
        return {
            onUpdates: async (updates: readonly MurmurUpdate[]) => {
                for (const update of updates) {
                    this.messages.push({
                        sender: encodeBase64Url(update.sender),
                        text: utf8Decode(update.bytes),
                    });
                }
            },
            onDeviceAdded: async (devices) => {
                for (const device of devices) {
                    this.deviceAdded.push(encodeBase64Url(device.device));
                }
            },
            onDeviceRevoked: async (devices) => {
                for (const device of devices) {
                    this.deviceRevoked.push(encodeBase64Url(device.device));
                }
            },
            onContactRosterChanged: async (changes) => {
                for (const change of changes) {
                    this.contactRosterChanges.push({
                        account: encodeBase64Url(change.account),
                        change: change.change,
                    });
                }
            },
        };
    }

    /** One synchronization round plus messenger-level session activation. */
    async pump(): Promise<void> {
        await this.client.synchronize({ waitMilliseconds: 0 }, this.#lifecycle());
        const page = await this.client.sessions();
        for (const session of page.sessions) {
            if (
                session.status === "pending" &&
                utf8Decode(session.descriptor) === utf8Decode(CHAT_DESCRIPTOR)
            ) {
                await this.client.activateSession(session.id);
            }
        }
        await this.client.synchronize({ waitMilliseconds: 0 }, this.#lifecycle());
    }
}

async function pumpAll(messengers: readonly Messenger[], rounds: number): Promise<void> {
    for (let round = 0; round < rounds; round += 1) {
        for (const messenger of messengers) {
            await messenger.pump();
            // A macrotask hop lets the vitest worker service its RPC channel.
            await new Promise((resolve) => setTimeout(resolve, 0));
        }
    }
}

async function establishContact(invited: Messenger, requester: Messenger): Promise<Uint8Array> {
    const session = await requester.client.requestContact(await invited.client.createInvitation(), {
        name: "Requester",
    });
    let accepted = false;
    for (let index = 0; index < 8; index += 1) {
        await requester.client.synchronize({ waitMilliseconds: 0 });
        await invited.client.synchronize(
            { waitMilliseconds: 0 },
            {
                onContactRequested: async (events) => {
                    if (!accepted && events.length > 0) {
                        await invited.client.acceptContact(session.id, { name: "Invited" });
                        accepted = true;
                    }
                },
            },
        );
        if (
            (await invited.client.contact(requester.client.accountKey)) !== undefined &&
            (await requester.client.contact(invited.client.accountKey)) !== undefined
        ) {
            return session.id;
        }
    }
    throw new Error("Contact did not converge");
}

describe("multidevice messenger", () => {
    test(
        "links, converges, messages, and revokes transparently",
        { timeout: 120_000 },
        async () => {
            const relay = new RelayService(
                new SqliteRelayStore(":memory:"),
                {},
                undefined,
                () => NOW,
            );
            const fetch = relayFetch(relay);
            const open = async (): Promise<MurmurClient> =>
                MurmurClient.open({
                    relay: "https://relay.test",
                    fetch,
                    store: new MemoryMurmurStore(),
                    now: () => NOW,
                });
            const alice1 = new Messenger(await open());
            const alice2 = new Messenger(await open());
            const bob = new Messenger(await open());
            try {
                await establishContact(bob, alice1);

                const chat = await alice1.client.createSession({
                    descriptor: CHAT_DESCRIPTOR,
                    contacts: [bob.client.accountKey],
                });
                await pumpAll([alice1, bob], 4);
                await alice1.client.send(chat.id, utf8Encode("hello bob"));
                await pumpAll([alice1, bob], 4);
                expect(bob.messages.map(({ text }) => text)).toContain("hello bob");

                // Only the QR-sized request travels out of band; the encrypted
                // envelope arrives automatically through the new device's inbox.
                const request = await alice2.client.linkDevice();
                expect(request.length).toBeLessThan(1_200);
                await alice1.client.authorizeDevice(request);
                await pumpAll([alice2], 2);
                expect(alice2.client.accountKey).toEqual(alice1.client.accountKey);
                await pumpAll([alice1, alice2, bob], 8);

                const aliceDevices = await alice1.client.devices();
                expect(aliceDevices.map(({ status }) => status)).toEqual(["active", "active"]);
                expect(alice1.deviceAdded.length).toBeGreaterThan(0);
                expect(bob.contactRosterChanges.some(({ change }) => change === "added")).toBe(
                    true,
                );

                // Chat membership stays two accounts even with three device leaves.
                const bobChat = await bob.client.session(chat.id);
                expect(bobChat?.members.length).toBe(2);

                // Messages from anyone reach every device of every member account.
                await bob.client.send(chat.id, utf8Encode("hi alice devices"));
                await pumpAll([alice1, alice2, bob], 6);
                expect(alice1.messages.map(({ text }) => text)).toContain("hi alice devices");
                expect(alice2.messages.map(({ text }) => text)).toContain("hi alice devices");

                await alice2.client.send(chat.id, utf8Encode("from second device"));
                await pumpAll([alice1, alice2, bob], 6);
                const fromSecond = bob.messages.find(({ text }) => text === "from second device");
                expect(fromSecond).toBeDefined();
                expect(fromSecond?.sender).toEqual(encodeBase64Url(alice1.client.accountKey));

                // Any active device may revoke another; peers observe it.
                await alice1.client.revokeDevice(alice2.client.identity);
                await pumpAll([alice1, bob], 8);
                expect(alice1.deviceRevoked.length).toBeGreaterThan(0);
                expect(bob.contactRosterChanges.some(({ change }) => change === "revoked")).toBe(
                    true,
                );

                const revokedCount = alice2.messages.length;
                await bob.client.send(chat.id, utf8Encode("after revocation"));
                await pumpAll([alice1, bob], 6);
                await alice2.pump().catch(() => undefined);
                expect(alice1.messages.map(({ text }) => text)).toContain("after revocation");
                expect(alice2.messages.slice(revokedCount).map(({ text }) => text)).not.toContain(
                    "after revocation",
                );
            } finally {
                alice1.client.close();
                alice2.client.close();
                bob.client.close();
                await relay.close();
            }
        },
    );
});
