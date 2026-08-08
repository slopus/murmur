import { describe, expect, test } from "vitest";
import { MemoryMurmurStore, MurmurClient } from "../sources/index.js";

const relay = process.env.MURMUR_E2E_RELAY;

describe.skipIf(relay === undefined)("production relay contacts", () => {
    test("establishes and removes an ephemeral contact without retained queue work", async () => {
        const alice = await MurmurClient.open({
            relay: relay!,
            store: new MemoryMurmurStore(),
        });
        const bob = await MurmurClient.open({
            relay: relay!,
            store: new MemoryMurmurStore(),
        });
        try {
            const session = await bob.requestContact(await alice.createInvitation(), {
                test: "production-contact-e2e",
            });
            for (let index = 0; index < 10; index += 1) {
                await bob.synchronize({ waitMilliseconds: 0 });
                await alice.synchronize({ waitMilliseconds: 0 });
                if ((await alice.contactRequests()).length === 1) break;
            }
            expect(await alice.contactRequests()).toHaveLength(1);
            await alice.acceptContact(session.id, { test: "production-contact-e2e" });
            for (let index = 0; index < 10; index += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
                if ((await alice.contacts()).length === 1 && (await bob.contacts()).length === 1) {
                    break;
                }
            }
            expect(await alice.contacts()).toHaveLength(1);
            expect(await bob.contacts()).toHaveLength(1);

            await bob.removeContact(alice.identity);
            for (let index = 0; index < 10; index += 1) {
                await bob.synchronize({ waitMilliseconds: 0 });
                await alice.synchronize({ waitMilliseconds: 0 });
                if ((await alice.contacts()).length === 0 && (await bob.contacts()).length === 0) {
                    break;
                }
            }
            expect(await alice.contacts()).toEqual([]);
            expect(await bob.contacts()).toEqual([]);
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
        } finally {
            alice.close();
            bob.close();
        }
    }, 60_000);
});
