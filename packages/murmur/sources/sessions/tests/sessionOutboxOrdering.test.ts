import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    type DeliveryFetch,
    type DeliveryTransport,
} from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient, type MurmurUpdate } from "../index.js";

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "session-outbox-ordering-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(relay: RelayService): Promise<MurmurClient> {
    return MurmurClient.open({
        relay: "https://relay.test",
        fetch: relayFetch(relay),
        store: new MemoryMurmurStore(),
        now: () => NOW,
    });
}

async function consume(
    value: MurmurClient,
    process: (update: MurmurUpdate) => void | Promise<void>,
): Promise<void> {
    await value.synchronize(
        { waitMilliseconds: 0 },
        {
            onUpdates: async (updates) => {
                for (const update of updates) await process(update);
            },
        },
    );
}

describe("session outbox ordering", () => {
    test("preserves durable FIFO after a transient head failure across paging and restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const aliceStore = new MemoryMurmurStore();
        const base = new HttpDeliveryTransport("https://relay.test", {
            fetch: relayFetch(relay),
        });
        let alice = await MurmurClient.open({
            transport: base,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("ordered sends"),
                members: [await bob.createKeyPackage()],
            });
            await alice.synchronize();
            await bob.synchronize();
            await bob.activateSession(session.id);

            const expected = Array.from(
                { length: 70 },
                (_, index) => `m${index.toString().padStart(2, "0")}`,
            );
            for (const value of expected) {
                await alice.send(session.id, utf8Encode(value));
            }
            alice.close();
            let failFirstApplication = true;
            const transientHead: DeliveryTransport = {
                publish: (delivery, signal) => {
                    if (failFirstApplication && delivery.ciphertext[0] === 2) {
                        failFirstApplication = false;
                        throw new DeliveryTransportError(503, "overloaded");
                    }
                    return base.publish(delivery, signal);
                },
                read: (request, signal) => base.read(request, signal),
                acknowledge: (request, signal) => base.acknowledge(request, signal),
            };
            alice = await MurmurClient.open({
                transport: transientHead,
                store: aliceStore,
                now: () => NOW,
            });
            expect(await alice.synchronize()).toMatchObject({
                published: 71,
                transientPublicationFailures: 1,
                pendingOutboxes: 70,
            });
            await alice.synchronize();
            await bob.synchronize();
            const received: string[] = [];
            await consume(bob, async (event) => {
                received.push(utf8Decode(event.bytes));
            });
            expect(received).toEqual(expected);
        } finally {
            alice.close();
            bob.close();
            await relay.close();
        }
    }, 20_000);
});
