import { createRootContext } from "@steve.kite/stdlib";
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

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "session-outbox-ordering-tests",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(relay: RelayService): Promise<MurmurClient> {
    return MurmurClient.open(ctx, {
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
        ctx,
        { waitMilliseconds: 0 },
        {
            onUpdates: async (_ctx, updates) => {
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
        let alice = await MurmurClient.open(ctx, {
            transport: base,
            store: aliceStore,
            now: () => NOW,
        });
        const bob = await client(relay);
        try {
            const session = await alice.createSession(ctx, {
                descriptor: utf8Encode("ordered sends"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
            await bob.activateSession(ctx, session.id);

            const expected = Array.from(
                { length: 70 },
                (_, index) => `m${index.toString().padStart(2, "0")}`,
            );
            for (const value of expected) {
                await alice.send(ctx, session.id, utf8Encode(value));
            }
            alice.close();
            let failFirstApplication = true;
            const transientHead: DeliveryTransport = {
                publish: (_ctx, delivery, signal) => {
                    if (failFirstApplication && delivery.ciphertext[0] === 2) {
                        failFirstApplication = false;
                        throw new DeliveryTransportError(503, "overloaded");
                    }
                    return base.publish(ctx, delivery, signal);
                },
                read: (_ctx, request, signal) => base.read(ctx, request, signal),
                acknowledge: (_ctx, request, signal) => base.acknowledge(ctx, request, signal),
            };
            alice = await MurmurClient.open(ctx, {
                transport: transientHead,
                store: aliceStore,
                now: () => NOW,
            });
            expect(await alice.synchronize(ctx)).toMatchObject({
                published: 71,
                transientPublicationFailures: 1,
                pendingOutboxes: 70,
            });
            await alice.synchronize(ctx);
            await bob.synchronize(ctx);
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
        // Relay-derived fanout adds a round trip per publication, so this
        // paging-plus-restart scenario needs more headroom on slow runners.
    }, 60_000);
});
