import { createRootContext } from "@steve.kite/stdlib";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    HttpDeliveryTransport,
    createSignedDelivery,
    type DeliveryFetch,
} from "../../delivery/index.js";
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { equalBytes, utf8Encode } from "../../utils/index.js";
import { MurmurClient, MurmurResetRequiredError, type MurmurResetEvent } from "../index.js";

const ctx = createRootContext().named("test");

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "continuity-tests",
    });
    return async (_ctx, input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(
    relay: RelayService,
    store: MemoryMurmurStore,
    now: () => number,
): Promise<MurmurClient> {
    return MurmurClient.open(ctx, {
        relay: "https://relay.test",
        fetch: relayFetch(relay),
        store,
        now,
    });
}

describe("device inbox continuity", () => {
    test("retries one durable snapshot, then atomically purges and adopts the relay tip", async () => {
        let now = NOW;
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const alice = await client(relay, aliceStore, () => now);
        const bob = await client(relay, bobStore, () => now);
        const expiringSender = generateIdentityKeyPair();
        const bobIdentity = bob.identity;
        const snapshots: MurmurResetEvent[] = [];
        try {
            const created = await alice.createSession(ctx, {
                descriptor: utf8Encode("continuity reset"),
                members: [await bob.createKeyPackage(ctx)],
            });
            await alice.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.synchronize(ctx, { waitMilliseconds: 0 });
            await bob.activateSession(ctx, created.id);
            await bobStore.set(ctx, "murmur/test/technical", utf8Encode("destroy"));
            await bobStore.set(ctx, "application/preserved", utf8Encode("keep"));

            const transport = new HttpDeliveryTransport("https://relay.test", {
                fetch: relayFetch(relay),
            });
            await transport.publish(
                ctx,
                createSignedDelivery(expiringSender, [bob.deviceKey], utf8Encode("will expire"), {
                    createdAt: now,
                    expiresAt: now + 1,
                }),
            );
            now += 2;
            await expect(relay.pruneExpired()).resolves.toBe(1);

            const failure = await bob
                .synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onReset: (_ctx, reset) => {
                            snapshots.push(reset);
                            throw new Error("application retry");
                        },
                    },
                )
                .catch((error: unknown) => error);
            expect(failure).toMatchObject({
                code: "callback_failed",
                callback: "onReset",
                eventIds: [snapshots[0]?.id],
            });
            expect(await bob.session(ctx, created.id)).toBeDefined();
            expect(await bobStore.get(ctx, "murmur/reset/v1/pending")).toBeDefined();

            await expect(
                bob.synchronize(
                    ctx,
                    { waitMilliseconds: 0 },
                    {
                        onReset: (_ctx, reset) => {
                            snapshots.push(reset);
                        },
                    },
                ),
            ).rejects.toMatchObject({
                name: "MurmurResetRequiredError",
                committed: true,
            } satisfies Partial<MurmurResetRequiredError>);

            expect(snapshots).toHaveLength(2);
            expect(snapshots[1]!.id).toBe(snapshots[0]!.id);
            expect(snapshots[1]!.sessions).toHaveLength(1);
            expect(equalBytes(snapshots[1]!.sessions[0]!.id, created.id)).toBe(true);
            expect(equalBytes(snapshots[1]!.sessions[0]!.descriptor, created.descriptor)).toBe(
                true,
            );
            expect(await bob.session(ctx, created.id)).toBeUndefined();
            expect(equalBytes(bob.identity, bobIdentity)).toBe(true);
            expect(await bobStore.get(ctx, "murmur/test/technical")).toBeUndefined();
            expect(await bobStore.get(ctx, "application/preserved")).toBeDefined();
            expect(await bobStore.get(ctx, "murmur/reset/v1/pending")).toBeUndefined();

            await expect(bob.synchronize(ctx, { waitMilliseconds: 0 })).resolves.toMatchObject({
                inbox: { processed: 1 },
            });

            await alice.send(ctx, created.id, utf8Encode("refresh restored roster"));
            for (let cycle = 0; cycle < 8; cycle += 1) {
                await alice.synchronize(ctx, { waitMilliseconds: 0 });
                await bob.synchronize(ctx, { waitMilliseconds: 0 });
            }
            await expect(bob.session(ctx, created.id)).resolves.toMatchObject({
                descriptor: created.descriptor,
                status: "pending",
            });
        } finally {
            alice.close();
            bob.close();
            destroyIdentity(expiringSender);
            await relay.close();
        }
    });
});
