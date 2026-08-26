import {
    RelayService,
    SqlitePrivateGroupStateStore,
    SqliteRelayStore,
    createPrivateGroupStateServiceFromSecret,
    createRelayFetchHandler,
    type PrivateGroupStateService,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import type { PrivateGroupStateConnection } from "../../privateGroupState/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

const NOW = 1_800_000_000_000;

function bytes(seed: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 29) & 0xff);
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "private-state-integration",
    });
    return async (input, init): Promise<Response> => await handler(new Request(input, init));
}

async function client(
    relay: RelayService,
    privateGroupState: PrivateGroupStateConnection,
    store = new MemoryMurmurStore(),
): Promise<MurmurClient> {
    return await MurmurClient.open({
        relay: "https://relay.test",
        fetch: relayFetch(relay),
        privateGroupState,
        store,
        now: () => NOW,
    });
}

describe("session-bound private-group state", () => {
    test("distributes one stable secret through Welcome and retains rollback state on restart", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const stateService: PrivateGroupStateService = createPrivateGroupStateServiceFromSecret({
            store: new SqlitePrivateGroupStateStore(":memory:"),
            secret: bytes(91),
            now: () => NOW,
        });
        const connection: PrivateGroupStateConnection = { transport: stateService };
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const alice = await client(relay, connection, aliceStore);
        let bob = await client(relay, connection, bobStore);
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("private state integration"),
                members: [await bob.discovery()],
            });
            await expect(alice.privateGroupState(session.id)).rejects.toThrow("active MLS session");

            await alice.synchronize({ waitMilliseconds: 0 });
            await alice.synchronize({ waitMilliseconds: 0 });
            expect(await alice.session(session.id)).toMatchObject({ status: "active" });

            await bob.synchronize({ waitMilliseconds: 0 });
            expect(await bob.session(session.id)).toMatchObject({ status: "pending" });
            await expect(bob.privateGroupState(session.id)).rejects.toThrow("active MLS session");
            await bob.activateSession(session.id);

            const aliceState = await alice.privateGroupState(session.id);
            expect(await alice.privateGroupState(session.id)).toBe(aliceState);
            expect(await aliceState.create(utf8Encode("alpha"))).toMatchObject({ revision: 1 });

            const bobState = await bob.privateGroupState(session.id);
            const joined = await bobState.join();
            expect(joined.revision).toBe(1);
            expect(utf8Decode(joined.attributes)).toBe("alpha");
            bobState.close();
            bob.close();

            bob = await client(relay, connection, bobStore);
            const reopened = await bob.privateGroupState(session.id);
            expect(utf8Decode((await reopened.read()).attributes)).toBe("alpha");

            expect(await aliceState.mutate(utf8Encode("beta"))).toMatchObject({ revision: 2 });
            const successor = await reopened.read();
            expect(successor.revision).toBe(2);
            expect(utf8Decode(successor.attributes)).toBe("beta");
            reopened.close();
        } finally {
            alice.close();
            bob.close();
            stateService.close();
            await relay.close();
        }
    });
});
