import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { HttpDeliveryTransport } from "../../delivery/index.js";
import { MurmurClient } from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Encode } from "../../utils/index.js";

describe("restored-account device registration", () => {
    test("self-registers a second device and removes it", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"));
        const handler = createRelayFetchHandler(relay, {
            defaultAdmissionPrincipal: "test",
            requireRemoteAddress: false,
        });
        const fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        const account = generateIdentityKeyPair();
        const first = await MurmurClient.open({
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const peer = await MurmurClient.open({
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        const session = await first.createSession({
            descriptor: utf8Encode("device-roster-convergence"),
            members: [await peer.createKeyPackage()],
        });
        for (let round = 0; round < 4; round += 1) {
            await first.synchronize({ waitMilliseconds: 0 });
            await peer.synchronize({ waitMilliseconds: 0 });
        }
        if ((await peer.session(session.id))?.status === "pending") {
            await peer.activateSession(session.id);
        }
        const second = await MurmurClient.open({
            identity: account,
            transport: new HttpDeliveryTransport("https://relay.test", { fetch }),
            store: new MemoryMurmurStore(),
        });
        try {
            const firstNotification = await first.synchronize({ waitMilliseconds: 0 });
            const secondNotification = await second.synchronize({ waitMilliseconds: 0 });
            expect(firstNotification.inbox.processed).toBeGreaterThan(0);
            expect(secondNotification.inbox.processed).toBeGreaterThan(0);
            for (let round = 0; round < 8; round += 1) {
                await first.synchronize({ waitMilliseconds: 0 });
                await peer.synchronize({ waitMilliseconds: 0 });
                await second.synchronize({ waitMilliseconds: 0 });
            }
            expect((await second.session(session.id))?.status).toBe("pending");
            await second.activateSession(session.id);
            expect((await second.session(session.id))?.status).toBe("active");
            expect(await first.devices()).toHaveLength(2);
            await first.removeDevice(second.deviceKey);
            expect(await first.devices()).toHaveLength(1);
        } finally {
            first.close();
            second.close();
            peer.close();
            await relay.close();
        }
    });
});
