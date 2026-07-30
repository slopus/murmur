import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    createRelayEvent,
    encodeRelayEventWire,
    utf8Decode,
    utf8Encode,
} from "@murmur/core";
import { describe, expect, it } from "vitest";
import { RelayService } from "../../relay/index.js";
import { MemoryRelayStore } from "../../storage/index.js";
import { createRelayFetchHandler } from "../index.js";

describe("Fetch relay protocol", () => {
    it("carries realtime/offline events and ciphertext blobs", async () => {
        const handler = createRelayFetchHandler(new RelayService(new MemoryRelayStore()));
        const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
            handler(new Request(input, init));
        const transport = new HttpRelayTransport("fetch", "https://relay.test", fetch);
        const aliceClient = new MurmurClient({
            identity: generateIdentityKeyPair(),
            store: new MemoryMurmurStore(),
            transports: [transport],
        });
        const bobClient = new MurmurClient({
            identity: generateIdentityKeyPair(),
            store: new MemoryMurmurStore(),
            transports: [transport],
        });

        await bobClient.subscribe("room");
        await aliceClient.publish("room", utf8Encode("opaque"));
        const received = await bobClient.sync();
        expect(utf8Decode(received[0]?.event.payload ?? new Uint8Array())).toBe("opaque");
        await received[0]?.acknowledge();
        expect(await bobClient.sync()).toHaveLength(0);

        const uploaded = await aliceClient.putBlob(utf8Encode("ciphertext"));
        expect((await bobClient.getBlob(uploaded.id))?.bytes).toEqual(utf8Encode("ciphertext"));
    });

    it("rejects encoded blob paths and malformed request bodies", async () => {
        const handler = createRelayFetchHandler(new RelayService(new MemoryRelayStore()));

        expect((await handler(new Request("https://relay.test/v1/blobs/foo%2Fbar"))).status).toBe(
            404,
        );
        expect(
            (await handler(new Request(`https://relay.test/v1/blobs/${"A".repeat(42)}B`))).status,
        ).toBe(404);
        expect(
            (
                await handler(
                    new Request("https://relay.test/v1/events", {
                        method: "POST",
                        body: "{",
                    }),
                )
            ).status,
        ).toBe(400);
    });

    it("does not expose unexpected store failures", async () => {
        class FailingStore extends MemoryRelayStore {
            override async publish(): Promise<never> {
                throw new Error("database password leaked");
            }
        }
        const handler = createRelayFetchHandler(new RelayService(new FailingStore()));
        const event = createRelayEvent(generateIdentityKeyPair(), "topic", utf8Encode("opaque"));
        const response = await handler(
            new Request("https://relay.test/v1/events", {
                method: "POST",
                body: encodeRelayEventWire(event).slice().buffer as ArrayBuffer,
            }),
        );

        expect(response.status).toBe(500);
        expect(await response.text()).toBe("Internal relay error");
    });
});
