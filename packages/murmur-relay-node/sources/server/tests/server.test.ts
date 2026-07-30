import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    utf8Decode,
    utf8Encode,
} from "@murmur/core";
import { createRelayFetchHandler, RelayService } from "@murmur/relay";
import { afterEach, describe, expect, it } from "vitest";
import { createNodeRelayServer } from "../index.js";
import { SqliteRelayStore } from "../../storage/index.js";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
    await Promise.all(cleanups.splice(0).map(async (cleanup) => cleanup()));
});

describe("Node relay server", () => {
    it("serves the browser-safe HTTP transport over a real socket", async () => {
        const store = new SqliteRelayStore(":memory:");
        const server = createNodeRelayServer(createRelayFetchHandler(new RelayService(store)));
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        cleanups.push(
            async () =>
                new Promise<void>((resolve, reject) =>
                    server.close((error) => {
                        store.close();
                        if (error === undefined) {
                            resolve();
                        } else {
                            reject(error);
                        }
                    }),
                ),
        );
        const address = server.address();
        if (address === null || typeof address === "string") {
            throw new Error("Expected a TCP relay address");
        }
        const baseUrl = `http://127.0.0.1:${address.port}`;
        const preflight = await fetch(`${baseUrl}/v1/events`, {
            method: "OPTIONS",
            headers: {
                origin: "https://murmur.example",
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type",
            },
        });
        expect(preflight.status).toBe(204);
        expect(preflight.headers.get("access-control-allow-origin")).toBe("*");

        const transport = new HttpRelayTransport("node", baseUrl);
        const alice = new MurmurClient({
            identity: generateIdentityKeyPair(),
            store: new MemoryMurmurStore(),
            transports: [transport],
        });
        const bob = new MurmurClient({
            identity: generateIdentityKeyPair(),
            store: new MemoryMurmurStore(),
            transports: [transport],
        });

        await bob.subscribe("room");
        await alice.publish("room", utf8Encode("hello"));
        const deliveries = await bob.sync();

        expect(utf8Decode(deliveries[0]?.event.payload ?? new Uint8Array())).toBe("hello");
        await deliveries[0]?.acknowledge();
    });

    it("rejects browser origins outside an explicit allowlist", async () => {
        const server = createNodeRelayServer(async () => new Response("unexpected"), {
            allowedOrigins: ["https://allowed.example"],
        });
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        cleanups.push(
            async () =>
                new Promise<void>((resolve, reject) =>
                    server.close((error) => (error === undefined ? resolve() : reject(error))),
                ),
        );
        const address = server.address();
        if (address === null || typeof address === "string") {
            throw new Error("Expected a TCP relay address");
        }

        const response = await fetch(`http://127.0.0.1:${address.port}/v1/events`, {
            headers: { origin: "https://forbidden.example" },
        });
        expect(response.status).toBe(403);
        expect(await response.text()).toBe("Origin not allowed");
    });
});
