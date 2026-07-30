import { MemoryMurmurStore } from "@murmur/core";
import { EmbeddedRelayTransport, MemoryRelayStore, RelayService } from "@murmur/relay";
import { describe, expect, it } from "vitest";
import { MurmurCliRuntime } from "../../runtime/index.js";
import { runCli } from "../index.js";

describe("runCli", () => {
    it("creates and prints one stable identity", async () => {
        const runtime = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [
                new EmbeddedRelayTransport("relay", new RelayService(new MemoryRelayStore())),
            ],
        });
        const output: string[] = [];

        await runCli(
            runtime,
            ["sign-in", "--first-name", "Alice", "--last-name", "Agent"],
            (text) => output.push(text),
        );
        await runCli(runtime, ["me"], (text) => output.push(text));

        expect(JSON.parse(output[0] ?? "{}")).toMatchObject({ name: "Alice Agent" });
        expect(JSON.parse(output[1] ?? "{}")).toEqual(JSON.parse(output[0] ?? "{}"));
        await expect(
            runtime.send(
                "missing",
                "too many",
                Array.from({ length: 65 }, (_, index) => ({
                    name: `${index}.txt`,
                    bytes: new Uint8Array(),
                })),
            ),
        ).rejects.toThrow("at most 64");
        runtime.destroy();
    });

    it("does not persist a profile rejected by the core profile contract", async () => {
        const runtime = await MurmurCliRuntime.open({
            store: new MemoryMurmurStore(),
            transports: [
                new EmbeddedRelayTransport("relay", new RelayService(new MemoryRelayStore())),
            ],
        });

        await expect(runtime.signIn({ name: "x".repeat(257) })).rejects.toThrow("1 to 256");
        expect(runtime.signedIn).toBe(false);
        await expect(
            runtime.signIn({
                name: "valid",
                avatar: new Uint8Array(700_000),
            }),
        ).rejects.toThrow("relay event payload");
        expect(runtime.signedIn).toBe(false);
    });

    it("rejects duplicate relay IDs before loading or mutating an account", async () => {
        const store = new MemoryMurmurStore();
        const relay = new RelayService(new MemoryRelayStore());
        const first = await MurmurCliRuntime.open({
            store,
            transports: [new EmbeddedRelayTransport("relay", relay)],
        });
        await first.signIn({ name: "Alice" });
        first.destroy();

        await expect(
            MurmurCliRuntime.open({
                store,
                transports: [
                    new EmbeddedRelayTransport("duplicate", relay),
                    new EmbeddedRelayTransport("duplicate", relay),
                ],
            }),
        ).rejects.toThrow("unique");

        const reopened = await MurmurCliRuntime.open({
            store,
            transports: [new EmbeddedRelayTransport("relay", relay)],
        });
        expect(reopened.publicIdentity().profile.name).toBe("Alice");
        reopened.destroy();
    });
});
