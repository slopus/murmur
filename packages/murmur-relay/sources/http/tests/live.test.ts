import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

const DEFAULT_LIVE_RELAY_URL = "https://murmur.cluster-fluster.com";
const relayUrl = (process.env.MURMUR_LIVE_RELAY_URL ?? DEFAULT_LIVE_RELAY_URL).replace(/\/+$/, "");
const describeLive = process.env.MURMUR_LIVE_TESTS === "true" ? describe : describe.skip;

describeLive(
    "public Murmur relay",
    () => {
        it("serves the human-readable welcome over HTTPS", async () => {
            const response = await fetch(`${relayUrl}/`);

            expect(response.status).toBe(200);
            expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
            await expect(response.text()).resolves.toBe("Welcome to Murmur Relay!");
        });

        it("reports healthy storage with browser CORS", async () => {
            const response = await fetch(`${relayUrl}/health`, {
                headers: { origin: "https://smoke.test" },
            });

            expect(response.status).toBe(200);
            expect(response.headers.get("access-control-allow-origin")).toBe("*");
            await expect(response.json()).resolves.toEqual({ ok: true });
        });

        it("returns the fixed JSON contract for a harmless missing-topic read", async () => {
            const topic = `live-smoke-${randomUUID()}`;
            const response = await fetch(
                `${relayUrl}/v1/topics/${encodeURIComponent(topic)}/state`,
                { headers: { origin: "https://smoke.test" } },
            );

            expect(response.status).toBe(404);
            expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
            expect(response.headers.get("access-control-allow-origin")).toBe("*");
            await expect(response.json()).resolves.toEqual({ error: "not_found" });
        });
    },
    15_000,
);
