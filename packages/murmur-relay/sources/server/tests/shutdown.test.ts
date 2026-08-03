import { createServer, type AddressInfo } from "node:net";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { createRelayFetchHandler } from "../../http/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import {
    closeNodeRelayServer,
    createNodeRelayServer,
    listenNodeRelayServer,
    type NodeRelayCloseOptions,
} from "../index.js";

const now = 4_000_000;

async function within<Result>(promise: Promise<Result>, milliseconds: number): Promise<Result> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            promise,
            new Promise<never>((_resolve, reject) => {
                timer = setTimeout(
                    () => reject(new Error("Relay shutdown did not finish in time")),
                    milliseconds,
                );
            }),
        ]);
    } finally {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
    }
}

function addressOf(server: ReturnType<typeof createNodeRelayServer>): string {
    const address = server.address();
    if (address === null || typeof address === "string") {
        throw new Error("expected a bound TCP address");
    }
    return `http://127.0.0.1:${(address as AddressInfo).port.toString()}`;
}

/** Whether the shutdown promise is still pending after the event loop turns. */
async function pending(promise: Promise<void>): Promise<boolean> {
    const marker = Symbol("pending");
    const settled = await Promise.race([
        promise.then(() => marker as symbol).catch(() => marker as symbol),
        new Promise<symbol>((resolve) => setTimeout(() => resolve(marker), 150)),
    ]);
    return settled === marker;
}

/**
 * Whether this machine lets a test bind a loopback port.
 *
 * These tests need a real listener, which a sandboxed developer shell may
 * refuse. The probe therefore skips them locally, but CI must never skip
 * silently: a runner that cannot bind would turn this whole file green while
 * testing nothing, and the shutdown hang it covers would return unnoticed.
 */
async function canBindLoopback(): Promise<boolean> {
    return await new Promise<boolean>((resolve) => {
        const probe = createServer();
        probe.once("error", () => {
            resolve(false);
        });
        probe.listen(0, "127.0.0.1", () => {
            probe.close(() => {
                resolve(true);
            });
        });
    });
}

describe("Node relay graceful shutdown", () => {
    let bindable = false;

    beforeAll(async () => {
        bindable = await canBindLoopback();
        if (!bindable && process.env.CI !== undefined) {
            throw new Error("CI must be able to bind a loopback port for the shutdown tests");
        }
    });
    let service: RelayService | undefined;
    let server: ReturnType<typeof createNodeRelayServer> | undefined;

    afterEach(async () => {
        if (server !== undefined) {
            await closeNodeRelayServer(server, { graceMilliseconds: 0 });
            server = undefined;
        }
        await service?.close();
        service = undefined;
    });

    async function startWithOpenStream(): Promise<{
        readonly reader: ReadableStreamDefaultReader<Uint8Array>;
        readonly stopped: (options: NodeRelayCloseOptions) => Promise<void>;
    }> {
        service = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        server = createNodeRelayServer(createRelayFetchHandler(service));
        await listenNodeRelayServer(server, { host: "127.0.0.1", port: 0 });
        const response = await fetch(`${addressOf(server)}/v1/topics/room/stream`);
        expect(response.status).toBe(200);
        const body = response.body;
        if (body === null) {
            throw new Error("expected a streaming body");
        }
        const reader = body.getReader();
        // The `ready` event proves the response is live and the connection active.
        const first = await reader.read();
        expect(new TextDecoder().decode(first.value)).toContain("event: ready");
        const started = server;
        return {
            reader,
            stopped: (options): Promise<void> => closeNodeRelayServer(started, options),
        };
    }

    it("finishes promptly when the service closes its streams after the listener stops", async (context) => {
        if (!bindable) {
            context.skip();
        }
        const { reader, stopped } = await startWithOpenStream();
        // A generous grace so only the ordering, never the forced-close
        // backstop, can be what lets this finish.
        const drained = stopped({ graceMilliseconds: 30_000 });
        expect(await pending(drained)).toBe(true);

        service?.closeStreams();
        await within(drained, 2_000);

        // The client saw an orderly end of stream, not a destroyed socket.
        let done = false;
        for (let guard = 0; guard < 10 && !done; guard += 1) {
            done = (await reader.read()).done;
        }
        expect(done).toBe(true);
    });

    it("destroys a stream that outlives the shutdown grace period", async (context) => {
        if (!bindable) {
            context.skip();
        }
        const { reader, stopped } = await startWithOpenStream();
        // Nothing closes the subscription here, so only the grace deadline can
        // end this shutdown.
        await within(stopped({ graceMilliseconds: 50 }), 2_000);
        await reader.cancel().catch(() => undefined);
    });
});
