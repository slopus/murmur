import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRelayFetchHandler } from "../../http/index.js";
import { relayEventSigningBytes, type SignedRelayEvent } from "../../protocol/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { closeNodeRelayServer, createNodeRelayServer } from "../index.js";

const now = 3_000_000;
const privateKey = new Uint8Array(32).fill(13);
const signingKey = ed25519.getPublicKey(privateKey);
const encoder = new TextEncoder();

function event(): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode("disconnect"))),
        topic: "disconnect",
        author: { signingKey },
        createdAt: now,
        payload: new Uint8Array(),
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), privateKey),
    };
}

async function within<Result>(promise: Promise<Result>, milliseconds: number): Promise<Result> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            promise,
            new Promise<never>((_resolve, reject) => {
                timer = setTimeout(
                    () => reject(new Error("Timed out waiting for Node relay test event")),
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

describe("Node relay server", () => {
    let service: RelayService | undefined;
    let server: ReturnType<typeof createNodeRelayServer> | undefined;

    afterEach(async () => {
        if (server !== undefined) {
            await closeNodeRelayServer(server);
        }
        await service?.close();
    });

    it("releases a long-poll waiter promptly when its client disconnects", async () => {
        const store = new SqliteRelayStore(":memory:");
        const originalReadEvents = store.readEvents.bind(store);
        let readCount = 0;
        let parked: (() => void) | undefined;
        const parkedPromise = new Promise<void>((resolve) => {
            parked = resolve;
        });
        vi.spyOn(store, "readEvents").mockImplementation(async (...arguments_) => {
            const page = await originalReadEvents(...arguments_);
            readCount += 1;
            if (readCount === 2) {
                parked?.();
            }
            return page;
        });
        service = new RelayService(
            store,
            {
                maximumConcurrentLongPolls: 1,
                maximumLongPollMilliseconds: 30_000,
            },
            undefined,
            () => now,
        );
        await service.publish(event());
        server = createNodeRelayServer(createRelayFetchHandler(service));
        const incoming = new IncomingMessage(new Socket());
        incoming.method = "GET";
        incoming.url = "/v1/topics/disconnect/events?since=1&wait=30000";
        incoming.headers.host = "localhost";
        incoming.complete = true;
        const outgoing = new ServerResponse(incoming);
        server.emit("request", incoming, outgoing);
        await within(parkedPromise, 1_000);

        outgoing.emit("close");
        await new Promise<void>((resolve) => setImmediate(resolve));

        await expect(service.readEvents("disconnect", 1n, 10, 5)).resolves.toMatchObject({
            events: [],
            reset: false,
            seq: 1n,
        });
    });
});
