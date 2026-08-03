import { describe, expect, it, vi } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import type {
    EventPage,
    ListPage,
    PublishOutcome,
    RelayBlob,
    RelayStreamHandlers,
    RelayTransport,
    TopicState,
} from "../../transport/index.js";
import { utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

/** Minimal non-streaming relay double reused by the client stream tests. */
class BaseTransport implements RelayTransport {
    constructor(readonly id: string) {}

    async publish(): Promise<PublishOutcome> {
        return { seq: 1n, duplicate: false };
    }

    async readState(): Promise<TopicState | undefined> {
        return undefined;
    }

    async readList(): Promise<ListPage | undefined> {
        return { elements: [], nextCursor: null };
    }

    async readEvents(): Promise<EventPage | undefined> {
        return undefined;
    }

    async putBlob(): Promise<void> {}

    async getBlob(): Promise<RelayBlob | undefined> {
        return undefined;
    }
}

/** A relay whose stream the test drives one connection at a time. */
class ScriptedStreamTransport extends BaseTransport {
    connections = 0;
    #handlers: RelayStreamHandlers | undefined;
    #end: (() => void) | undefined;
    #fail: ((error: Error) => void) | undefined;

    async openStream(
        _topic: string,
        handlers: RelayStreamHandlers,
        signal: AbortSignal,
    ): Promise<void> {
        this.connections += 1;
        this.#handlers = handlers;
        return new Promise<void>((resolve, reject) => {
            this.#end = resolve;
            this.#fail = reject;
            if (signal.aborted) {
                resolve();
                return;
            }
            signal.addEventListener("abort", () => resolve(), { once: true });
        });
    }

    ready(): void {
        this.#handlers?.onReady?.();
    }

    frame(bytes: Uint8Array): void {
        this.#handlers?.onFrame?.(bytes);
    }

    wake(): void {
        this.#handlers?.onWake?.();
    }

    drop(frames: number): void {
        this.#handlers?.onDrop?.(frames);
    }

    endStream(): void {
        this.#end?.();
    }

    failStream(error: Error): void {
        this.#fail?.(error);
    }
}

/** A relay that supports ephemeral publishing with a scripted outcome. */
class EphemeralTransport extends BaseTransport {
    readonly #deliver: () => Promise<number>;

    constructor(id: string, deliver: () => Promise<number>) {
        super(id);
        this.#deliver = deliver;
    }

    async publishEphemeral(): Promise<number> {
        return this.#deliver();
    }
}

function makeClient(transports: readonly RelayTransport[]): MurmurClient {
    return new MurmurClient({
        identity: generateIdentityKeyPair(),
        store: new MemoryMurmurStore(),
        transports,
    });
}

async function flush(): Promise<void> {
    await Promise.resolve();
    await Promise.resolve();
}

describe("MurmurClient topic streams", () => {
    it("forwards frames tagged with the relay id and reports connection status", async () => {
        const relay = new ScriptedStreamTransport("relay");
        const frames: Array<{ relayId: string; bytes: Uint8Array }> = [];
        const statuses: Array<{ relayId: string; connected: boolean }> = [];
        const stream = makeClient([relay]).openTopicStream("room", {
            onFrame: (frame) => frames.push(frame),
            onStatus: (status) =>
                statuses.push({ relayId: status.relayId, connected: status.connected }),
        });
        await flush();

        relay.ready();
        relay.frame(utf8Encode("hi"));
        await flush();

        expect(stream.connected).toBe(true);
        expect(frames).toEqual([{ relayId: "relay", bytes: utf8Encode("hi") }]);
        expect(statuses).toContainEqual({ relayId: "relay", connected: true });

        stream.close();
    });

    it("reconnects after the stream ends", async () => {
        const relay = new ScriptedStreamTransport("relay");
        const stream = makeClient([relay]).openTopicStream("room", {});
        await flush();
        expect(relay.connections).toBe(1);

        relay.endStream();
        // The first backoff lands in [250, 500) ms of real time.
        await vi.waitFor(() => expect(relay.connections).toBe(2), { timeout: 2_000 });

        stream.close();
    });

    it("does not reconnect after close()", async () => {
        const relay = new ScriptedStreamTransport("relay");
        const stream = makeClient([relay]).openTopicStream("room", {});
        await flush();
        expect(relay.connections).toBe(1);

        stream.close();
        relay.endStream();
        await new Promise((resolve) => setTimeout(resolve, 400));

        expect(relay.connections).toBe(1);
        expect(stream.connected).toBe(false);
    });

    it("keeps reconnecting when a status handler throws", async () => {
        const relay = new ScriptedStreamTransport("relay");
        const stream = makeClient([relay]).openTopicStream("room", {
            onStatus: (): void => {
                throw new Error("status handler exploded");
            },
        });
        await flush();
        expect(relay.connections).toBe(1);

        relay.endStream();
        await vi.waitFor(() => expect(relay.connections).toBe(2), { timeout: 2_000 });

        relay.ready();
        await flush();
        expect(stream.connected).toBe(true);

        stream.close();
    });

    it("isolates every throwing application handler", async () => {
        const relay = new ScriptedStreamTransport("relay");
        const explode = (): never => {
            throw new Error("handler exploded");
        };
        const stream = makeClient([relay]).openTopicStream("room", {
            onFrame: explode,
            onWake: explode,
            onDrop: explode,
            onStatus: explode,
        });
        await flush();

        expect(() => relay.ready()).not.toThrow();
        expect(() => relay.frame(utf8Encode("hi"))).not.toThrow();
        expect(() => relay.wake()).not.toThrow();
        expect(() => relay.drop(3)).not.toThrow();
        expect(stream.connected).toBe(true);

        stream.close();
    });

    it("throws when no transport supports topic streaming", () => {
        const client = makeClient([new BaseTransport("plain")]);

        expect(() => client.openTopicStream("room", {})).toThrow(
            "No configured transport supports topic streaming",
        );
    });

    it("fans out ephemeral publishes and tolerates a single relay failure", async () => {
        const healthy = new EphemeralTransport("healthy", async () => 2);
        const broken = new EphemeralTransport("broken", async () => {
            throw new Error("broken relay is offline");
        });
        const client = makeClient([healthy, broken]);

        await expect(client.publishEphemeral("room", utf8Encode("frame"))).resolves.toBe(2);
    });

    it("throws only when every ephemeral publish fails", async () => {
        const broken = new EphemeralTransport("broken", async () => {
            throw new Error("offline");
        });
        const client = makeClient([broken]);

        await expect(client.publishEphemeral("room", utf8Encode("frame"))).rejects.toThrow(
            "Every transport failed",
        );
    });

    it("throws when no transport supports ephemeral publishing", async () => {
        const client = makeClient([new BaseTransport("plain")]);

        await expect(client.publishEphemeral("room", utf8Encode("frame"))).rejects.toThrow(
            "No configured transport supports ephemeral publishing",
        );
    });
});
