import { describe, expect, it } from "vitest";
import type { EphemeralStreamMessage } from "../../types.js";
import { InProcessEphemeralFanout } from "../ephemeralFanout.js";

const encoder = new TextEncoder();

function frame(text: string): Uint8Array {
    return encoder.encode(text);
}

function kinds(messages: readonly EphemeralStreamMessage[]): readonly string[] {
    return messages.map((message) => message.kind);
}

describe("InProcessEphemeralFanout", () => {
    it("fans a frame to every subscriber of a topic and counts deliveries", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
        });
        const first = fanout.subscribe("t");
        const second = fanout.subscribe("t");
        const other = fanout.subscribe("u");
        expect(first).toBeDefined();
        expect(second).toBeDefined();
        expect(other).toBeDefined();

        expect(fanout.publishFrame("t", frame("hello"))).toBe(2);
        expect(fanout.publishFrame("missing", frame("x"))).toBe(0);

        expect(first?.take()).toEqual([{ kind: "frame", bytes: frame("hello") }]);
        expect(second?.take()).toEqual([{ kind: "frame", bytes: frame("hello") }]);
        expect(other?.take()).toEqual([]);
        fanout.close();
    });

    it("drops the oldest frames past the frame-count bound and coalesces one drop", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamQueueFrames: 2,
            maximumStreamQueueBytes: 1_000_000,
        });
        const subscription = fanout.subscribe("t");
        expect(subscription).toBeDefined();
        for (let index = 0; index < 5; index += 1) {
            fanout.publishFrame("t", frame(`f${index.toString()}`));
        }
        const messages = subscription?.take() ?? [];
        expect(kinds(messages)).toEqual(["frame", "frame", "drop"]);
        expect(messages[0]).toEqual({ kind: "frame", bytes: frame("f3") });
        expect(messages[1]).toEqual({ kind: "frame", bytes: frame("f4") });
        expect(messages[2]).toEqual({ kind: "drop", frames: 3 });
        // Draining resets the coalesced drop counter.
        expect(subscription?.take()).toEqual([]);
        fanout.close();
    });

    it("drops the oldest frames past the byte bound", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamQueueFrames: 1_000,
            maximumStreamQueueBytes: 10,
        });
        const subscription = fanout.subscribe("t");
        fanout.publishFrame("t", frame("aaaaaa")); // 6 bytes
        fanout.publishFrame("t", frame("bbbbbb")); // 6 bytes -> 12 > 10, drop first
        const messages = subscription?.take() ?? [];
        expect(kinds(messages)).toEqual(["frame", "drop"]);
        expect(messages[0]).toEqual({ kind: "frame", bytes: frame("bbbbbb") });
        expect(messages[1]).toEqual({ kind: "drop", frames: 1 });
        fanout.close();
    });

    it("coalesces wake into a single pending event", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
        });
        const subscription = fanout.subscribe("t");
        fanout.wake("t");
        fanout.wake("t");
        fanout.wake("t");
        expect(subscription?.take()).toEqual([{ kind: "wake" }]);
        expect(subscription?.take()).toEqual([]);
        fanout.close();
    });

    it("returns undefined once the concurrent-stream cap is reached", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 1,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
        });
        const first = fanout.subscribe("t");
        expect(first).toBeDefined();
        expect(fanout.subscribe("t")).toBeUndefined();
        expect(fanout.subscriberCount).toBe(1);

        first?.close();
        expect(fanout.subscriberCount).toBe(0);
        expect(fanout.subscribe("t")).toBeDefined();
        expect(fanout.subscriberCount).toBe(1);
        fanout.close();
        expect(fanout.subscriberCount).toBe(0);
    });

    it("resolves waitForActivity on enqueue, keepalive, and close", async () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
        });
        const subscription = fanout.subscribe("t");
        if (subscription === undefined) {
            throw new Error("subscription expected");
        }

        // Enqueue before waiting: returns immediately without a timer.
        fanout.publishFrame("t", frame("early"));
        await subscription.waitForActivity(10_000);
        expect(kinds(subscription.take())).toEqual(["frame"]);

        // Keepalive tick resolves an idle wait.
        const started = Date.now();
        await subscription.waitForActivity(15);
        expect(Date.now() - started).toBeGreaterThanOrEqual(10);
        expect(subscription.take()).toEqual([]);

        // A late enqueue resolves a pending wait promptly.
        const pending = subscription.waitForActivity(10_000);
        fanout.publishFrame("t", frame("late"));
        await pending;
        expect(kinds(subscription.take())).toEqual(["frame"]);

        // Closing resolves a pending wait and marks the subscription closed.
        const closing = subscription.waitForActivity(10_000);
        subscription.close();
        await closing;
        expect(subscription.closed).toBe(true);
    });
});
