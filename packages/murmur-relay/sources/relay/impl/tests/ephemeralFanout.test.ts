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
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
            maximumTotalStreamQueueBytes: 10_000_000,
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
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 2,
            maximumStreamQueueBytes: 1_000_000,
            maximumTotalStreamQueueBytes: 10_000_000,
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
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 1_000,
            maximumStreamQueueBytes: 10,
            maximumTotalStreamQueueBytes: 10_000_000,
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
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
            maximumTotalStreamQueueBytes: 10_000_000,
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
            maximumStreamsPerTopic: 1,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
            maximumTotalStreamQueueBytes: 10_000_000,
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

    it("returns undefined once one topic reaches the per-topic cap", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 100,
            maximumStreamsPerTopic: 2,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
            maximumTotalStreamQueueBytes: 10_000_000,
        });
        const first = fanout.subscribe("t");
        expect(fanout.subscribe("t")).toBeDefined();
        // The process-wide cap is nowhere near reached, so only the per-topic
        // ceiling can reject this: without it one client holds every slot.
        expect(fanout.subscribe("t")).toBeUndefined();
        expect(fanout.subscriberCountForTopic("t")).toBe(2);
        expect(fanout.subscriberCount).toBe(2);

        // A different topic is unaffected, and a rejected subscribe leaves no
        // empty topic entry behind.
        expect(fanout.subscribe("u")).toBeDefined();
        expect(fanout.subscriberCountForTopic("u")).toBe(1);
        expect(fanout.subscriberCountForTopic("rejected-only")).toBe(0);

        first?.close();
        expect(fanout.subscriberCountForTopic("t")).toBe(1);
        expect(fanout.subscribe("t")).toBeDefined();
        expect(fanout.subscriberCountForTopic("t")).toBe(2);
        fanout.close();
        expect(fanout.subscriberCountForTopic("t")).toBe(0);
    });

    it("bounds retained bytes across subscribers, evicting the longest backlogged", () => {
        // Per subscriber this configuration allows 100 bytes each, so three
        // subscribers could hold 300 without an aggregate bound.
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 100,
            maximumStreamQueueBytes: 100,
            maximumTotalStreamQueueBytes: 100,
        });
        const first = fanout.subscribe("a");
        const second = fanout.subscribe("b");
        const third = fanout.subscribe("c");
        if (first === undefined || second === undefined || third === undefined) {
            throw new Error("subscriptions expected");
        }

        fanout.publishFrame("a", frame("x".repeat(60)));
        expect(fanout.retainedBytes).toBe(60);
        fanout.publishFrame("b", frame("y".repeat(60)));
        // 120 > 100, so the longest-backlogged reader loses its oldest frame.
        expect(fanout.retainedBytes).toBe(60);
        fanout.publishFrame("c", frame("z".repeat(60)));
        expect(fanout.retainedBytes).toBe(60);

        // The eviction is reported to the evicted reader as an ordinary drop,
        // and the newest subscriber still holds its frame.
        expect(first.take()).toEqual([{ kind: "drop", frames: 1 }]);
        expect(second.take()).toEqual([{ kind: "drop", frames: 1 }]);
        expect(kinds(third.take())).toEqual(["frame"]);
        fanout.close();
        expect(fanout.retainedBytes).toBe(0);
    });

    it("keeps a batch handed to a reader inside the aggregate budget", () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 100,
            maximumStreamQueueBytes: 100,
            maximumTotalStreamQueueBytes: 100,
        });
        const reader = fanout.subscribe("a");
        const other = fanout.subscribe("b");
        if (reader === undefined || other === undefined) {
            throw new Error("subscriptions expected");
        }

        fanout.publishFrame("a", frame("x".repeat(60)));
        // Taking hands the batch to the response body; the bytes are still held
        // by this process, so they keep counting until the reader returns.
        expect(kinds(reader.take())).toEqual(["frame"]);
        expect(fanout.retainedBytes).toBe(60);

        fanout.publishFrame("b", frame("y".repeat(60)));
        expect(fanout.retainedBytes).toBe(60);
        expect(other.take()).toEqual([{ kind: "drop", frames: 1 }]);

        // The reader coming back for more releases the batch it was handed.
        expect(reader.take()).toEqual([]);
        expect(fanout.retainedBytes).toBe(0);
        fanout.publishFrame("b", frame("y".repeat(60)));
        expect(kinds(other.take())).toEqual(["frame"]);
        fanout.close();
    });

    it("rejects an aggregate budget below one subscriber's queue", () => {
        expect(
            () =>
                new InProcessEphemeralFanout({
                    maximumConcurrentStreams: 10,
                    maximumStreamsPerTopic: 10,
                    maximumStreamQueueFrames: 8,
                    maximumStreamQueueBytes: 4096,
                    maximumTotalStreamQueueBytes: 4095,
                }),
        ).toThrow("Maximum total stream queue bytes");
    });

    it("resolves waitForActivity on enqueue, keepalive, and close", async () => {
        const fanout = new InProcessEphemeralFanout({
            maximumConcurrentStreams: 10,
            maximumStreamsPerTopic: 10,
            maximumStreamQueueFrames: 8,
            maximumStreamQueueBytes: 4096,
            maximumTotalStreamQueueBytes: 10_000_000,
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
