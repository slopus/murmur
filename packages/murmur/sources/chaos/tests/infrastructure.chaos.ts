import { createRootContext, type Context } from "@steve.kite/stdlib";
import { describe, expect, test } from "vitest";
import type {
    DeliveryPublishOutcome,
    DeliveryTransport,
    InboxDelivery,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../../delivery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    ChaosInjectedError,
    FaultInjectingDeliveryTransport,
    FaultInjectingMurmurStore,
    ManualVirtualClock,
    SeededChaosSchedule,
    SeededRandom,
    settleChaos,
} from "../index.js";

const ctx = createRootContext().named("test");

const IDENTITY = new Uint8Array(32).fill(1);
const SECOND_IDENTITY = new Uint8Array(32).fill(2);

function delivery(id: string, marker: number = 1): SignedDelivery {
    return {
        version: 1,
        id,
        sender: IDENTITY.slice(),
        senderAccount: IDENTITY.slice(),
        recipients: [SECOND_IDENTITY.slice()],
        targetAccounts: [],
        ownerAccount: null,
        sessionId: null,
        sessionControl: null,
        createdAt: 1_700_000_000_000,
        expiresAt: 1_700_000_060_000,
        ciphertext: new Uint8Array([marker, marker + 1, marker + 2]),
        signature: new Uint8Array(64).fill(3),
    };
}

function readRequest(): SignedInboxRead {
    return {
        version: 1,
        recipient: SECOND_IDENTITY.slice(),
        after: null,
        limit: 100,
        waitMilliseconds: 0,
        createdAt: 1_700_000_000_000,
        signature: new Uint8Array(64).fill(4),
    };
}

function ackRequest(through: string): SignedInboxAck {
    return {
        version: 1,
        recipient: SECOND_IDENTITY.slice(),
        through,
        createdAt: 1_700_000_000_000,
        signature: new Uint8Array(64).fill(5),
    };
}

function inboxDelivery(eventId: string, marker: number): InboxDelivery {
    return { eventId, delivery: delivery(`delivery-${eventId}`, marker) };
}

class RecordingTransport implements DeliveryTransport {
    readonly accepted = new Map<string, string>();
    publishCalls = 0;
    readCalls = 0;
    acknowledgeCalls = 0;
    acknowledgedThrough: string | null = null;
    page: InboxPage = {
        deliveries: [],
        head: null,
        acknowledgedThrough: null,
        exhausted: true,
    };

    async publish(_ctx: Context, input: SignedDelivery): Promise<DeliveryPublishOutcome> {
        this.publishCalls += 1;
        const existing = this.accepted.get(input.id);
        if (existing !== undefined) return { eventId: existing, duplicate: true };
        const eventId = `event-${this.accepted.size + 1}`;
        this.accepted.set(input.id, eventId);
        return { eventId, duplicate: false };
    }

    async read(_ctx: Context): Promise<InboxPage> {
        this.readCalls += 1;
        return this.page;
    }

    async acknowledge(
        _ctx: Context,
        request: SignedInboxAck,
    ): Promise<{ readonly removed: number }> {
        this.acknowledgeCalls += 1;
        if (this.acknowledgedThrough !== null && request.through <= this.acknowledgedThrough) {
            return { removed: 0 };
        }
        this.acknowledgedThrough = request.through;
        return { removed: 1 };
    }
}

describe("chaos infrastructure", () => {
    test("INF-01 replays every 32-bit seed deterministically", () => {
        const seeds = [0, 1, 0xffff_ffff];
        const runs = seeds.map((seed) => {
            const random = new SeededRandom(seed);
            return Array.from({ length: 32 }, () => random.nextUint32());
        });
        const replay = seeds.map((seed) => {
            const random = new SeededRandom(seed);
            return Array.from({ length: 32 }, () => random.nextUint32());
        });

        expect(replay).toEqual(runs);
        expect(new Set(runs.map((run) => JSON.stringify(run))).size).toBe(seeds.length);
    });

    test("INF-02 isolates labeled random forks from unrelated actors", () => {
        const first = new SeededRandom(0x1234_5678);
        const firstA = first.fork("A");
        const firstB = first.fork("B");
        const expectedA = Array.from({ length: 8 }, () => firstA.nextUint32());
        const expectedB = Array.from({ length: 8 }, () => firstB.nextUint32());

        const second = new SeededRandom(0x1234_5678);
        const secondA = second.fork("A");
        const unrelated = second.fork("C");
        const secondB = second.fork("B");
        for (let index = 0; index < 100; index += 1) unrelated.nextUint32();

        expect(Array.from({ length: 8 }, () => secondA.nextUint32())).toEqual(expectedA);
        expect(Array.from({ length: 8 }, () => secondB.nextUint32())).toEqual(expectedB);
        expect(expectedA).not.toEqual(expectedB);
    });

    test("INF-03 advances a monotonic virtual clock at exact boundaries", () => {
        const clock = new ManualVirtualClock(1_700_000_000_000);
        clock.advance(0);
        clock.advance(1);
        clock.advance(299_999);
        expect(clock.now()).toBe(1_700_000_300_000);

        expect(() => clock.set(clock.now() - 1)).toThrow("cannot move backward");
        expect(() => clock.advance(-1)).toThrow("non-negative safe integer");
        expect(() => clock.advance(Number.POSITIVE_INFINITY)).toThrow("non-negative safe integer");
        expect(clock.now()).toBe(1_700_000_300_000);
    });

    test("INF-04 rolls a transaction back when its callback-time write response fails", async () => {
        const delegate = new MemoryMurmurStore();
        const schedule = new SeededChaosSchedule(4, [
            {
                id: "fail-second-write",
                selector: {
                    boundary: "store",
                    operation: "transaction.set",
                    phase: "after",
                    key: "b",
                },
                effect: { type: "throw", message: "injected callback failure" },
            },
        ]);
        const store = new FaultInjectingMurmurStore({
            actor: "alice",
            delegate,
            schedule,
        });

        await expect(
            store.tx(ctx, async (transaction) => {
                await store.set(transaction, "a", new Uint8Array([1]));
                await store.set(transaction, "b", new Uint8Array([2]));
            }),
        ).rejects.toThrow("injected callback failure");
        expect(await delegate.get(ctx, "a")).toBeUndefined();
        expect(await delegate.get(ctx, "b")).toBeUndefined();
        schedule.assertConsumed();
    });

    test("INF-05 preserves an atomic commit when only its response is lost", async () => {
        const delegate = new MemoryMurmurStore();
        const schedule = new SeededChaosSchedule(5, [
            {
                id: "lose-commit-response",
                selector: { boundary: "store", operation: "transaction", phase: "after" },
                effect: { type: "throw", message: "injected lost response" },
            },
        ]);
        const store = new FaultInjectingMurmurStore({
            actor: "alice",
            delegate,
            schedule,
        });

        await expect(
            store.tx(ctx, async (transaction) => {
                await store.set(transaction, "a", new Uint8Array([1]));
                await store.set(transaction, "b", new Uint8Array([2]));
            }),
        ).rejects.toThrow("injected lost response");
        expect(await delegate.get(ctx, "a")).toEqual(new Uint8Array([1]));
        expect(await delegate.get(ctx, "b")).toEqual(new Uint8Array([2]));
        schedule.assertConsumed();
    });

    test("INF-06 preserves defensive copies through store faults", async () => {
        const delegate = new MemoryMurmurStore();
        const schedule = new SeededChaosSchedule(6);
        const store = new FaultInjectingMurmurStore({
            actor: "alice",
            delegate,
            schedule,
        });
        const source = new Uint8Array([1, 2, 3]);
        await store.set(ctx, "copy/a", source);
        source[0] = 9;
        const first = await store.get(ctx, "copy/a");
        first![1] = 9;
        const page = await store.scan(ctx, "copy/", { limit: 10 });
        page.get("copy/a")![2] = 9;

        expect(await store.get(ctx, "copy/a")).toEqual(new Uint8Array([1, 2, 3]));
    });

    test("INF-07 rejects a publish before delegate acceptance", async () => {
        const delegate = new RecordingTransport();
        const schedule = new SeededChaosSchedule(7, [
            {
                id: "reject-first-publish",
                selector: {
                    boundary: "transport",
                    operation: "publish",
                    phase: "before",
                    ordinal: 1,
                },
                effect: { type: "throw", message: "injected relay outage" },
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate,
            schedule,
        });
        const input = delivery("delivery-1");

        await expect(transport.publish(ctx, input)).rejects.toThrow("injected relay outage");
        expect(delegate.publishCalls).toBe(0);
        await expect(transport.publish(ctx, input)).resolves.toMatchObject({ duplicate: false });
        expect(delegate.publishCalls).toBe(1);
        schedule.assertConsumed();
    });

    test("INF-08 retries the exact delivery after an accepted response is lost", async () => {
        const delegate = new RecordingTransport();
        const schedule = new SeededChaosSchedule(8, [
            {
                id: "lose-first-publish-response",
                selector: {
                    boundary: "transport",
                    operation: "publish",
                    phase: "after",
                    ordinal: 1,
                },
                effect: { type: "throw", message: "injected lost publish response" },
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate,
            schedule,
        });
        const input = delivery("delivery-1");

        await expect(transport.publish(ctx, input)).rejects.toThrow("lost publish response");
        await expect(transport.publish(ctx, input)).resolves.toMatchObject({ duplicate: true });
        expect(delegate.publishCalls).toBe(2);
        expect(delegate.accepted.size).toBe(1);
        schedule.assertConsumed();
    });

    test("INF-09 deterministically duplicates, reorders, and truncates one page", async () => {
        const delegate = new RecordingTransport();
        delegate.page = {
            deliveries: [
                inboxDelivery("event-1", 1),
                inboxDelivery("event-2", 2),
                inboxDelivery("event-3", 3),
            ],
            head: "event-3",
            acknowledgedThrough: null,
            exhausted: true,
        };
        const schedule = new SeededChaosSchedule(9, [
            {
                id: "mutate-page",
                selector: { boundary: "transport", operation: "read", phase: "after" },
                effect: {
                    type: "sequence",
                    effects: [
                        { type: "duplicate", copies: 1, index: 1 },
                        { type: "reorder", order: "reverse" },
                        { type: "truncate", limit: 2 },
                    ],
                },
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate,
            schedule,
        });

        const page = await transport.read(ctx, readRequest());
        expect(page.deliveries.map((item) => item.eventId)).toEqual(["event-3", "event-2"]);
        expect(page.exhausted).toBe(false);
        expect(delegate.page.deliveries.map((item) => item.eventId)).toEqual([
            "event-1",
            "event-2",
            "event-3",
        ]);
        schedule.assertConsumed();
    });

    test("INF-10 retries an acknowledgement whose accepted response was lost", async () => {
        const delegate = new RecordingTransport();
        const schedule = new SeededChaosSchedule(10, [
            {
                id: "lose-first-ack-response",
                selector: {
                    boundary: "transport",
                    operation: "acknowledge",
                    phase: "after",
                    ordinal: 1,
                },
                effect: { type: "drop" },
            },
        ]);
        const transport = new FaultInjectingDeliveryTransport({
            actor: "bob",
            delegate,
            schedule,
        });

        await expect(transport.acknowledge(ctx, ackRequest("event-3"))).rejects.toBeInstanceOf(
            ChaosInjectedError,
        );
        await expect(transport.acknowledge(ctx, ackRequest("event-3"))).resolves.toEqual({
            removed: 0,
        });
        expect(delegate.acknowledgedThrough).toBe("event-3");
        expect(delegate.acknowledgeCalls).toBe(2);
        schedule.assertConsumed();
    });

    test("INF-11 reports exact rules whose target point was never reached", () => {
        const schedule = new SeededChaosSchedule(11, [
            {
                id: "missing-cut",
                selector: { boundary: "store", operation: "set", key: "never" },
                effect: { type: "crash", message: "unreached crash" },
            },
        ]);
        schedule.decide({
            actor: "alice",
            boundary: "store",
            operation: "get",
            phase: "before",
            ordinal: 1,
            key: "observed",
        });

        expect(() => schedule.assertConsumed()).toThrow(/missing-cut.*alice:store:get:before#1/);
    });

    test("INF-12 keeps secret values and ciphertext out of traces", async () => {
        const secret = new TextEncoder().encode("do-not-leak-this-secret");
        const schedule = new SeededChaosSchedule(12);
        const store = new FaultInjectingMurmurStore({
            actor: "alice",
            delegate: new MemoryMurmurStore(),
            schedule,
        });
        const delegate = new RecordingTransport();
        const transport = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate,
            schedule,
        });
        await store.set(ctx, "murmur/public-test-key", secret);
        await transport.publish(ctx, { ...delivery("public-id"), ciphertext: secret });

        const serialized = JSON.stringify(schedule.trace);
        expect(serialized).not.toContain("do-not-leak-this-secret");
        expect(serialized).not.toContain(JSON.stringify([...secret]));
        expect(serialized).toContain("public-id");
    });

    test("INF-13 settles stable state and bounds an oscillating system", async () => {
        const stable = await settleChaos({
            maximumRounds: 5,
            act: () => undefined,
            snapshot: () => "stable",
        });
        expect(stable).toEqual({ rounds: 2, state: "stable" });

        let value = false;
        await expect(
            settleChaos({
                maximumRounds: 3,
                act: () => {
                    value = !value;
                },
                snapshot: () => value,
            }),
        ).rejects.toThrow("did not settle within 3 rounds");
    });

    test("INF-14 honors aborts before acceptance and during injected delay", async () => {
        const delegate = new RecordingTransport();
        const immediate = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate,
            schedule: new SeededChaosSchedule(14),
        });
        const alreadyAborted = new AbortController();
        alreadyAborted.abort(new Error("stop before publish"));
        await expect(
            immediate.publish(ctx, delivery("aborted-1"), alreadyAborted.signal),
        ).rejects.toThrow("stop before publish");

        const controller = new AbortController();
        const schedule = new SeededChaosSchedule(14, [
            {
                id: "delay-and-abort",
                selector: { boundary: "transport", operation: "publish", phase: "before" },
                effect: { type: "delay", milliseconds: 10 },
            },
        ]);
        const clock = new ManualVirtualClock(1_700_000_000_000);
        const delayed = new FaultInjectingDeliveryTransport({
            actor: "alice",
            delegate,
            schedule,
            delay: (milliseconds) => {
                clock.advance(milliseconds);
                controller.abort(new Error("stop during delay"));
            },
        });
        await expect(
            delayed.publish(ctx, delivery("aborted-2"), controller.signal),
        ).rejects.toThrow("stop during delay");
        expect(clock.now()).toBe(1_700_000_000_010);
        expect(delegate.publishCalls).toBe(0);
        schedule.assertConsumed();
    });
});
