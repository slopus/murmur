import { createRootContext } from "@steve.kite/stdlib";
import { describe, expect, it } from "vitest";
import { MemoryMurmurStore } from "../index.js";

const ctx = createRootContext().named("test");

describe("MemoryMurmurStore", () => {
    it("rolls a failed transaction back", async () => {
        const store = new MemoryMurmurStore();
        await store.set(ctx, "value", new Uint8Array([1]));

        await expect(
            store.tx(ctx, async (transaction) => {
                await store.set(transaction, "value", new Uint8Array([2]));
                throw new Error("stop");
            }),
        ).rejects.toThrow("stop");

        expect(await store.get(ctx, "value")).toEqual(new Uint8Array([1]));
    });

    it("copies values at the storage boundary", async () => {
        const store = new MemoryMurmurStore();
        const value = new Uint8Array([1]);
        await store.set(ctx, "prefix/value", value);
        value[0] = 9;

        expect(await store.get(ctx, "prefix/value")).toEqual(new Uint8Array([1]));
        expect(await store.list(ctx, "prefix/")).toEqual(
            new Map([["prefix/value", new Uint8Array([1])]]),
        );
    });

    it("scans one bounded lexicographic page", async () => {
        const store = new MemoryMurmurStore();
        await store.set(ctx, "events/0003", new Uint8Array([3]));
        await store.set(ctx, "events/0001", new Uint8Array([1]));
        await store.set(ctx, "other/0000", new Uint8Array([9]));
        await store.set(ctx, "events/0002", new Uint8Array([2]));

        expect(await store.scan(ctx, "events/", { limit: 2 })).toEqual(
            new Map([
                ["events/0001", new Uint8Array([1])],
                ["events/0002", new Uint8Array([2])],
            ]),
        );
        expect(
            await store.scan(ctx, "events/", {
                after: "events/0002",
                limit: 2,
            }),
        ).toEqual(new Map([["events/0003", new Uint8Array([3])]]));
        await expect(store.scan(ctx, "events/", { after: "other/0000", limit: 1 })).rejects.toThrow(
            "Invalid Murmur store scan",
        );
    });

    it("does not roll back a successful write queued behind a failed transaction", async () => {
        const store = new MemoryMurmurStore();
        let releaseTransaction: (() => void) | undefined;
        const transactionGate = new Promise<void>((resolve) => {
            releaseTransaction = resolve;
        });
        const failedTransaction = store.tx(ctx, async (transaction) => {
            await store.set(transaction, "inside", new Uint8Array([1]));
            await transactionGate;
            throw new Error("rollback");
        });
        const concurrentWrite = store.set(ctx, "outside", new Uint8Array([2]));

        releaseTransaction?.();
        await expect(failedTransaction).rejects.toThrow("rollback");
        await concurrentWrite;

        expect(await store.get(ctx, "inside")).toBeUndefined();
        expect(await store.get(ctx, "outside")).toEqual(new Uint8Array([2]));
    });

    it("reuses one transaction context across nested transactions", async () => {
        const store = new MemoryMurmurStore();
        let outerContext: typeof ctx | undefined;

        await expect(
            store.tx(ctx, async (transaction) => {
                outerContext = transaction;
                await store.set(transaction, "outer", new Uint8Array([1]));
                await store.tx(transaction, async (nested) => {
                    expect(nested).toBe(transaction);
                    await store.set(nested, "nested", new Uint8Array([2]));
                });
                throw new Error("rollback nested transaction");
            }),
        ).rejects.toThrow("rollback nested transaction");

        expect(outerContext).toBeDefined();
        expect(await store.get(ctx, "outer")).toBeUndefined();
        expect(await store.get(ctx, "nested")).toBeUndefined();
    });

    it("runs after-commit work after releasing the transaction", async () => {
        const store = new MemoryMurmurStore();
        const order: string[] = [];

        await store.tx(ctx, async (transaction) => {
            await store.set(transaction, "committed", new Uint8Array([1]));
            transaction.afterCommit(async (afterCommitContext) => {
                order.push("after-commit");
                expect(await store.get(afterCommitContext, "committed")).toEqual(
                    new Uint8Array([1]),
                );
                await store.set(afterCommitContext, "follow-up", new Uint8Array([2]));
            });
            order.push("transaction");
        });

        expect(order).toEqual(["transaction", "after-commit"]);
        expect(await store.get(ctx, "follow-up")).toEqual(new Uint8Array([2]));
    });

    it("does not run after-commit work for a rolled-back transaction", async () => {
        const store = new MemoryMurmurStore();
        let called = false;

        await expect(
            store.tx(ctx, async (transaction) => {
                transaction.afterCommit(() => {
                    called = true;
                });
                throw new Error("rollback");
            }),
        ).rejects.toThrow("rollback");

        expect(called).toBe(false);
    });
});
