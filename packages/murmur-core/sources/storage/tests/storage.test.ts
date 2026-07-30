import { describe, expect, it } from "vitest";
import { MemoryMurmurStore } from "../index.js";

describe("MemoryMurmurStore", () => {
    it("rolls a failed transaction back", async () => {
        const store = new MemoryMurmurStore();
        await store.set("value", new Uint8Array([1]));

        await expect(
            store.transaction(async (transaction) => {
                await transaction.set("value", new Uint8Array([2]));
                throw new Error("stop");
            }),
        ).rejects.toThrow("stop");

        expect(await store.get("value")).toEqual(new Uint8Array([1]));
    });

    it("copies values at the storage boundary", async () => {
        const store = new MemoryMurmurStore();
        const value = new Uint8Array([1]);
        await store.set("prefix/value", value);
        value[0] = 9;

        expect(await store.get("prefix/value")).toEqual(new Uint8Array([1]));
        expect(await store.list("prefix/")).toEqual(
            new Map([["prefix/value", new Uint8Array([1])]]),
        );
    });

    it("does not roll back a successful write queued behind a failed transaction", async () => {
        const store = new MemoryMurmurStore();
        let releaseTransaction: (() => void) | undefined;
        const transactionGate = new Promise<void>((resolve) => {
            releaseTransaction = resolve;
        });
        const failedTransaction = store.transaction(async (transaction) => {
            await transaction.set("inside", new Uint8Array([1]));
            await transactionGate;
            throw new Error("rollback");
        });
        const concurrentWrite = store.set("outside", new Uint8Array([2]));

        releaseTransaction?.();
        await expect(failedTransaction).rejects.toThrow("rollback");
        await concurrentWrite;

        expect(await store.get("inside")).toBeUndefined();
        expect(await store.get("outside")).toEqual(new Uint8Array([2]));
    });
});
