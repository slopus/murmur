import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SqliteMurmurStore } from "../index.js";

describe("SqliteMurmurStore", () => {
    it("copies values and persists them across reopening", async () => {
        const directory = mkdtempSync(join(tmpdir(), "murmur-cli-store-"));
        const path = join(directory, "client.sqlite");
        try {
            const first = new SqliteMurmurStore(path);
            expect(statSync(path).mode & 0o077).toBe(0);
            const value = new Uint8Array([1, 2, 3]);
            await first.set("key", value);
            value.fill(9);
            const read = await first.get("key");
            read?.fill(8);
            expect(await first.get("key")).toEqual(new Uint8Array([1, 2, 3]));
            await first.close();

            const second = new SqliteMurmurStore(path);
            expect(await second.get("key")).toEqual(new Uint8Array([1, 2, 3]));
            await second.close();
        } finally {
            rmSync(directory, { recursive: true, force: true });
        }
    });

    it("rolls back all values when an async transaction fails", async () => {
        const store = new SqliteMurmurStore(":memory:");
        await store.set("before", new Uint8Array([1]));

        await expect(
            store.transaction(async (transaction) => {
                await transaction.set("before", new Uint8Array([2]));
                await transaction.set("created", new Uint8Array([3]));
                throw new Error("rollback");
            }),
        ).rejects.toThrow("rollback");

        expect(await store.get("before")).toEqual(new Uint8Array([1]));
        expect(await store.get("created")).toBeUndefined();
        await store.close();
    });
});
