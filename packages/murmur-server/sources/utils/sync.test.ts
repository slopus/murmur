import { describe, it, expect, vi } from "vitest";
import { InvalidateSync } from "./sync";

describe("InvalidateSync", () => {
    it("should execute handler when invalidated", async () => {
        const handler = vi.fn(async () => {});
        const sync = new InvalidateSync(handler);

        sync.invalidate();
        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(handler).toHaveBeenCalledTimes(1);
    });

    it("should not execute multiple times for concurrent invalidations", async () => {
        let executionCount = 0;
        const handler = vi.fn(async () => {
            executionCount++;
            await new Promise((resolve) => setTimeout(resolve, 50));
        });

        const sync = new InvalidateSync(handler);

        // Invalidate multiple times while handler is executing
        sync.invalidate();
        sync.invalidate();
        sync.invalidate();

        await new Promise((resolve) => setTimeout(resolve, 200));

        // Should execute once immediately, then once more for the invalidations during execution
        expect(executionCount).toBe(2);
    });

    it("should handle handler errors gracefully", async () => {
        const handler = vi.fn(async () => {
            throw new Error("Test error");
        });

        const sync = new InvalidateSync(handler);

        sync.invalidate();
        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(handler).toHaveBeenCalledTimes(1);
        // Should not throw
    });

    it("should support invalidateAndAwait", async () => {
        let executed = false;
        const handler = vi.fn(async () => {
            await new Promise((resolve) => setTimeout(resolve, 50));
            executed = true;
        });

        const sync = new InvalidateSync(handler);

        await sync.invalidateAndAwait();

        expect(executed).toBe(true);
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it("should stop accepting invalidations after stop", async () => {
        const handler = vi.fn(async () => {});
        const sync = new InvalidateSync(handler);

        sync.stop();
        sync.invalidate();
        await new Promise((resolve) => setTimeout(resolve, 10));

        expect(handler).toHaveBeenCalledTimes(0);
    });
});
