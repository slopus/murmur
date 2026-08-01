import { describe, expect, it } from "vitest";
import { InMemoryTokenBucketRateLimiter } from "../index.js";

describe("InMemoryTokenBucketRateLimiter", () => {
    it("allows a burst, denies over limit, and reports refill time", async () => {
        const limiter = new InMemoryTokenBucketRateLimiter({
            capacity: 2,
            refillTokensPerSecond: 1,
            maximumBuckets: 10,
        });

        await expect(limiter.consume("ip:a", 1, 0)).resolves.toEqual({
            allowed: true,
            retryAfterMilliseconds: 0,
        });
        await expect(limiter.consume("ip:a", 1, 0)).resolves.toEqual({
            allowed: true,
            retryAfterMilliseconds: 0,
        });
        await expect(limiter.consume("ip:a", 1, 0)).resolves.toEqual({
            allowed: false,
            retryAfterMilliseconds: 1_000,
        });
        await expect(limiter.consume("ip:a", 1, 1_000)).resolves.toEqual({
            allowed: true,
            retryAfterMilliseconds: 0,
        });
    });

    it("keeps keys independent", async () => {
        const limiter = new InMemoryTokenBucketRateLimiter({
            capacity: 1,
            refillTokensPerSecond: 1,
            maximumBuckets: 10,
        });
        await expect(limiter.consume("ip:a", 1, 0)).resolves.toMatchObject({ allowed: true });
        await expect(limiter.consume("ip:a", 1, 0)).resolves.toMatchObject({ allowed: false });
        await expect(limiter.consume("author:a", 1, 0)).resolves.toMatchObject({
            allowed: true,
        });
    });

    it("evicts least-recently-used buckets at a strict bound", async () => {
        const limiter = new InMemoryTokenBucketRateLimiter({
            capacity: 1,
            refillTokensPerSecond: 1,
            maximumBuckets: 3,
        });
        for (let index = 0; index < 100; index += 1) {
            await limiter.consume(`fake:${index.toString()}`, 1, 0);
            expect(limiter.bucketCount).toBeLessThanOrEqual(3);
        }
        expect(limiter.bucketCount).toBe(3);
    });
});
