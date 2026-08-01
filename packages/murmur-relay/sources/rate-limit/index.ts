import type { RateLimitDecision, RateLimiter } from "./types.js";

interface Bucket {
    readonly tokens: number;
    readonly updatedAt: number;
}

/** Construction options for a bounded in-process token-bucket limiter. */
export interface InMemoryTokenBucketOptions {
    readonly capacity: number;
    readonly refillTokensPerSecond: number;
    readonly maximumBuckets: number;
}

function positiveFinite(value: number, name: string): number {
    if (!Number.isFinite(value) || value <= 0) {
        throw new Error(`${name} must be a positive finite number`);
    }
    return value;
}

/**
 * Bounded least-recently-used map of in-memory token buckets.
 *
 * This implementation deliberately exposes the generic `RateLimiter`
 * interface so a shared durable limiter can replace it at the HTTP boundary.
 */
export class InMemoryTokenBucketRateLimiter implements RateLimiter {
    readonly #capacity: number;
    readonly #refillTokensPerMillisecond: number;
    readonly #maximumBuckets: number;
    readonly #buckets = new Map<string, Bucket>();

    constructor(options: InMemoryTokenBucketOptions) {
        this.#capacity = positiveFinite(options.capacity, "Token bucket capacity");
        this.#refillTokensPerMillisecond =
            positiveFinite(options.refillTokensPerSecond, "Token bucket refill rate") / 1_000;
        if (!Number.isSafeInteger(options.maximumBuckets) || options.maximumBuckets < 1) {
            throw new Error("Maximum token buckets must be a positive safe integer");
        }
        this.#maximumBuckets = options.maximumBuckets;
    }

    /** Current bucket count, exposed for operational diagnostics and bound tests. */
    get bucketCount(): number {
        return this.#buckets.size;
    }

    /** Consume one cost from a key's bucket without allowing the map to grow unbounded. */
    async consume(key: string, cost: number, now: number): Promise<RateLimitDecision> {
        if (key.length === 0) {
            throw new Error("Rate-limit key cannot be empty");
        }
        positiveFinite(cost, "Rate-limit cost");
        if (cost > this.#capacity) {
            throw new Error("Rate-limit cost cannot exceed bucket capacity");
        }
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Rate-limit time must be a non-negative safe integer");
        }

        const existing = this.#buckets.get(key);
        const updatedAt = existing === undefined ? now : Math.max(now, existing.updatedAt);
        const elapsed = existing === undefined ? 0 : updatedAt - existing.updatedAt;
        const tokens =
            existing === undefined
                ? this.#capacity
                : Math.min(
                      this.#capacity,
                      existing.tokens + elapsed * this.#refillTokensPerMillisecond,
                  );
        if (existing !== undefined) {
            this.#buckets.delete(key);
        } else if (this.#buckets.size >= this.#maximumBuckets) {
            const oldestKey = this.#buckets.keys().next().value;
            if (typeof oldestKey === "string") {
                this.#buckets.delete(oldestKey);
            }
        }

        if (tokens >= cost) {
            this.#buckets.set(key, { tokens: tokens - cost, updatedAt });
            return { allowed: true, retryAfterMilliseconds: 0 };
        }
        this.#buckets.set(key, { tokens, updatedAt });
        return {
            allowed: false,
            retryAfterMilliseconds: Math.max(
                1,
                Math.ceil((cost - tokens) / this.#refillTokensPerMillisecond),
            ),
        };
    }
}

export type { RateLimitDecision, RateLimiter } from "./types.js";
