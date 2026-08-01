/** Result of consuming tokens from one rate-limit bucket. */
export interface RateLimitDecision {
    readonly allowed: boolean;
    readonly retryAfterMilliseconds: number;
}

/** Replaceable asynchronous boundary for per-key request admission. */
export interface RateLimiter {
    consume(key: string, cost: number, now: number): Promise<RateLimitDecision>;
}
