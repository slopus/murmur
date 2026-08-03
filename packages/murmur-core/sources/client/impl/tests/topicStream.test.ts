import { describe, expect, it } from "vitest";
import { backoffDelay } from "../topicStream.js";

const SAMPLES = 200;

function samples(attempt: number): number[] {
    return Array.from({ length: SAMPLES }, () => backoffDelay(attempt));
}

describe("reconnect backoff", () => {
    it("jitters the first attempt instead of returning one fixed delay", () => {
        const distinct = new Set(samples(0));

        // Every relay reaches attempt 0 together after a blip; a constant here
        // is exactly the lockstep retry the jitter exists to prevent.
        expect(distinct.size).toBeGreaterThan(1);
        for (const delay of distinct) {
            expect(delay).toBeGreaterThanOrEqual(250);
            expect(delay).toBeLessThan(500);
        }
    });

    it("grows the window with each attempt and saturates at the ceiling", () => {
        for (const delay of samples(1)) {
            expect(delay).toBeGreaterThanOrEqual(500);
            expect(delay).toBeLessThan(1_000);
        }
        for (const delay of samples(6)) {
            expect(delay).toBeGreaterThanOrEqual(7_500);
            expect(delay).toBeLessThanOrEqual(15_000);
        }
    });

    it("stays inside the fixed bounds for every attempt, however extreme", () => {
        const attempts = [-1, 0, 1, 5, 40, 1_000, Number.MAX_SAFE_INTEGER];
        for (const attempt of attempts) {
            for (const delay of samples(attempt)) {
                expect(Number.isFinite(delay)).toBe(true);
                expect(delay).toBeGreaterThanOrEqual(250);
                expect(delay).toBeLessThanOrEqual(15_000);
            }
        }
    });
});
