import type { VirtualClock } from "../types.js";

function timestamp(value: number, label: string): number {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${label} must be a non-negative safe integer`);
    }
    return value;
}

/** Monotonic synchronous clock for deterministic expiry and retry tests. */
export class ManualVirtualClock implements VirtualClock {
    #timestamp: number;

    constructor(initialTimestamp: number) {
        this.#timestamp = timestamp(initialTimestamp, "Initial virtual timestamp");
        this.now = this.now.bind(this);
    }

    /** Return the current virtual Unix time in milliseconds. */
    now(): number {
        return this.#timestamp;
    }

    /** Advance virtual time without scheduling a real timer. */
    advance(milliseconds: number): void {
        const amount = timestamp(milliseconds, "Virtual clock advance");
        const next = this.#timestamp + amount;
        if (!Number.isSafeInteger(next)) {
            throw new Error("Virtual timestamp exceeds the safe integer range");
        }
        this.#timestamp = next;
    }

    /** Move to an equal or later explicit timestamp. */
    set(value: number): void {
        const next = timestamp(value, "Virtual timestamp");
        if (next < this.#timestamp) {
            throw new Error("Virtual clock cannot move backward");
        }
        this.#timestamp = next;
    }
}
