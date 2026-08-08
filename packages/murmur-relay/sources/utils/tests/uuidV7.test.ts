import { expect, test } from "vitest";
import { isUuidV7, nextUuidV7 } from "../uuidV7.js";

test("UUIDv7 event IDs remain strictly monotonic across same-time and rollback calls", () => {
    const first = nextUuidV7(1_000, null);
    const second = nextUuidV7(1_000, first);
    const rollback = nextUuidV7(999, second);
    expect(isUuidV7(first)).toBe(true);
    expect(second > first).toBe(true);
    expect(rollback > second).toBe(true);
});

test("UUIDv7 random overflow carries into the timestamp", () => {
    expect(nextUuidV7(0, "00000000-0001-7fff-bfff-ffffffffffff")).toBe(
        "00000000-0002-7000-8000-000000000000",
    );
});

test("UUIDv7 rejects corrupt state and exhaustion", () => {
    expect(isUuidV7("00000000-0000-4000-8000-000000000000")).toBe(false);
    expect(() => nextUuidV7(0, "not-a-uuid")).toThrow("Stored event ID");
    expect(() => nextUuidV7(0xffff_ffff_ffff, "ffffffff-ffff-7fff-bfff-ffffffffffff")).toThrow(
        "exhausted",
    );
});
