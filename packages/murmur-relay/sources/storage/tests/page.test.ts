import { expect, test } from "vitest";
import { eventId } from "../../protocol/tests/helpers.js";
import { selectQueuePageMetadata } from "../page.js";

test("queue page selection always returns the first item and respects later byte bounds", () => {
    const candidates = [
        { eventId: eventId(2), sequence: 1, encodedBytes: 10_000 },
        { eventId: eventId(5), sequence: 2, encodedBytes: 10 },
        { eventId: eventId(9), sequence: 3, encodedBytes: 10 },
    ];
    const generation = new Uint8Array(32);
    expect(
        selectQueuePageMetadata(candidates, eventId(9), 3, null, 0, generation, null, 3, {
            maximumEncodedBytes: 1,
        }),
    ).toEqual({
        candidates: [candidates[0]],
        head: eventId(9),
        headSequence: 3,
        acknowledgedThrough: null,
        acknowledgedSequence: 0,
        generation,
        exhausted: false,
    });
    expect(
        selectQueuePageMetadata(candidates, eventId(9), 3, null, 0, generation, null, 2, {
            maximumEncodedBytes: 100_000,
        }),
    ).toEqual({
        candidates: candidates.slice(0, 2),
        head: eventId(9),
        headSequence: 3,
        acknowledgedThrough: null,
        acknowledgedSequence: 0,
        generation,
        exhausted: false,
    });
});
