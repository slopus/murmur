import { expect, test } from "vitest";
import { eventId } from "../../protocol/tests/helpers.js";
import { selectQueuePageMetadata } from "../page.js";

test("queue page selection always returns the first item and respects later byte bounds", () => {
    const candidates = [
        { eventId: eventId(2), encodedBytes: 10_000 },
        { eventId: eventId(5), encodedBytes: 10 },
        { eventId: eventId(9), encodedBytes: 10 },
    ];
    expect(
        selectQueuePageMetadata(candidates, eventId(9), null, null, 3, {
            maximumEncodedBytes: 1,
        }),
    ).toEqual({
        candidates: [candidates[0]],
        head: eventId(9),
        acknowledgedThrough: null,
        exhausted: false,
    });
    expect(
        selectQueuePageMetadata(candidates, eventId(9), null, null, 2, {
            maximumEncodedBytes: 100_000,
        }),
    ).toEqual({
        candidates: candidates.slice(0, 2),
        head: eventId(9),
        acknowledgedThrough: null,
        exhausted: false,
    });
});
