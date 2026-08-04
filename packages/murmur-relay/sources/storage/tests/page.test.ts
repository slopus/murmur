import { describe, expect, test } from "vitest";
import { selectEventPageMetadata, type StoredPageCandidate } from "../page.js";

function selectionWork(limit: number): {
    readonly candidateEncodings: number;
    readonly selected: number;
    readonly exhausted: boolean;
} {
    const candidates: StoredPageCandidate[] = Array.from({ length: limit + 1 }, (_, index) => ({
        seq: BigInt(index + 1),
        encodedBytes: 512,
    }));
    let candidateEncodings = 0;
    const page = selectEventPageMetadata(
        candidates,
        BigInt(candidates.length),
        limit,
        { maximumEncodedBytes: Number.MAX_SAFE_INTEGER },
        {
            candidateEncoded: () => {
                candidateEncodings += 1;
            },
        },
    );
    return {
        candidateEncodings,
        selected: page.candidates.length,
        exhausted: page.exhausted,
    };
}

describe("event page selection", () => {
    test("accounts each selectable candidate once as the page limit grows", () => {
        const small = selectionWork(1_024);
        const large = selectionWork(4_096);

        expect(small).toEqual({
            candidateEncodings: 1_024,
            selected: 1_024,
            exhausted: false,
        });
        expect(large).toEqual({
            candidateEncodings: 4_096,
            selected: 4_096,
            exhausted: false,
        });
        expect(large.candidateEncodings / small.candidateEncodings).toBe(4);
    });
});
