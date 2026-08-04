import { describe, expect, test } from "vitest";
import type { SignedRelayEvent } from "../../protocol/index.js";
import { selectEventPage, type StoredPageCandidate } from "../page.js";

const event: SignedRelayEvent = {
    version: 1,
    id: "A".repeat(43),
    topic: {
        type: "write",
        name: "linear-page",
        writeKey: new Uint8Array(32),
    },
    author: { signingKey: new Uint8Array(32) },
    createdAt: 0,
    payload: new Uint8Array(),
    signature: new Uint8Array(64),
};

function selectionWork(limit: number): {
    readonly candidateEncodings: number;
    readonly selected: number;
    readonly exhausted: boolean;
} {
    const candidates: StoredPageCandidate[] = Array.from({ length: limit + 1 }, (_, index) => ({
        seq: BigInt(index + 1),
        event,
        encodedBytes: 512,
    }));
    let candidateEncodings = 0;
    const page = selectEventPage(
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
        selected: page.events.length,
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
