import { signedRelayEventToJson, type SignedRelayEvent } from "../protocol/index.js";
import type { EventPage, PageReadConstraints, RetainedRelayEvent } from "./types.js";

const textEncoder = new TextEncoder();

/** Compact JSON and its exact UTF-8 byte length, persisted identically by every store. */
export function encodeStoredRelayEvent(event: SignedRelayEvent): {
    readonly json: string;
    readonly encodedBytes: number;
} {
    const json = JSON.stringify(signedRelayEventToJson(event));
    return { json, encodedBytes: textEncoder.encode(json).length };
}

/** A retained row plus the persisted compact event JSON byte length. */
export interface StoredPageCandidate extends RetainedRelayEvent {
    readonly encodedBytes: number;
}

/** Optional deterministic accounting hook used by complexity regressions. */
export interface PageSelectionInstrumentation {
    readonly candidateEncoded: () => void;
}

function encodedEmptyPageBytes(head: bigint, exhausted: boolean): number {
    return textEncoder.encode(
        `{"events":[],"head":"${head.toString()}","exhausted":${exhausted.toString()}}`,
    ).length;
}

function encodedCandidateBytes(
    retained: StoredPageCandidate,
    index: number,
    instrumentation: PageSelectionInstrumentation | undefined,
): number {
    const metadataBytes = textEncoder.encode(`{"seq":"${retained.seq.toString()}","event":`).length;
    instrumentation?.candidateEncoded();
    return (index === 0 ? 0 : 1) + metadataBytes + retained.encodedBytes + 1;
}

/**
 * Materialize a page from no more than `limit + 1` retained candidates.
 *
 * The first retained event is always returned so a small configured budget
 * cannot permanently strand a large valid event. Later events must fit the
 * exact compact HTTP response byte budget.
 */
export function selectEventPage(
    candidates: readonly StoredPageCandidate[],
    head: bigint,
    limit: number,
    constraints: PageReadConstraints,
    instrumentation?: PageSelectionInstrumentation,
): EventPage {
    if (candidates.length === 0) {
        return { events: [], head, exhausted: true };
    }
    const available = candidates.slice(0, limit);
    let exhaustedBytes = encodedEmptyPageBytes(head, true);
    let continuedBytes = encodedEmptyPageBytes(head, false);
    let selectedCount = 1;
    for (const [index, retained] of available.entries()) {
        const encodedBytes = encodedCandidateBytes(retained, index, instrumentation);
        exhaustedBytes += encodedBytes;
        continuedBytes += encodedBytes;
        if (index > 0 && continuedBytes <= constraints.maximumEncodedBytes) {
            selectedCount = index + 1;
        }
    }
    if (
        candidates.length <= limit &&
        (available.length === 1 || exhaustedBytes <= constraints.maximumEncodedBytes)
    ) {
        return { events: available, head, exhausted: true };
    }
    return {
        events: available.slice(0, selectedCount),
        head,
        exhausted: false,
    };
}
