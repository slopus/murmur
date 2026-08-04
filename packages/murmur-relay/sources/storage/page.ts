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

function encodedPageBytes(
    events: readonly StoredPageCandidate[],
    head: bigint,
    exhausted: boolean,
): number {
    let bytes = textEncoder.encode(
        `{"events":[],"head":"${head.toString()}","exhausted":${exhausted.toString()}}`,
    ).length;
    for (const [index, retained] of events.entries()) {
        bytes +=
            (index === 0 ? 0 : 1) +
            textEncoder.encode(`{"seq":"${retained.seq.toString()}","event":`).length +
            retained.encodedBytes +
            1;
    }
    return bytes;
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
): EventPage {
    if (candidates.length === 0) {
        return { events: [], head, exhausted: true };
    }
    const available = candidates.slice(0, limit);
    if (
        candidates.length <= limit &&
        (available.length === 1 ||
            encodedPageBytes(available, head, true) <= constraints.maximumEncodedBytes)
    ) {
        return { events: available, head, exhausted: true };
    }
    let selectedCount = 1;
    while (
        selectedCount < available.length &&
        encodedPageBytes(available.slice(0, selectedCount + 1), head, false) <=
            constraints.maximumEncodedBytes
    ) {
        selectedCount += 1;
    }
    return {
        events: available.slice(0, selectedCount),
        head,
        exhausted: false,
    };
}
