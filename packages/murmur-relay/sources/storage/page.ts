import { signedDeliveryToJson, type SignedDelivery } from "../protocol/index.js";
import type { PageReadConstraints } from "./types.js";

const textEncoder = new TextEncoder();

/** Compact delivery JSON and its exact UTF-8 byte length. */
export function encodeStoredDelivery(delivery: SignedDelivery): {
    readonly json: string;
    readonly encodedBytes: number;
} {
    const json = JSON.stringify(signedDeliveryToJson(delivery));
    return { json, encodedBytes: textEncoder.encode(json).length };
}

/** Bounded queue-row metadata selected before delivery JSON hydration. */
export interface StoredPageCandidate {
    readonly eventId: string;
    readonly sequence: number;
    readonly encodedBytes: number;
}

/** Selected queue metadata and transaction state ready for exact hydration. */
export interface StoredPageSelection {
    readonly candidates: readonly StoredPageCandidate[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;
    readonly exhausted: boolean;
}

function encodedEmptyPageBytes(
    head: string | null,
    headSequence: number,
    acknowledgedThrough: string | null,
    acknowledgedSequence: number,
    exhausted: boolean,
): number {
    return textEncoder.encode(
        `{"deliveries":[],"head":${head === null ? "null" : `"${head}"`},"headSequence":${headSequence},"acknowledgedThrough":${acknowledgedThrough === null ? "null" : `"${acknowledgedThrough}"`},"acknowledgedSequence":${acknowledgedSequence},"generation":"${"A".repeat(43)}","exhausted":${exhausted.toString()}}`,
    ).length;
}

function encodedCandidateBytes(candidate: StoredPageCandidate, index: number): number {
    const metadataBytes = textEncoder.encode(
        `{"eventId":"${candidate.eventId}","sequence":${candidate.sequence},"delivery":`,
    ).length;
    return (index === 0 ? 0 : 1) + metadataBytes + candidate.encodedBytes + 1;
}

/**
 * Select no more than `limit` queue references from `limit + 1` metadata rows.
 *
 * The first valid delivery is always returned even when it alone exceeds the
 * response budget. The HTTP boundary independently rejects a configured budget
 * too small for one maximum-sized delivery.
 */
export function selectQueuePageMetadata(
    candidates: readonly StoredPageCandidate[],
    head: string | null,
    headSequence: number,
    acknowledgedThrough: string | null,
    acknowledgedSequence: number,
    generation: Uint8Array,
    after: string | null,
    limit: number,
    constraints: PageReadConstraints,
): StoredPageSelection {
    if (candidates.length === 0) {
        return {
            candidates: [],
            head,
            headSequence,
            acknowledgedThrough,
            acknowledgedSequence,
            generation,
            exhausted: true,
        };
    }
    const available = candidates.slice(0, limit);
    let exhaustedBytes = encodedEmptyPageBytes(
        head,
        headSequence,
        acknowledgedThrough,
        acknowledgedSequence,
        true,
    );
    let continuedBytes = encodedEmptyPageBytes(
        head,
        headSequence,
        acknowledgedThrough,
        acknowledgedSequence,
        false,
    );
    let selectedCount = 1;
    for (const [index, candidate] of available.entries()) {
        const encodedBytes = encodedCandidateBytes(candidate, index);
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
        return {
            candidates: available,
            head,
            headSequence,
            acknowledgedThrough,
            acknowledgedSequence,
            generation,
            exhausted: true,
        };
    }
    return {
        candidates: available.slice(0, selectedCount),
        head,
        headSequence,
        acknowledgedThrough,
        acknowledgedSequence,
        generation,
        exhausted: false,
    };
}
