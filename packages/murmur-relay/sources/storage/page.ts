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
    readonly encodedBytes: number;
}

/** Selected queue metadata and transaction state ready for exact hydration. */
export interface StoredPageSelection {
    readonly candidates: readonly StoredPageCandidate[];
    readonly head: string | null;
    readonly acknowledgedThrough: string | null;
    readonly exhausted: boolean;
}

function encodedEmptyPageBytes(
    head: string | null,
    acknowledgedThrough: string | null,
    exhausted: boolean,
): number {
    return textEncoder.encode(
        `{"deliveries":[],"head":${head === null ? "null" : `"${head}"`},"acknowledgedThrough":${acknowledgedThrough === null ? "null" : `"${acknowledgedThrough}"`},"exhausted":${exhausted.toString()}}`,
    ).length;
}

function encodedCandidateBytes(candidate: StoredPageCandidate, index: number): number {
    const metadataBytes = textEncoder.encode(
        `{"eventId":"${candidate.eventId}","delivery":`,
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
    acknowledgedThrough: string | null,
    after: string | null,
    limit: number,
    constraints: PageReadConstraints,
): StoredPageSelection {
    if (candidates.length === 0) {
        return {
            candidates: [],
            head: after,
            acknowledgedThrough,
            exhausted: true,
        };
    }
    const available = candidates.slice(0, limit);
    let exhaustedBytes = encodedEmptyPageBytes(head, acknowledgedThrough, true);
    let continuedBytes = encodedEmptyPageBytes(head, acknowledgedThrough, false);
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
            acknowledgedThrough,
            exhausted: true,
        };
    }
    return {
        candidates: available.slice(0, selectedCount),
        head,
        acknowledgedThrough,
        exhausted: false,
    };
}
