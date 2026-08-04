import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

/** Durable state for one locally-authored friend request. */
export interface OutgoingRequestTracker {
    readonly state: "pending" | "retired" | "answered";
    readonly previousRequestId: string | null;
}

const MAX_TRACKER_BYTES = 128;

function validateRequestId(id: string): void {
    if (id.length !== 32) {
        throw new Error("Invalid outgoing friend request tracker");
    }
    const bytes = decodeBase64Url(id);
    if (bytes.length !== 24 || encodeBase64Url(bytes) !== id) {
        throw new Error("Invalid outgoing friend request tracker");
    }
}

/** Encode a strict outgoing-request tracker with its signed causal edge. */
export function encodeOutgoingRequestTracker(tracker: OutgoingRequestTracker): Uint8Array {
    if (
        tracker.state !== "pending" &&
        tracker.state !== "retired" &&
        tracker.state !== "answered"
    ) {
        throw new Error("Invalid outgoing friend request tracker");
    }
    if (tracker.previousRequestId !== null) {
        validateRequestId(tracker.previousRequestId);
    }
    return utf8Encode(
        JSON.stringify({
            version: 1,
            state: tracker.state,
            previousRequestId: tracker.previousRequestId,
        }),
    );
}

/** Decode a bounded, exact outgoing-request tracker. */
export function decodeOutgoingRequestTracker(bytes: Uint8Array): OutgoingRequestTracker {
    if (bytes.length > MAX_TRACKER_BYTES) {
        throw new Error("Invalid outgoing friend request tracker");
    }
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (
        typeof decoded !== "object" ||
        decoded === null ||
        Array.isArray(decoded) ||
        Object.keys(decoded).length !== 3 ||
        !("version" in decoded) ||
        decoded.version !== 1 ||
        !("state" in decoded) ||
        (decoded.state !== "pending" &&
            decoded.state !== "retired" &&
            decoded.state !== "answered") ||
        !("previousRequestId" in decoded) ||
        (decoded.previousRequestId !== null && typeof decoded.previousRequestId !== "string")
    ) {
        throw new Error("Invalid outgoing friend request tracker");
    }
    if (typeof decoded.previousRequestId === "string") {
        validateRequestId(decoded.previousRequestId);
    }
    return {
        state: decoded.state,
        previousRequestId: decoded.previousRequestId,
    };
}
