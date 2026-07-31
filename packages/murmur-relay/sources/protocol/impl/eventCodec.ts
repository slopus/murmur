import type {
    ListOperation,
    SignedRelayEvent,
    SignedRelayEventJson,
    SnapshotMutation,
} from "../types.js";
import { RelayError } from "../errors.js";
import { decodeBase64Url, encodeBase64Url, isBase64Url } from "../../utils/base64Url.js";

const TOPIC_PATTERN = /^[A-Za-z0-9_.:-]{1,512}$/;
const ELEMENT_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;
const EVENT_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function objectValue(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exactKeys(
    value: Record<string, unknown>,
    required: readonly string[],
    optional: readonly string[],
    name: string,
): void {
    const allowed = new Set([...required, ...optional]);
    if (
        required.some((key) => !Object.hasOwn(value, key)) ||
        Object.keys(value).some((key) => !allowed.has(key))
    ) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function safeInteger(value: unknown, name: string): number {
    if (!Number.isSafeInteger(value) || typeof value !== "number" || value < 0) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function bytesValue(value: unknown, name: string, expectedBytes?: number): Uint8Array {
    if (typeof value !== "string") {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        return decodeBase64Url(value, expectedBytes);
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function parseSnapshot(value: unknown): SnapshotMutation {
    const snapshot = objectValue(value, "snapshot mutation");
    exactKeys(snapshot, ["expectedVersion"], ["bytes"], "snapshot mutation");
    const expectedVersion = safeInteger(snapshot.expectedVersion, "snapshot version");
    if (Object.hasOwn(snapshot, "bytes")) {
        return {
            expectedVersion,
            bytes: bytesValue(snapshot.bytes, "snapshot bytes"),
        };
    }
    return { expectedVersion };
}

function parseListOperation(value: unknown): ListOperation {
    const operation = objectValue(value, "list operation");
    if (operation.op === "append") {
        exactKeys(operation, ["op", "id", "bytes"], [], "append operation");
        if (typeof operation.id !== "string" || !ELEMENT_PATTERN.test(operation.id)) {
            throw new RelayError(400, "Invalid list element id", { error: "malformed" });
        }
        return {
            op: "append",
            id: operation.id,
            bytes: bytesValue(operation.bytes, "list element bytes"),
        };
    }
    if (operation.op === "replace") {
        exactKeys(operation, ["op", "id", "bytes"], ["expectedVersion"], "replace operation");
        if (typeof operation.id !== "string" || !ELEMENT_PATTERN.test(operation.id)) {
            throw new RelayError(400, "Invalid list element id", { error: "malformed" });
        }
        const bytes = bytesValue(operation.bytes, "list element bytes");
        if (Object.hasOwn(operation, "expectedVersion")) {
            return {
                op: "replace",
                id: operation.id,
                expectedVersion: safeInteger(operation.expectedVersion, "list element version"),
                bytes,
            };
        }
        return { op: "replace", id: operation.id, bytes };
    }
    if (operation.op === "delete") {
        exactKeys(operation, ["op", "id"], ["expectedVersion"], "delete operation");
        if (typeof operation.id !== "string" || !ELEMENT_PATTERN.test(operation.id)) {
            throw new RelayError(400, "Invalid list element id", { error: "malformed" });
        }
        if (Object.hasOwn(operation, "expectedVersion")) {
            return {
                op: "delete",
                id: operation.id,
                expectedVersion: safeInteger(operation.expectedVersion, "list element version"),
            };
        }
        return { op: "delete", id: operation.id };
    }
    throw new RelayError(400, "Invalid list operation", { error: "malformed" });
}

/** Return whether a topic identifier is valid at every route and store boundary. */
export function isTopicId(value: string): boolean {
    return TOPIC_PATTERN.test(value);
}

/** Return whether an event identifier is exactly one encoded 32-byte value. */
export function isEventId(value: string): boolean {
    return EVENT_ID_PATTERN.test(value) && isBase64Url(value, 32);
}

/** Return whether an opaque list element identifier is within the protocol alphabet and bound. */
export function isElementId(value: string): boolean {
    return ELEMENT_PATTERN.test(value);
}

/** Strictly decode one signed relay event without applying policy or cryptography. */
export function parseSignedRelayEvent(value: unknown): SignedRelayEvent {
    const event = objectValue(value, "relay event");
    exactKeys(
        event,
        ["version", "id", "topic", "author", "createdAt", "payload", "signature"],
        ["snapshot", "list"],
        "relay event",
    );
    if (event.version !== 1) {
        throw new RelayError(400, "Unsupported relay event version", {
            error: "malformed",
        });
    }
    if (typeof event.id !== "string" || !isEventId(event.id)) {
        throw new RelayError(400, "Invalid event id", { error: "malformed" });
    }
    if (typeof event.topic !== "string" || !TOPIC_PATTERN.test(event.topic)) {
        throw new RelayError(400, "Invalid topic id", { error: "malformed" });
    }
    const author = objectValue(event.author, "event author");
    exactKeys(author, ["signingKey"], [], "event author");
    const parsed: {
        version: 1;
        id: string;
        topic: string;
        author: { signingKey: Uint8Array };
        createdAt: number;
        payload: Uint8Array;
        snapshot?: SnapshotMutation;
        list?: readonly ListOperation[];
        signature: Uint8Array;
    } = {
        version: 1,
        id: event.id,
        topic: event.topic,
        author: {
            signingKey: bytesValue(author.signingKey, "author signing key", 32),
        },
        createdAt: safeInteger(event.createdAt, "event timestamp"),
        payload: bytesValue(event.payload, "event payload"),
        signature: bytesValue(event.signature, "event signature", 64),
    };
    if (Object.hasOwn(event, "snapshot")) {
        parsed.snapshot = parseSnapshot(event.snapshot);
    }
    if (Object.hasOwn(event, "list")) {
        if (!Array.isArray(event.list)) {
            throw new RelayError(400, "Invalid event list", { error: "malformed" });
        }
        parsed.list = event.list.map(parseListOperation);
    }
    return parsed;
}

function snapshotJson(snapshot: SnapshotMutation): {
    readonly expectedVersion: number;
    readonly bytes?: string;
} {
    if (snapshot.bytes === undefined) {
        return { expectedVersion: snapshot.expectedVersion };
    }
    return {
        expectedVersion: snapshot.expectedVersion,
        bytes: encodeBase64Url(snapshot.bytes),
    };
}

type SignedRelayEventListJson = NonNullable<SignedRelayEventJson["list"]>[number];

function operationJson(operation: ListOperation): SignedRelayEventListJson {
    if (operation.op === "append") {
        return {
            op: "append",
            id: operation.id,
            bytes: encodeBase64Url(operation.bytes),
        };
    }
    if (operation.op === "replace") {
        if (operation.expectedVersion === undefined) {
            return {
                op: "replace",
                id: operation.id,
                bytes: encodeBase64Url(operation.bytes),
            };
        }
        return {
            op: "replace",
            id: operation.id,
            expectedVersion: operation.expectedVersion,
            bytes: encodeBase64Url(operation.bytes),
        };
    }
    if (operation.expectedVersion === undefined) {
        return { op: "delete", id: operation.id };
    }
    return {
        op: "delete",
        id: operation.id,
        expectedVersion: operation.expectedVersion,
    };
}

/** Convert an internal event to its exact JSON wire representation. */
export function signedRelayEventToJson(event: SignedRelayEvent): SignedRelayEventJson {
    const encoded: {
        version: 1;
        id: string;
        topic: string;
        author: { signingKey: string };
        createdAt: number;
        payload: string;
        snapshot?: NonNullable<SignedRelayEventJson["snapshot"]>;
        list?: NonNullable<SignedRelayEventJson["list"]>;
        signature: string;
    } = {
        version: 1,
        id: event.id,
        topic: event.topic,
        author: { signingKey: encodeBase64Url(event.author.signingKey) },
        createdAt: event.createdAt,
        payload: encodeBase64Url(event.payload),
        signature: encodeBase64Url(event.signature),
    };
    if (event.snapshot !== undefined) {
        encoded.snapshot = snapshotJson(event.snapshot);
    }
    if (event.list !== undefined) {
        encoded.list = event.list.map(operationJson);
    }
    return encoded;
}

/** Copy an event so no caller retains mutable aliases to stored opaque bytes. */
export function copySignedRelayEvent(event: SignedRelayEvent): SignedRelayEvent {
    return parseSignedRelayEvent(signedRelayEventToJson(event));
}
