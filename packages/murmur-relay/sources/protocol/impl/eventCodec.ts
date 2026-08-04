import type {
    RelayTopic,
    RelayTopicJson,
    SignedRelayEvent,
    SignedRelayEventJson,
} from "../types.js";
import { RelayError } from "../errors.js";
import { decodeBase64Url, encodeBase64Url, isBase64Url } from "../../utils/base64Url.js";

const NAME_PATTERN = /^[\x20-\x7e]{1,128}$/;
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
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
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

/** Strictly decode one topic descriptor. */
export function parseRelayTopic(value: unknown): RelayTopic {
    const topic = objectValue(value, "topic");
    if (typeof topic.name !== "string" || !NAME_PATTERN.test(topic.name)) {
        throw new RelayError(400, "Invalid topic name", { error: "malformed" });
    }
    if (topic.type === "write") {
        exactKeys(topic, ["type", "name", "writeKey"], [], "topic");
        return {
            type: "write",
            name: topic.name,
            writeKey: bytesValue(topic.writeKey, "write key", 32),
        };
    }
    if (topic.type === "read") {
        exactKeys(topic, ["type", "name", "readKey"], [], "topic");
        return {
            type: "read",
            name: topic.name,
            readKey: bytesValue(topic.readKey, "read key", 32),
        };
    }
    if (topic.type === "read-write") {
        exactKeys(topic, ["type", "name", "readKey", "writeKey"], [], "topic");
        return {
            type: "read-write",
            name: topic.name,
            readKey: bytesValue(topic.readKey, "read key", 32),
            writeKey: bytesValue(topic.writeKey, "write key", 32),
        };
    }
    throw new RelayError(400, "Invalid topic type", { error: "malformed" });
}

/** Convert a topic descriptor to its canonical JSON representation. */
export function relayTopicToJson(topic: RelayTopic): RelayTopicJson {
    if (topic.type === "write") {
        return { type: topic.type, name: topic.name, writeKey: encodeBase64Url(topic.writeKey) };
    }
    if (topic.type === "read") {
        return { type: topic.type, name: topic.name, readKey: encodeBase64Url(topic.readKey) };
    }
    return {
        type: topic.type,
        name: topic.name,
        readKey: encodeBase64Url(topic.readKey),
        writeKey: encodeBase64Url(topic.writeKey),
    };
}

/** Return whether an event identifier encodes exactly 32 bytes. */
export function isEventId(value: string): boolean {
    return EVENT_ID_PATTERN.test(value) && isBase64Url(value, 32);
}

/** Strictly decode one signed relay event without applying policy or cryptography. */
export function parseSignedRelayEvent(value: unknown): SignedRelayEvent {
    const event = objectValue(value, "relay event");
    exactKeys(
        event,
        ["version", "id", "topic", "author", "createdAt", "payload", "signature"],
        ["expiresAt", "collapseKey"],
        "relay event",
    );
    if (event.version !== 1 || typeof event.id !== "string" || !isEventId(event.id)) {
        throw new RelayError(400, "Invalid relay event", { error: "malformed" });
    }
    const author = objectValue(event.author, "event author");
    exactKeys(author, ["signingKey"], [], "event author");
    const parsed: {
        version: 1;
        id: string;
        topic: RelayTopic;
        author: { signingKey: Uint8Array };
        createdAt: number;
        expiresAt?: number;
        collapseKey?: Uint8Array;
        payload: Uint8Array;
        signature: Uint8Array;
    } = {
        version: 1,
        id: event.id,
        topic: parseRelayTopic(event.topic),
        author: { signingKey: bytesValue(author.signingKey, "author signing key", 32) },
        createdAt: safeInteger(event.createdAt, "event timestamp"),
        payload: bytesValue(event.payload, "event payload"),
        signature: bytesValue(event.signature, "event signature", 64),
    };
    if (Object.hasOwn(event, "expiresAt")) {
        parsed.expiresAt = safeInteger(event.expiresAt, "event expiration");
    }
    if (Object.hasOwn(event, "collapseKey")) {
        parsed.collapseKey = bytesValue(event.collapseKey, "collapse key");
    }
    return parsed;
}

/** Convert an internal event to its exact JSON wire representation. */
export function signedRelayEventToJson(event: SignedRelayEvent): SignedRelayEventJson {
    return {
        version: 1,
        id: event.id,
        topic: relayTopicToJson(event.topic),
        author: { signingKey: encodeBase64Url(event.author.signingKey) },
        createdAt: event.createdAt,
        ...(event.expiresAt === undefined ? {} : { expiresAt: event.expiresAt }),
        ...(event.collapseKey === undefined
            ? {}
            : { collapseKey: encodeBase64Url(event.collapseKey) }),
        payload: encodeBase64Url(event.payload),
        signature: encodeBase64Url(event.signature),
    };
}

/** Deep-copy an event at a trust boundary. */
export function copySignedRelayEvent(event: SignedRelayEvent): SignedRelayEvent {
    return parseSignedRelayEvent(signedRelayEventToJson(event));
}
