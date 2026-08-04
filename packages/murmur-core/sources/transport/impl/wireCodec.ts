import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { EventPage, RelayTopic, SignedRelayEvent } from "../types.js";

export type RelayTopicJson =
    | { readonly type: "write"; readonly name: string; readonly writeKey: string }
    | { readonly type: "read"; readonly name: string; readonly readKey: string }
    | {
          readonly type: "read-write";
          readonly name: string;
          readonly readKey: string;
          readonly writeKey: string;
      };

export interface SignedRelayEventJson {
    readonly version: 1;
    readonly id: string;
    readonly topic: RelayTopicJson;
    readonly author: { readonly signingKey: string };
    readonly createdAt: number;
    readonly expiresAt?: number;
    readonly collapseKey?: string;
    readonly payload: string;
    readonly signature: string;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function bytes(value: unknown, name: string, length?: number): Uint8Array {
    if (typeof value !== "string") throw new Error(`Invalid ${name}`);
    const decoded = decodeBase64Url(value);
    if (encodeBase64Url(decoded) !== value || (length !== undefined && decoded.length !== length)) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function integer(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

/** Convert a topic to its canonical JSON representation. */
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

function topic(value: unknown): RelayTopic {
    const input = object(value, "topic");
    if (typeof input.name !== "string" || input.name.length < 1 || input.name.length > 128) {
        throw new Error("Invalid topic");
    }
    if (input.type === "write") {
        return {
            type: "write",
            name: input.name,
            writeKey: bytes(input.writeKey, "write key", 32),
        };
    }
    if (input.type === "read") {
        return { type: "read", name: input.name, readKey: bytes(input.readKey, "read key", 32) };
    }
    if (input.type === "read-write") {
        return {
            type: "read-write",
            name: input.name,
            readKey: bytes(input.readKey, "read key", 32),
            writeKey: bytes(input.writeKey, "write key", 32),
        };
    }
    throw new Error("Invalid topic");
}

/** Convert an event to exact relay JSON. */
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

function event(value: unknown): SignedRelayEvent {
    const input = object(value, "relay event");
    const author = object(input.author, "event author");
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(input.id)
    ) {
        throw new Error("Invalid relay event");
    }
    const result: {
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
        id: input.id,
        topic: topic(input.topic),
        author: { signingKey: bytes(author.signingKey, "author key", 32) },
        createdAt: integer(input.createdAt, "created time"),
        payload: bytes(input.payload, "payload"),
        signature: bytes(input.signature, "signature", 64),
    };
    if (input.expiresAt !== undefined) result.expiresAt = integer(input.expiresAt, "expiration");
    if (input.collapseKey !== undefined)
        result.collapseKey = bytes(input.collapseKey, "collapse key");
    return result;
}

/** Encode one signed event as UTF-8 JSON. */
export function encodeSignedRelayEventWire(eventValue: SignedRelayEvent): Uint8Array {
    return utf8Encode(JSON.stringify(signedRelayEventToJson(eventValue)));
}

/** Decode one strictly validated signed event. */
export function decodeSignedRelayEventWire(value: Uint8Array): SignedRelayEvent {
    return event(JSON.parse(utf8Decode(value)) as unknown);
}

/** Decode one event page response. */
export function decodeEventPageWire(value: Uint8Array): EventPage {
    const input = object(JSON.parse(utf8Decode(value)) as unknown, "event page");
    if (
        !Array.isArray(input.events) ||
        typeof input.head !== "string" ||
        typeof input.exhausted !== "boolean"
    ) {
        throw new Error("Invalid event page");
    }
    return {
        events: input.events.map((item) => {
            const retained = object(item, "retained event");
            if (typeof retained.seq !== "string") throw new Error("Invalid event sequence");
            return { seq: BigInt(retained.seq), event: event(retained.event) };
        }),
        head: BigInt(input.head),
        exhausted: input.exhausted,
    };
}
