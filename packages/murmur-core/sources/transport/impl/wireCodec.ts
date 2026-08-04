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

const TOPIC_NAME = /^[\x20-\x7e]{1,128}$/;
const MAXIMUM_SEQUENCE = 9_223_372_036_854_775_807n;
const DECIMAL_SEQUENCE = /^(0|[1-9]\d*)$/;

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(
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
        throw new Error(`Invalid ${name}`);
    }
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

function sequence(value: unknown, name: string, minimum: bigint): bigint {
    if (typeof value !== "string" || value.length > 19 || !DECIMAL_SEQUENCE.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const parsed = BigInt(value);
    if (parsed < minimum || parsed > MAXIMUM_SEQUENCE) {
        throw new Error(`Invalid ${name}`);
    }
    return parsed;
}

/** Convert a topic to its canonical JSON representation. */
export function relayTopicToJson(topic: RelayTopic): RelayTopicJson {
    validateRelayTopic(topic);
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

/** Strictly validate an in-memory relay topic descriptor. */
export function validateRelayTopic(topicValue: RelayTopic): void {
    const input = object(topicValue, "topic");
    if (typeof topicValue.name !== "string" || !TOPIC_NAME.test(topicValue.name)) {
        throw new Error("Invalid topic name");
    }
    if (topicValue.type === "write") {
        exact(input, ["type", "name", "writeKey"], [], "topic");
        if (!(topicValue.writeKey instanceof Uint8Array) || topicValue.writeKey.length !== 32) {
            throw new Error("Invalid write key");
        }
        return;
    }
    if (topicValue.type === "read") {
        exact(input, ["type", "name", "readKey"], [], "topic");
        if (!(topicValue.readKey instanceof Uint8Array) || topicValue.readKey.length !== 32) {
            throw new Error("Invalid read key");
        }
        return;
    }
    if (topicValue.type === "read-write") {
        exact(input, ["type", "name", "readKey", "writeKey"], [], "topic");
        if (
            !(topicValue.readKey instanceof Uint8Array) ||
            topicValue.readKey.length !== 32 ||
            !(topicValue.writeKey instanceof Uint8Array) ||
            topicValue.writeKey.length !== 32
        ) {
            throw new Error("Invalid topic keys");
        }
        return;
    }
    throw new Error("Invalid topic type");
}

function topic(value: unknown): RelayTopic {
    const input = object(value, "topic");
    if (typeof input.name !== "string" || !TOPIC_NAME.test(input.name)) {
        throw new Error("Invalid topic");
    }
    if (input.type === "write") {
        exact(input, ["type", "name", "writeKey"], [], "topic");
        const parsed: RelayTopic = {
            type: "write",
            name: input.name,
            writeKey: bytes(input.writeKey, "write key", 32),
        };
        validateRelayTopic(parsed);
        return parsed;
    }
    if (input.type === "read") {
        exact(input, ["type", "name", "readKey"], [], "topic");
        const parsed: RelayTopic = {
            type: "read",
            name: input.name,
            readKey: bytes(input.readKey, "read key", 32),
        };
        validateRelayTopic(parsed);
        return parsed;
    }
    if (input.type === "read-write") {
        exact(input, ["type", "name", "readKey", "writeKey"], [], "topic");
        const parsed: RelayTopic = {
            type: "read-write",
            name: input.name,
            readKey: bytes(input.readKey, "read key", 32),
            writeKey: bytes(input.writeKey, "write key", 32),
        };
        validateRelayTopic(parsed);
        return parsed;
    }
    throw new Error("Invalid topic");
}

/** Convert an event to exact relay JSON. */
export function signedRelayEventToJson(event: SignedRelayEvent): SignedRelayEventJson {
    const value = object(event, "relay event");
    exact(
        value,
        ["version", "id", "topic", "author", "createdAt", "payload", "signature"],
        ["expiresAt", "collapseKey"],
        "relay event",
    );
    const author = object(event.author, "event author");
    exact(author, ["signingKey"], [], "event author");
    validateRelayTopic(event.topic);
    if (
        event.version !== 1 ||
        bytes(event.id, "event id", 32).length !== 32 ||
        !(event.author.signingKey instanceof Uint8Array) ||
        event.author.signingKey.length !== 32 ||
        !Number.isSafeInteger(event.createdAt) ||
        event.createdAt < 0 ||
        !(event.payload instanceof Uint8Array) ||
        !(event.signature instanceof Uint8Array) ||
        event.signature.length !== 64
    ) {
        throw new Error("Invalid relay event");
    }
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
    exact(
        input,
        ["version", "id", "topic", "author", "createdAt", "payload", "signature"],
        ["expiresAt", "collapseKey"],
        "relay event",
    );
    const author = object(input.author, "event author");
    exact(author, ["signingKey"], [], "event author");
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
    exact(input, ["events", "head", "exhausted"], [], "event page");
    if (
        !Array.isArray(input.events) ||
        typeof input.head !== "string" ||
        typeof input.exhausted !== "boolean"
    ) {
        throw new Error("Invalid event page");
    }
    const head = sequence(input.head, "event page head", 0n);
    return {
        events: input.events.map((item) => {
            const retained = object(item, "retained event");
            exact(retained, ["seq", "event"], [], "retained event");
            const seq = sequence(retained.seq, "event sequence", 1n);
            return { seq, event: event(retained.event) };
        }),
        head,
        exhausted: input.exhausted,
    };
}
