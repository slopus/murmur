import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type {
    EventPage,
    ListElement,
    ListOperation,
    ListPage,
    PublishOutcome,
    SignedRelayEvent,
    SnapshotMutation,
    TopicSnapshot,
    TopicState,
} from "../types.js";

interface SignedRelayEventJson {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly author: { readonly signingKey: string };
    readonly createdAt: number;
    readonly payload: string;
    readonly snapshot?: { readonly expectedVersion: number; readonly bytes?: string };
    readonly list?: readonly (
        | { readonly op: "append"; readonly id: string; readonly bytes: string }
        | {
              readonly op: "replace";
              readonly id: string;
              readonly expectedVersion?: number;
              readonly bytes: string;
          }
        | { readonly op: "delete"; readonly id: string; readonly expectedVersion?: number }
    )[];
    readonly signature: string;
}

const MAXIMUM_PAGE_WIRE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_EVENT_WIRE_BYTES = 8 * 1024 * 1024;
const TOPIC_PATTERN = /^[A-Za-z0-9_.:-]{1,512}$/;
const ELEMENT_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;
const EVENT_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function object(value: unknown, name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exactFields(
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

function stringField(value: Record<string, unknown>, key: string): string {
    const field = value[key];
    if (typeof field !== "string") {
        throw new Error(`Invalid ${key}`);
    }
    return field;
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function decimalBigint(value: unknown, name: string): bigint {
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return BigInt(value);
}

function canonicalBytes(value: unknown, name: string, length?: number): Uint8Array {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (encodeBase64Url(decoded) !== value || (length !== undefined && decoded.length !== length)) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function snapshotFromUnknown(value: unknown): SnapshotMutation {
    const snapshot = object(value, "snapshot mutation");
    exactFields(snapshot, ["expectedVersion"], ["bytes"], "snapshot mutation");
    const expectedVersion = safeInteger(snapshot.expectedVersion, "snapshot version");
    return Object.hasOwn(snapshot, "bytes")
        ? {
              expectedVersion,
              bytes: canonicalBytes(snapshot.bytes, "snapshot bytes"),
          }
        : { expectedVersion };
}

function operationFromUnknown(value: unknown): ListOperation {
    const operation = object(value, "list operation");
    const id = stringField(operation, "id");
    if (!ELEMENT_PATTERN.test(id)) {
        throw new Error("Invalid list element id");
    }
    if (operation.op === "append") {
        exactFields(operation, ["op", "id", "bytes"], [], "append operation");
        return {
            op: "append",
            id,
            bytes: canonicalBytes(operation.bytes, "list element bytes"),
        };
    }
    if (operation.op === "replace") {
        exactFields(operation, ["op", "id", "bytes"], ["expectedVersion"], "replace operation");
        const common = {
            op: "replace" as const,
            id,
            bytes: canonicalBytes(operation.bytes, "list element bytes"),
        };
        return Object.hasOwn(operation, "expectedVersion")
            ? {
                  ...common,
                  expectedVersion: safeInteger(operation.expectedVersion, "list element version"),
              }
            : common;
    }
    if (operation.op === "delete") {
        exactFields(operation, ["op", "id"], ["expectedVersion"], "delete operation");
        const common = { op: "delete" as const, id };
        return Object.hasOwn(operation, "expectedVersion")
            ? {
                  ...common,
                  expectedVersion: safeInteger(operation.expectedVersion, "list element version"),
              }
            : common;
    }
    throw new Error("Invalid list operation");
}

function eventFromUnknown(value: unknown): SignedRelayEvent {
    const event = object(value, "relay event");
    exactFields(
        event,
        ["version", "id", "topic", "author", "createdAt", "payload", "signature"],
        ["snapshot", "list"],
        "relay event",
    );
    const id = stringField(event, "id");
    const topic = stringField(event, "topic");
    const author = object(event.author, "event author");
    exactFields(author, ["signingKey"], [], "event author");
    if (
        event.version !== 1 ||
        !EVENT_ID_PATTERN.test(id) ||
        canonicalBytes(id, "event id", 32).length !== 32 ||
        !TOPIC_PATTERN.test(topic)
    ) {
        throw new Error("Invalid relay event");
    }
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
        id,
        topic,
        author: { signingKey: canonicalBytes(author.signingKey, "author signing key", 32) },
        createdAt: safeInteger(event.createdAt, "event timestamp"),
        payload: canonicalBytes(event.payload, "event payload"),
        signature: canonicalBytes(event.signature, "event signature", 64),
    };
    if (Object.hasOwn(event, "snapshot")) {
        parsed.snapshot = snapshotFromUnknown(event.snapshot);
    }
    if (Object.hasOwn(event, "list")) {
        if (!Array.isArray(event.list)) {
            throw new Error("Invalid event list");
        }
        parsed.list = event.list.map(operationFromUnknown);
    }
    return parsed;
}

function operationJson(
    operation: ListOperation,
): NonNullable<SignedRelayEventJson["list"]>[number] {
    if (operation.op === "append") {
        return { op: "append", id: operation.id, bytes: encodeBase64Url(operation.bytes) };
    }
    if (operation.op === "replace") {
        return {
            op: "replace",
            id: operation.id,
            ...(operation.expectedVersion === undefined
                ? {}
                : { expectedVersion: operation.expectedVersion }),
            bytes: encodeBase64Url(operation.bytes),
        };
    }
    return {
        op: "delete",
        id: operation.id,
        ...(operation.expectedVersion === undefined
            ? {}
            : { expectedVersion: operation.expectedVersion }),
    };
}

/** Convert an internal event to the relay's exact JSON representation. */
export function signedRelayEventToJson(event: SignedRelayEvent): SignedRelayEventJson {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        author: { signingKey: encodeBase64Url(event.author.signingKey) },
        createdAt: event.createdAt,
        payload: encodeBase64Url(event.payload),
        ...(event.snapshot === undefined
            ? {}
            : {
                  snapshot: {
                      expectedVersion: event.snapshot.expectedVersion,
                      ...(event.snapshot.bytes === undefined
                          ? {}
                          : { bytes: encodeBase64Url(event.snapshot.bytes) }),
                  },
              }),
        ...(event.list === undefined ? {} : { list: event.list.map(operationJson) }),
        signature: encodeBase64Url(event.signature),
    };
}

/** Encode one signed event as UTF-8 JSON for an HTTP relay. */
export function encodeSignedRelayEventWire(event: SignedRelayEvent): Uint8Array {
    return utf8Encode(JSON.stringify(signedRelayEventToJson(event)));
}

/** Decode and strictly validate one signed event from UTF-8 JSON. */
export function decodeSignedRelayEventWire(bytes: Uint8Array): SignedRelayEvent {
    if (bytes.length > MAXIMUM_EVENT_WIRE_BYTES) {
        throw new Error("Relay event wire payload is too large");
    }
    return eventFromUnknown(JSON.parse(utf8Decode(bytes)));
}

function parseWire(bytes: Uint8Array): unknown {
    if (bytes.length > MAXIMUM_PAGE_WIRE_BYTES) {
        throw new Error("Relay response is too large");
    }
    return JSON.parse(utf8Decode(bytes)) as unknown;
}

function listElementFromUnknown(value: unknown): ListElement {
    const element = object(value, "list element");
    exactFields(element, ["id", "version", "bytes"], [], "list element");
    const id = stringField(element, "id");
    if (!ELEMENT_PATTERN.test(id)) {
        throw new Error("Invalid list element");
    }
    return {
        id,
        version: decimalBigint(element.version, "list element version"),
        bytes: canonicalBytes(element.bytes, "list element bytes"),
    };
}

function listPageFromUnknown(value: unknown): ListPage {
    const page = object(value, "list page");
    exactFields(page, ["elements", "nextCursor"], [], "list page");
    if (
        !Array.isArray(page.elements) ||
        (page.nextCursor !== null && typeof page.nextCursor !== "string")
    ) {
        throw new Error("Invalid list page");
    }
    return {
        elements: page.elements.map(listElementFromUnknown),
        nextCursor: page.nextCursor,
    };
}

/** Decode a relay list page. */
export function decodeListPageWire(bytes: Uint8Array): ListPage {
    return listPageFromUnknown(parseWire(bytes));
}

/** Decode a relay topic state response. */
export function decodeTopicStateWire(bytes: Uint8Array): TopicState {
    const state = object(parseWire(bytes), "topic state");
    exactFields(state, ["seq", "snapshot", "list"], [], "topic state");
    let snapshot: TopicSnapshot | null = null;
    if (state.snapshot !== null) {
        const value = object(state.snapshot, "topic snapshot");
        exactFields(value, ["version", "bytes"], [], "topic snapshot");
        snapshot = {
            version: decimalBigint(value.version, "snapshot version"),
            bytes: canonicalBytes(value.bytes, "snapshot bytes"),
        };
    }
    return {
        seq: decimalBigint(state.seq, "topic sequence"),
        snapshot,
        list: listPageFromUnknown(state.list),
    };
}

/** Decode a retained-event page, including its mandatory reset flag. */
export function decodeEventPageWire(bytes: Uint8Array): EventPage {
    const page = object(parseWire(bytes), "event page");
    exactFields(page, ["events", "reset", "seq"], [], "event page");
    if (!Array.isArray(page.events) || typeof page.reset !== "boolean") {
        throw new Error("Invalid event page");
    }
    return {
        events: page.events.map((value) => {
            const retained = object(value, "retained relay event");
            const { seq, ...event } = retained;
            return {
                seq: decimalBigint(seq, "retained event sequence"),
                event: eventFromUnknown(event),
            };
        }),
        reset: page.reset,
        seq: decimalBigint(page.seq, "topic sequence"),
    };
}

/** Decode an idempotent publish outcome. */
export function decodePublishOutcomeWire(bytes: Uint8Array): PublishOutcome {
    const outcome = object(parseWire(bytes), "publish outcome");
    exactFields(outcome, ["seq", "duplicate"], ["snapshotVersion"], "publish outcome");
    if (typeof outcome.duplicate !== "boolean") {
        throw new Error("Invalid publish outcome");
    }
    return {
        seq: decimalBigint(outcome.seq, "publish sequence"),
        duplicate: outcome.duplicate,
        ...(Object.hasOwn(outcome, "snapshotVersion")
            ? {
                  snapshotVersion: decimalBigint(outcome.snapshotVersion, "snapshot version"),
              }
            : {}),
    };
}
