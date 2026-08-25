import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";
import { validateServiceId } from "./serviceId.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_ID_BYTES = 32;
const MAXIMUM_RECORD_BYTES = 1024;
/** Durable namespace containing one owner record per MLS session. */
export const SESSION_OWNER_PREFIX = "murmur/session-owners/v1/";
/** Durable namespace containing one routing marker per inbox event. */
export const SESSION_ROUTING_PREFIX = "murmur/session-routing/v1/";
/** Backward-neutral integration name for the routing marker namespace. */
export const ROUTING_MARKER_PREFIX = SESSION_ROUTING_PREFIX;

/** Durable owner assigned to one MLS session. */
export type SessionOwnerRecord =
    | { readonly version: 1; readonly owner: "ignored" }
    | { readonly version: 1; readonly owner: "contact" }
    | { readonly version: 1; readonly owner: "account" }
    | {
          readonly version: 1;
          readonly owner: "service";
          readonly serviceId: string;
      };

/** Durable marker connecting one routed inbox event to its session. */
export interface SessionRoutingRecord {
    readonly version: 1;
    readonly sessionId: Uint8Array;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function parseCanonical(value: Uint8Array, name: string): Record<string, unknown> {
    if (value.length < 1 || value.length > MAXIMUM_RECORD_BYTES) {
        throw new Error(`Invalid ${name}`);
    }
    let parsed: Record<string, unknown>;
    try {
        parsed = object(JSON.parse(utf8Decode(value)) as unknown, name);
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    const canonical = canonicalJsonBytes(parsed as unknown as JsonValue);
    if (!equalBytes(value, canonical)) {
        throw new Error(`${name} must use canonical JSON`);
    }
    return parsed;
}

function validateSessionId(id: Uint8Array): void {
    if (!(id instanceof Uint8Array) || id.length !== SESSION_ID_BYTES) {
        throw new Error("Invalid Murmur session ID");
    }
}

function validateEventId(eventId: string): void {
    if (!UUID_V7.test(eventId)) {
        throw new Error("Invalid Murmur routing event ID");
    }
}

/** Return the durable owner key for one 32-byte MLS session ID. */
export function sessionOwnerKey(sessionId: Uint8Array): string {
    validateSessionId(sessionId);
    return `${SESSION_OWNER_PREFIX}${encodeBase64Url(sessionId)}`;
}

/** Return the durable routing marker key for one UUIDv7 inbox event. */
export function sessionRoutingKey(eventId: string): string {
    validateEventId(eventId);
    return `${SESSION_ROUTING_PREFIX}${eventId}`;
}

/** Return the durable routing marker key for one UUIDv7 inbox event. */
export const routingMarkerKey = sessionRoutingKey;

/** Encode one strict, versioned session owner record. */
export function encodeSessionOwner(record: SessionOwnerRecord): Uint8Array {
    if (record.version !== 1) {
        throw new Error("Invalid session owner");
    }
    if (record.owner === "service") {
        validateServiceId(record.serviceId);
        return canonicalJsonBytes({
            version: 1,
            owner: "service",
            serviceId: record.serviceId,
        });
    }
    if (record.owner !== "ignored" && record.owner !== "contact" && record.owner !== "account") {
        throw new Error("Invalid session owner");
    }
    return canonicalJsonBytes({ version: 1, owner: record.owner });
}

/** Decode one strict, canonical session owner record. */
export function decodeSessionOwner(value: Uint8Array): SessionOwnerRecord {
    const input = parseCanonical(value, "session owner");
    if (
        input.version !== 1 ||
        (input.owner !== "ignored" &&
            input.owner !== "contact" &&
            input.owner !== "account" &&
            input.owner !== "service")
    ) {
        throw new Error("Invalid session owner");
    }
    if (input.owner === "service") {
        exact(input, ["version", "owner", "serviceId"], "session owner");
        if (typeof input.serviceId !== "string") {
            throw new Error("Invalid session owner");
        }
        validateServiceId(input.serviceId);
        return Object.freeze({
            version: 1,
            owner: "service",
            serviceId: input.serviceId,
        });
    }
    exact(input, ["version", "owner"], "session owner");
    return Object.freeze({ version: 1, owner: input.owner });
}

/** Encode one strict, versioned routed-event marker. */
export function encodeSessionRouting(record: SessionRoutingRecord): Uint8Array {
    if (record.version !== 1) {
        throw new Error("Invalid routing marker");
    }
    validateSessionId(record.sessionId);
    return canonicalJsonBytes({
        version: 1,
        sessionId: encodeBase64Url(record.sessionId),
    });
}

/** Decode one strict, canonical routed-event marker with defensive bytes. */
export function decodeSessionRouting(value: Uint8Array): SessionRoutingRecord {
    const input = parseCanonical(value, "routing marker");
    exact(input, ["version", "sessionId"], "routing marker");
    if (input.version !== 1 || typeof input.sessionId !== "string") {
        throw new Error("Invalid routing marker");
    }
    const sessionId = decodeBase64Url(input.sessionId);
    validateSessionId(sessionId);
    if (encodeBase64Url(sessionId) !== input.sessionId) {
        throw new Error("Invalid routing marker");
    }
    return Object.freeze({ version: 1, sessionId });
}

/** Integration alias for encoding one routed-event marker. */
export const encodeRoutingMarker = encodeSessionRouting;
/** Integration alias for decoding one routed-event marker. */
export const decodeRoutingMarker = decodeSessionRouting;
