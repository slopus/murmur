import { validateIdentityPublicKey } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";
import type { MurmurContactProfile } from "../types.js";
import { validateContactProfile } from "./contactCodec.js";

export const CONTACT_IDENTITY_PREFIX = "murmur/contacts/v1/by-identity/";
export const CONTACT_SESSION_PREFIX = "murmur/contacts/v1/by-session/";
export const CONTACT_HANDSHAKE_PREFIX = "murmur/contacts/v1/handshakes/";
export const CONTACT_EVENT_PREFIX = "murmur/contacts/v1/events/";

const DELIVERY_ID = /^[A-Za-z0-9_-]{32}$/;
const EVENT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAXIMUM_RECORD_BYTES = 96 * 1024;

export interface ContactRecord {
    readonly version: 1;
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly localProfile: MurmurContactProfile;
    readonly profile: MurmurContactProfile;
    readonly status: "active" | "removing";
    readonly confirmedAt: number;
    readonly removeDeliveryId?: string;
}

export interface ContactHandshakeRecord {
    readonly version: 1;
    readonly direction: "incoming" | "outgoing";
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly localProfile?: MurmurContactProfile;
    readonly remoteProfile?: MurmurContactProfile;
    readonly localHelloDeliveryId?: string;
    readonly localHelloProcessed: boolean;
    readonly remoteHelloProcessed: boolean;
    readonly requestEventId?: string;
    readonly createdAt: number;
}

export type ContactEventRecord =
    | {
          readonly version: 1;
          readonly type: "requested";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
          readonly profile: MurmurContactProfile;
      }
    | {
          readonly version: 1;
          readonly type: "added";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
          readonly localProfile: MurmurContactProfile;
          readonly profile: MurmurContactProfile;
      }
    | {
          readonly version: 1;
          readonly type: "removed";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
      };

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

function parse(value: Uint8Array, name: string): Record<string, unknown> {
    if (value.length < 1 || value.length > MAXIMUM_RECORD_BYTES) {
        throw new Error(`Invalid ${name}`);
    }
    let input: Record<string, unknown>;
    try {
        input = object(JSON.parse(utf8Decode(value)) as unknown, name);
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    let canonical: Uint8Array;
    try {
        canonical = canonicalJsonBytes(input as unknown as JsonValue);
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    if (!equalBytes(canonical, value)) {
        throw new Error(`Non-canonical ${name}`);
    }
    return input;
}

function bytes(value: unknown, minimum: number, maximum: number, name: string): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximum * 4) / 3)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (
        decoded.length < minimum ||
        decoded.length > maximum ||
        encodeBase64Url(decoded) !== value
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function timestamp(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function optionalDeliveryId(value: unknown, name: string): string | undefined {
    if (value === null) {
        return undefined;
    }
    if (typeof value !== "string" || !DELIVERY_ID.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function optionalEventId(value: unknown, name: string): string | undefined {
    if (value === null) {
        return undefined;
    }
    if (typeof value !== "string" || !EVENT_ID.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function eventId(value: unknown, name: string): string {
    const result = optionalEventId(value, name);
    if (result === undefined) {
        throw new Error(`Invalid ${name}`);
    }
    return result;
}

function profileJson(profile: MurmurContactProfile): JsonValue {
    return validateContactProfile(profile) as unknown as JsonValue;
}

function nullableProfile(value: unknown): MurmurContactProfile | undefined {
    return value === null ? undefined : validateContactProfile(value);
}

function keyBytes(value: Uint8Array, minimum: number, maximum: number, name: string): string {
    if (value.length < minimum || value.length > maximum) {
        throw new Error(`Invalid ${name}`);
    }
    return encodeBase64Url(value);
}

function identityBytes(value: unknown, name: string): Uint8Array {
    const identity = bytes(value, 32, 32, name);
    validateIdentityPublicKey({ publicKey: identity });
    return identity;
}

function identityKeyBytes(value: Uint8Array, name: string): string {
    if (value.length !== 32) {
        throw new Error(`Invalid ${name}`);
    }
    validateIdentityPublicKey({ publicKey: value });
    return encodeBase64Url(value);
}

/** Return the durable contact lookup key for a peer identity. */
export function contactIdentityKey(identity: Uint8Array): string {
    return `${CONTACT_IDENTITY_PREFIX}${identityKeyBytes(identity, "contact identity")}`;
}

/** Return the durable contact lookup key for a technical session. */
export function contactSessionKey(sessionId: Uint8Array): string {
    return `${CONTACT_SESSION_PREFIX}${keyBytes(sessionId, 32, 32, "contact session")}`;
}

/** Return the durable handshake key for a technical session. */
export function contactHandshakeKey(sessionId: Uint8Array): string {
    return `${CONTACT_HANDSHAKE_PREFIX}${keyBytes(sessionId, 32, 32, "contact session")}`;
}

/** Return the durable lifecycle-event key for a stable event identifier. */
export function contactEventKey(id: string): string {
    if (!EVENT_ID.test(id)) {
        throw new Error("Invalid contact event identifier");
    }
    return `${CONTACT_EVENT_PREFIX}${id}`;
}

/** Encode one confirmed contact record. */
export function encodeContactRecord(record: ContactRecord): Uint8Array {
    if (
        record.version !== 1 ||
        (record.status !== "active" && record.status !== "removing") ||
        !Number.isSafeInteger(record.confirmedAt) ||
        record.confirmedAt < 0 ||
        (record.removeDeliveryId !== undefined && !DELIVERY_ID.test(record.removeDeliveryId))
    ) {
        throw new Error("Invalid contact record");
    }
    return canonicalJsonBytes({
        version: 1,
        identity: identityKeyBytes(record.identity, "contact identity"),
        sessionId: keyBytes(record.sessionId, 32, 32, "contact session"),
        localProfile: profileJson(record.localProfile),
        profile: profileJson(record.profile),
        status: record.status,
        confirmedAt: record.confirmedAt,
        removeDeliveryId: record.removeDeliveryId ?? null,
    });
}

/** Decode one strict confirmed contact record. */
export function decodeContactRecord(value: Uint8Array): ContactRecord {
    const input = parse(value, "contact record");
    exact(
        input,
        [
            "version",
            "identity",
            "sessionId",
            "localProfile",
            "profile",
            "status",
            "confirmedAt",
            "removeDeliveryId",
        ],
        "contact record",
    );
    if (input.version !== 1 || (input.status !== "active" && input.status !== "removing")) {
        throw new Error("Invalid contact record");
    }
    const removeDeliveryId = optionalDeliveryId(input.removeDeliveryId, "contact removal delivery");
    return {
        version: 1,
        identity: identityBytes(input.identity, "contact identity"),
        sessionId: bytes(input.sessionId, 32, 32, "contact session"),
        localProfile: validateContactProfile(input.localProfile),
        profile: validateContactProfile(input.profile),
        status: input.status,
        confirmedAt: timestamp(input.confirmedAt, "contact confirmation time"),
        ...(removeDeliveryId === undefined ? {} : { removeDeliveryId }),
    };
}

/** Encode one in-progress contact handshake. */
export function encodeContactHandshakeRecord(record: ContactHandshakeRecord): Uint8Array {
    if (
        record.version !== 1 ||
        (record.direction !== "incoming" && record.direction !== "outgoing") ||
        (record.localHelloDeliveryId !== undefined &&
            !DELIVERY_ID.test(record.localHelloDeliveryId)) ||
        (record.requestEventId !== undefined && !EVENT_ID.test(record.requestEventId)) ||
        !Number.isSafeInteger(record.createdAt) ||
        record.createdAt < 0
    ) {
        throw new Error("Invalid contact handshake");
    }
    return canonicalJsonBytes({
        version: 1,
        direction: record.direction,
        identity: identityKeyBytes(record.identity, "contact identity"),
        sessionId: keyBytes(record.sessionId, 32, 32, "contact session"),
        localProfile: record.localProfile === undefined ? null : profileJson(record.localProfile),
        remoteProfile:
            record.remoteProfile === undefined ? null : profileJson(record.remoteProfile),
        localHelloDeliveryId: record.localHelloDeliveryId ?? null,
        localHelloProcessed: record.localHelloProcessed,
        remoteHelloProcessed: record.remoteHelloProcessed,
        requestEventId: record.requestEventId ?? null,
        createdAt: record.createdAt,
    });
}

/** Decode one strict in-progress contact handshake. */
export function decodeContactHandshakeRecord(value: Uint8Array): ContactHandshakeRecord {
    const input = parse(value, "contact handshake");
    exact(
        input,
        [
            "version",
            "direction",
            "identity",
            "sessionId",
            "localProfile",
            "remoteProfile",
            "localHelloDeliveryId",
            "localHelloProcessed",
            "remoteHelloProcessed",
            "requestEventId",
            "createdAt",
        ],
        "contact handshake",
    );
    if (
        input.version !== 1 ||
        (input.direction !== "incoming" && input.direction !== "outgoing") ||
        typeof input.localHelloProcessed !== "boolean" ||
        typeof input.remoteHelloProcessed !== "boolean"
    ) {
        throw new Error("Invalid contact handshake");
    }
    const localProfile = nullableProfile(input.localProfile);
    const remoteProfile = nullableProfile(input.remoteProfile);
    const localHelloDeliveryId = optionalDeliveryId(
        input.localHelloDeliveryId,
        "contact hello delivery",
    );
    const requestEventId = optionalEventId(input.requestEventId, "contact request event");
    return {
        version: 1,
        direction: input.direction,
        identity: identityBytes(input.identity, "contact identity"),
        sessionId: bytes(input.sessionId, 32, 32, "contact session"),
        ...(localProfile === undefined ? {} : { localProfile }),
        ...(remoteProfile === undefined ? {} : { remoteProfile }),
        ...(localHelloDeliveryId === undefined ? {} : { localHelloDeliveryId }),
        localHelloProcessed: input.localHelloProcessed,
        remoteHelloProcessed: input.remoteHelloProcessed,
        ...(requestEventId === undefined ? {} : { requestEventId }),
        createdAt: timestamp(input.createdAt, "contact handshake creation time"),
    };
}

/** Encode one durable contact lifecycle callback record. */
export function encodeContactEventRecord(record: ContactEventRecord): Uint8Array {
    if (record.version !== 1 || !EVENT_ID.test(record.id)) {
        throw new Error("Invalid contact event");
    }
    const common = {
        version: 1,
        type: record.type,
        id: record.id,
        identity: identityKeyBytes(record.identity, "contact identity"),
        sessionId: keyBytes(record.sessionId, 32, 32, "contact session"),
    };
    if (record.type === "requested") {
        return canonicalJsonBytes({
            ...common,
            profile: profileJson(record.profile),
        });
    }
    if (record.type === "added") {
        return canonicalJsonBytes({
            ...common,
            localProfile: profileJson(record.localProfile),
            profile: profileJson(record.profile),
        });
    }
    return canonicalJsonBytes(common);
}

/** Decode one strict durable contact lifecycle callback record. */
export function decodeContactEventRecord(value: Uint8Array): ContactEventRecord {
    const input = parse(value, "contact event");
    if (input.type === "requested") {
        exact(
            input,
            ["version", "type", "id", "identity", "sessionId", "profile"],
            "contact request event",
        );
        if (input.version !== 1) {
            throw new Error("Invalid contact request event");
        }
        return {
            version: 1,
            type: "requested",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
            profile: validateContactProfile(input.profile),
        };
    }
    if (input.type === "added") {
        exact(
            input,
            ["version", "type", "id", "identity", "sessionId", "localProfile", "profile"],
            "contact added event",
        );
        if (input.version !== 1) {
            throw new Error("Invalid contact added event");
        }
        return {
            version: 1,
            type: "added",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
            localProfile: validateContactProfile(input.localProfile),
            profile: validateContactProfile(input.profile),
        };
    }
    if (input.type === "removed") {
        exact(input, ["version", "type", "id", "identity", "sessionId"], "contact removed event");
        if (input.version !== 1) {
            throw new Error("Invalid contact removed event");
        }
        return {
            version: 1,
            type: "removed",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
        };
    }
    throw new Error("Invalid contact event");
}
