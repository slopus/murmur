import { validateIdentityPublicKey } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";
import type { MurmurContactAdmission, MurmurContactProfile } from "../types.js";
import { validateContactAdmission, validateContactProfile } from "./contactCodec.js";

export const CONTACT_IDENTITY_PREFIX = "murmur/contacts/v2/by-identity/";
export const CONTACT_SESSION_PREFIX = "murmur/contacts/v2/by-session/";
export const CONTACT_HANDSHAKE_PREFIX = "murmur/contacts/v2/handshakes/";
export const CONTACT_EVENT_PREFIX = "murmur/contacts/v2/events/";
export const CONTACT_LOCAL_PROFILE_KEY = "murmur/contacts/v2/local-profile";

const DELIVERY_ID = /^[A-Za-z0-9_-]{32}$/;
const EVENT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAXIMUM_RECORD_BYTES = 96 * 1024;

export interface ContactRecord {
    readonly version: 2;
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly localProfile: MurmurContactProfile;
    readonly profile: MurmurContactProfile;
    readonly localProfileRevision: number;
    readonly remoteProfileRevision: number;
    readonly status: "active" | "removing";
    readonly confirmedAt: number;
    readonly removeDeliveryId?: string;
    readonly localAdmissionGeneration: number;
    readonly remoteAdmission: MurmurContactAdmission;
    readonly refillNeeded: boolean;
    readonly refillRequestDeliveryId?: string;
    readonly supplyRequestEventId?: string;
}

export interface ContactHandshakeRecord {
    readonly version: 2;
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
    readonly localAdmission?: MurmurContactAdmission;
    readonly remoteAdmission?: MurmurContactAdmission;
}

export interface ContactLocalProfileRecord {
    readonly version: 1;
    readonly revision: number;
    readonly profile: MurmurContactProfile;
}

export type ContactEventRecord =
    | {
          readonly version: 2;
          readonly type: "requested";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
          readonly profile: MurmurContactProfile;
      }
    | {
          readonly version: 2;
          readonly type: "added";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
          readonly localProfile: MurmurContactProfile;
          readonly profile: MurmurContactProfile;
      }
    | {
          readonly version: 2;
          readonly type: "removed";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
      }
    | {
          readonly version: 2;
          readonly type: "updated";
          readonly id: string;
          readonly identity: Uint8Array;
          readonly sessionId: Uint8Array;
          readonly localProfile: MurmurContactProfile;
          readonly profile: MurmurContactProfile;
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

function admissionJson(admission: MurmurContactAdmission): JsonValue {
    const value = validateContactAdmission(admission);
    return {
        generation: value.generation,
        oneTimeKeyPackages: value.oneTimeKeyPackages.map(encodeBase64Url),
        lastResortKeyPackage: encodeBase64Url(value.lastResortKeyPackage),
    };
}

function nullableAdmission(value: unknown): MurmurContactAdmission | undefined {
    return value === null ? undefined : validateContactAdmission(value);
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
        record.version !== 2 ||
        (record.status !== "active" && record.status !== "removing") ||
        !Number.isSafeInteger(record.confirmedAt) ||
        record.confirmedAt < 0 ||
        !Number.isSafeInteger(record.localProfileRevision) ||
        record.localProfileRevision < 0 ||
        !Number.isSafeInteger(record.remoteProfileRevision) ||
        record.remoteProfileRevision < 0 ||
        (record.removeDeliveryId !== undefined && !DELIVERY_ID.test(record.removeDeliveryId)) ||
        !Number.isSafeInteger(record.localAdmissionGeneration) ||
        record.localAdmissionGeneration < 1 ||
        typeof record.refillNeeded !== "boolean" ||
        (record.refillRequestDeliveryId !== undefined &&
            !DELIVERY_ID.test(record.refillRequestDeliveryId)) ||
        (record.supplyRequestEventId !== undefined && !EVENT_ID.test(record.supplyRequestEventId))
    ) {
        throw new Error("Invalid contact record");
    }
    return canonicalJsonBytes({
        version: 2,
        identity: identityKeyBytes(record.identity, "contact identity"),
        sessionId: keyBytes(record.sessionId, 32, 32, "contact session"),
        localProfile: profileJson(record.localProfile),
        profile: profileJson(record.profile),
        localProfileRevision: record.localProfileRevision,
        remoteProfileRevision: record.remoteProfileRevision,
        status: record.status,
        confirmedAt: record.confirmedAt,
        removeDeliveryId: record.removeDeliveryId ?? null,
        localAdmissionGeneration: record.localAdmissionGeneration,
        remoteAdmission: admissionJson(record.remoteAdmission),
        refillNeeded: record.refillNeeded,
        refillRequestDeliveryId: record.refillRequestDeliveryId ?? null,
        supplyRequestEventId: record.supplyRequestEventId ?? null,
    });
}

/** Decode one strict confirmed contact record. */
export function decodeContactRecord(value: Uint8Array): ContactRecord {
    const input = parse(value, "contact record");
    const hasProfileRevisions =
        Object.hasOwn(input, "localProfileRevision") ||
        Object.hasOwn(input, "remoteProfileRevision");
    exact(
        input,
        [
            "version",
            "identity",
            "sessionId",
            "localProfile",
            "profile",
            ...(hasProfileRevisions ? ["localProfileRevision", "remoteProfileRevision"] : []),
            "status",
            "confirmedAt",
            "removeDeliveryId",
            "localAdmissionGeneration",
            "remoteAdmission",
            "refillNeeded",
            "refillRequestDeliveryId",
            "supplyRequestEventId",
        ],
        "contact record",
    );
    if (
        input.version !== 2 ||
        (input.status !== "active" && input.status !== "removing") ||
        typeof input.refillNeeded !== "boolean"
    ) {
        throw new Error("Invalid contact record");
    }
    const removeDeliveryId = optionalDeliveryId(input.removeDeliveryId, "contact removal delivery");
    const refillRequestDeliveryId = optionalDeliveryId(
        input.refillRequestDeliveryId,
        "contact refill request delivery",
    );
    const supplyRequestEventId = optionalEventId(
        input.supplyRequestEventId,
        "contact supply request event",
    );
    const localAdmissionGeneration = timestamp(
        input.localAdmissionGeneration,
        "local contact admission generation",
    );
    if (localAdmissionGeneration < 1) {
        throw new Error("Invalid local contact admission generation");
    }
    return {
        version: 2,
        identity: identityBytes(input.identity, "contact identity"),
        sessionId: bytes(input.sessionId, 32, 32, "contact session"),
        localProfile: validateContactProfile(input.localProfile),
        profile: validateContactProfile(input.profile),
        localProfileRevision: hasProfileRevisions
            ? timestamp(input.localProfileRevision, "local contact profile revision")
            : 0,
        remoteProfileRevision: hasProfileRevisions
            ? timestamp(input.remoteProfileRevision, "remote contact profile revision")
            : 0,
        status: input.status,
        confirmedAt: timestamp(input.confirmedAt, "contact confirmation time"),
        ...(removeDeliveryId === undefined ? {} : { removeDeliveryId }),
        localAdmissionGeneration,
        remoteAdmission: validateContactAdmission(input.remoteAdmission),
        refillNeeded: input.refillNeeded,
        ...(refillRequestDeliveryId === undefined ? {} : { refillRequestDeliveryId }),
        ...(supplyRequestEventId === undefined ? {} : { supplyRequestEventId }),
    };
}

/** Encode the identity-wide local profile and its monotonic publication revision. */
export function encodeContactLocalProfileRecord(record: ContactLocalProfileRecord): Uint8Array {
    if (record.version !== 1 || !Number.isSafeInteger(record.revision) || record.revision < 1) {
        throw new Error("Invalid local contact profile record");
    }
    return canonicalJsonBytes({
        version: 1,
        revision: record.revision,
        profile: profileJson(record.profile),
    });
}

/** Decode the identity-wide local profile publication record. */
export function decodeContactLocalProfileRecord(value: Uint8Array): ContactLocalProfileRecord {
    const input = parse(value, "local contact profile record");
    exact(input, ["version", "revision", "profile"], "local contact profile record");
    const revision = timestamp(input.revision, "local contact profile revision");
    if (input.version !== 1 || revision < 1) {
        throw new Error("Invalid local contact profile record");
    }
    return {
        version: 1,
        revision,
        profile: validateContactProfile(input.profile),
    };
}

/** Encode one in-progress contact handshake. */
export function encodeContactHandshakeRecord(record: ContactHandshakeRecord): Uint8Array {
    if (
        record.version !== 2 ||
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
        version: 2,
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
        localAdmission:
            record.localAdmission === undefined ? null : admissionJson(record.localAdmission),
        remoteAdmission:
            record.remoteAdmission === undefined ? null : admissionJson(record.remoteAdmission),
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
            "localAdmission",
            "remoteAdmission",
        ],
        "contact handshake",
    );
    if (
        input.version !== 2 ||
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
    const localAdmission = nullableAdmission(input.localAdmission);
    const remoteAdmission = nullableAdmission(input.remoteAdmission);
    return {
        version: 2,
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
        ...(localAdmission === undefined ? {} : { localAdmission }),
        ...(remoteAdmission === undefined ? {} : { remoteAdmission }),
    };
}

/** Encode one durable contact lifecycle callback record. */
export function encodeContactEventRecord(record: ContactEventRecord): Uint8Array {
    if (record.version !== 2 || !EVENT_ID.test(record.id)) {
        throw new Error("Invalid contact event");
    }
    const common = {
        version: 2,
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
    if (record.type === "updated") {
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
        if (input.version !== 2) {
            throw new Error("Invalid contact request event");
        }
        return {
            version: 2,
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
        if (input.version !== 2) {
            throw new Error("Invalid contact added event");
        }
        return {
            version: 2,
            type: "added",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
            localProfile: validateContactProfile(input.localProfile),
            profile: validateContactProfile(input.profile),
        };
    }
    if (input.type === "updated") {
        exact(
            input,
            ["version", "type", "id", "identity", "sessionId", "localProfile", "profile"],
            "contact updated event",
        );
        if (input.version !== 2) {
            throw new Error("Invalid contact updated event");
        }
        return {
            version: 2,
            type: "updated",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
            localProfile: validateContactProfile(input.localProfile),
            profile: validateContactProfile(input.profile),
        };
    }
    if (input.type === "removed") {
        exact(input, ["version", "type", "id", "identity", "sessionId"], "contact removed event");
        if (input.version !== 2) {
            throw new Error("Invalid contact removed event");
        }
        return {
            version: 2,
            type: "removed",
            id: eventId(input.id, "contact event identifier"),
            identity: identityBytes(input.identity, "contact identity"),
            sessionId: bytes(input.sessionId, 32, 32, "contact session"),
        };
    }
    throw new Error("Invalid contact event");
}
