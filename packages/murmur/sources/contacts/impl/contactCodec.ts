import { decodeMlsKeyPackage, encodeMlsKeyPackage, verifyMlsKeyPackage } from "../../mls/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";
import type {
    MurmurContactAdmission,
    MurmurContactPacket,
    MurmurContactProfile,
    MurmurContactProfileValue,
} from "../types.js";

const CONTACT_PROTOCOL = "murmur.contacts";
const CONTACT_VERSION = 2;
const MAXIMUM_DESCRIPTOR_BYTES = 128;
const MAXIMUM_PACKET_BYTES = 32 * 1024;
const MAXIMUM_KEY_PACKAGE_BYTES = 4 * 1024;
const MAXIMUM_PROFILE_DEPTH = 16;
const MAXIMUM_PROFILE_NODES = 1_024;
const MAXIMUM_CONTAINER_ITEMS = 128;
const MAXIMUM_STRING_CHARACTERS = 4_096;

export const CONTACT_ADMISSION_TARGET_KEY_PACKAGES = 15;
export const CONTACT_ADMISSION_LOW_WATERMARK = 5;
export const CONTACT_ADMISSION_MAXIMUM_KEY_PACKAGES = 32;

const DESCRIPTOR = canonicalJsonBytes({
    protocol: CONTACT_PROTOCOL,
    version: CONTACT_VERSION,
});

interface ValidationState {
    nodes: number;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        Reflect.ownKeys(value).some((field) => typeof field !== "string") ||
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function addNode(state: ValidationState): void {
    state.nodes += 1;
    if (state.nodes > MAXIMUM_PROFILE_NODES) {
        throw new Error("Contact profile is too complex");
    }
}

function cloneValue(
    value: unknown,
    depth: number,
    state: ValidationState,
): MurmurContactProfileValue {
    addNode(state);
    if (depth > MAXIMUM_PROFILE_DEPTH) {
        throw new Error("Contact profile is too deep");
    }
    if (value === null || typeof value === "boolean") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            throw new Error("Contact profile contains a non-finite number");
        }
        return value;
    }
    if (typeof value === "string") {
        if (value.length > MAXIMUM_STRING_CHARACTERS) {
            throw new Error("Contact profile string is too long");
        }
        return value;
    }
    if (Array.isArray(value)) {
        if (value.length > MAXIMUM_CONTAINER_ITEMS) {
            throw new Error("Contact profile array is too large");
        }
        const keys = Reflect.ownKeys(value);
        if (
            keys.some((key) => typeof key !== "string") ||
            keys.length !== value.length + 1 ||
            keys.some(
                (key) =>
                    key !== "length" &&
                    (!/^(0|[1-9]\d*)$/.test(key as string) || Number(key) >= value.length),
            )
        ) {
            throw new Error("Contact profile array is invalid");
        }
        return Object.freeze(value.map((entry) => cloneValue(entry, depth + 1, state)));
    }

    const input = object(value, "contact profile value");
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string") || keys.length > MAXIMUM_CONTAINER_ITEMS) {
        throw new Error("Contact profile object is invalid");
    }
    const result: Record<string, MurmurContactProfileValue> = Object.create(null) as Record<
        string,
        MurmurContactProfileValue
    >;
    for (const key of keys as string[]) {
        if (key.length > MAXIMUM_STRING_CHARACTERS) {
            throw new Error("Contact profile key is too long");
        }
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (
            descriptor === undefined ||
            !descriptor.enumerable ||
            !Object.hasOwn(descriptor, "value")
        ) {
            throw new Error("Contact profile object is invalid");
        }
        Object.defineProperty(result, key, {
            configurable: false,
            enumerable: true,
            value: cloneValue(descriptor.value, depth + 1, state),
            writable: false,
        });
    }
    return Object.freeze(result);
}

function parseCanonicalObject(
    value: Uint8Array,
    maximumBytes: number,
    name: string,
): Record<string, unknown> {
    if (value.length < 1 || value.length > maximumBytes) {
        throw new Error(`Invalid ${name}`);
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value)) as unknown;
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    const input = object(parsed, name);
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

/** Return an immutable defensive copy after enforcing contact-profile limits. */
export function validateContactProfile(value: unknown): MurmurContactProfile {
    object(value, "contact profile");
    return cloneValue(value, 0, { nodes: 0 }) as MurmurContactProfile;
}

function keyPackageBytes(value: unknown, name: string): Uint8Array {
    if (typeof value !== "string") throw new Error(`Invalid ${name}`);
    const bytes = decodeBase64Url(value);
    if (bytes.length < 1 || bytes.length > MAXIMUM_KEY_PACKAGE_BYTES) {
        throw new Error(`Invalid ${name}`);
    }
    const keyPackage = decodeMlsKeyPackage(bytes);
    if (
        !verifyMlsKeyPackage(keyPackage, null) ||
        !equalBytes(encodeMlsKeyPackage(keyPackage), bytes) ||
        encodeBase64Url(bytes) !== value
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return bytes;
}

/** Return a strict defensive copy of one contact admission inventory. */
export function validateContactAdmission(value: unknown): MurmurContactAdmission {
    const input = object(value, "contact admission");
    exact(input, ["generation", "oneTimeKeyPackages", "lastResortKeyPackage"], "contact admission");
    if (
        typeof input.generation !== "number" ||
        !Number.isSafeInteger(input.generation) ||
        input.generation < 1 ||
        !Array.isArray(input.oneTimeKeyPackages) ||
        input.oneTimeKeyPackages.length > CONTACT_ADMISSION_MAXIMUM_KEY_PACKAGES
    ) {
        throw new Error("Invalid contact admission");
    }
    const oneTimeKeyPackages = input.oneTimeKeyPackages.map((entry, index) =>
        entry instanceof Uint8Array
            ? keyPackageBytes(
                  encodeBase64Url(entry),
                  `contact admission KeyPackage ${String(index)}`,
              )
            : keyPackageBytes(entry, `contact admission KeyPackage ${String(index)}`),
    );
    const lastResortKeyPackage =
        input.lastResortKeyPackage instanceof Uint8Array
            ? keyPackageBytes(
                  encodeBase64Url(input.lastResortKeyPackage),
                  "contact last-resort KeyPackage",
              )
            : keyPackageBytes(input.lastResortKeyPackage, "contact last-resort KeyPackage");
    const encoded = [
        ...oneTimeKeyPackages.map(encodeBase64Url),
        encodeBase64Url(lastResortKeyPackage),
    ];
    if (new Set(encoded).size !== encoded.length) {
        throw new Error("Duplicate contact admission KeyPackage");
    }
    return Object.freeze({
        generation: input.generation,
        oneTimeKeyPackages: Object.freeze(oneTimeKeyPackages),
        lastResortKeyPackage,
    });
}

function admissionJson(admission: MurmurContactAdmission): JsonValue {
    const value = validateContactAdmission(admission);
    return {
        generation: value.generation,
        oneTimeKeyPackages: value.oneTimeKeyPackages.map(encodeBase64Url),
        lastResortKeyPackage: encodeBase64Url(value.lastResortKeyPackage),
    };
}

function suppliedAdmission(value: unknown): MurmurContactAdmission {
    const admission = validateContactAdmission(value);
    if (admission.oneTimeKeyPackages.length !== CONTACT_ADMISSION_TARGET_KEY_PACKAGES) {
        throw new Error("Contact admission supply must contain fifteen one-use KeyPackages");
    }
    return admission;
}

function suppliedAdmissionJson(admission: MurmurContactAdmission): JsonValue {
    return admissionJson(suppliedAdmission(admission));
}

/** Return the one canonical descriptor identifying technical contact sessions. */
export function contactSessionDescriptor(): Uint8Array {
    return DESCRIPTOR.slice();
}

/** Check whether bytes are exactly the supported contact-session descriptor. */
export function isContactSessionDescriptor(value: Uint8Array): boolean {
    return value.length <= MAXIMUM_DESCRIPTOR_BYTES && equalBytes(value, DESCRIPTOR);
}

/** Decode and validate the exact contact-session descriptor. */
export function decodeContactSessionDescriptor(value: Uint8Array): void {
    if (!isContactSessionDescriptor(value)) {
        throw new Error("Invalid contact session descriptor");
    }
}

/** Encode one validated contact packet to canonical JSON bytes. */
export function encodeContactPacket(packet: MurmurContactPacket): Uint8Array {
    let encoded: Uint8Array;
    if (packet.version !== CONTACT_VERSION) {
        throw new Error("Invalid contact packet");
    }
    if (packet.type === "hello") {
        const profile = validateContactProfile(packet.profile);
        encoded = canonicalJsonBytes({
            admission: suppliedAdmissionJson(packet.admission),
            profile: profile as unknown as JsonValue,
            type: "hello",
            version: CONTACT_VERSION,
        });
    } else if (packet.type === "remove") {
        encoded = canonicalJsonBytes({
            type: "remove",
            version: CONTACT_VERSION,
        });
    } else if (packet.type === "profile_update") {
        if (!Number.isSafeInteger(packet.revision) || packet.revision < 1) {
            throw new Error("Invalid contact profile revision");
        }
        encoded = canonicalJsonBytes({
            profile: validateContactProfile(packet.profile) as unknown as JsonValue,
            revision: packet.revision,
            type: "profile_update",
            version: CONTACT_VERSION,
        });
    } else if (packet.type === "admission_request") {
        if (!Number.isSafeInteger(packet.generation) || packet.generation < 0) {
            throw new Error("Invalid contact admission request");
        }
        encoded = canonicalJsonBytes({
            generation: packet.generation,
            type: "admission_request",
            version: CONTACT_VERSION,
        });
    } else if (packet.type === "admission_response") {
        encoded = canonicalJsonBytes({
            admission: suppliedAdmissionJson(packet.admission),
            type: "admission_response",
            version: CONTACT_VERSION,
        });
    } else {
        throw new Error("Invalid contact packet");
    }
    if (encoded.length > MAXIMUM_PACKET_BYTES) {
        throw new Error("Contact packet is too large");
    }
    return encoded;
}

/** Parse strict canonical JSON into one immutable contact packet. */
export function decodeContactPacket(value: Uint8Array): MurmurContactPacket {
    const input = parseCanonicalObject(value, MAXIMUM_PACKET_BYTES, "contact packet");
    if (input.version !== CONTACT_VERSION) {
        throw new Error("Unsupported contact packet version");
    }
    if (input.type === "hello") {
        exact(input, ["admission", "profile", "type", "version"], "contact hello");
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "hello",
            profile: validateContactProfile(input.profile),
            admission: suppliedAdmission(input.admission),
        });
    }
    if (input.type === "remove") {
        exact(input, ["type", "version"], "contact removal");
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "remove",
        });
    }
    if (input.type === "profile_update") {
        exact(input, ["profile", "revision", "type", "version"], "contact profile update");
        if (
            typeof input.revision !== "number" ||
            !Number.isSafeInteger(input.revision) ||
            input.revision < 1
        ) {
            throw new Error("Invalid contact profile revision");
        }
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "profile_update",
            revision: input.revision,
            profile: validateContactProfile(input.profile),
        });
    }
    if (input.type === "admission_request") {
        exact(input, ["generation", "type", "version"], "contact admission request");
        if (
            typeof input.generation !== "number" ||
            !Number.isSafeInteger(input.generation) ||
            input.generation < 0
        ) {
            throw new Error("Invalid contact admission request");
        }
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "admission_request",
            generation: input.generation,
        });
    }
    if (input.type === "admission_response") {
        exact(input, ["admission", "type", "version"], "contact admission response");
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "admission_response",
            admission: suppliedAdmission(input.admission),
        });
    }
    throw new Error("Unsupported contact packet type");
}
