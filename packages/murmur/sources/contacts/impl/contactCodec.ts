import { canonicalJsonBytes, equalBytes, utf8Decode, type JsonValue } from "../../utils/index.js";
import type {
    MurmurContactPacket,
    MurmurContactProfile,
    MurmurContactProfileValue,
} from "../types.js";

const CONTACT_PROTOCOL = "murmur.contacts";
const CONTACT_VERSION = 1;
const MAXIMUM_DESCRIPTOR_BYTES = 128;
const MAXIMUM_PACKET_BYTES = 32 * 1024;
const MAXIMUM_PROFILE_DEPTH = 16;
const MAXIMUM_PROFILE_NODES = 1_024;
const MAXIMUM_CONTAINER_ITEMS = 128;
const MAXIMUM_STRING_CHARACTERS = 4_096;

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
            profile: profile as unknown as JsonValue,
            type: "hello",
            version: CONTACT_VERSION,
        });
    } else if (packet.type === "remove") {
        encoded = canonicalJsonBytes({
            type: "remove",
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
        exact(input, ["profile", "type", "version"], "contact hello");
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "hello",
            profile: validateContactProfile(input.profile),
        });
    }
    if (input.type === "remove") {
        exact(input, ["type", "version"], "contact removal");
        return Object.freeze({
            version: CONTACT_VERSION,
            type: "remove",
        });
    }
    throw new Error("Unsupported contact packet type");
}
