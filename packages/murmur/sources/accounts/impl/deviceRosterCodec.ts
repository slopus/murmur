import { validateIdentityPublicKey } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
} from "../../utils/index.js";
import type {
    MurmurDeviceRoster,
    MurmurDeviceRosterEntry,
    MurmurDeviceRosterMutation,
} from "../types.js";

const MAXIMUM_ROSTER_DEVICES = 256;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const MAXIMUM_ENCRYPTED_METADATA_BYTES = 16 * 1024;

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

function identity(value: unknown, name: string): Uint8Array {
    if (typeof value !== "string") throw new Error(`Invalid ${name}`);
    const decoded = decodeBase64Url(value);
    validateIdentityPublicKey({ publicKey: decoded });
    if (encodeBase64Url(decoded) !== value) throw new Error(`Invalid ${name}`);
    return decoded;
}

function generation(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return 0;
}

/** Serialize one current relay-owned roster. */
export function serializeDeviceRoster(roster: MurmurDeviceRoster): Uint8Array {
    validateDeviceRoster(roster);
    return canonicalJsonBytes({
        version: 1,
        accountKey: encodeBase64Url(roster.accountKey),
        revision: roster.revision,
        devices: roster.devices.map((entry) => ({
            deviceKey: encodeBase64Url(entry.deviceKey),
            resetGeneration: entry.resetGeneration,
            lastAccessedAt: entry.lastAccessedAt,
            encryptedMetadata: encodeBase64Url(entry.encryptedMetadata),
        })),
        admissions: roster.admissions.map((entry) => ({
            deviceKey: encodeBase64Url(entry.deviceKey),
            keyPackage: encodeBase64Url(entry.keyPackage),
        })),
    });
}

/** Strictly parse one current relay-owned roster. */
export function parseDeviceRoster(bytes: Uint8Array): MurmurDeviceRoster {
    let value: unknown;
    try {
        value = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid device roster");
    }
    return parseDeviceRosterValue(value);
}

/** Strictly parse one current relay-owned roster JSON value. */
export function parseDeviceRosterValue(value: unknown): MurmurDeviceRoster {
    const input = object(value, "device roster");
    exact(input, ["version", "accountKey", "revision", "devices", "admissions"], "device roster");
    if (
        input.version !== 1 ||
        !Array.isArray(input.devices) ||
        !Array.isArray(input.admissions) ||
        input.devices.length > MAXIMUM_ROSTER_DEVICES ||
        input.admissions.length !== input.devices.length
    ) {
        throw new Error("Invalid device roster");
    }
    const devices = input.devices.map((candidate): MurmurDeviceRosterEntry => {
        const entry = object(candidate, "device roster entry");
        exact(
            entry,
            ["deviceKey", "resetGeneration", "lastAccessedAt", "encryptedMetadata"],
            "device roster entry",
        );
        if (typeof entry.encryptedMetadata !== "string") {
            throw new Error("Invalid device roster metadata");
        }
        const encryptedMetadata = decodeBase64Url(entry.encryptedMetadata);
        if (encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES) {
            throw new Error("Invalid device roster metadata");
        }
        return {
            deviceKey: identity(entry.deviceKey, "device roster key"),
            resetGeneration: generation(entry.resetGeneration, "device reset generation"),
            lastAccessedAt: generation(entry.lastAccessedAt, "device last access time"),
            encryptedMetadata,
        };
    });
    const admissions = input.admissions.map((candidate) => {
        const entry = object(candidate, "device admission");
        exact(entry, ["deviceKey", "keyPackage"], "device admission");
        if (typeof entry.keyPackage !== "string") throw new Error("Invalid device admission");
        const keyPackage = decodeBase64Url(entry.keyPackage);
        if (keyPackage.length < 1 || keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES) {
            throw new Error("Invalid device admission");
        }
        return { deviceKey: identity(entry.deviceKey, "device admission key"), keyPackage };
    });
    const roster: MurmurDeviceRoster = {
        version: 1,
        accountKey: identity(input.accountKey, "device roster account"),
        revision: generation(input.revision, "device roster revision"),
        devices,
        admissions,
    };
    validateDeviceRoster(roster);
    return roster;
}

/** Return JSON suitable for the relay HTTP boundary. */
export function deviceRosterToJson(roster: MurmurDeviceRoster): unknown {
    return JSON.parse(utf8Decode(serializeDeviceRoster(roster))) as unknown;
}

/** Validate one complete current roster. */
export function validateDeviceRoster(roster: MurmurDeviceRoster): void {
    validateIdentityPublicKey({ publicKey: roster.accountKey });
    if (
        roster.version !== 1 ||
        !Number.isSafeInteger(roster.revision) ||
        roster.revision < 1 ||
        roster.devices.length > MAXIMUM_ROSTER_DEVICES ||
        roster.admissions.length !== roster.devices.length
    ) {
        throw new Error("Invalid device roster");
    }
    let previous: Uint8Array | undefined;
    for (const entry of roster.devices) {
        validateIdentityPublicKey({ publicKey: entry.deviceKey });
        generation(entry.resetGeneration, "device reset generation");
        generation(entry.lastAccessedAt, "device last access time");
        if (entry.encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES) {
            throw new Error("Invalid device roster metadata");
        }
        if (previous !== undefined && compareBytes(previous, entry.deviceKey) >= 0) {
            throw new Error("Device roster entries must be sorted and unique");
        }
        previous = entry.deviceKey;
        const admission = roster.admissions.find((value) =>
            equalBytes(value.deviceKey, entry.deviceKey),
        );
        if (admission === undefined || admission.keyPackage.length < 1) {
            throw new Error("Device roster admission is missing");
        }
    }
}

/** Return whether one exact device is active in the current roster. */
export function isActiveDevice(roster: MurmurDeviceRoster, deviceKey: Uint8Array): boolean {
    return roster.devices.some((entry) => equalBytes(entry.deviceKey, deviceKey));
}

/** Serialize one roster mutation carried by an account-signed delivery. */
export function encodeDeviceRosterMutation(mutation: MurmurDeviceRosterMutation): Uint8Array {
    validateIdentityPublicKey({ publicKey: mutation.deviceKey });
    generation(mutation.resetGeneration, "device reset generation");
    if (mutation.type === "register") {
        if (
            mutation.keyPackage.length < 1 ||
            mutation.keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES ||
            mutation.encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES
        ) {
            throw new Error("Invalid device registration");
        }
        return canonicalJsonBytes({
            version: 1,
            type: "register",
            deviceKey: encodeBase64Url(mutation.deviceKey),
            resetGeneration: mutation.resetGeneration,
            keyPackage: encodeBase64Url(mutation.keyPackage),
            encryptedMetadata: encodeBase64Url(mutation.encryptedMetadata),
        });
    }
    if (mutation.type === "update_metadata") {
        if (mutation.encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES) {
            throw new Error("Invalid encrypted device metadata");
        }
        return canonicalJsonBytes({
            version: 1,
            type: "update_metadata",
            deviceKey: encodeBase64Url(mutation.deviceKey),
            resetGeneration: mutation.resetGeneration,
            encryptedMetadata: encodeBase64Url(mutation.encryptedMetadata),
        });
    }
    return canonicalJsonBytes({
        version: 1,
        type: "remove",
        deviceKey: encodeBase64Url(mutation.deviceKey),
        resetGeneration: mutation.resetGeneration,
    });
}

/** Strictly parse one roster mutation carried by an account-signed delivery. */
export function decodeDeviceRosterMutation(bytes: Uint8Array): MurmurDeviceRosterMutation {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid device roster mutation");
    }
    const input = object(parsed, "device roster mutation");
    if (
        input.version !== 1 ||
        (input.type !== "register" && input.type !== "update_metadata" && input.type !== "remove")
    ) {
        throw new Error("Invalid device roster mutation");
    }
    const base = {
        version: 1 as const,
        deviceKey: identity(input.deviceKey, "device mutation key"),
        resetGeneration: generation(input.resetGeneration, "device reset generation"),
    };
    if (input.type === "remove") {
        exact(input, ["version", "type", "deviceKey", "resetGeneration"], "device removal");
        return { ...base, type: "remove" };
    }
    if (input.type === "update_metadata") {
        exact(
            input,
            ["version", "type", "deviceKey", "resetGeneration", "encryptedMetadata"],
            "device metadata update",
        );
        if (typeof input.encryptedMetadata !== "string") {
            throw new Error("Invalid device metadata update");
        }
        const encryptedMetadata = decodeBase64Url(input.encryptedMetadata);
        if (encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES) {
            throw new Error("Invalid device metadata update");
        }
        return { ...base, type: "update_metadata", encryptedMetadata };
    }
    exact(
        input,
        ["version", "type", "deviceKey", "resetGeneration", "keyPackage", "encryptedMetadata"],
        "device registration",
    );
    if (typeof input.keyPackage !== "string") throw new Error("Invalid device registration");
    const keyPackage = decodeBase64Url(input.keyPackage);
    if (keyPackage.length < 1 || keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES) {
        throw new Error("Invalid device registration");
    }
    if (typeof input.encryptedMetadata !== "string") {
        throw new Error("Invalid device registration");
    }
    const encryptedMetadata = decodeBase64Url(input.encryptedMetadata);
    if (encryptedMetadata.length > MAXIMUM_ENCRYPTED_METADATA_BYTES) {
        throw new Error("Invalid device registration");
    }
    return { ...base, type: "register", keyPackage, encryptedMetadata };
}
