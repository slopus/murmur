import { ed25519 } from "@noble/curves/ed25519";
import { RelayError } from "../errors.js";
import type { DeviceRoster, DeviceRosterJson, DeviceRosterMutation } from "../types.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";

const MAXIMUM_DEVICES = 256;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function malformed(message: string): never {
    throw new RelayError(400, message, { error: "malformed" });
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return malformed(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        malformed(`Invalid ${name}`);
    }
}

function identity(value: unknown, name: string): Uint8Array {
    if (typeof value !== "string") return malformed(`Invalid ${name}`);
    let bytes: Uint8Array;
    try {
        bytes = decodeBase64Url(value, 32);
        const point = ed25519.Point.fromBytes(bytes, false);
        point.assertValidity();
        if (
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(point.toBytes(), bytes)
        ) {
            return malformed(`Invalid ${name}`);
        }
    } catch {
        return malformed(`Invalid ${name}`);
    }
    return bytes;
}

function integer(value: unknown, name: string, minimum: number = 0): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
        return malformed(`Invalid ${name}`);
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

/** Convert one current roster to exact relay JSON. */
export function deviceRosterToJson(roster: DeviceRoster): DeviceRosterJson {
    validateDeviceRoster(roster);
    return {
        version: 1,
        accountKey: encodeBase64Url(roster.accountKey),
        revision: roster.revision,
        devices: roster.devices.map((entry) => ({
            deviceKey: encodeBase64Url(entry.deviceKey),
            resetGeneration: entry.resetGeneration,
        })),
        admissions: roster.admissions.map((entry) => ({
            deviceKey: encodeBase64Url(entry.deviceKey),
            keyPackage: encodeBase64Url(entry.keyPackage),
        })),
    };
}

/** Validate one in-memory current roster. */
export function validateDeviceRoster(roster: DeviceRoster): void {
    if (
        roster.version !== 1 ||
        !Number.isSafeInteger(roster.revision) ||
        roster.revision < 1 ||
        roster.devices.length > MAXIMUM_DEVICES ||
        roster.admissions.length !== roster.devices.length
    ) {
        malformed("Invalid device roster");
    }
    identity(encodeBase64Url(roster.accountKey), "device roster account");
    let previous: Uint8Array | undefined;
    for (const entry of roster.devices) {
        identity(encodeBase64Url(entry.deviceKey), "device roster key");
        integer(entry.resetGeneration, "device reset generation");
        if (previous !== undefined && compareBytes(previous, entry.deviceKey) >= 0) {
            malformed("Device roster entries must be sorted and unique");
        }
        previous = entry.deviceKey;
        const admission = roster.admissions.find((value) =>
            equalBytes(value.deviceKey, entry.deviceKey),
        );
        if (admission === undefined || admission.keyPackage.length < 1) {
            malformed("Device roster admission is missing");
        }
    }
}

/** Strictly parse one account-key lookup body. */
export function parseDeviceRosterLookup(value: unknown): Uint8Array {
    const input = object(value, "device roster lookup");
    exact(input, ["version", "accountKey"], "device roster lookup");
    if (input.version !== 1) malformed("Invalid device roster lookup");
    return identity(input.accountKey, "device roster account");
}

/** Strictly parse one current roster JSON response. */
export function parseDeviceRoster(value: unknown): DeviceRoster {
    const input = object(value, "device roster");
    exact(input, ["version", "accountKey", "revision", "devices", "admissions"], "device roster");
    if (
        input.version !== 1 ||
        !Array.isArray(input.devices) ||
        !Array.isArray(input.admissions) ||
        input.devices.length > MAXIMUM_DEVICES ||
        input.admissions.length !== input.devices.length
    ) {
        malformed("Invalid device roster");
    }
    const roster: DeviceRoster = {
        version: 1,
        accountKey: identity(input.accountKey, "device roster account"),
        revision: integer(input.revision, "device roster revision", 1),
        devices: input.devices.map((candidate) => {
            const entry = object(candidate, "device roster entry");
            exact(entry, ["deviceKey", "resetGeneration"], "device roster entry");
            return {
                deviceKey: identity(entry.deviceKey, "device roster key"),
                resetGeneration: integer(entry.resetGeneration, "device reset generation"),
            };
        }),
        admissions: input.admissions.map((candidate) => {
            const entry = object(candidate, "device admission");
            exact(entry, ["deviceKey", "keyPackage"], "device admission");
            if (typeof entry.keyPackage !== "string") malformed("Invalid device admission");
            let keyPackage: Uint8Array;
            try {
                keyPackage = decodeBase64Url(entry.keyPackage as string);
            } catch {
                return malformed("Invalid device admission");
            }
            if (keyPackage.length < 1 || keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES) {
                malformed("Invalid device admission");
            }
            return { deviceKey: identity(entry.deviceKey, "device admission key"), keyPackage };
        }),
    };
    validateDeviceRoster(roster);
    return roster;
}

/** Decode the canonical plaintext action in a roster-mutation delivery. */
export function parseDeviceRosterMutation(bytes: Uint8Array): DeviceRosterMutation {
    let parsed: unknown;
    try {
        parsed = JSON.parse(textDecoder.decode(bytes)) as unknown;
    } catch {
        return malformed("Invalid device roster mutation");
    }
    const input = object(parsed, "device roster mutation");
    if (input.version !== 1 || (input.type !== "register" && input.type !== "remove")) {
        return malformed("Invalid device roster mutation");
    }
    const base = {
        version: 1 as const,
        deviceKey: identity(input.deviceKey, "device mutation key"),
        resetGeneration: integer(input.resetGeneration, "device reset generation"),
    };
    if (input.type === "remove") {
        exact(input, ["version", "type", "deviceKey", "resetGeneration"], "device removal");
        return { ...base, type: "remove" };
    }
    exact(
        input,
        ["version", "type", "deviceKey", "resetGeneration", "keyPackage"],
        "device registration",
    );
    if (typeof input.keyPackage !== "string") return malformed("Invalid device registration");
    let keyPackage: Uint8Array;
    try {
        keyPackage = decodeBase64Url(input.keyPackage);
    } catch {
        return malformed("Invalid device registration");
    }
    if (keyPackage.length < 1 || keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES) {
        return malformed("Invalid device registration");
    }
    return { ...base, type: "register", keyPackage };
}
