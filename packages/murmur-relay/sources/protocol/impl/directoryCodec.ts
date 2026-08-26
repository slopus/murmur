import { ed25519 } from "@noble/curves/ed25519";
import { RelayError } from "../errors.js";
import type { DirectoryClaim, DirectoryPrekeyUpload, SignedDeliveryJson } from "../types.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { parseSignedDelivery, signedDeliveryToJson } from "./deliveryCodec.js";

const MAXIMUM_PREKEYS = 256;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const MAXIMUM_TICKET_BYTES = 8 * 1024;
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

function bytes(value: unknown, name: string, length?: number): Uint8Array {
    if (typeof value !== "string") return malformed(`Invalid ${name}`);
    try {
        const decoded = decodeBase64Url(value, length);
        if (decoded.length < 1 || decoded.length > MAXIMUM_KEY_PACKAGE_BYTES) {
            return malformed(`Invalid ${name}`);
        }
        return decoded;
    } catch {
        return malformed(`Invalid ${name}`);
    }
}

function identity(value: unknown, name: string): Uint8Array {
    const decoded = bytes(value, name, 32);
    try {
        const point = ed25519.Point.fromBytes(decoded, false);
        point.assertValidity();
        if (
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(point.toBytes(), decoded)
        ) {
            return malformed(`Invalid ${name}`);
        }
        return decoded;
    } catch {
        return malformed(`Invalid ${name}`);
    }
}

function integer(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
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

/** Parse the harmless device-signed plaintext notification for one spent prekey. */
export function parseDirectorySpentNotification(bytesValue: Uint8Array): Uint8Array {
    let parsed: unknown;
    try {
        parsed = JSON.parse(textDecoder.decode(bytesValue)) as unknown;
    } catch {
        return malformed("Invalid spent-prekey notification");
    }
    const input = object(parsed, "spent-prekey notification");
    exact(input, ["version", "type", "reference"], "spent-prekey notification");
    if (input.version !== 1 || input.type !== "directory_prekey_spent") {
        return malformed("Invalid spent-prekey notification");
    }
    return bytes(input.reference, "spent-prekey reference", 32);
}

/** Parse one account-signed directory upload plaintext. */
export function parseDirectoryPrekeyUpload(bytesValue: Uint8Array): DirectoryPrekeyUpload {
    let parsed: unknown;
    try {
        parsed = JSON.parse(textDecoder.decode(bytesValue)) as unknown;
    } catch {
        return malformed("Invalid directory prekey upload");
    }
    const input = object(parsed, "directory prekey upload");
    exact(
        input,
        ["version", "type", "mode", "deviceKey", "resetGeneration", "oneTimePrekeys", "lastResort"],
        "directory prekey upload",
    );
    if (
        input.version !== 1 ||
        input.type !== "directory_prekey_upload" ||
        (input.mode !== "replenish" && input.mode !== "rotate") ||
        !Array.isArray(input.oneTimePrekeys) ||
        input.oneTimePrekeys.length > MAXIMUM_PREKEYS
    ) {
        return malformed("Invalid directory prekey upload");
    }
    let previous: Uint8Array | undefined;
    const oneTimePrekeys = input.oneTimePrekeys.map((candidate) => {
        const entry = object(candidate, "directory one-time prekey");
        exact(
            entry,
            ["reference", "keyPackage", "expiresAt", "spentNotification"],
            "directory one-time prekey",
        );
        const reference = bytes(entry.reference, "directory prekey reference", 32);
        if (previous !== undefined && compareBytes(previous, reference) >= 0) {
            return malformed("Directory prekeys must be sorted and unique");
        }
        previous = reference;
        const spentNotification = parseSignedDelivery(entry.spentNotification);
        if (!equalBytes(parseDirectorySpentNotification(spentNotification.ciphertext), reference)) {
            return malformed("Spent notification does not match its prekey");
        }
        return {
            reference,
            keyPackage: bytes(entry.keyPackage, "directory KeyPackage"),
            expiresAt: integer(entry.expiresAt, "directory prekey expiration"),
            spentNotification,
        };
    });
    const lastResortInput = object(input.lastResort, "directory last-resort prekey");
    exact(
        lastResortInput,
        ["reference", "keyPackage", "expiresAt"],
        "directory last-resort prekey",
    );
    const lastResort = {
        reference: bytes(lastResortInput.reference, "last-resort prekey reference", 32),
        keyPackage: bytes(lastResortInput.keyPackage, "last-resort KeyPackage"),
        expiresAt: integer(lastResortInput.expiresAt, "last-resort prekey expiration"),
    };
    if (oneTimePrekeys.some((entry) => equalBytes(entry.reference, lastResort.reference))) {
        return malformed("Last-resort and one-time prekeys must be distinct");
    }
    return {
        version: 1,
        type: "directory_prekey_upload",
        mode: input.mode,
        deviceKey: identity(input.deviceKey, "directory device key"),
        resetGeneration: integer(input.resetGeneration, "directory reset generation"),
        oneTimePrekeys,
        lastResort,
    };
}

/** Parse one exact identity-key claim request and opaque authentication ticket. */
export function parseDirectoryClaimRequest(value: unknown): {
    readonly accountKey: Uint8Array;
    readonly ticket: Uint8Array;
} {
    const input = object(value, "directory claim");
    exact(input, ["version", "accountKey", "ticket"], "directory claim");
    if (input.version !== 1 || typeof input.ticket !== "string") {
        return malformed("Invalid directory claim");
    }
    let ticket: Uint8Array;
    try {
        ticket = decodeBase64Url(input.ticket);
    } catch {
        return malformed("Invalid directory claim ticket");
    }
    if (ticket.length < 1 || ticket.length > MAXIMUM_TICKET_BYTES) {
        return malformed("Invalid directory claim ticket");
    }
    return { accountKey: identity(input.accountKey, "directory account key"), ticket };
}

/** Convert a known or unknown exact-account claim to one indistinguishable response envelope. */
export function directoryClaimToJson(claim: DirectoryClaim): unknown {
    return {
        version: 1,
        accountKey: encodeBase64Url(claim.accountKey),
        rosterRevision: claim.rosterRevision,
        devices: claim.devices.map((device) => ({
            deviceKey: encodeBase64Url(device.deviceKey),
            resetGeneration: device.resetGeneration,
            keyPackage: encodeBase64Url(device.keyPackage),
            source: device.source,
        })),
    };
}

/** JSON helper used by account clients when constructing signed uploads. */
export interface DirectoryPrekeyUploadJson {
    readonly version: 1;
    readonly type: "directory_prekey_upload";
    readonly mode: "replenish" | "rotate";
    readonly deviceKey: string;
    readonly resetGeneration: number;
    readonly oneTimePrekeys: readonly {
        readonly reference: string;
        readonly keyPackage: string;
        readonly expiresAt: number;
        readonly spentNotification: SignedDeliveryJson;
    }[];
    readonly lastResort: {
        readonly reference: string;
        readonly keyPackage: string;
        readonly expiresAt: number;
    };
}

/** Convert an already validated upload to JSON for diagnostics and tests. */
export function directoryPrekeyUploadToJson(
    upload: DirectoryPrekeyUpload,
): DirectoryPrekeyUploadJson {
    return {
        version: 1,
        type: "directory_prekey_upload",
        mode: upload.mode,
        deviceKey: encodeBase64Url(upload.deviceKey),
        resetGeneration: upload.resetGeneration,
        oneTimePrekeys: upload.oneTimePrekeys.map((entry) => ({
            reference: encodeBase64Url(entry.reference),
            keyPackage: encodeBase64Url(entry.keyPackage),
            expiresAt: entry.expiresAt,
            spentNotification: signedDeliveryToJson(entry.spentNotification),
        })),
        lastResort: {
            reference: encodeBase64Url(upload.lastResort.reference),
            keyPackage: encodeBase64Url(upload.lastResort.keyPackage),
            expiresAt: upload.lastResort.expiresAt,
        },
    };
}
