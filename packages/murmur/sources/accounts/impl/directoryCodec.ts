import { signedDeliveryToJson } from "../../delivery/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
} from "../../utils/index.js";
import type { MurmurDirectoryPrekeyUpload } from "../types.js";

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return 0;
}

/** Encode the harmless device-signed plaintext notification for one spent prekey. */
export function encodeDirectorySpentNotification(reference: Uint8Array): Uint8Array {
    if (reference.length !== 32) throw new Error("Invalid spent directory prekey reference");
    return canonicalJsonBytes({
        version: 1,
        type: "directory_prekey_spent",
        reference: encodeBase64Url(reference),
    } as never);
}

/** Strictly decode one spent-prekey inbox notification. */
export function decodeDirectorySpentNotification(bytes: Uint8Array): Uint8Array {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid spent directory prekey notification");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid spent directory prekey notification");
    }
    const input = parsed as Record<string, unknown>;
    if (
        input.version !== 1 ||
        input.type !== "directory_prekey_spent" ||
        typeof input.reference !== "string" ||
        Object.keys(input).some((field) => !["version", "type", "reference"].includes(field))
    ) {
        throw new Error("Invalid spent directory prekey notification");
    }
    const reference = decodeBase64Url(input.reference);
    if (reference.length !== 32 || encodeBase64Url(reference) !== input.reference) {
        throw new Error("Invalid spent directory prekey notification");
    }
    return reference;
}

/** Encode one account-signed directory upload plaintext. */
export function encodeDirectoryPrekeyUpload(upload: MurmurDirectoryPrekeyUpload): Uint8Array {
    if (
        upload.version !== 1 ||
        upload.type !== "directory_prekey_upload" ||
        (upload.mode !== "replenish" && upload.mode !== "rotate") ||
        upload.deviceKey.length !== 32 ||
        !Number.isSafeInteger(upload.resetGeneration) ||
        upload.resetGeneration < 0 ||
        upload.oneTimePrekeys.length > 256 ||
        upload.lastResort.reference.length !== 32 ||
        upload.lastResort.keyPackage.length < 1 ||
        !Number.isSafeInteger(upload.lastResort.expiresAt) ||
        upload.lastResort.expiresAt < 1
    ) {
        throw new Error("Invalid directory prekey upload");
    }
    let previous: Uint8Array | undefined;
    for (const entry of upload.oneTimePrekeys) {
        if (
            entry.reference.length !== 32 ||
            entry.keyPackage.length < 1 ||
            !Number.isSafeInteger(entry.expiresAt) ||
            entry.expiresAt < 1 ||
            !equalBytes(
                decodeDirectorySpentNotification(entry.spentNotification.ciphertext),
                entry.reference,
            ) ||
            (previous !== undefined && compareBytes(previous, entry.reference) >= 0)
        ) {
            throw new Error("Invalid directory one-time prekey");
        }
        previous = entry.reference;
    }
    if (
        upload.oneTimePrekeys.some((entry) =>
            equalBytes(entry.reference, upload.lastResort.reference),
        )
    ) {
        throw new Error("Directory prekeys must be distinct");
    }
    return canonicalJsonBytes({
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
    } as never);
}
