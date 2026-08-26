import type { StoreTransaction } from "../../storage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
} from "../../utils/index.js";

export const DIRECTORY_INITIALIZED_KEY = "murmur/accounts/v1/directory/initialized";
export const DIRECTORY_LAST_RESORT_KEY = "murmur/accounts/v1/directory/last-resort";
export const DIRECTORY_ONE_TIME_PREFIX = "murmur/accounts/v1/directory/one-time/";
export const DIRECTORY_PENDING_PREFIX = "murmur/accounts/v1/directory/pending/";
export const DIRECTORY_SPENT_PREFIX = "murmur/accounts/v1/directory/spent/";

/** Durable public metadata pointing at one private SessionEngine KeyPackage bundle. */
export interface DirectoryLocalPrekey {
    readonly reference: Uint8Array;
    readonly keyPackage: Uint8Array;
    readonly expiresAt: number;
}

/** Encode non-secret local directory metadata. */
export function encodeDirectoryLocalPrekey(value: DirectoryLocalPrekey): Uint8Array {
    if (
        value.reference.length !== 32 ||
        value.keyPackage.length < 1 ||
        !Number.isSafeInteger(value.expiresAt) ||
        value.expiresAt < 1
    ) {
        throw new Error("Invalid local directory prekey");
    }
    return canonicalJsonBytes({
        version: 1,
        reference: encodeBase64Url(value.reference),
        keyPackage: encodeBase64Url(value.keyPackage),
        expiresAt: value.expiresAt,
    });
}

/** Decode non-secret local directory metadata. */
export function decodeDirectoryLocalPrekey(bytes: Uint8Array): DirectoryLocalPrekey {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid local directory prekey");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid local directory prekey");
    }
    const input = parsed as Record<string, unknown>;
    if (
        input.version !== 1 ||
        typeof input.reference !== "string" ||
        typeof input.keyPackage !== "string" ||
        typeof input.expiresAt !== "number" ||
        !Number.isSafeInteger(input.expiresAt) ||
        input.expiresAt < 1 ||
        Object.keys(input).some(
            (field) => !["version", "reference", "keyPackage", "expiresAt"].includes(field),
        )
    ) {
        throw new Error("Invalid local directory prekey");
    }
    const reference = decodeBase64Url(input.reference);
    const keyPackage = decodeBase64Url(input.keyPackage);
    if (reference.length !== 32 || keyPackage.length < 1) {
        throw new Error("Invalid local directory prekey");
    }
    return { reference, keyPackage, expiresAt: input.expiresAt };
}

/** Remove every local marker associated with a KeyPackage consumed by a Welcome. */
export async function deleteDirectoryPrekeyMarkers(
    transaction: StoreTransaction,
    reference: Uint8Array,
): Promise<void> {
    const suffix = encodeBase64Url(reference);
    await transaction.delete(`${DIRECTORY_ONE_TIME_PREFIX}${suffix}`);
    await transaction.delete(`${DIRECTORY_PENDING_PREFIX}${suffix}`);
    await transaction.delete(`${DIRECTORY_SPENT_PREFIX}${suffix}`);
}
