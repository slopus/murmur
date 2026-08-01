import { decodeBase64Url } from "../utils/base64Url.js";

/** Return whether a value is one canonical base64url SHA-256 blob identifier. */
export function isBlobId(value: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
        return false;
    }
    try {
        return decodeBase64Url(value, 32).length === 32;
    } catch {
        return false;
    }
}
