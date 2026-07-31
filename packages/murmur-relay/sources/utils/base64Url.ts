const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/** Encode bytes as unpadded RFC 4648 base64url. */
export function encodeBase64Url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

/** Decode canonical unpadded base64url, rejecting alternate or malformed spellings. */
export function decodeBase64Url(value: string, expectedBytes?: number): Uint8Array {
    if (!BASE64_URL_PATTERN.test(value) || value.includes("=") || value.length % 4 === 1) {
        throw new Error("Invalid base64url");
    }
    const decoded = new Uint8Array(Buffer.from(value, "base64url"));
    if (
        encodeBase64Url(decoded) !== value ||
        (expectedBytes !== undefined && decoded.length !== expectedBytes)
    ) {
        throw new Error("Invalid base64url");
    }
    return decoded;
}

/** Return whether a string is the unique unpadded encoding of the requested byte length. */
export function isBase64Url(value: string, expectedBytes?: number): boolean {
    try {
        decodeBase64Url(value, expectedBytes);
        return true;
    } catch {
        return false;
    }
}
