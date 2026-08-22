const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Encode bytes as unpadded RFC 4648 base64url. */
export function encodeBase64Url(bytes: Uint8Array): string {
    let result = "";
    for (let offset = 0; offset < bytes.length; offset += 3) {
        const first = bytes[offset] ?? 0;
        const second = bytes[offset + 1] ?? 0;
        const third = bytes[offset + 2] ?? 0;
        const value = (first << 16) | (second << 8) | third;
        result += ALPHABET[(value >>> 18) & 63];
        result += ALPHABET[(value >>> 12) & 63];
        if (offset + 1 < bytes.length) result += ALPHABET[(value >>> 6) & 63];
        if (offset + 2 < bytes.length) result += ALPHABET[value & 63];
    }
    return result;
}

/** Decode canonical unpadded base64url, rejecting alternate or malformed spellings. */
export function decodeBase64Url(value: string, expectedBytes?: number): Uint8Array {
    if (!BASE64_URL_PATTERN.test(value) || value.includes("=") || value.length % 4 === 1) {
        throw new Error("Invalid base64url");
    }
    const decoded = new Uint8Array(Math.floor((value.length * 6) / 8));
    let accumulator = 0;
    let bitCount = 0;
    let outputOffset = 0;
    for (const character of value) {
        const index = ALPHABET.indexOf(character);
        if (index < 0) throw new Error("Invalid base64url");
        accumulator = (accumulator << 6) | index;
        bitCount += 6;
        if (bitCount >= 8) {
            bitCount -= 8;
            decoded[outputOffset] = (accumulator >>> bitCount) & 0xff;
            outputOffset += 1;
        }
    }
    if (bitCount > 0 && (accumulator & ((1 << bitCount) - 1)) !== 0) {
        throw new Error("Invalid base64url");
    }
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
