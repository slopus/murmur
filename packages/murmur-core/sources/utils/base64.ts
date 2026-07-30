const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode bytes as unpadded base64url without relying on Node.js globals.
 */
export function encodeBase64Url(bytes: Uint8Array): string {
    let result = "";

    for (let offset = 0; offset < bytes.length; offset += 3) {
        const first = bytes[offset] ?? 0;
        const second = bytes[offset + 1] ?? 0;
        const third = bytes[offset + 2] ?? 0;
        const value = (first << 16) | (second << 8) | third;

        result += ALPHABET[(value >>> 18) & 63];
        result += ALPHABET[(value >>> 12) & 63];
        if (offset + 1 < bytes.length) {
            result += ALPHABET[(value >>> 6) & 63];
        }
        if (offset + 2 < bytes.length) {
            result += ALPHABET[value & 63];
        }
    }

    return result;
}

/**
 * Decode unpadded base64url.
 *
 * @throws Error when the input is not canonical base64url.
 */
export function decodeBase64Url(value: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
        throw new Error("Invalid base64url value");
    }

    const output = new Uint8Array(Math.floor((value.length * 6) / 8));
    let accumulator = 0;
    let bitCount = 0;
    let outputOffset = 0;

    for (const character of value) {
        const index = ALPHABET.indexOf(character);
        if (index < 0) {
            throw new Error("Invalid base64url value");
        }
        accumulator = (accumulator << 6) | index;
        bitCount += 6;
        if (bitCount >= 8) {
            bitCount -= 8;
            output[outputOffset] = (accumulator >>> bitCount) & 0xff;
            outputOffset += 1;
        }
    }

    if (bitCount > 0 && (accumulator & ((1 << bitCount) - 1)) !== 0) {
        throw new Error("Non-canonical base64url value");
    }

    return output;
}
