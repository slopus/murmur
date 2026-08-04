const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function encodeBase64Url(bytes: Uint8Array): string {
    let result = "";
    for (let offset = 0; offset < bytes.length; offset += 3) {
        const value =
            ((bytes[offset] ?? 0) << 16) |
            ((bytes[offset + 1] ?? 0) << 8) |
            (bytes[offset + 2] ?? 0);
        result += ALPHABET[(value >>> 18) & 63];
        result += ALPHABET[(value >>> 12) & 63];
        if (offset + 1 < bytes.length) result += ALPHABET[(value >>> 6) & 63];
        if (offset + 2 < bytes.length) result += ALPHABET[value & 63];
    }
    return result;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    let difference = left.length ^ right.length;
    const length = Math.max(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

export function abortError(signal: AbortSignal): unknown {
    return signal.reason ?? new DOMException("The operation was aborted", "AbortError");
}

export function ensureNotAborted(signal: AbortSignal): void {
    if (signal.aborted) throw abortError(signal);
}

export function sequenceKey(sequence: bigint): string {
    return sequence.toString(16).padStart(16, "0");
}

export function bytesFromU32(value: number): Uint8Array {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value);
    return bytes;
}

export function bytesFromU64(value: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value);
    return bytes;
}
