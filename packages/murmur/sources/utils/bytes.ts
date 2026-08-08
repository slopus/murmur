const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Concatenate byte arrays into a newly allocated array. */
export function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
    const length = values.reduce((total, value) => total + value.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;

    for (const value of values) {
        result.set(value, offset);
        offset += value.length;
    }

    return result;
}

/** Encode a string as UTF-8. */
export function utf8Encode(value: string): Uint8Array {
    return encoder.encode(value);
}

/** Decode strict UTF-8. */
export function utf8Decode(value: Uint8Array): string {
    return decoder.decode(value);
}

/** Compare two arrays without returning early on the first different byte. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    const length = Math.max(left.length, right.length);
    let difference = left.length ^ right.length;

    for (let index = 0; index < length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }

    return difference === 0;
}

/** Overwrite a secret byte array in place. */
export function zeroBytes(value: Uint8Array): void {
    value.fill(0);
}

/** Return an independent copy of bytes crossing a mutable boundary. */
export function copyBytes(value: Uint8Array): Uint8Array {
    return value.slice();
}
