/** Compare byte arrays in constant time when their public lengths agree. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}

/** Copy a database byte value into an ordinary Uint8Array. */
export function copyBytes(value: unknown, name: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`Invalid ${name} bytes in relay store`);
    }
    return new Uint8Array(value);
}

/** Convert a database int8 value from pg, PGlite, or SQLite into one bigint. */
export function normalizeBigInt(value: string | number | bigint): bigint {
    if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) {
        throw new Error("Invalid relay store bigint");
    }
    if (typeof value === "string" && !/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new Error("Invalid relay store bigint");
    }
    const normalized = BigInt(value);
    if (normalized < 0n) {
        throw new Error("Invalid relay store bigint");
    }
    return normalized;
}

/** Narrow an unknown database column before applying the shared bigint normalizer. */
export function bigintColumn(value: unknown): bigint {
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") {
        throw new Error("Invalid relay store bigint column");
    }
    return normalizeBigInt(value);
}

/** Convert a non-negative database integer to a safe JavaScript number. */
export function safeNumberColumn(value: unknown): number {
    const normalized = bigintColumn(value);
    if (normalized > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("Relay store integer exceeds JavaScript's safe range");
    }
    return Number(normalized);
}
