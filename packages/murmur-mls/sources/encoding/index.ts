import { concatBytes } from "@murmur/core";

const MAXIMUM_VARINT = (1n << 30n) - 1n;

/** Encode an unsigned 16-bit integer in network byte order. */
export function encodeUint16(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new Error("Value does not fit uint16");
    }
    return new Uint8Array([value >>> 8, value & 0xff]);
}

/** Encode an unsigned 32-bit integer in network byte order. */
export function encodeUint32(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new Error("Value does not fit uint32");
    }
    return new Uint8Array([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
    ]);
}

/** Encode an unsigned 64-bit integer in network byte order. */
export function encodeUint64(value: number | bigint): Uint8Array {
    const bigint = typeof value === "number" ? BigInt(value) : value;
    if (
        (typeof value === "number" && !Number.isSafeInteger(value)) ||
        bigint < 0n ||
        bigint > 0xffff_ffff_ffff_ffffn
    ) {
        throw new Error("Value does not fit uint64");
    }
    const encoded = new Uint8Array(8);
    let remaining = bigint;
    for (let index = 7; index >= 0; index -= 1) {
        encoded[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return encoded;
}

/** Encode the MLS variable-length unsigned integer. */
export function encodeVarint(value: number | bigint): Uint8Array {
    const bigint = typeof value === "number" ? BigInt(value) : value;
    if (
        (typeof value === "number" && !Number.isSafeInteger(value)) ||
        bigint < 0n ||
        bigint > MAXIMUM_VARINT
    ) {
        throw new Error("Value does not fit an MLS variable-length integer");
    }

    const length = bigint < 64n ? 1 : bigint < 16_384n ? 2 : 4;
    const encoded = new Uint8Array(length);
    let remaining = bigint;
    for (let index = length - 1; index >= 0; index -= 1) {
        encoded[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    encoded[0] = (encoded[0] ?? 0) | ({ 1: 0, 2: 0x40, 4: 0x80 }[length] ?? 0);
    return encoded;
}

/** Decode one canonical MLS variable-length integer. */
export function decodeVarint(
    bytes: Uint8Array,
    offset: number = 0,
): { readonly value: bigint; readonly bytesRead: 1 | 2 | 4 } {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) {
        throw new Error("Invalid variable-length integer offset");
    }
    const prefix = (bytes[offset] ?? 0) >>> 6;
    if (prefix === 3) {
        throw new Error("Reserved MLS variable-length integer prefix");
    }
    const length = [1, 2, 4][prefix] as 1 | 2 | 4;
    if (offset + length > bytes.length) {
        throw new Error("Truncated variable-length integer");
    }

    let value = BigInt((bytes[offset] ?? 0) & 0x3f);
    for (let index = 1; index < length; index += 1) {
        value = (value << 8n) | BigInt(bytes[offset + index] ?? 0);
    }
    const minimum = { 1: 0n, 2: 64n, 4: 16_384n }[length];
    if (value < minimum) {
        throw new Error("Non-canonical variable-length integer");
    }
    return { value, bytesRead: length };
}

/** Encode an MLS `opaque<V>` vector. */
export function encodeOpaqueV(value: Uint8Array): Uint8Array {
    return concatBytes(encodeVarint(value.length), value);
}
