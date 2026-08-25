import { concatBytes, utf8Encode } from "../../utils/index.js";

/** Encode an unsigned 16-bit integer in network byte order. */
export function encodeUint16(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new Error("Value must fit uint16");
    }
    return new Uint8Array([value >>> 8, value & 0xff]);
}

/** Decode an unsigned 16-bit integer in network byte order. */
export function decodeUint16(value: Uint8Array, offset: number): number {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + 2 > value.length) {
        throw new Error("Truncated uint16");
    }
    return ((value[offset] ?? 0) << 8) | (value[offset + 1] ?? 0);
}

/** Encode an unsigned 32-bit integer in network byte order. */
export function encodeUint32(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new Error("Value must fit uint32");
    }
    const result = new Uint8Array(4);
    new DataView(result.buffer).setUint32(0, value, false);
    return result;
}

/** Encode a non-negative safe integer as uint64. */
export function encodeUint64(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("Value must be a non-negative safe integer");
    }
    const result = new Uint8Array(8);
    new DataView(result.buffer).setBigUint64(0, BigInt(value), false);
    return result;
}

/** Decode a uint64 which must fit a JavaScript safe integer. */
export function decodeUint64(value: Uint8Array, offset: number): number {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + 8 > value.length) {
        throw new Error("Truncated uint64");
    }
    const decoded = new DataView(value.buffer, value.byteOffset + offset, 8).getBigUint64(0, false);
    const number = Number(decoded);
    if (!Number.isSafeInteger(number)) {
        throw new Error("uint64 exceeds the safe integer range");
    }
    return number;
}

/** Canonically length-prefix one byte string with a uint32. */
export function lengthPrefix(value: Uint8Array): Uint8Array {
    return concatBytes(encodeUint32(value.length), value);
}

/** Canonically encode an ASCII protocol label. */
export function protocolLabel(value: string): Uint8Array {
    if (!/^[\x20-\x7e]{1,128}$/.test(value)) {
        throw new Error("Protocol labels must be 1-128 printable ASCII characters");
    }
    return utf8Encode(value);
}
