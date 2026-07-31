import { decodeBase64Url, encodeBase64Url } from "./base64Url.js";

const CURSOR_BYTES = 8;
const MAX_CURSOR = (1n << 63n) - 1n;

/** Encode an ordered list position as an opaque fixed-width cursor. */
export function encodeListCursor(position: bigint): string {
    if (position < 0n || position > MAX_CURSOR) {
        throw new Error("Invalid list cursor position");
    }
    const bytes = new Uint8Array(CURSOR_BYTES);
    let remainder = position;
    for (let index = CURSOR_BYTES - 1; index >= 0; index -= 1) {
        bytes[index] = Number(remainder & 0xffn);
        remainder >>= 8n;
    }
    return encodeBase64Url(bytes);
}

/** Decode a canonical list cursor into its ordered position. */
export function decodeListCursor(cursor: string): bigint {
    const bytes = decodeBase64Url(cursor, CURSOR_BYTES);
    let position = 0n;
    for (const byte of bytes) {
        position = (position << 8n) | BigInt(byte);
    }
    if (position > MAX_CURSOR) {
        throw new Error("Invalid list cursor");
    }
    return position;
}
