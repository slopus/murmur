const encoder = new TextEncoder();

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

/** UTF-8 encoding for fixed protocol labels. */
export function utf8Encode(value: string): Uint8Array {
    return encoder.encode(value);
}

/** Constant-work byte comparison for public authentication values. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    const length = Math.max(left.length, right.length);
    let difference = left.length ^ right.length;
    for (let index = 0; index < length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}

/** Encode an unsigned 16-bit integer. */
export function encodeUint16(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new Error("Value does not fit uint16");
    }
    return new Uint8Array([value >>> 8, value & 0xff]);
}

/** Encode an unsigned 32-bit integer. */
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

/** Encode an unsigned 64-bit integer. */
export function encodeUint64(value: bigint): Uint8Array {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
        throw new Error("Value does not fit uint64");
    }
    const encoded = new Uint8Array(8);
    let remaining = value;
    for (let index = encoded.length - 1; index >= 0; index -= 1) {
        encoded[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return encoded;
}

/** Render public key bytes as a stable set identifier. */
export function byteIdentifier(value: Uint8Array): string {
    let result = "";
    for (const byte of value) {
        result += byte.toString(16).padStart(2, "0");
    }
    return result;
}

/** Strict reader for versioned package encodings. */
export class ByteReader {
    #offset = 0;

    constructor(
        readonly bytes: Uint8Array,
        readonly label: string,
    ) {}

    get remaining(): number {
        return this.bytes.length - this.#offset;
    }

    readBytes(length: number): Uint8Array {
        if (
            !Number.isSafeInteger(length) ||
            length < 0 ||
            this.#offset + length > this.bytes.length
        ) {
            throw new Error(`Truncated ${this.label}`);
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    readUint8(): number {
        return this.readBytes(1)[0] ?? 0;
    }

    readUint16(): number {
        return (this.readUint8() << 8) | this.readUint8();
    }

    readUint32(): number {
        return (
            this.readUint8() * 0x1_00_00_00 +
            (this.readUint8() << 16) +
            (this.readUint8() << 8) +
            this.readUint8()
        );
    }

    readUint64(): bigint {
        let result = 0n;
        for (let index = 0; index < 8; index += 1) {
            result = (result << 8n) | BigInt(this.readUint8());
        }
        return result;
    }

    ensureEnd(): void {
        if (this.remaining !== 0) {
            throw new Error(`Trailing bytes in ${this.label}`);
        }
    }
}
