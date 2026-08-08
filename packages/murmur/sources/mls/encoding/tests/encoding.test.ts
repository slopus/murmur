import { describe, expect, it } from "vitest";
import { decodeVarint, encodeVarint } from "../index.js";

describe("MLS variable-length integers", () => {
    it.each([
        [0, [0x00]],
        [63, [0x3f]],
        [64, [0x40, 0x40]],
        [16_383, [0x7f, 0xff]],
        [16_384, [0x80, 0x00, 0x40, 0x00]],
        [1_073_741_823, [0xbf, 0xff, 0xff, 0xff]],
    ])("encodes %s canonically", (value, expected) => {
        const encoded = encodeVarint(value);

        expect(encoded).toEqual(new Uint8Array(expected));
        expect(decodeVarint(encoded).value).toBe(BigInt(value));
    });

    it("rejects a non-minimal two-byte value", () => {
        expect(() => decodeVarint(new Uint8Array([0x40, 0x01]))).toThrow("Non-canonical");
    });

    it("rejects the reserved eight-byte prefix", () => {
        expect(() => decodeVarint(new Uint8Array([0xc0, 0, 0, 0, 0, 0, 0, 0]))).toThrow("Reserved");
        expect(() => encodeVarint(1n << 30n)).toThrow("does not fit");
    });
});
