import { describe, expect, it } from "vitest";
import { canonicalJson } from "../canonicalJson.js";

const decoder = new TextDecoder();

describe("canonical JSON", () => {
    it("sorts keys recursively and encodes byte arrays as unpadded base64url", () => {
        expect(
            decoder.decode(
                canonicalJson({
                    z: { b: 2, a: new Uint8Array([0xfb, 0xff]) },
                    a: [true, null],
                }),
            ),
        ).toBe('{"a":[true,null],"z":{"a":"-_8","b":2}}');
    });

    it("rejects undefined, non-finite numbers, unsafe integers, and class instances", () => {
        const sparse: unknown[] = [];
        sparse.length = 1;
        expect(() => canonicalJson({ value: undefined })).toThrow("undefined");
        expect(() => canonicalJson(sparse)).toThrow("undefined");
        expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow("non-finite");
        expect(() => canonicalJson(Number.MAX_SAFE_INTEGER + 1)).toThrow("unsafe integer");
        expect(() => canonicalJson(new Date())).toThrow("plain objects");
    });
});
