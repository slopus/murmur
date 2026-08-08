import { describe, expect, it } from "vitest";
import {
    canonicalJson,
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
} from "../index.js";

describe("base64url", () => {
    it("round trips browser-safe bytes", () => {
        const encoded = encodeBase64Url(utf8Encode("Murmur 🐱"));

        expect(encoded).toBe("TXVybXVyIPCfkLE");
        expect(utf8Decode(decodeBase64Url(encoded))).toBe("Murmur 🐱");
    });

    it("rejects non-canonical trailing bits", () => {
        expect(() => decodeBase64Url("AB")).toThrow("Non-canonical");
    });

    it("orders canonical JSON keys without locale rules", () => {
        expect(canonicalJson({ "\uffff": 1, a: 2, ä: 3 })).toBe('{"a":2,"ä":3,"￿":1}');
    });
});
