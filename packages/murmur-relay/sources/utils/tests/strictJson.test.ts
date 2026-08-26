import { describe, expect, test } from "vitest";
import { DuplicateJsonKeyError, parseStrictJson } from "../strictJson.js";

describe("strict JSON", () => {
    test("accepts unique keys and lets separate objects reuse names", () => {
        expect(parseStrictJson('{"value":1,"nested":{"value":2},"items":[{"value":3}]}')).toEqual({
            value: 1,
            nested: { value: 2 },
            items: [{ value: 3 }],
        });
    });

    test("rejects duplicate decoded keys at every object depth", () => {
        for (const input of [
            '{"value":1,"value":2}',
            '{"nested":{"value":1,"value":2}}',
            '{"items":[{"value":1,"value":2}]}',
            '{"value":1,"\\u0076alue":2}',
            '{"__proto__":1,"__proto__":2}',
        ]) {
            expect(() => parseStrictJson(input)).toThrow(DuplicateJsonKeyError);
        }
    });

    test("retains ordinary JSON syntax rejection", () => {
        expect(() => parseStrictJson('{"value":')).toThrow(SyntaxError);
        expect(() => parseStrictJson('{"value":"unterminated}')).toThrow(SyntaxError);
    });
});
