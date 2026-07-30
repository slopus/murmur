import { describe, it, expect } from "vitest";
import { trimIdent } from "./trimIndent";

describe("trimIdent", () => {
    it("should remove common indentation", () => {
        const input = `
            line 1
            line 2
            line 3
        `;

        const expected = "line 1\nline 2\nline 3";
        expect(trimIdent(input)).toBe(expected);
    });

    it("should handle empty string", () => {
        expect(trimIdent("")).toBe("");
    });

    it("should handle no indentation", () => {
        const input = "line 1\nline 2\nline 3";
        expect(trimIdent(input)).toBe(input);
    });

    it("should preserve relative indentation", () => {
        const input = `
            line 1
                line 2
            line 3
        `;

        const expected = "line 1\n    line 2\nline 3";
        expect(trimIdent(input)).toBe(expected);
    });

    it("should handle only whitespace lines", () => {
        const input = `

            line 1

        `;

        const expected = "line 1";
        expect(trimIdent(input)).toBe(expected);
    });
});
