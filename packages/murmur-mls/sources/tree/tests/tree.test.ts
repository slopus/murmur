import { describe, expect, it } from "vitest";
import { copath, directPath, leafNode, nodeLevel, treeRoot, treeWidth } from "../index.js";

describe("RFC 9420 left-balanced tree math", () => {
    it("matches the five-leaf tree shape", () => {
        expect(treeWidth(5)).toBe(9);
        expect(treeRoot(5)).toBe(7);
        expect([0, 1, 2, 3, 4, 5, 6, 7, 8].map(nodeLevel)).toEqual([0, 1, 0, 2, 0, 1, 0, 3, 0]);
        expect(leafNode(4, 5)).toBe(8);
    });

    it("computes direct paths and copaths", () => {
        expect(directPath(0, 5)).toEqual([1, 3, 7]);
        expect(copath(0, 5)).toEqual([2, 5, 8]);
        expect(directPath(4, 5)).toEqual([7]);
        expect(copath(4, 5)).toEqual([3]);
    });
});
