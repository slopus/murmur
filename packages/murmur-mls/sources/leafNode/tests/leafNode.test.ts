import { generateIdentityKeyPair } from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import {
    createMlsKeyPackage,
    decodeMlsKeyPackage,
    encodeMlsKeyPackage,
} from "../../keyPackage/index.js";
import { defaultMlsLeafCapabilities } from "../index.js";

describe("MLS LeafNode codec", () => {
    it("places source-specific data before extensions in KeyPackage leaves", () => {
        const identity = generateIdentityKeyPair();
        const bundle = createMlsKeyPackage(identity, 10, 20);
        const encoded = encodeMlsKeyPackage(bundle.keyPackage);
        const decoded = decodeMlsKeyPackage(encoded);

        expect(decoded).toEqual(bundle.keyPackage);
        expect(defaultMlsLeafCapabilities().proposals).toEqual([]);
    });
});
