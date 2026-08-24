import { describe, expect, it } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../../crypto/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
} from "../../../mls/index.js";
import { utf8Encode } from "../../../utils/index.js";
import {
    CONTACT_ADMISSION_TARGET_KEY_PACKAGES,
    contactSessionDescriptor,
    decodeContactPacket,
    decodeContactSessionDescriptor,
    encodeContactPacket,
    isContactSessionDescriptor,
    validateContactProfile,
} from "../contactCodec.js";
import type { MurmurContactAdmission } from "../../types.js";

function admission(generation = 1): MurmurContactAdmission {
    const identity = generateIdentityKeyPair();
    const oneTime = Array.from({ length: CONTACT_ADMISSION_TARGET_KEY_PACKAGES }, () =>
        createMlsKeyPackage(identity),
    );
    const fallback = createMlsKeyPackage(identity);
    try {
        return {
            generation,
            oneTimeKeyPackages: oneTime.map((bundle) => encodeMlsKeyPackage(bundle.keyPackage)),
            lastResortKeyPackage: encodeMlsKeyPackage(fallback.keyPackage),
        };
    } finally {
        for (const bundle of oneTime) destroyMlsKeyPackageBundle(bundle);
        destroyMlsKeyPackageBundle(fallback);
        destroyIdentity(identity);
    }
}

describe("contact codec", () => {
    it("uses one exact descriptor and canonical packet encoding", () => {
        const descriptor = contactSessionDescriptor();
        expect(new TextDecoder().decode(descriptor)).toBe(
            '{"protocol":"murmur.contacts","version":2}',
        );
        expect(isContactSessionDescriptor(descriptor)).toBe(true);
        expect(decodeContactSessionDescriptor(descriptor)).toBeUndefined();
        expect(() =>
            decodeContactSessionDescriptor(
                utf8Encode('{ "protocol":"murmur.contacts","version":2}'),
            ),
        ).toThrow("Invalid contact session descriptor");

        const hello = encodeContactPacket({
            version: 2,
            type: "hello",
            profile: { z: true, name: "Alice", nested: { b: 2, a: 1 } },
            admission: admission(),
        });
        const decodedHello = decodeContactPacket(hello);
        expect(encodeContactPacket(decodedHello)).toEqual(hello);
        expect(decodedHello).toMatchObject({
            version: 2,
            type: "hello",
            profile: { name: "Alice", nested: { a: 1, b: 2 }, z: true },
        });
        if (decodedHello.type !== "hello") throw new Error("Expected a contact hello");
        expect(decodedHello.admission.oneTimeKeyPackages).toHaveLength(
            CONTACT_ADMISSION_TARGET_KEY_PACKAGES,
        );
        expect(new TextDecoder().decode(encodeContactPacket({ version: 2, type: "remove" }))).toBe(
            '{"type":"remove","version":2}',
        );
        const request = encodeContactPacket({
            version: 2,
            type: "admission_request",
            generation: 1,
        });
        expect(decodeContactPacket(request)).toEqual({
            version: 2,
            type: "admission_request",
            generation: 1,
        });
        const profileUpdate = encodeContactPacket({
            version: 2,
            type: "profile_update",
            revision: 3,
            profile: { name: "Alice Updated" },
        });
        expect(decodeContactPacket(profileUpdate)).toEqual({
            version: 2,
            type: "profile_update",
            revision: 3,
            profile: { name: "Alice Updated" },
        });
    });

    it("rejects alternate encodings, extra fields, and unsupported packets", () => {
        const undersupplied = admission();
        expect(() =>
            encodeContactPacket({
                version: 2,
                type: "hello",
                profile: {},
                admission: {
                    ...undersupplied,
                    oneTimeKeyPackages: undersupplied.oneTimeKeyPackages.slice(1),
                },
            }),
        ).toThrow("fifteen one-use KeyPackages");
        expect(() =>
            decodeContactPacket(
                utf8Encode('{"version":2,"type":"remove","type":"hello","profile":{}}'),
            ),
        ).toThrow();
        expect(() =>
            decodeContactPacket(utf8Encode('{"extra":false,"type":"remove","version":2}')),
        ).toThrow("Invalid contact removal");
        expect(() => decodeContactPacket(utf8Encode('{"type":"wave","version":2}'))).toThrow(
            "Unsupported contact packet type",
        );
        expect(() => decodeContactPacket(utf8Encode('{"type":"remove","version":1}'))).toThrow(
            "Unsupported contact packet version",
        );
        expect(() =>
            decodeContactPacket(
                utf8Encode(
                    '{"profile":{"name":"Alice"},"revision":0,"type":"profile_update","version":2}',
                ),
            ),
        ).toThrow("Invalid contact profile revision");
    });

    it("bounds, clones, and freezes profiles recursively", () => {
        const source = {
            name: "Alice",
            nested: [{ available: true }],
        };
        const profile = validateContactProfile(source);
        source.name = "Changed";
        source.nested[0]!.available = false;
        expect(profile).toEqual({
            name: "Alice",
            nested: [{ available: true }],
        });
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.nested)).toBe(true);
        expect(Object.isFrozen((profile.nested as readonly object[])[0])).toBe(true);

        expect(() => validateContactProfile({ value: Number.NaN })).toThrow("non-finite");
        expect(() => validateContactProfile(["not", "an", "object"])).toThrow(
            "Invalid contact profile",
        );
        expect(() =>
            validateContactProfile({ values: Array.from({ length: 129 }, () => null) }),
        ).toThrow("array is too large");
        expect(() => validateContactProfile({ value: "x".repeat(4_097) })).toThrow(
            "string is too long",
        );
        let deep: unknown = null;
        for (let index = 0; index < 17; index += 1) {
            deep = [deep];
        }
        expect(() => validateContactProfile({ deep })).toThrow("too deep");
        const sparse: unknown[] = [];
        sparse.length = 1;
        expect(() => validateContactProfile({ sparse })).toThrow("array is invalid");
        const getter = Object.create(null) as Record<string, unknown>;
        Object.defineProperty(getter, "name", {
            enumerable: true,
            get: () => "Alice",
        });
        expect(() => validateContactProfile(getter)).toThrow("object is invalid");
    });

    it("enforces the encoded hello size ceiling", () => {
        const profile: Record<string, string> = {};
        for (let index = 0; index < 128; index += 1) {
            profile[`field-${index.toString().padStart(3, "0")}`] = "x".repeat(300);
        }
        expect(() =>
            encodeContactPacket({
                version: 2,
                type: "hello",
                profile,
                admission: admission(),
            }),
        ).toThrow("Contact packet is too large");
    });
});
