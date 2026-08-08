import { describe, expect, it } from "vitest";
import { utf8Encode } from "../../../utils/index.js";
import {
    contactSessionDescriptor,
    decodeContactPacket,
    decodeContactSessionDescriptor,
    encodeContactPacket,
    isContactSessionDescriptor,
    validateContactProfile,
} from "../contactCodec.js";

describe("contact codec", () => {
    it("uses one exact descriptor and canonical packet encoding", () => {
        const descriptor = contactSessionDescriptor();
        expect(new TextDecoder().decode(descriptor)).toBe(
            '{"protocol":"murmur.contacts","version":1}',
        );
        expect(isContactSessionDescriptor(descriptor)).toBe(true);
        expect(decodeContactSessionDescriptor(descriptor)).toBeUndefined();
        expect(() =>
            decodeContactSessionDescriptor(
                utf8Encode('{ "protocol":"murmur.contacts","version":1}'),
            ),
        ).toThrow("Invalid contact session descriptor");

        const hello = encodeContactPacket({
            version: 1,
            type: "hello",
            profile: { z: true, name: "Alice", nested: { b: 2, a: 1 } },
        });
        expect(new TextDecoder().decode(hello)).toBe(
            '{"profile":{"name":"Alice","nested":{"a":1,"b":2},"z":true},"type":"hello","version":1}',
        );
        expect(decodeContactPacket(hello)).toEqual({
            version: 1,
            type: "hello",
            profile: { name: "Alice", nested: { a: 1, b: 2 }, z: true },
        });
        expect(new TextDecoder().decode(encodeContactPacket({ version: 1, type: "remove" }))).toBe(
            '{"type":"remove","version":1}',
        );
    });

    it("rejects alternate encodings, extra fields, and unsupported packets", () => {
        expect(() =>
            decodeContactPacket(
                utf8Encode('{"version":1,"type":"remove","type":"hello","profile":{}}'),
            ),
        ).toThrow();
        expect(() =>
            decodeContactPacket(utf8Encode('{"extra":false,"type":"remove","version":1}')),
        ).toThrow("Invalid contact removal");
        expect(() => decodeContactPacket(utf8Encode('{"type":"wave","version":1}'))).toThrow(
            "Unsupported contact packet type",
        );
        expect(() => decodeContactPacket(utf8Encode('{"type":"remove","version":2}'))).toThrow(
            "Unsupported contact packet version",
        );
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
        expect(() => encodeContactPacket({ version: 1, type: "hello", profile })).toThrow(
            "Contact packet is too large",
        );
    });
});
