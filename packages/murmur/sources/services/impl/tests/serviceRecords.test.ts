import { describe, expect, it } from "vitest";
import {
    ROUTING_MARKER_PREFIX,
    SESSION_OWNER_PREFIX,
    decodeSessionOwner,
    decodeSessionRouting,
    encodeSessionOwner,
    encodeSessionRouting,
    routingMarkerKey,
    sessionOwnerKey,
    sessionRoutingKey,
    type SessionOwnerRecord,
} from "../serviceRecords.js";

const EVENT_ID = "018f1f22-3e8c-7abc-8def-0123456789ab";

describe("service records", () => {
    it("round-trips every session owner variant canonically", () => {
        const records: readonly SessionOwnerRecord[] = [
            { version: 1, owner: "ignored" },
            { version: 1, owner: "account" },
            { version: 1, owner: "service", serviceId: "chat.v1" },
        ];
        for (const record of records) {
            const encoded = encodeSessionOwner(record);
            expect(decodeSessionOwner(encoded)).toEqual(record);
            expect(new TextDecoder().decode(encoded)).not.toContain(" ");
        }
    });

    it("round-trips routing records with defensive session IDs", () => {
        const original = new Uint8Array(32).fill(7);
        const encoded = encodeSessionRouting({ version: 1, sessionId: original });
        const decoded = decodeSessionRouting(encoded);
        decoded.sessionId[0] = 9;

        expect(original[0]).toBe(7);
        expect(decodeSessionRouting(encoded).sessionId).toEqual(original);
        expect(sessionOwnerKey(original)).toBe(
            `${SESSION_OWNER_PREFIX}BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc`,
        );
        expect(sessionRoutingKey(EVENT_ID)).toBe(`${ROUTING_MARKER_PREFIX}${EVENT_ID}`);
        expect(routingMarkerKey(EVENT_ID)).toBe(`${ROUTING_MARKER_PREFIX}${EVENT_ID}`);
    });

    it("rejects invalid keys and noncanonical or malformed records", () => {
        expect(() => sessionOwnerKey(new Uint8Array(31))).toThrow("Invalid Murmur session ID");
        expect(() => sessionRoutingKey("not-a-uuid")).toThrow("Invalid Murmur routing event ID");
        expect(() =>
            decodeSessionOwner(new TextEncoder().encode('{ "version":1,"owner":"account"}')),
        ).toThrow("must use canonical JSON");
        expect(() =>
            decodeSessionOwner(
                new TextEncoder().encode('{"extra":true,"owner":"account","version":1}'),
            ),
        ).toThrow("Invalid session owner");
        expect(() =>
            decodeSessionOwner(
                new TextEncoder().encode('{"owner":"service","serviceId":"Bad","version":1}'),
            ),
        ).toThrow("Invalid Murmur service ID");
        expect(() =>
            decodeSessionRouting(new TextEncoder().encode('{"sessionId":"AA","version":1}')),
        ).toThrow("Invalid Murmur session ID");
        expect(() => decodeSessionRouting(new Uint8Array([0xff]))).toThrow(
            "Invalid routing marker",
        );
    });
});
