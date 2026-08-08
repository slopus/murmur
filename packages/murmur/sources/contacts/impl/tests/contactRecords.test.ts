import { describe, expect, it } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../../crypto/index.js";
import { utf8Encode } from "../../../utils/index.js";
import {
    CONTACT_EVENT_PREFIX,
    CONTACT_HANDSHAKE_PREFIX,
    CONTACT_IDENTITY_PREFIX,
    CONTACT_SESSION_PREFIX,
    contactEventKey,
    contactHandshakeKey,
    contactIdentityKey,
    contactSessionKey,
    decodeContactEventRecord,
    decodeContactHandshakeRecord,
    decodeContactRecord,
    encodeContactEventRecord,
    encodeContactHandshakeRecord,
    encodeContactRecord,
    type ContactEventRecord,
    type ContactHandshakeRecord,
    type ContactRecord,
} from "../contactRecords.js";

const identityKeyPair = generateIdentityKeyPair();
const identity = identityKeyPair.publicKey.slice();
destroyIdentity(identityKeyPair);
const sessionId = new Uint8Array(32).fill(2);
const deliveryId = "a".repeat(32);
const eventId = "019b6d53-7c34-7000-8000-000000000001";

describe("contact records", () => {
    it("builds separate canonical durable keys", () => {
        expect(contactIdentityKey(identity)).toMatch(
            new RegExp(`^${CONTACT_IDENTITY_PREFIX}[A-Za-z0-9_-]{43}$`),
        );
        expect(contactSessionKey(sessionId)).toMatch(
            new RegExp(`^${CONTACT_SESSION_PREFIX}[A-Za-z0-9_-]{43}$`),
        );
        expect(contactHandshakeKey(sessionId)).toMatch(
            new RegExp(`^${CONTACT_HANDSHAKE_PREFIX}[A-Za-z0-9_-]{43}$`),
        );
        expect(contactEventKey(eventId)).toBe(`${CONTACT_EVENT_PREFIX}${eventId}`);
        expect(() => contactIdentityKey(new Uint8Array(31))).toThrow();
        expect(() => contactSessionKey(new Uint8Array())).toThrow();
        expect(() => contactEventKey("../event")).toThrow();
    });

    it("round-trips confirmed contacts", () => {
        const record: ContactRecord = {
            version: 1,
            identity,
            sessionId,
            localProfile: { name: "Alice" },
            profile: { name: "Bob", tags: ["friend"] },
            status: "removing",
            confirmedAt: 123,
            removeDeliveryId: deliveryId,
        };
        const encoded = encodeContactRecord(record);
        const decoded = decodeContactRecord(encoded);
        expect(decoded).toEqual(record);
        expect(decoded.identity).not.toBe(identity);
        expect(Object.isFrozen(decoded.profile)).toBe(true);
        expect(() =>
            decodeContactRecord(utf8Encode(`${new TextDecoder().decode(encoded)} `)),
        ).toThrow("Non-canonical contact record");
    });

    it("round-trips in-progress handshakes", () => {
        const record: ContactHandshakeRecord = {
            version: 1,
            direction: "incoming",
            identity,
            sessionId,
            remoteProfile: { name: "Bob" },
            localHelloProcessed: false,
            remoteHelloProcessed: true,
            requestEventId: eventId,
            createdAt: 456,
        };
        expect(decodeContactHandshakeRecord(encodeContactHandshakeRecord(record))).toEqual(record);
        expect(() =>
            decodeContactHandshakeRecord(
                utf8Encode(
                    '{"createdAt":0,"direction":"incoming","identity":"","localHelloDeliveryId":null,"localHelloProcessed":false,"localProfile":null,"remoteHelloProcessed":false,"remoteProfile":null,"requestEventId":null,"sessionId":"","version":1}',
                ),
            ),
        ).toThrow();
    });

    it("round-trips every lifecycle event variant", () => {
        const records: readonly ContactEventRecord[] = [
            {
                version: 1,
                type: "requested",
                id: eventId,
                identity,
                sessionId,
                profile: { name: "Bob" },
            },
            {
                version: 1,
                type: "added",
                id: eventId,
                identity,
                sessionId,
                localProfile: { name: "Alice" },
                profile: { name: "Bob" },
            },
            {
                version: 1,
                type: "removed",
                id: eventId,
                identity,
                sessionId,
            },
        ];
        for (const record of records) {
            expect(decodeContactEventRecord(encodeContactEventRecord(record))).toEqual(record);
        }
        expect(() =>
            decodeContactEventRecord(
                utf8Encode(
                    `{"id":"${eventId}","identity":"${"A".repeat(43)}","profile":{},"sessionId":"${"A".repeat(43)}","type":"requested","unexpected":true,"version":1}`,
                ),
            ),
        ).toThrow("Invalid contact request event");
    });
});
