import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import {
    parseSignedRelayEvent,
    relayEventSigningBytes,
    signedRelayEventToJson,
    verifyRelayEventSignature,
    type SignedRelayEvent,
} from "../index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";

const privateKey = new Uint8Array(32).fill(3);
const signingKey = ed25519.getPublicKey(privateKey);
const encoder = new TextEncoder();

function signedEvent(): SignedRelayEvent {
    const event: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(sha256(encoder.encode("protocol"))),
        topic: "topic:strict",
        author: { signingKey },
        createdAt: 123,
        payload: new Uint8Array(),
        snapshot: { expectedVersion: 0, bytes: encoder.encode("opaque") },
        list: [{ op: "append", id: "one", bytes: encoder.encode("element") }],
        signature: new Uint8Array(64),
    };
    return {
        ...event,
        signature: ed25519.sign(relayEventSigningBytes(event), privateKey),
    };
}

describe("relay protocol", () => {
    it("round-trips and authenticates the exact canonical wire event", () => {
        const event = signedEvent();
        const decoded = parseSignedRelayEvent(signedRelayEventToJson(event));
        expect(decoded).toEqual(event);
        expect(verifyRelayEventSignature(decoded)).toBe(true);
        expect(new TextDecoder().decode(relayEventSigningBytes(decoded))).not.toContain(
            "signature",
        );
    });

    it("detects mutation and rejects extra or non-canonical fields", () => {
        const event = signedEvent();
        expect(
            verifyRelayEventSignature({
                ...event,
                payload: encoder.encode("tampered"),
            }),
        ).toBe(false);
        expect(() =>
            parseSignedRelayEvent({
                ...signedRelayEventToJson(event),
                extra: true,
            }),
        ).toThrow("Invalid relay event");
        expect(() =>
            parseSignedRelayEvent({
                ...signedRelayEventToJson(event),
                id: `${event.id}=`,
            }),
        ).toThrow("Invalid event id");
        expect(() =>
            parseSignedRelayEvent({
                ...signedRelayEventToJson(event),
                createdAt: Number.MAX_SAFE_INTEGER + 1,
            }),
        ).toThrow("timestamp");
    });
});
