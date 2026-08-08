import { describe, expect, test } from "vitest";
import {
    parseSignedDelivery,
    parseSignedQueueAck,
    parseSignedQueueRead,
    signedDeliveryToJson,
    signedQueueAckToJson,
    signedQueueReadToJson,
    verifyDeliverySignature,
    verifyQueueAckSignature,
    verifyQueueReadSignature,
} from "../index.js";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedAck,
    signedDelivery,
    signedRead,
} from "./helpers.js";

describe("identity queue protocol", () => {
    test("roundtrips and verifies exact delivery, read, and ack shapes", () => {
        const alice = secret(1);
        const bob = secret(2);
        const delivery = signedDelivery(alice, recipients(identity(alice), identity(bob)));
        const read = signedRead(bob);
        const ack = signedAck(bob, eventId(7));

        const decodedDelivery = parseSignedDelivery(signedDeliveryToJson(delivery));
        const decodedRead = parseSignedQueueRead(signedQueueReadToJson(read));
        const decodedAck = parseSignedQueueAck(signedQueueAckToJson(ack));
        expect(verifyDeliverySignature(decodedDelivery)).toBe(true);
        expect(verifyQueueReadSignature(decodedRead)).toBe(true);
        expect(verifyQueueAckSignature(decodedAck)).toBe(true);
        expect(decodedDelivery).toEqual(delivery);
        expect(decodedRead).toEqual(read);
        expect(decodedAck).toEqual(ack);
    });

    test("rejects unsorted recipients, unknown fields, and tampering", () => {
        const alice = secret(3);
        const bob = secret(4);
        const ordered = recipients(identity(alice), identity(bob));
        const delivery = signedDelivery(alice, ordered);
        expect(() =>
            parseSignedDelivery({
                ...signedDeliveryToJson(delivery),
                recipients: [...signedDeliveryToJson(delivery).recipients].reverse(),
            }),
        ).toThrow("sorted and unique");
        expect(() =>
            parseSignedDelivery({ ...signedDeliveryToJson(delivery), unknownField: "no" }),
        ).toThrow("Invalid delivery");
        expect(
            verifyDeliverySignature({
                ...delivery,
                ciphertext: new Uint8Array([9]),
            }),
        ).toBe(false);
        expect(() =>
            parseSignedQueueRead({
                ...signedQueueReadToJson(signedRead(bob)),
                recipient: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }),
        ).toThrow("Invalid queue recipient");
        expect(() =>
            parseSignedDelivery({
                ...signedDeliveryToJson(delivery),
                recipients: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            }),
        ).toThrow("Invalid delivery recipient");
    });
});
