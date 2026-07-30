import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import {
    createQueueAcknowledgeRequest,
    createQueueReadRequest,
    HttpRelayTransport,
    createRelayBlob,
    createRelayEvent,
    createTopicSubscription,
    verifyRelayBlob,
    verifyRelayEvent,
    verifyQueueRequest,
    verifyTopicSubscription,
    decodeQueueRequestWire,
    decodeRelayDeliveriesWire,
    decodeRelayEventWire,
    decodeTopicSubscriptionWire,
    deriveNestedTopic,
    encodeQueueRequestWire,
    encodeRelayDeliveriesWire,
    encodeRelayEventWire,
    encodeTopicSubscriptionWire,
} from "../index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";

describe("relay protocol", () => {
    it("binds a publisher signature to the payload and recipients", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), [bob], 42);

        expect(verifyRelayEvent(event)).toBe(true);
        expect("signingSecretKey" in event.sender).toBe(false);
        expect("encryptionSecretKey" in event.sender).toBe(false);
        expect(verifyRelayEvent({ ...event, payload: utf8Encode("changed") })).toBe(false);
    });

    it("authenticates subscriptions", () => {
        const alice = generateIdentityKeyPair();
        const subscription = createTopicSubscription(alice, "topic", 42);

        expect(verifyTopicSubscription(subscription)).toBe(true);
        expect("signingSecretKey" in subscription.subscriber).toBe(false);
        expect(verifyTopicSubscription({ ...subscription, topic: "other" })).toBe(false);
    });

    it("authenticates single-use queue request envelopes", () => {
        const alice = generateIdentityKeyPair();
        const read = createQueueReadRequest(alice, 42);
        const acknowledgement = createQueueAcknowledgeRequest(alice, "delivery", 42);

        expect(verifyQueueRequest(read)).toBe(true);
        expect(verifyQueueRequest(acknowledgement)).toBe(true);
        expect(verifyQueueRequest({ ...acknowledgement, deliveryId: "other" })).toBe(false);
        expect("signingSecretKey" in read.recipient).toBe(false);
    });

    it("returns false rather than throwing for malformed identity keys", () => {
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), [], 42);

        expect(
            verifyRelayEvent({
                ...event,
                sender: {
                    ...event.sender,
                    signingKey: new Uint8Array(31),
                },
            }),
        ).toBe(false);
    });

    it("content-addresses ciphertext blobs", () => {
        const blob = createRelayBlob(utf8Encode("ciphertext"));

        expect(verifyRelayBlob(blob)).toBe(true);
        expect(verifyRelayBlob({ ...blob, bytes: utf8Encode("changed") })).toBe(false);
    });

    it("derives opaque nested topics without a depth limit in the relay API", () => {
        const document = deriveNestedTopic("group", utf8Encode("document"));
        const comments = deriveNestedTopic(document, utf8Encode("comments"));

        expect(document).toMatch(/^topic:[A-Za-z0-9_-]{43}$/);
        expect(comments).toMatch(/^topic:[A-Za-z0-9_-]{43}$/);
        expect(comments).not.toBe(document);
        expect(deriveNestedTopic("group", utf8Encode("document"))).toBe(document);
    });

    it("round trips every HTTP JSON envelope without secret-key extras", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), [bob], 42);
        const subscription = createTopicSubscription(bob, "topic", 42);
        const read = createQueueReadRequest(bob, 42);
        const acknowledgement = createQueueAcknowledgeRequest(bob, "delivery", 42);

        expect(decodeRelayEventWire(encodeRelayEventWire(event))).toEqual(event);
        expect(decodeTopicSubscriptionWire(encodeTopicSubscriptionWire(subscription))).toEqual(
            subscription,
        );
        expect(decodeQueueRequestWire(encodeQueueRequestWire(read))).toEqual(read);
        expect(decodeQueueRequestWire(encodeQueueRequestWire(acknowledgement))).toEqual(
            acknowledgement,
        );
        expect(
            decodeRelayDeliveriesWire(
                encodeRelayDeliveriesWire([{ deliveryId: "delivery", event }]),
            ),
        ).toEqual([{ deliveryId: "delivery", event }]);
    });

    it("rejects an oversized HTTP response before reading its body", async () => {
        const alice = generateIdentityKeyPair();
        const transport = new HttpRelayTransport(
            "hostile",
            "https://relay.test",
            async () =>
                new Response("[]", {
                    headers: {
                        "content-length": String(33 * 1024 * 1024),
                    },
                }),
        );

        await expect(transport.pull(createQueueReadRequest(alice, 42))).rejects.toThrow(
            "too large",
        );
    });

    it("rejects extra wire fields and unacknowledgeable delivery identifiers", () => {
        const alice = generateIdentityKeyPair();
        const event = createRelayEvent(alice, "topic", utf8Encode("opaque"), [], 42);
        const eventWithExtraField = utf8Decode(encodeRelayEventWire(event)).replace(
            '"version":1,',
            '"version":1,"extra":true,',
        );
        const oversizedDeliveryId = utf8Decode(
            encodeRelayDeliveriesWire([{ deliveryId: "delivery", event }]),
        ).replace('"deliveryId":"delivery"', `"deliveryId":"${"x".repeat(257)}"`);
        const emptyDeliveryId = utf8Decode(
            encodeRelayDeliveriesWire([{ deliveryId: "delivery", event }]),
        ).replace('"deliveryId":"delivery"', '"deliveryId":""');

        expect(() => decodeRelayEventWire(utf8Encode(eventWithExtraField))).toThrow("relay event");
        expect(() => decodeRelayDeliveriesWire(utf8Encode(oversizedDeliveryId))).toThrow(
            "deliveryId",
        );
        expect(() => decodeRelayDeliveriesWire(utf8Encode(emptyDeliveryId))).toThrow("deliveryId");
    });

    it("authenticates blobs returned by the public HTTP transport", async () => {
        const expected = createRelayBlob(utf8Encode("expected"));
        const transport = new HttpRelayTransport(
            "hostile",
            "https://relay.test",
            async () => new Response(utf8Encode("tampered").slice().buffer as ArrayBuffer),
        );

        await expect(transport.getBlob(expected.id)).rejects.toThrow("content-address");
        await expect(transport.getBlob(`${expected.id.slice(0, -1)}B`)).rejects.toThrow(
            "identifier",
        );
    });
});
