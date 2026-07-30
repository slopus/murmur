import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import {
    createQueueAcknowledgeRequest,
    createQueueReadRequest,
    createRelayBlob,
    createRelayEvent,
    createTopicSubscription,
    verifyRelayBlob,
    verifyRelayEvent,
    verifyQueueRequest,
    verifyTopicSubscription,
} from "../index.js";
import { utf8Encode } from "../../utils/index.js";

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
});
