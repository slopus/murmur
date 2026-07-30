import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes, randomBytes, signBytes, verifyBytes } from "../crypto/index.js";
import { identityId, serializePublicIdentity } from "../identity/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    type JsonValue,
} from "../utils/index.js";
import type {
    QueueAcknowledgeRequest,
    QueueReadRequest,
    RelayBlob,
    RelayEvent,
    TopicSubscription,
} from "./types.js";
import { MAX_RELAY_EVENT_PAYLOAD_BYTES } from "./types.js";

export type {
    QueueAcknowledgeRequest,
    QueueReadRequest,
    RelayBlob,
    RelayDelivery,
    RelayEvent,
    RelayTransport,
    TopicSubscription,
} from "./types.js";
export { MAX_RELAY_EVENT_PAYLOAD_BYTES } from "./types.js";
export { HttpRelayTransport } from "./impl/httpTransport.js";
export {
    decodeQueueRequestWire,
    decodeRelayDeliveriesWire,
    decodeRelayEventWire,
    decodeTopicSubscriptionWire,
    encodeQueueRequestWire,
    encodeRelayDeliveriesWire,
    encodeRelayEventWire,
    encodeTopicSubscriptionWire,
} from "./impl/wireCodec.js";

export const MAX_RELAY_RECIPIENTS = 1_024;
export const MAX_RELAY_TOPIC_CHARACTERS = 512;
export const MAX_RELAY_DELIVERY_BATCH = 16;
export const MAX_NESTED_TOPIC_COMPONENT_BYTES = 1_024;

function publicIdentityJson(identity: IdentityPublicKeys): JsonValue {
    const serialized = serializePublicIdentity(identity);
    return {
        encryptionKey: serialized.encryptionKey,
        signingKey: serialized.signingKey,
    };
}

/** Derive an opaque child topic which can itself be nested without a depth limit. */
export function deriveNestedTopic(parentTopic: string, component: Uint8Array): string {
    if (
        parentTopic.length === 0 ||
        parentTopic.length > MAX_RELAY_TOPIC_CHARACTERS ||
        component.length === 0 ||
        component.length > MAX_NESTED_TOPIC_COMPONENT_BYTES
    ) {
        throw new Error("Invalid nested topic input");
    }
    return `topic:${encodeBase64Url(
        hashBytes(
            canonicalJsonBytes({
                component: encodeBase64Url(component),
                parent: parentTopic,
                version: 1,
            }),
        ),
    )}`;
}

/** Whether a string is the canonical base64url form of a 32-byte identity key. */
export function isIdentityId(value: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
        return false;
    }
    try {
        return decodeBase64Url(value).length === 32;
    } catch {
        return false;
    }
}

/** Canonical bytes signed by every relay event publisher. */
export function relayEventSignaturePayload(event: Omit<RelayEvent, "signature">): Uint8Array {
    return canonicalJsonBytes({
        createdAt: event.createdAt,
        id: event.id,
        payload: encodeBase64Url(event.payload),
        recipients: [...event.recipients].sort(),
        sender: publicIdentityJson(event.sender),
        topic: event.topic,
        version: event.version,
    });
}

/** Create a signed opaque relay event suitable for fan-out to multiple relays. */
export function createRelayEvent(
    sender: IdentityKeyPair,
    topic: string,
    payload: Uint8Array,
    recipients: readonly IdentityPublicKeys[] = [],
    now: number = Date.now(),
): RelayEvent {
    if (topic.length === 0 || topic.length > MAX_RELAY_TOPIC_CHARACTERS) {
        throw new Error(`Topic must contain 1 to ${MAX_RELAY_TOPIC_CHARACTERS} characters`);
    }
    if (!(payload instanceof Uint8Array) || payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
        throw new Error(`Event payload exceeds ${MAX_RELAY_EVENT_PAYLOAD_BYTES} bytes`);
    }
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Event time must be a non-negative safe integer");
    }

    const recipientIds = [...new Set(recipients.map((recipient) => identityId(recipient)))].sort();
    if (recipientIds.length > MAX_RELAY_RECIPIENTS) {
        throw new Error(`An event may address at most ${MAX_RELAY_RECIPIENTS} recipients`);
    }

    const unsigned = {
        version: 1 as const,
        id: encodeBase64Url(randomBytes(24)),
        topic,
        sender: {
            signingKey: sender.signingKey.slice(),
            encryptionKey: sender.encryptionKey.slice(),
        },
        recipients: recipientIds,
        createdAt: now,
        payload: payload.slice(),
    };
    return {
        ...unsigned,
        signature: signBytes(sender, relayEventSignaturePayload(unsigned)),
    };
}

/** Verify publisher authentication and stable routing fields. */
export function verifyRelayEvent(event: RelayEvent): boolean {
    try {
        if (
            event.version !== 1 ||
            !/^[A-Za-z0-9_-]{32}$/.test(event.id) ||
            decodeBase64Url(event.id).length !== 24 ||
            event.topic.length === 0 ||
            event.topic.length > MAX_RELAY_TOPIC_CHARACTERS ||
            event.payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES ||
            !Array.isArray(event.recipients) ||
            event.recipients.length > MAX_RELAY_RECIPIENTS ||
            event.recipients.some((recipient) => !isIdentityId(recipient)) ||
            !(event.payload instanceof Uint8Array) ||
            event.sender.signingKey.length !== 32 ||
            event.sender.encryptionKey.length !== 32 ||
            !Number.isSafeInteger(event.createdAt) ||
            event.createdAt < 0
        ) {
            return false;
        }
        const uniqueRecipients = [...new Set(event.recipients)].sort();
        if (
            uniqueRecipients.length !== event.recipients.length ||
            uniqueRecipients.some((recipient, index) => recipient !== event.recipients[index])
        ) {
            return false;
        }
        return verifyBytes(event.sender, relayEventSignaturePayload(event), event.signature);
    } catch {
        return false;
    }
}

/** Canonical bytes signed when subscribing an identity to a topic. */
export function topicSubscriptionSignaturePayload(
    subscription: Omit<TopicSubscription, "signature">,
): Uint8Array {
    return canonicalJsonBytes({
        createdAt: subscription.createdAt,
        subscriber: publicIdentityJson(subscription.subscriber),
        topic: subscription.topic,
        version: subscription.version,
    });
}

/** Create an authenticated topic subscription. */
export function createTopicSubscription(
    subscriber: IdentityKeyPair,
    topic: string,
    now: number = Date.now(),
): TopicSubscription {
    const unsigned = {
        version: 1 as const,
        topic,
        subscriber: {
            signingKey: subscriber.signingKey.slice(),
            encryptionKey: subscriber.encryptionKey.slice(),
        },
        createdAt: now,
    };
    return {
        ...unsigned,
        signature: signBytes(subscriber, topicSubscriptionSignaturePayload(unsigned)),
    };
}

/** Verify that a subscriber controls the routing identity. */
export function verifyTopicSubscription(subscription: TopicSubscription): boolean {
    try {
        return (
            subscription.version === 1 &&
            subscription.topic.length > 0 &&
            subscription.topic.length <= MAX_RELAY_TOPIC_CHARACTERS &&
            subscription.subscriber.signingKey.length === 32 &&
            subscription.subscriber.encryptionKey.length === 32 &&
            Number.isSafeInteger(subscription.createdAt) &&
            subscription.createdAt >= 0 &&
            verifyBytes(
                subscription.subscriber,
                topicSubscriptionSignaturePayload(subscription),
                subscription.signature,
            )
        );
    } catch {
        return false;
    }
}

type QueueRequest = QueueReadRequest | QueueAcknowledgeRequest;

/** Canonical bytes signed to authenticate queue access. */
export function queueRequestSignaturePayload(
    request: Omit<QueueReadRequest, "signature"> | Omit<QueueAcknowledgeRequest, "signature">,
): Uint8Array {
    return canonicalJsonBytes({
        action: request.action,
        createdAt: request.createdAt,
        ...(request.action === "acknowledge" ? { deliveryId: request.deliveryId } : {}),
        recipient: publicIdentityJson(request.recipient),
        requestId: request.requestId,
        version: request.version,
    });
}

/** Create a signed, single-use queue-read request. */
export function createQueueReadRequest(
    recipient: IdentityKeyPair,
    now: number = Date.now(),
): QueueReadRequest {
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Queue request time must be a non-negative safe integer");
    }
    const unsigned = {
        version: 1 as const,
        action: "read" as const,
        requestId: encodeBase64Url(randomBytes(24)),
        createdAt: now,
        recipient: {
            signingKey: recipient.signingKey.slice(),
            encryptionKey: recipient.encryptionKey.slice(),
        },
    };
    return {
        ...unsigned,
        signature: signBytes(recipient, queueRequestSignaturePayload(unsigned)),
    };
}

/** Create a signed, single-use delivery acknowledgement. */
export function createQueueAcknowledgeRequest(
    recipient: IdentityKeyPair,
    deliveryId: string,
    now: number = Date.now(),
): QueueAcknowledgeRequest {
    if (deliveryId.length === 0 || deliveryId.length > 256) {
        throw new Error("Delivery identifier must contain 1 to 256 characters");
    }
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Queue request time must be a non-negative safe integer");
    }
    const unsigned = {
        version: 1 as const,
        action: "acknowledge" as const,
        requestId: encodeBase64Url(randomBytes(24)),
        createdAt: now,
        recipient: {
            signingKey: recipient.signingKey.slice(),
            encryptionKey: recipient.encryptionKey.slice(),
        },
        deliveryId,
    };
    return {
        ...unsigned,
        signature: signBytes(recipient, queueRequestSignaturePayload(unsigned)),
    };
}

/** Verify a queue request's structure and recipient signature. */
export function verifyQueueRequest(request: QueueRequest): boolean {
    try {
        return (
            request.version === 1 &&
            (request.action === "read" || request.action === "acknowledge") &&
            /^[A-Za-z0-9_-]{32}$/.test(request.requestId) &&
            decodeBase64Url(request.requestId).length === 24 &&
            request.recipient.signingKey.length === 32 &&
            request.recipient.encryptionKey.length === 32 &&
            Number.isSafeInteger(request.createdAt) &&
            request.createdAt >= 0 &&
            (request.action !== "acknowledge" ||
                (request.deliveryId.length > 0 && request.deliveryId.length <= 256)) &&
            verifyBytes(request.recipient, queueRequestSignaturePayload(request), request.signature)
        );
    } catch {
        return false;
    }
}

/** Build a content-addressed ciphertext blob. */
export function createRelayBlob(bytes: Uint8Array): RelayBlob {
    return {
        id: encodeBase64Url(hashBytes(bytes)),
        bytes: bytes.slice(),
    };
}

/** Verify a relay blob's SHA-256 content identifier. */
export function verifyRelayBlob(blob: RelayBlob): boolean {
    return blob.id === encodeBase64Url(hashBytes(blob.bytes));
}
