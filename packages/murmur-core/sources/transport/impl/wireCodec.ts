import {
    deserializePublicIdentity,
    serializePublicIdentity,
    type SerializedPublicIdentity,
} from "../../identity/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type {
    QueueAcknowledgeRequest,
    QueueReadRequest,
    RelayDelivery,
    RelayEvent,
    TopicSubscription,
} from "../types.js";
import { MAX_RELAY_EVENT_PAYLOAD_BYTES } from "../types.js";

interface WireRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly sender: SerializedPublicIdentity;
    readonly recipients: readonly string[];
    readonly createdAt: number;
    readonly payload: string;
    readonly signature: string;
}

interface WireTopicSubscription {
    readonly version: 1;
    readonly topic: string;
    readonly subscriber: SerializedPublicIdentity;
    readonly createdAt: number;
    readonly signature: string;
}

interface WireQueueRequest {
    readonly version: 1;
    readonly action: "read" | "acknowledge";
    readonly requestId: string;
    readonly createdAt: number;
    readonly recipient: SerializedPublicIdentity;
    readonly deliveryId?: string;
    readonly signature: string;
}

const MAXIMUM_EVENT_WIRE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_DELIVERY_BATCH_WIRE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_RELAY_RECIPIENTS = 1_024;
const MAXIMUM_RELAY_TOPIC_CHARACTERS = 512;
const MAXIMUM_DELIVERY_BATCH = 16;
const MAXIMUM_DELIVERY_ID_CHARACTERS = 256;
const MAXIMUM_EVENT_PAYLOAD_CHARACTERS = Math.ceil((MAX_RELAY_EVENT_PAYLOAD_BYTES * 4) / 3);

function object(value: unknown, name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exactFields(
    value: Record<string, unknown>,
    fields: readonly string[],
    name: string,
): void {
    const allowed = new Set(fields);
    if (Object.keys(value).some((field) => !allowed.has(field))) {
        throw new Error(`Invalid ${name}`);
    }
}

function stringField(value: Record<string, unknown>, key: string): string {
    const field = value[key];
    if (typeof field !== "string") {
        throw new Error(`Invalid ${key}`);
    }
    return field;
}

function boundedStringField(
    value: Record<string, unknown>,
    key: string,
    maximumCharacters: number,
): string {
    const field = stringField(value, key);
    if (field.length > maximumCharacters) {
        throw new Error(`Invalid ${key}`);
    }
    return field;
}

function numberField(value: Record<string, unknown>, key: string): number {
    const field = value[key];
    if (typeof field !== "number" || !Number.isSafeInteger(field)) {
        throw new Error(`Invalid ${key}`);
    }
    return field;
}

function identityField(value: Record<string, unknown>, key: string): SerializedPublicIdentity {
    const identity = object(value[key], key);
    exactFields(identity, ["signingKey", "encryptionKey"], key);
    return {
        signingKey: boundedStringField(identity, "signingKey", 43),
        encryptionKey: boundedStringField(identity, "encryptionKey", 43),
    };
}

function wireEvent(event: RelayEvent): WireRelayEvent {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        sender: serializePublicIdentity(event.sender),
        recipients: [...event.recipients],
        createdAt: event.createdAt,
        payload: encodeBase64Url(event.payload),
        signature: encodeBase64Url(event.signature),
    };
}

function eventFromUnknown(value: unknown): RelayEvent {
    const event = object(value, "relay event");
    exactFields(
        event,
        ["version", "id", "topic", "sender", "recipients", "createdAt", "payload", "signature"],
        "relay event",
    );
    if (event.version !== 1 || !Array.isArray(event.recipients)) {
        throw new Error("Invalid relay event");
    }
    if (event.recipients.length > MAXIMUM_RELAY_RECIPIENTS) {
        throw new Error("Invalid relay recipients");
    }
    const recipients = event.recipients.map((recipient) => {
        if (typeof recipient !== "string" || recipient.length !== 43) {
            throw new Error("Invalid relay recipient");
        }
        return recipient;
    });
    return {
        version: 1,
        id: boundedStringField(event, "id", 32),
        topic: boundedStringField(event, "topic", MAXIMUM_RELAY_TOPIC_CHARACTERS),
        sender: deserializePublicIdentity(identityField(event, "sender")),
        recipients,
        createdAt: numberField(event, "createdAt"),
        payload: decodeBase64Url(
            boundedStringField(event, "payload", MAXIMUM_EVENT_PAYLOAD_CHARACTERS),
        ),
        signature: decodeBase64Url(boundedStringField(event, "signature", 86)),
    };
}

/** Encode one event as UTF-8 JSON for an HTTP relay. */
export function encodeRelayEventWire(event: RelayEvent): Uint8Array {
    return utf8Encode(JSON.stringify(wireEvent(event)));
}

/** Decode one event from UTF-8 JSON. */
export function decodeRelayEventWire(bytes: Uint8Array): RelayEvent {
    if (bytes.length > MAXIMUM_EVENT_WIRE_BYTES) {
        throw new Error("Relay event wire payload is too large");
    }
    return eventFromUnknown(JSON.parse(utf8Decode(bytes)));
}

/** Encode one subscription as UTF-8 JSON. */
export function encodeTopicSubscriptionWire(subscription: TopicSubscription): Uint8Array {
    const value: WireTopicSubscription = {
        version: 1,
        topic: subscription.topic,
        subscriber: serializePublicIdentity(subscription.subscriber),
        createdAt: subscription.createdAt,
        signature: encodeBase64Url(subscription.signature),
    };
    return utf8Encode(JSON.stringify(value));
}

/** Decode one subscription from UTF-8 JSON. */
export function decodeTopicSubscriptionWire(bytes: Uint8Array): TopicSubscription {
    if (bytes.length > MAXIMUM_EVENT_WIRE_BYTES) {
        throw new Error("Topic subscription wire payload is too large");
    }
    const value = object(JSON.parse(utf8Decode(bytes)), "topic subscription");
    exactFields(
        value,
        ["version", "topic", "subscriber", "createdAt", "signature"],
        "topic subscription",
    );
    if (value.version !== 1) {
        throw new Error("Invalid topic subscription version");
    }
    return {
        version: 1,
        topic: boundedStringField(value, "topic", MAXIMUM_RELAY_TOPIC_CHARACTERS),
        subscriber: deserializePublicIdentity(identityField(value, "subscriber")),
        createdAt: numberField(value, "createdAt"),
        signature: decodeBase64Url(boundedStringField(value, "signature", 86)),
    };
}

function encodeQueueRequestWireValue(
    request: QueueReadRequest | QueueAcknowledgeRequest,
): WireQueueRequest {
    return {
        version: 1,
        action: request.action,
        requestId: request.requestId,
        createdAt: request.createdAt,
        recipient: serializePublicIdentity(request.recipient),
        ...(request.action === "acknowledge" ? { deliveryId: request.deliveryId } : {}),
        signature: encodeBase64Url(request.signature),
    };
}

/** Encode a signed queue request as UTF-8 JSON. */
export function encodeQueueRequestWire(
    request: QueueReadRequest | QueueAcknowledgeRequest,
): Uint8Array {
    return utf8Encode(JSON.stringify(encodeQueueRequestWireValue(request)));
}

/** Decode a signed queue request from UTF-8 JSON. */
export function decodeQueueRequestWire(
    bytes: Uint8Array,
): QueueReadRequest | QueueAcknowledgeRequest {
    if (bytes.length > MAXIMUM_EVENT_WIRE_BYTES) {
        throw new Error("Queue request wire payload is too large");
    }
    const value = object(JSON.parse(utf8Decode(bytes)), "queue request");
    if (value.version !== 1 || (value.action !== "read" && value.action !== "acknowledge")) {
        throw new Error("Invalid queue request");
    }
    exactFields(
        value,
        value.action === "read"
            ? ["version", "action", "requestId", "createdAt", "recipient", "signature"]
            : [
                  "version",
                  "action",
                  "requestId",
                  "createdAt",
                  "recipient",
                  "deliveryId",
                  "signature",
              ],
        "queue request",
    );
    const common = {
        version: 1 as const,
        requestId: boundedStringField(value, "requestId", 32),
        createdAt: numberField(value, "createdAt"),
        recipient: deserializePublicIdentity(identityField(value, "recipient")),
        signature: decodeBase64Url(boundedStringField(value, "signature", 86)),
    };
    return value.action === "read"
        ? { ...common, action: "read" }
        : {
              ...common,
              action: "acknowledge",
              deliveryId: boundedStringField(value, "deliveryId", MAXIMUM_DELIVERY_ID_CHARACTERS),
          };
}

/** Encode a delivery batch as UTF-8 JSON. */
export function encodeRelayDeliveriesWire(deliveries: readonly RelayDelivery[]): Uint8Array {
    return utf8Encode(
        JSON.stringify(
            deliveries.map((delivery) => ({
                deliveryId: delivery.deliveryId,
                event: wireEvent(delivery.event),
            })),
        ),
    );
}

/** Decode a delivery batch from UTF-8 JSON. */
export function decodeRelayDeliveriesWire(bytes: Uint8Array): readonly RelayDelivery[] {
    if (bytes.length > MAXIMUM_DELIVERY_BATCH_WIRE_BYTES) {
        throw new Error("Relay delivery batch is too large");
    }
    const value: unknown = JSON.parse(utf8Decode(bytes));
    if (!Array.isArray(value) || value.length > MAXIMUM_DELIVERY_BATCH) {
        throw new Error("Invalid relay delivery batch");
    }
    return value.map((entry) => {
        const delivery = object(entry, "relay delivery");
        exactFields(delivery, ["deliveryId", "event"], "relay delivery");
        const deliveryId = boundedStringField(
            delivery,
            "deliveryId",
            MAXIMUM_DELIVERY_ID_CHARACTERS,
        );
        if (deliveryId.length === 0) {
            throw new Error("Invalid deliveryId");
        }
        return {
            deliveryId,
            event: eventFromUnknown(delivery.event),
        };
    });
}
