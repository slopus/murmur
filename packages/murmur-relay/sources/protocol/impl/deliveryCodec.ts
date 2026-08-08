import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { RelayError } from "../errors.js";
import type {
    SignedDelivery,
    SignedDeliveryJson,
    SignedQueueAck,
    SignedQueueAckJson,
    SignedQueueRead,
    SignedQueueReadJson,
} from "../types.js";
import { decodeBase64Url, encodeBase64Url, isBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { isUuidV7 } from "../../utils/uuidV7.js";

const DELIVERY_ID_BYTES = 24;
const IDENTITY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const textEncoder = new TextEncoder();

function objectValue(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exactKeys(
    value: Record<string, unknown>,
    required: readonly string[],
    name: string,
): void {
    const allowed = new Set(required);
    if (
        required.some((key) => !Object.hasOwn(value, key)) ||
        Object.keys(value).some((key) => !allowed.has(key))
    ) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function eventCursor(value: unknown, name: string): string {
    if (typeof value !== "string" || !isUuidV7(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function bytesValue(value: unknown, name: string, expectedBytes?: number): Uint8Array {
    if (typeof value !== "string") {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        return decodeBase64Url(value, expectedBytes);
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return left.length - right.length;
}

function validateIdentity(value: unknown, name: string): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        const point = ed25519.Point.fromBytes(value, false);
        point.assertValidity();
        const canonical = point.toBytes();
        if (
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(canonical, value)
        ) {
            throw new Error("Invalid identity point");
        }
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function validateSignature(value: unknown): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array) || value.length !== SIGNATURE_BYTES) {
        throw new RelayError(400, "Invalid signature", { error: "malformed" });
    }
}

/** Return whether a delivery identifier is the canonical encoding of 24 bytes. */
export function isDeliveryId(value: string): boolean {
    return isBase64Url(value, DELIVERY_ID_BYTES);
}

/** Validate one exact in-memory delivery shape without applying relay policy. */
export function validateSignedDeliveryShape(delivery: SignedDelivery): void {
    const value = objectValue(delivery, "delivery");
    exactKeys(
        value,
        [
            "version",
            "id",
            "sender",
            "recipients",
            "createdAt",
            "expiresAt",
            "ciphertext",
            "signature",
        ],
        "delivery",
    );
    if (delivery.version !== 1 || typeof delivery.id !== "string" || !isDeliveryId(delivery.id)) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    validateIdentity(delivery.sender, "delivery sender");
    if (!Array.isArray(delivery.recipients) || delivery.recipients.length === 0) {
        throw new RelayError(400, "Invalid delivery recipients", { error: "malformed" });
    }
    let previous: Uint8Array | undefined;
    for (const recipient of delivery.recipients) {
        validateIdentity(recipient, "delivery recipient");
        if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
            throw new RelayError(400, "Delivery recipients must be sorted and unique", {
                error: "malformed",
            });
        }
        previous = recipient;
    }
    if (
        !Number.isSafeInteger(delivery.createdAt) ||
        delivery.createdAt < 0 ||
        !Number.isSafeInteger(delivery.expiresAt) ||
        delivery.expiresAt < 0 ||
        !(delivery.ciphertext instanceof Uint8Array)
    ) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    validateSignature(delivery.signature);
}

/** Convert one exact delivery to JSON. */
export function signedDeliveryToJson(delivery: SignedDelivery): SignedDeliveryJson {
    return {
        version: 1,
        id: delivery.id,
        sender: encodeBase64Url(delivery.sender),
        recipients: delivery.recipients.map(encodeBase64Url),
        createdAt: delivery.createdAt,
        expiresAt: delivery.expiresAt,
        ciphertext: encodeBase64Url(delivery.ciphertext),
        signature: encodeBase64Url(delivery.signature),
    };
}

/** Strictly decode one signed delivery. */
export function parseSignedDelivery(value: unknown): SignedDelivery {
    const input = objectValue(value, "delivery");
    exactKeys(
        input,
        [
            "version",
            "id",
            "sender",
            "recipients",
            "createdAt",
            "expiresAt",
            "ciphertext",
            "signature",
        ],
        "delivery",
    );
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !isDeliveryId(input.id) ||
        !Array.isArray(input.recipients)
    ) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    const delivery: SignedDelivery = {
        version: 1,
        id: input.id,
        sender: bytesValue(input.sender, "delivery sender", IDENTITY_BYTES),
        recipients: input.recipients.map((recipient) =>
            bytesValue(recipient, "delivery recipient", IDENTITY_BYTES),
        ),
        createdAt: safeInteger(input.createdAt, "delivery timestamp"),
        expiresAt: safeInteger(input.expiresAt, "delivery expiration"),
        ciphertext: bytesValue(input.ciphertext, "delivery ciphertext"),
        signature: bytesValue(input.signature, "delivery signature", SIGNATURE_BYTES),
    };
    validateSignedDeliveryShape(delivery);
    return delivery;
}

/** Canonical bytes covered by the delivery signature. */
export function deliverySigningBytes(delivery: SignedDelivery): Uint8Array {
    const encoded = signedDeliveryToJson(delivery);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.delivery.v1", unsigned);
}

/** Verify a delivery under its public sender identity. */
export function verifyDeliverySignature(delivery: SignedDelivery): boolean {
    try {
        return ed25519.verify(delivery.signature, deliverySigningBytes(delivery), delivery.sender, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

/** Hash the complete signed delivery for pending idempotency. */
export function deliveryFingerprint(delivery: SignedDelivery): Uint8Array {
    return sha256(canonicalJson(signedDeliveryToJson(delivery)));
}

function validateReadShape(read: SignedQueueRead): void {
    const value = objectValue(read, "queue read");
    exactKeys(
        value,
        ["version", "recipient", "after", "limit", "waitMilliseconds", "createdAt", "signature"],
        "queue read",
    );
    if (
        read.version !== 1 ||
        (read.after !== null && !isUuidV7(read.after)) ||
        !Number.isSafeInteger(read.limit) ||
        read.limit < 0 ||
        !Number.isSafeInteger(read.waitMilliseconds) ||
        read.waitMilliseconds < 0 ||
        !Number.isSafeInteger(read.createdAt) ||
        read.createdAt < 0
    ) {
        throw new RelayError(400, "Invalid queue read", { error: "malformed" });
    }
    validateIdentity(read.recipient, "queue recipient");
    validateSignature(read.signature);
}

/** Convert one signed queue read to JSON. */
export function signedQueueReadToJson(read: SignedQueueRead): SignedQueueReadJson {
    validateReadShape(read);
    return {
        version: 1,
        recipient: encodeBase64Url(read.recipient),
        after: read.after,
        limit: read.limit,
        waitMilliseconds: read.waitMilliseconds,
        createdAt: read.createdAt,
        signature: encodeBase64Url(read.signature),
    };
}

/** Strictly decode one signed queue read. */
export function parseSignedQueueRead(value: unknown): SignedQueueRead {
    const input = objectValue(value, "queue read");
    exactKeys(
        input,
        ["version", "recipient", "after", "limit", "waitMilliseconds", "createdAt", "signature"],
        "queue read",
    );
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid queue read", { error: "malformed" });
    }
    const read: SignedQueueRead = {
        version: 1,
        recipient: bytesValue(input.recipient, "queue recipient", IDENTITY_BYTES),
        after: input.after === null ? null : eventCursor(input.after, "queue cursor"),
        limit: safeInteger(input.limit, "queue limit"),
        waitMilliseconds: safeInteger(input.waitMilliseconds, "long-poll duration"),
        createdAt: safeInteger(input.createdAt, "queue read timestamp"),
        signature: bytesValue(input.signature, "queue read signature", SIGNATURE_BYTES),
    };
    validateReadShape(read);
    return read;
}

/** Canonical bytes covered by a queue-read signature. */
export function queueReadSigningBytes(read: SignedQueueRead): Uint8Array {
    const encoded = signedQueueReadToJson(read);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.queue-read.v1", unsigned);
}

/** Verify a queue read under the recipient identity. */
export function verifyQueueReadSignature(read: SignedQueueRead): boolean {
    try {
        return ed25519.verify(read.signature, queueReadSigningBytes(read), read.recipient, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

function validateAckShape(ack: SignedQueueAck): void {
    const value = objectValue(ack, "queue acknowledgement");
    exactKeys(
        value,
        ["version", "recipient", "through", "createdAt", "signature"],
        "queue acknowledgement",
    );
    if (
        ack.version !== 1 ||
        !isUuidV7(ack.through) ||
        !Number.isSafeInteger(ack.createdAt) ||
        ack.createdAt < 0
    ) {
        throw new RelayError(400, "Invalid queue acknowledgement", {
            error: "malformed",
        });
    }
    validateIdentity(ack.recipient, "queue recipient");
    validateSignature(ack.signature);
}

/** Convert one signed queue acknowledgement to JSON. */
export function signedQueueAckToJson(ack: SignedQueueAck): SignedQueueAckJson {
    validateAckShape(ack);
    return {
        version: 1,
        recipient: encodeBase64Url(ack.recipient),
        through: ack.through,
        createdAt: ack.createdAt,
        signature: encodeBase64Url(ack.signature),
    };
}

/** Strictly decode one signed queue acknowledgement. */
export function parseSignedQueueAck(value: unknown): SignedQueueAck {
    const input = objectValue(value, "queue acknowledgement");
    exactKeys(
        input,
        ["version", "recipient", "through", "createdAt", "signature"],
        "queue acknowledgement",
    );
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid queue acknowledgement", {
            error: "malformed",
        });
    }
    const ack: SignedQueueAck = {
        version: 1,
        recipient: bytesValue(input.recipient, "queue recipient", IDENTITY_BYTES),
        through: eventCursor(input.through, "acknowledgement event ID"),
        createdAt: safeInteger(input.createdAt, "acknowledgement timestamp"),
        signature: bytesValue(input.signature, "acknowledgement signature", SIGNATURE_BYTES),
    };
    validateAckShape(ack);
    return ack;
}

/** Canonical bytes covered by a queue-acknowledgement signature. */
export function queueAckSigningBytes(ack: SignedQueueAck): Uint8Array {
    const encoded = signedQueueAckToJson(ack);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.queue-ack.v1", unsigned);
}

/** Verify a queue acknowledgement under the recipient identity. */
export function verifyQueueAckSignature(ack: SignedQueueAck): boolean {
    try {
        return ed25519.verify(ack.signature, queueAckSigningBytes(ack), ack.recipient, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

function domainSeparated(domain: string, value: unknown): Uint8Array {
    const prefix = textEncoder.encode(`${domain}\0`);
    const body = canonicalJson(value);
    const result = new Uint8Array(prefix.length + body.length);
    result.set(prefix);
    result.set(body, prefix.length);
    return result;
}
