import type { IdentityKeyPair } from "../../crypto/index.js";
import {
    randomBytes,
    signBytes,
    validateIdentityPublicKey,
    verifyBytes,
} from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Encode,
} from "../../utils/index.js";
import type {
    CreateDeliveryOptions,
    CreateInboxReadOptions,
    InboxDelivery,
    InboxContinuity,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../types.js";

const DELIVERY_DOMAIN = "murmur.relay.delivery.v1";
const READ_DOMAIN = "murmur.relay.queue-read.v1";
const ACK_DOMAIN = "murmur.relay.queue-ack.v1";
const MAXIMUM_INBOX_READ_ITEMS = 256;
const MAXIMUM_INBOX_WAIT_MILLISECONDS = 30_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface SignedDeliveryJson {
    readonly version: 1;
    readonly id: string;
    readonly sender: string;
    readonly recipients: readonly string[];
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly ciphertext: string;
    readonly signature: string;
}

export interface SignedInboxReadJson {
    readonly version: 1;
    readonly recipient: string;
    readonly after: string | null;
    readonly limit: number;
    readonly waitMilliseconds: number;
    readonly createdAt: number;
    readonly signature: string;
}

export interface SignedInboxAckJson {
    readonly version: 1;
    readonly recipient: string;
    readonly through: string;
    readonly createdAt: number;
    readonly signature: string;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return 0;
}

function validateUuid(value: unknown, name: string): string {
    if (typeof value !== "string" || !UUID_V7.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function validateDeliveryId(value: string): void {
    const bytes = decodeBase64Url(value);
    if (bytes.length !== 24 || encodeBase64Url(bytes) !== value) {
        throw new Error("Invalid delivery ID");
    }
}

function separated(domain: string, value: Parameters<typeof canonicalJsonBytes>[0]): Uint8Array {
    const prefix = utf8Encode(`${domain}\0`);
    const body = canonicalJsonBytes(value);
    const bytes = new Uint8Array(prefix.length + body.length);
    bytes.set(prefix);
    bytes.set(body, prefix.length);
    return bytes;
}

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

function deliverySigningBytes(delivery: SignedDelivery): Uint8Array {
    const { signature: _signature, ...unsigned } = signedDeliveryToJson(delivery);
    return separated(DELIVERY_DOMAIN, unsigned);
}

export function validateSignedDelivery(delivery: SignedDelivery): void {
    validateDeliveryId(delivery.id);
    validateIdentityPublicKey({ publicKey: delivery.sender });
    if (
        delivery.version !== 1 ||
        delivery.recipients.length < 1 ||
        !Number.isSafeInteger(delivery.createdAt) ||
        delivery.createdAt < 0 ||
        !Number.isSafeInteger(delivery.expiresAt) ||
        delivery.expiresAt <= delivery.createdAt ||
        delivery.signature.length !== 64
    ) {
        throw new Error("Invalid signed delivery");
    }
    let previous: Uint8Array | undefined;
    for (const recipient of delivery.recipients) {
        validateIdentityPublicKey({ publicKey: recipient });
        if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
            throw new Error("Delivery recipients must be sorted and unique");
        }
        previous = recipient;
    }
}

export function verifySignedDelivery(delivery: SignedDelivery): boolean {
    try {
        validateSignedDelivery(delivery);
        return verifyBytes(
            { publicKey: delivery.sender },
            deliverySigningBytes(delivery),
            delivery.signature,
        );
    } catch {
        return false;
    }
}

export function createSignedDelivery(
    identity: IdentityKeyPair,
    recipients: readonly Uint8Array[],
    ciphertext: Uint8Array,
    options: CreateDeliveryOptions,
): SignedDelivery {
    const createdAt = options.createdAt ?? Date.now();
    const unsigned: SignedDelivery = {
        version: 1,
        id: options.id ?? encodeBase64Url(randomBytes(24)),
        sender: identity.publicKey.slice(),
        recipients: recipients.map((value) => value.slice()).sort(compareBytes),
        createdAt,
        expiresAt: options.expiresAt,
        ciphertext: ciphertext.slice(),
        signature: new Uint8Array(64),
    };
    validateSignedDelivery(unsigned);
    return { ...unsigned, signature: signBytes(identity, deliverySigningBytes(unsigned)) };
}

function parseSignedDeliveryValue(value: unknown, validateIdentity: boolean): SignedDelivery {
    const input = object(value, "signed delivery");
    exact(
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
        "signed delivery",
    );
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        typeof input.sender !== "string" ||
        !Array.isArray(input.recipients) ||
        input.recipients.some((entry) => typeof entry !== "string") ||
        typeof input.ciphertext !== "string" ||
        typeof input.signature !== "string"
    ) {
        throw new Error("Invalid signed delivery");
    }
    const delivery: SignedDelivery = {
        version: 1,
        id: input.id,
        sender: decodeBase64Url(input.sender),
        recipients: input.recipients.map((entry) => decodeBase64Url(entry as string)),
        createdAt: safeInteger(input.createdAt, "delivery timestamp"),
        expiresAt: safeInteger(input.expiresAt, "delivery expiration"),
        ciphertext: decodeBase64Url(input.ciphertext),
        signature: decodeBase64Url(input.signature),
    };
    if (validateIdentity) {
        validateSignedDelivery(delivery);
    } else {
        validateDeliveryId(delivery.id);
        if (
            delivery.sender.length !== 32 ||
            delivery.version !== 1 ||
            delivery.recipients.length < 1 ||
            !Number.isSafeInteger(delivery.createdAt) ||
            delivery.createdAt < 0 ||
            !Number.isSafeInteger(delivery.expiresAt) ||
            delivery.expiresAt <= delivery.createdAt ||
            delivery.signature.length !== 64
        ) {
            throw new Error("Invalid signed delivery");
        }
        let previous: Uint8Array | undefined;
        for (const recipient of delivery.recipients) {
            if (recipient.length !== 32) throw new Error("Invalid delivery recipient");
            if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
                throw new Error("Delivery recipients must be sorted and unique");
            }
            previous = recipient;
        }
    }
    return delivery;
}

/** Parse one strict signed-delivery value and validate its identity point. */
export function parseSignedDelivery(value: unknown): SignedDelivery {
    return parseSignedDeliveryValue(value, true);
}

export function signedInboxReadToJson(read: SignedInboxRead): SignedInboxReadJson {
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

function readSigningBytes(read: SignedInboxRead): Uint8Array {
    const { signature: _signature, ...unsigned } = signedInboxReadToJson(read);
    return separated(READ_DOMAIN, unsigned);
}

export function createSignedInboxRead(
    identity: IdentityKeyPair,
    options: CreateInboxReadOptions = {},
): SignedInboxRead {
    const read: SignedInboxRead = {
        version: 1,
        recipient: identity.publicKey.slice(),
        after: options.after ?? null,
        limit: options.limit ?? 256,
        waitMilliseconds: options.waitMilliseconds ?? 0,
        createdAt: options.createdAt ?? Date.now(),
        signature: new Uint8Array(64),
    };
    if (
        (read.after !== null && !UUID_V7.test(read.after)) ||
        !Number.isSafeInteger(read.limit) ||
        read.limit < 1 ||
        read.limit > MAXIMUM_INBOX_READ_ITEMS ||
        !Number.isSafeInteger(read.waitMilliseconds) ||
        read.waitMilliseconds < 0 ||
        read.waitMilliseconds > MAXIMUM_INBOX_WAIT_MILLISECONDS ||
        !Number.isSafeInteger(read.createdAt) ||
        read.createdAt < 0
    ) {
        throw new Error("Invalid inbox read");
    }
    return { ...read, signature: signBytes(identity, readSigningBytes(read)) };
}

export function signedInboxAckToJson(ack: SignedInboxAck): SignedInboxAckJson {
    return {
        version: 1,
        recipient: encodeBase64Url(ack.recipient),
        through: ack.through,
        createdAt: ack.createdAt,
        signature: encodeBase64Url(ack.signature),
    };
}

function ackSigningBytes(ack: SignedInboxAck): Uint8Array {
    const { signature: _signature, ...unsigned } = signedInboxAckToJson(ack);
    return separated(ACK_DOMAIN, unsigned);
}

export function createSignedInboxAck(
    identity: IdentityKeyPair,
    through: string,
    createdAt: number = Date.now(),
): SignedInboxAck {
    validateUuid(through, "inbox acknowledgement");
    safeInteger(createdAt, "acknowledgement timestamp");
    const ack: SignedInboxAck = {
        version: 1,
        recipient: identity.publicKey.slice(),
        through,
        createdAt,
        signature: new Uint8Array(64),
    };
    return { ...ack, signature: signBytes(identity, ackSigningBytes(ack)) };
}

export function parseInboxPage(
    value: unknown,
    maximumDeliveries: number = MAXIMUM_INBOX_READ_ITEMS,
): {
    readonly deliveries: readonly InboxDelivery[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;
    readonly exhausted: boolean;
} {
    const input = object(value, "inbox page");
    exact(
        input,
        [
            "deliveries",
            "head",
            "headSequence",
            "acknowledgedThrough",
            "acknowledgedSequence",
            "generation",
            "exhausted",
        ],
        "inbox page",
    );
    if (
        !Number.isSafeInteger(maximumDeliveries) ||
        maximumDeliveries < 1 ||
        maximumDeliveries > MAXIMUM_INBOX_READ_ITEMS ||
        !Array.isArray(input.deliveries) ||
        input.deliveries.length > maximumDeliveries ||
        (input.head !== null && typeof input.head !== "string") ||
        (input.acknowledgedThrough !== null && typeof input.acknowledgedThrough !== "string") ||
        typeof input.generation !== "string" ||
        typeof input.exhausted !== "boolean"
    ) {
        throw new Error("Invalid inbox page");
    }
    return {
        deliveries: input.deliveries.map(parseInboxDelivery),
        head: input.head === null ? null : validateUuid(input.head, "inbox head"),
        headSequence: safeInteger(input.headSequence, "inbox head sequence"),
        acknowledgedThrough:
            input.acknowledgedThrough === null
                ? null
                : validateUuid(input.acknowledgedThrough, "acknowledged event ID"),
        acknowledgedSequence: safeInteger(
            input.acknowledgedSequence,
            "acknowledged inbox sequence",
        ),
        generation: (() => {
            const generation = decodeBase64Url(input.generation);
            if (generation.length !== 32) throw new Error("Invalid inbox generation");
            return generation;
        })(),
        exhausted: input.exhausted,
    };
}

/** Strictly decode one queued delivery from a relay page or SSE event. */
export function parseInboxDelivery(value: unknown): InboxDelivery {
    const queued = object(value, "queued delivery");
    exact(queued, ["eventId", "sequence", "delivery"], "queued delivery");
    return {
        eventId: validateUuid(queued.eventId, "relay event ID"),
        sequence: safeInteger(queued.sequence, "inbox sequence"),
        delivery: parseSignedDeliveryValue(queued.delivery, false),
    };
}

/** Strictly decode one relay stream continuity control frame. */
export function parseInboxContinuity(value: unknown): InboxContinuity {
    const input = object(value, "inbox continuity");
    exact(
        input,
        ["generation", "head", "headSequence", "acknowledgedThrough", "acknowledgedSequence"],
        "inbox continuity",
    );
    if (
        typeof input.generation !== "string" ||
        (input.head !== null && typeof input.head !== "string") ||
        (input.acknowledgedThrough !== null && typeof input.acknowledgedThrough !== "string")
    ) {
        throw new Error("Invalid inbox continuity");
    }
    const generation = decodeBase64Url(input.generation);
    if (generation.length !== 32) throw new Error("Invalid inbox continuity");
    return {
        type: "continuity",
        generation,
        head: input.head === null ? null : validateUuid(input.head, "inbox head"),
        headSequence: safeInteger(input.headSequence, "inbox head sequence"),
        acknowledgedThrough:
            input.acknowledgedThrough === null
                ? null
                : validateUuid(input.acknowledgedThrough, "acknowledged event ID"),
        acknowledgedSequence: safeInteger(input.acknowledgedSequence, "acknowledged sequence"),
    };
}

export function containsRecipient(delivery: SignedDelivery, recipient: Uint8Array): boolean {
    return delivery.recipients.some((value) => equalBytes(value, recipient));
}
