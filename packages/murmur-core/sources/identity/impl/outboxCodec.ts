import {
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import type {
    FriendControlIntentOutboxItem,
    FriendOutboxItem,
    FriendRequestEnvelope,
    FriendRequestOutboxItem,
    FriendResponseEnvelope,
    FriendResponseOutboxItem,
} from "../types.js";
import { deserializePublicIdentity, serializePublicIdentity } from "./identityCodec.js";

type FriendEnvelope = FriendRequestEnvelope | FriendResponseEnvelope;
const ID_CHARACTERS = 32;
const EPHEMERAL_KEY_CHARACTERS = 43;
const NONCE_CHARACTERS = 16;
const MAX_ENVELOPE_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
const MAX_ENVELOPE_CIPHERTEXT_CHARACTERS = Math.ceil((MAX_ENVELOPE_CIPHERTEXT_BYTES * 4) / 3);
const MAX_OUTBOX_BYTES = 3 * 1024 * 1024;

function validateId(id: string): void {
    if (id.length !== ID_CHARACTERS) {
        throw new Error("Invalid friend outbox ID");
    }
    const decoded = decodeBase64Url(id);
    if (decoded.length !== 24 || encodeBase64Url(decoded) !== id) {
        throw new Error("Invalid friend outbox ID");
    }
}

/** Validate a strict opaque relay destination address. */
export function validateFriendDestination(destination: string): void {
    const bytes = utf8Encode(destination).length;
    if (bytes === 0 || bytes > 4096) {
        throw new Error("Friend outbox destination must contain 1 to 4096 bytes");
    }
}

function validateEnvelope(envelope: FriendEnvelope): void {
    const fields = ["version", "type", "ephemeralPublicKey", "nonce", "ciphertext"];
    if (
        Object.keys(envelope).length !== fields.length ||
        Object.keys(envelope).some((key) => !fields.includes(key)) ||
        envelope.version !== 1 ||
        (envelope.type !== "friend-request" && envelope.type !== "friend-response") ||
        typeof envelope.ephemeralPublicKey !== "string" ||
        envelope.ephemeralPublicKey.length !== EPHEMERAL_KEY_CHARACTERS ||
        typeof envelope.nonce !== "string" ||
        envelope.nonce.length !== NONCE_CHARACTERS ||
        typeof envelope.ciphertext !== "string" ||
        envelope.ciphertext.length > MAX_ENVELOPE_CIPHERTEXT_CHARACTERS
    ) {
        throw new Error("Invalid friend outbox envelope");
    }
    const ephemeralPublicKey = decodeBase64Url(envelope.ephemeralPublicKey);
    const nonce = decodeBase64Url(envelope.nonce);
    const ciphertext = decodeBase64Url(envelope.ciphertext);
    if (
        ephemeralPublicKey.length !== 32 ||
        encodeBase64Url(ephemeralPublicKey) !== envelope.ephemeralPublicKey ||
        nonce.length !== 12 ||
        encodeBase64Url(nonce) !== envelope.nonce ||
        ciphertext.length > MAX_ENVELOPE_CIPHERTEXT_BYTES ||
        encodeBase64Url(ciphertext) !== envelope.ciphertext
    ) {
        throw new Error("Invalid friend outbox envelope");
    }
}

/** Deep-copy one exact outbox publication. */
export function copyFriendOutboxItem(item: FriendRequestOutboxItem): FriendRequestOutboxItem;
export function copyFriendOutboxItem(item: FriendResponseOutboxItem): FriendResponseOutboxItem;
export function copyFriendOutboxItem(
    item: FriendControlIntentOutboxItem,
): FriendControlIntentOutboxItem;
export function copyFriendOutboxItem(item: FriendOutboxItem): FriendOutboxItem;
export function copyFriendOutboxItem(item: FriendOutboxItem): FriendOutboxItem {
    const common = {
        id: item.id,
        peer: { publicKey: item.peer.publicKey.slice() },
        destination: item.destination,
        createdAt: item.createdAt,
    };
    if (item.kind === "request") {
        return { ...common, kind: "request", envelope: { ...item.envelope } };
    }
    if (item.kind === "response") {
        return { ...common, kind: "response", envelope: { ...item.envelope } };
    }
    return {
        ...common,
        kind: "control-intent",
        destination: "friend-channel",
        intent: { ...item.intent },
    };
}

/** Encode one exact relay-addressed semantic outbox item. */
export function encodeFriendOutboxItem(item: FriendOutboxItem): Uint8Array {
    validateId(item.id);
    validateFriendDestination(item.destination);
    if (!Number.isSafeInteger(item.createdAt) || item.createdAt < 0) {
        throw new Error("Invalid friend outbox item");
    }
    if (item.kind === "control-intent") {
        validateId(item.intent.requestId);
        if (item.destination !== "friend-channel" || item.intent.type !== "friendship-ended") {
            throw new Error("Invalid friend control intent");
        }
    } else {
        validateEnvelope(item.envelope);
        if (
            (item.kind === "request" && item.envelope.type !== "friend-request") ||
            (item.kind === "response" && item.envelope.type !== "friend-response")
        ) {
            throw new Error("Invalid friend outbox item");
        }
    }
    return utf8Encode(
        JSON.stringify({
            version: 1,
            id: item.id,
            kind: item.kind,
            peer: serializePublicIdentity(item.peer),
            destination: item.destination,
            envelope: item.kind === "control-intent" ? null : item.envelope,
            intent: item.kind === "control-intent" ? item.intent : null,
            createdAt: item.createdAt,
        }),
    );
}

/** Decode one strict clean-rewrite outbox item. */
export function decodeFriendOutboxItem(bytes: Uint8Array): FriendOutboxItem {
    if (bytes.length > MAX_OUTBOX_BYTES) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const value = decoded as Record<string, unknown>;
    const fields = [
        "version",
        "id",
        "kind",
        "peer",
        "destination",
        "envelope",
        "intent",
        "createdAt",
    ];
    if (
        Object.keys(value).length !== fields.length ||
        Object.keys(value).some((key) => !fields.includes(key)) ||
        value.version !== 1 ||
        typeof value.id !== "string" ||
        (value.kind !== "request" &&
            value.kind !== "response" &&
            value.kind !== "control-intent") ||
        typeof value.destination !== "string" ||
        typeof value.createdAt !== "number" ||
        !Number.isSafeInteger(value.createdAt) ||
        value.createdAt < 0 ||
        typeof value.peer !== "object" ||
        value.peer === null ||
        Array.isArray(value.peer)
    ) {
        throw new Error("Invalid persisted friend outbox item");
    }
    validateId(value.id);
    validateFriendDestination(value.destination);
    const peerValue = value.peer as Record<string, unknown>;
    if (
        Object.keys(peerValue).length !== 1 ||
        typeof peerValue.publicKey !== "string" ||
        peerValue.publicKey.length !== 43
    ) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const common = {
        id: value.id,
        peer: deserializePublicIdentity({ publicKey: peerValue.publicKey }),
        destination: value.destination,
        createdAt: value.createdAt,
    };
    if (value.kind === "control-intent") {
        if (
            value.envelope !== null ||
            value.destination !== "friend-channel" ||
            typeof value.intent !== "object" ||
            value.intent === null ||
            Array.isArray(value.intent)
        ) {
            throw new Error("Invalid persisted friend control intent");
        }
        const intent = value.intent as Record<string, unknown>;
        if (
            Object.keys(intent).length !== 2 ||
            intent.type !== "friendship-ended" ||
            typeof intent.requestId !== "string"
        ) {
            throw new Error("Invalid persisted friend control intent");
        }
        validateId(intent.requestId);
        return {
            ...common,
            kind: "control-intent",
            destination: "friend-channel",
            intent: { type: "friendship-ended", requestId: intent.requestId },
        };
    }
    if (
        value.intent !== null ||
        typeof value.envelope !== "object" ||
        value.envelope === null ||
        Array.isArray(value.envelope)
    ) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const envelopeValue = value.envelope as Record<string, unknown>;
    const envelopeFields = ["version", "type", "ephemeralPublicKey", "nonce", "ciphertext"];
    if (
        Object.keys(envelopeValue).length !== envelopeFields.length ||
        Object.keys(envelopeValue).some((key) => !envelopeFields.includes(key)) ||
        envelopeValue.version !== 1 ||
        (envelopeValue.type !== "friend-request" && envelopeValue.type !== "friend-response") ||
        typeof envelopeValue.ephemeralPublicKey !== "string" ||
        typeof envelopeValue.nonce !== "string" ||
        typeof envelopeValue.ciphertext !== "string" ||
        (value.kind === "request" && envelopeValue.type !== "friend-request") ||
        (value.kind === "response" && envelopeValue.type !== "friend-response")
    ) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const envelope: FriendEnvelope =
        envelopeValue.type === "friend-request"
            ? {
                  version: 1,
                  type: "friend-request",
                  ephemeralPublicKey: envelopeValue.ephemeralPublicKey,
                  nonce: envelopeValue.nonce,
                  ciphertext: envelopeValue.ciphertext,
              }
            : {
                  version: 1,
                  type: "friend-response",
                  ephemeralPublicKey: envelopeValue.ephemeralPublicKey,
                  nonce: envelopeValue.nonce,
                  ciphertext: envelopeValue.ciphertext,
              };
    validateEnvelope(envelope);
    return envelope.type === "friend-request"
        ? { ...common, kind: "request", envelope }
        : { ...common, kind: "response", envelope };
}

/** Compare canonical strict semantic encodings, independent of JSON insertion order. */
export function matchesFriendOutboxItem(item: FriendOutboxItem, persisted: Uint8Array): boolean {
    const decoded = decodeFriendOutboxItem(persisted);
    const expected = encodeFriendOutboxItem(item);
    const actual = encodeFriendOutboxItem(decoded);
    try {
        return equalBytes(expected, actual);
    } finally {
        zeroBytes(expected);
        zeroBytes(actual);
    }
}
