import {
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
} from "../../utils/index.js";
import type {
    FriendOutboxItem,
    FriendRequestEnvelope,
    FriendRequestOutboxItem,
    FriendResponseEnvelope,
    FriendResponseOutboxItem,
} from "../types.js";
import { deserializePublicIdentity, serializePublicIdentity } from "./identityCodec.js";

type FriendEnvelope = FriendRequestEnvelope | FriendResponseEnvelope;
const MAX_ENVELOPE_CIPHERTEXT_BYTES = 2 * 1024 * 1024;

function validateId(id: string): void {
    const decoded = decodeBase64Url(id);
    if (decoded.length !== 24 || encodeBase64Url(decoded) !== id) {
        throw new Error("Invalid friend outbox ID");
    }
}

/** Validate a transport-neutral destination address. */
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
        (envelope.type !== "friend-request" && envelope.type !== "friend-response")
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
export function copyFriendOutboxItem(item: FriendOutboxItem): FriendOutboxItem;
export function copyFriendOutboxItem(item: FriendOutboxItem): FriendOutboxItem {
    const common = {
        id: item.id,
        peer: { publicKey: item.peer.publicKey.slice() },
        destination: item.destination,
        createdAt: item.createdAt,
    };
    return item.kind === "request"
        ? { ...common, kind: "request", envelope: { ...item.envelope } }
        : { ...common, kind: "response", envelope: { ...item.envelope } };
}

/** Encode one exact transport-neutral outbox item. */
export function encodeFriendOutboxItem(item: FriendOutboxItem): Uint8Array {
    validateId(item.id);
    validateFriendDestination(item.destination);
    validateEnvelope(item.envelope);
    if (
        (item.kind === "request" && item.envelope.type !== "friend-request") ||
        (item.kind === "response" && item.envelope.type !== "friend-response") ||
        !Number.isSafeInteger(item.createdAt) ||
        item.createdAt < 0
    ) {
        throw new Error("Invalid friend outbox item");
    }
    return utf8Encode(
        JSON.stringify({
            version: 1,
            id: item.id,
            kind: item.kind,
            peer: serializePublicIdentity(item.peer),
            destination: item.destination,
            envelope: item.envelope,
            createdAt: item.createdAt,
        }),
    );
}

/** Decode one strict clean-rewrite outbox item. */
export function decodeFriendOutboxItem(bytes: Uint8Array): FriendOutboxItem {
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new Error("Invalid persisted friend outbox item");
    }
    const value = decoded as Record<string, unknown>;
    const fields = ["version", "id", "kind", "peer", "destination", "envelope", "createdAt"];
    if (
        Object.keys(value).length !== fields.length ||
        Object.keys(value).some((key) => !fields.includes(key)) ||
        value.version !== 1 ||
        typeof value.id !== "string" ||
        (value.kind !== "request" && value.kind !== "response") ||
        typeof value.destination !== "string" ||
        typeof value.createdAt !== "number" ||
        !Number.isSafeInteger(value.createdAt) ||
        value.createdAt < 0 ||
        typeof value.peer !== "object" ||
        value.peer === null ||
        Array.isArray(value.peer) ||
        typeof value.envelope !== "object" ||
        value.envelope === null ||
        Array.isArray(value.envelope)
    ) {
        throw new Error("Invalid persisted friend outbox item");
    }
    validateId(value.id);
    validateFriendDestination(value.destination);
    const peerValue = value.peer as Record<string, unknown>;
    if (Object.keys(peerValue).length !== 1 || typeof peerValue.publicKey !== "string") {
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
    const common = {
        id: value.id,
        peer: deserializePublicIdentity({ publicKey: peerValue.publicKey }),
        destination: value.destination,
        createdAt: value.createdAt,
    };
    return envelope.type === "friend-request"
        ? { ...common, kind: "request", envelope }
        : { ...common, kind: "response", envelope };
}

/** Compare an outbox item against exact persisted bytes. */
export function matchesFriendOutboxItem(item: FriendOutboxItem, persisted: Uint8Array): boolean {
    return equalBytes(encodeFriendOutboxItem(item), persisted);
}
