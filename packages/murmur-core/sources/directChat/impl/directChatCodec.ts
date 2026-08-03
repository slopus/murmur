import type { IdentityPublicKeys } from "../../crypto/index.js";
import {
    decodePrivateMessage,
    encodePrivateMessage,
    type PrivateMessage,
} from "../../messaging/index.js";
import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    type SignedRelayEvent,
} from "../../transport/index.js";
import {
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";

export interface DirectChatSendRecord {
    readonly friend: IdentityPublicKeys;
    readonly message: PrivateMessage;
    readonly fingerprint: string;
    readonly attachmentDigests: readonly string[];
}

export interface DirectChatRelayProgress {
    readonly relayId: string;
    readonly uploadedBlobIds: readonly string[];
    readonly eventPublished: boolean;
}

export interface DirectChatOutboxRecord {
    readonly schemaVersion: 1 | 2;
    readonly event: SignedRelayEvent;
    readonly previousEvent?: SignedRelayEvent;
    readonly friend: IdentityPublicKeys;
    readonly message: PrivateMessage;
    readonly blobIds: readonly string[];
    readonly relays: readonly DirectChatRelayProgress[];
    readonly published: boolean;
}

function record(value: unknown, fields: readonly string[], name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const result = value as Record<string, unknown>;
    if (
        Object.keys(result).length !== fields.length ||
        Object.keys(result).some((key) => !fields.includes(key))
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return result;
}

function canonicalDigest(value: string): boolean {
    let decoded: Uint8Array | undefined;
    try {
        decoded = decodeBase64Url(value);
        return decoded.length === 32 && encodeBase64Url(decoded) === value;
    } catch {
        return false;
    } finally {
        if (decoded !== undefined) {
            zeroBytes(decoded);
        }
    }
}

function encodeFriend(friend: IdentityPublicKeys): {
    readonly signingKey: string;
    readonly encryptionKey: string;
} {
    if (friend.signingKey.length !== 32 || friend.encryptionKey.length !== 32) {
        throw new Error("Invalid direct-chat friend identity");
    }
    return {
        signingKey: encodeBase64Url(friend.signingKey),
        encryptionKey: encodeBase64Url(friend.encryptionKey),
    };
}

function decodeFriend(value: unknown): IdentityPublicKeys {
    const friend = record(value, ["signingKey", "encryptionKey"], "direct-chat friend");
    if (typeof friend.signingKey !== "string" || typeof friend.encryptionKey !== "string") {
        throw new Error("Invalid direct-chat friend");
    }
    const signingKey = decodeBase64Url(friend.signingKey);
    const encryptionKey = decodeBase64Url(friend.encryptionKey);
    if (
        signingKey.length !== 32 ||
        encryptionKey.length !== 32 ||
        encodeBase64Url(signingKey) !== friend.signingKey ||
        encodeBase64Url(encryptionKey) !== friend.encryptionKey
    ) {
        throw new Error("Invalid direct-chat friend");
    }
    return { signingKey, encryptionKey };
}

/** Encode the permanent canonical-send decision for application retry idempotency. */
export function encodeDirectChatSendRecord(value: DirectChatSendRecord): Uint8Array {
    const message = encodePrivateMessage(value.message);
    try {
        return utf8Encode(
            JSON.stringify({
                version: 2,
                friend: encodeFriend(value.friend),
                message: encodeBase64Url(message),
                fingerprint: value.fingerprint,
                attachmentDigests: value.attachmentDigests,
            }),
        );
    } finally {
        zeroBytes(message);
    }
}

/** Decode one strict canonical-send decision. */
export function decodeDirectChatSendRecord(bytes: Uint8Array): DirectChatSendRecord {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    const version =
        typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
            ? (parsed as Record<string, unknown>).version
            : undefined;
    const value = record(
        parsed,
        version === 1
            ? ["version", "friend", "message", "fingerprint"]
            : ["version", "friend", "message", "fingerprint", "attachmentDigests"],
        "direct-chat send record",
    );
    if (
        (value.version !== 1 && value.version !== 2) ||
        typeof value.message !== "string" ||
        typeof value.fingerprint !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(value.fingerprint) ||
        (value.version === 2 &&
            (!Array.isArray(value.attachmentDigests) ||
                value.attachmentDigests.length > 64 ||
                value.attachmentDigests.some(
                    (digest) =>
                        typeof digest !== "string" ||
                        !/^[A-Za-z0-9_-]{43}$/.test(digest) ||
                        !canonicalDigest(digest),
                )))
    ) {
        throw new Error("Invalid direct-chat send record");
    }
    const fingerprint = decodeBase64Url(value.fingerprint);
    if (fingerprint.length !== 32 || encodeBase64Url(fingerprint) !== value.fingerprint) {
        throw new Error("Invalid direct-chat send record");
    }
    const message = decodeBase64Url(value.message);
    try {
        return {
            friend: decodeFriend(value.friend),
            message: decodePrivateMessage(message),
            fingerprint: value.fingerprint,
            attachmentDigests:
                value.version === 1 ? [] : (value.attachmentDigests as readonly string[]),
        };
    } finally {
        zeroBytes(message);
    }
}

/** Encode one exact pending two-copy relay event. */
export function encodeDirectChatOutboxRecord(value: DirectChatOutboxRecord): Uint8Array {
    const event = encodeSignedRelayEventWire(value.event);
    const previousEvent =
        value.previousEvent === undefined
            ? undefined
            : encodeSignedRelayEventWire(value.previousEvent);
    const message = encodePrivateMessage(value.message);
    try {
        return utf8Encode(
            JSON.stringify({
                version: 2,
                event: encodeBase64Url(event),
                ...(previousEvent === undefined
                    ? {}
                    : { previousEvent: encodeBase64Url(previousEvent) }),
                friend: encodeFriend(value.friend),
                message: encodeBase64Url(message),
                blobIds: value.blobIds,
                relays: value.relays,
                published: value.published,
            }),
        );
    } finally {
        zeroBytes(event);
        if (previousEvent !== undefined) {
            zeroBytes(previousEvent);
        }
        zeroBytes(message);
    }
}

/** Decode one strict pending direct-chat publication. */
export function decodeDirectChatOutboxRecord(bytes: Uint8Array): DirectChatOutboxRecord {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    const hasPrevious =
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed) &&
        Object.hasOwn(parsed, "previousEvent");
    const version =
        typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
            ? (parsed as Record<string, unknown>).version
            : undefined;
    const fields =
        version === 1
            ? [
                  "version",
                  "event",
                  ...(hasPrevious ? ["previousEvent"] : []),
                  "friend",
                  "message",
                  "published",
              ]
            : [
                  "version",
                  "event",
                  ...(hasPrevious ? ["previousEvent"] : []),
                  "friend",
                  "message",
                  "blobIds",
                  "relays",
                  "published",
              ];
    const value = record(parsed, fields, "direct-chat outbox");
    if (
        (value.version !== 1 && value.version !== 2) ||
        typeof value.event !== "string" ||
        (value.previousEvent !== undefined && typeof value.previousEvent !== "string") ||
        typeof value.message !== "string" ||
        typeof value.published !== "boolean" ||
        (value.version === 2 &&
            (!Array.isArray(value.blobIds) ||
                value.blobIds.length > 64 ||
                value.blobIds.some(
                    (blobId) => typeof blobId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(blobId),
                ) ||
                !Array.isArray(value.relays) ||
                value.relays.length > 256))
    ) {
        throw new Error("Invalid direct-chat outbox");
    }
    const relays: DirectChatRelayProgress[] =
        value.version === 1
            ? []
            : (value.relays as readonly unknown[]).map((item) => {
                  const relay = record(
                      item,
                      ["relayId", "uploadedBlobIds", "eventPublished"],
                      "direct-chat relay progress",
                  );
                  if (
                      typeof relay.relayId !== "string" ||
                      relay.relayId.length === 0 ||
                      relay.relayId.length > 1_024 ||
                      !Array.isArray(relay.uploadedBlobIds) ||
                      relay.uploadedBlobIds.length > 64 ||
                      relay.uploadedBlobIds.some(
                          (blobId) =>
                              typeof blobId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(blobId),
                      ) ||
                      typeof relay.eventPublished !== "boolean"
                  ) {
                      throw new Error("Invalid direct-chat relay progress");
                  }
                  return {
                      relayId: relay.relayId,
                      uploadedBlobIds: relay.uploadedBlobIds as readonly string[],
                      eventPublished: relay.eventPublished,
                  };
              });
    const event = decodeBase64Url(value.event);
    const previousEvent =
        value.previousEvent === undefined ? undefined : decodeBase64Url(value.previousEvent);
    const message = decodeBase64Url(value.message);
    try {
        return {
            schemaVersion: value.version,
            event: decodeSignedRelayEventWire(event),
            ...(previousEvent === undefined
                ? {}
                : { previousEvent: decodeSignedRelayEventWire(previousEvent) }),
            friend: decodeFriend(value.friend),
            message: decodePrivateMessage(message),
            blobIds: value.version === 1 ? [] : (value.blobIds as readonly string[]),
            relays,
            published: value.published,
        };
    } finally {
        zeroBytes(event);
        if (previousEvent !== undefined) {
            zeroBytes(previousEvent);
        }
        zeroBytes(message);
    }
}
