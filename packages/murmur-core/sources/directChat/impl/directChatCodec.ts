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
}

export interface DirectChatOutboxRecord {
    readonly event: SignedRelayEvent;
    readonly friend: IdentityPublicKeys;
    readonly message: PrivateMessage;
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
                version: 1,
                friend: encodeFriend(value.friend),
                message: encodeBase64Url(message),
                fingerprint: value.fingerprint,
            }),
        );
    } finally {
        zeroBytes(message);
    }
}

/** Decode one strict canonical-send decision. */
export function decodeDirectChatSendRecord(bytes: Uint8Array): DirectChatSendRecord {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "friend", "message", "fingerprint"],
        "direct-chat send record",
    );
    if (
        value.version !== 1 ||
        typeof value.message !== "string" ||
        typeof value.fingerprint !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(value.fingerprint)
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
        };
    } finally {
        zeroBytes(message);
    }
}

/** Encode one exact pending two-copy relay event. */
export function encodeDirectChatOutboxRecord(value: DirectChatOutboxRecord): Uint8Array {
    const event = encodeSignedRelayEventWire(value.event);
    const message = encodePrivateMessage(value.message);
    try {
        return utf8Encode(
            JSON.stringify({
                version: 1,
                event: encodeBase64Url(event),
                friend: encodeFriend(value.friend),
                message: encodeBase64Url(message),
            }),
        );
    } finally {
        zeroBytes(event);
        zeroBytes(message);
    }
}

/** Decode one strict pending direct-chat publication. */
export function decodeDirectChatOutboxRecord(bytes: Uint8Array): DirectChatOutboxRecord {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "event", "friend", "message"],
        "direct-chat outbox",
    );
    if (
        value.version !== 1 ||
        typeof value.event !== "string" ||
        typeof value.message !== "string"
    ) {
        throw new Error("Invalid direct-chat outbox");
    }
    const event = decodeBase64Url(value.event);
    const message = decodeBase64Url(value.message);
    try {
        return {
            event: decodeSignedRelayEventWire(event),
            friend: decodeFriend(value.friend),
            message: decodePrivateMessage(message),
        };
    } finally {
        zeroBytes(event);
        zeroBytes(message);
    }
}
