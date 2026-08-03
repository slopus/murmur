import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { FriendRecord } from "../types.js";
import { decodeProfilePayload, encodeProfilePayload } from "./profileCodec.js";

function exactRecord(value: unknown, allowed: readonly string[]): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Invalid persisted friend");
    }
    const record = value as Record<string, unknown>;
    if (Object.keys(record).some((key) => !allowed.includes(key))) {
        throw new Error("Invalid persisted friend");
    }
    return record;
}

/** Encode one durable friend lifecycle record. */
export function encodeFriendRecord(friend: FriendRecord): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 2,
            identity: {
                signingKey: encodeBase64Url(friend.identity.signingKey),
                encryptionKey: encodeBase64Url(friend.identity.encryptionKey),
            },
            profile: encodeBase64Url(encodeProfilePayload(friend.profile)),
            addedAt: friend.addedAt,
            updatedAt: friend.updatedAt,
            status: friend.status,
            statusUpdatedAt: friend.statusUpdatedAt,
        }),
    );
}

/** Decode one strict friend record, including legacy active ContactBook values. */
export function decodeFriendRecord(bytes: Uint8Array): FriendRecord {
    const value = exactRecord(JSON.parse(utf8Decode(bytes)) as unknown, [
        "version",
        "identity",
        "profile",
        "addedAt",
        "updatedAt",
        "status",
        "statusUpdatedAt",
    ]);
    const identity = exactRecord(value.identity, ["signingKey", "encryptionKey"]);
    if (
        (value.version !== undefined && value.version !== 2) ||
        typeof identity.signingKey !== "string" ||
        typeof identity.encryptionKey !== "string" ||
        Object.keys(identity).some((key) => !["signingKey", "encryptionKey"].includes(key)) ||
        typeof value.profile !== "string" ||
        typeof value.addedAt !== "number" ||
        !Number.isSafeInteger(value.addedAt) ||
        value.addedAt < 0 ||
        typeof value.updatedAt !== "number" ||
        !Number.isSafeInteger(value.updatedAt) ||
        value.updatedAt < value.addedAt
    ) {
        throw new Error("Invalid persisted friend");
    }
    const legacy = value.version === undefined;
    if (
        !legacy &&
        ((value.status !== "active" && value.status !== "removed") ||
            typeof value.statusUpdatedAt !== "number" ||
            !Number.isSafeInteger(value.statusUpdatedAt) ||
            value.statusUpdatedAt < value.addedAt)
    ) {
        throw new Error("Invalid persisted friend");
    }
    if (legacy && (value.status !== undefined || value.statusUpdatedAt !== undefined)) {
        throw new Error("Invalid persisted friend");
    }
    const signingKey = decodeBase64Url(identity.signingKey);
    const encryptionKey = decodeBase64Url(identity.encryptionKey);
    if (
        signingKey.length !== 32 ||
        encryptionKey.length !== 32 ||
        encodeBase64Url(signingKey) !== identity.signingKey ||
        encodeBase64Url(encryptionKey) !== identity.encryptionKey
    ) {
        throw new Error("Invalid persisted friend identity");
    }
    return {
        identity: { signingKey, encryptionKey },
        profile: decodeProfilePayload(decodeBase64Url(value.profile)),
        addedAt: value.addedAt,
        updatedAt: value.updatedAt,
        status: legacy ? "active" : (value.status as FriendRecord["status"]),
        statusUpdatedAt: legacy ? value.updatedAt : (value.statusUpdatedAt as number),
    };
}
