import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { FriendRecord, FriendStatus, IdentityProfile } from "../types.js";
import { deserializePublicIdentity, serializePublicIdentity } from "./identityCodec.js";
import { decodeProfilePayload, encodeProfilePayload } from "./profileCodec.js";

interface StoredFriendRecord {
    readonly version: 1;
    readonly identity: { readonly publicKey: string };
    readonly requester: { readonly publicKey: string };
    readonly status: FriendStatus;
    readonly requestId: string;
    readonly previousRequestId: string | null;
    readonly nextRequestPredecessorId: string | null;
    readonly profile: string | null;
    readonly peerResponseAddress: string | null;
    readonly localResponseAddress: string | null;
    readonly privateData: string | null;
    readonly createdAt: number;
    readonly updatedAt: number;
}

const MAX_PROFILE_BYTES = 1024 * 1024;
const MAX_PRIVATE_DATA_BYTES = 256 * 1024;
const MAX_PROFILE_CHARACTERS = Math.ceil((MAX_PROFILE_BYTES * 4) / 3);
const MAX_PRIVATE_DATA_CHARACTERS = Math.ceil((MAX_PRIVATE_DATA_BYTES * 4) / 3);
const MAX_FRIEND_RECORD_BYTES = 2 * 1024 * 1024;

function validTime(value: number): boolean {
    return Number.isSafeInteger(value) && value >= 0;
}

function validExchangeId(value: string): boolean {
    if (value.length !== 32) {
        return false;
    }
    try {
        const decoded = decodeBase64Url(value);
        return decoded.length === 24 && encodeBase64Url(decoded) === value;
    } catch {
        return false;
    }
}

/** Deep-copy friend state across a mutable application boundary. */
export function copyFriendRecord(record: FriendRecord): FriendRecord {
    return {
        identity: { publicKey: record.identity.publicKey.slice() },
        requester: { publicKey: record.requester.publicKey.slice() },
        status: record.status,
        requestId: record.requestId,
        previousRequestId: record.previousRequestId,
        nextRequestPredecessorId: record.nextRequestPredecessorId,
        ...(record.profile === undefined
            ? {}
            : {
                  profile: {
                      name: record.profile.name,
                      ...(record.profile.avatar === undefined
                          ? {}
                          : { avatar: record.profile.avatar.slice() }),
                      ...(record.profile.metadata === undefined
                          ? {}
                          : { metadata: { ...record.profile.metadata } }),
                  },
              }),
        ...(record.peerResponseAddress === undefined
            ? {}
            : { peerResponseAddress: record.peerResponseAddress }),
        ...(record.localResponseAddress === undefined
            ? {}
            : { localResponseAddress: record.localResponseAddress }),
        ...(record.privateData === undefined ? {} : { privateData: record.privateData.slice() }),
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
    };
}

/** Encode clean-rewrite friend state; no prior layouts are accepted. */
export function encodeFriendRecord(record: FriendRecord): Uint8Array {
    const profileBytes =
        record.profile === undefined ? undefined : encodeProfilePayload(record.profile);
    try {
        const stored: StoredFriendRecord = {
            version: 1,
            identity: serializePublicIdentity(record.identity),
            requester: serializePublicIdentity(record.requester),
            status: record.status,
            requestId: record.requestId,
            previousRequestId: record.previousRequestId,
            nextRequestPredecessorId: record.nextRequestPredecessorId,
            profile: profileBytes === undefined ? null : encodeBase64Url(profileBytes),
            peerResponseAddress: record.peerResponseAddress ?? null,
            localResponseAddress: record.localResponseAddress ?? null,
            privateData:
                record.privateData === undefined ? null : encodeBase64Url(record.privateData),
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
        };
        return utf8Encode(JSON.stringify(stored));
    } finally {
        profileBytes?.fill(0);
    }
}

/** Decode strict clean-rewrite friend state. */
export function decodeFriendRecord(bytes: Uint8Array): FriendRecord {
    if (bytes.length > MAX_FRIEND_RECORD_BYTES) {
        throw new Error("Invalid persisted friend record");
    }
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new Error("Invalid persisted friend record");
    }
    const value = decoded as Record<string, unknown>;
    const fields = [
        "version",
        "identity",
        "requester",
        "status",
        "requestId",
        "previousRequestId",
        "nextRequestPredecessorId",
        "profile",
        "peerResponseAddress",
        "localResponseAddress",
        "privateData",
        "createdAt",
        "updatedAt",
    ];
    if (
        Object.keys(value).length !== fields.length ||
        Object.keys(value).some((key) => !fields.includes(key)) ||
        value.version !== 1 ||
        (value.status !== "pending-incoming" &&
            value.status !== "pending-outgoing" &&
            value.status !== "active" &&
            value.status !== "ended") ||
        typeof value.requestId !== "string" ||
        !validExchangeId(value.requestId) ||
        (value.previousRequestId !== null &&
            (typeof value.previousRequestId !== "string" ||
                !validExchangeId(value.previousRequestId))) ||
        (value.nextRequestPredecessorId !== null &&
            (typeof value.nextRequestPredecessorId !== "string" ||
                !validExchangeId(value.nextRequestPredecessorId))) ||
        (value.profile !== null && typeof value.profile !== "string") ||
        (typeof value.profile === "string" && value.profile.length > MAX_PROFILE_CHARACTERS) ||
        (value.peerResponseAddress !== null && typeof value.peerResponseAddress !== "string") ||
        (value.localResponseAddress !== null && typeof value.localResponseAddress !== "string") ||
        (value.privateData !== null && typeof value.privateData !== "string") ||
        (typeof value.privateData === "string" &&
            value.privateData.length > MAX_PRIVATE_DATA_CHARACTERS) ||
        typeof value.createdAt !== "number" ||
        typeof value.updatedAt !== "number" ||
        !validTime(value.createdAt) ||
        !validTime(value.updatedAt) ||
        value.updatedAt < value.createdAt ||
        typeof value.identity !== "object" ||
        value.identity === null ||
        Array.isArray(value.identity) ||
        typeof value.requester !== "object" ||
        value.requester === null ||
        Array.isArray(value.requester)
    ) {
        throw new Error("Invalid persisted friend record");
    }
    const identityValue = value.identity as Record<string, unknown>;
    if (Object.keys(identityValue).length !== 1 || typeof identityValue.publicKey !== "string") {
        throw new Error("Invalid persisted friend record");
    }
    if (identityValue.publicKey.length !== 43) {
        throw new Error("Invalid persisted friend record");
    }
    const identity = deserializePublicIdentity({ publicKey: identityValue.publicKey });
    const requesterValue = value.requester as Record<string, unknown>;
    if (Object.keys(requesterValue).length !== 1 || typeof requesterValue.publicKey !== "string") {
        throw new Error("Invalid persisted friend record");
    }
    if (requesterValue.publicKey.length !== 43) {
        throw new Error("Invalid persisted friend record");
    }
    const requester = deserializePublicIdentity({ publicKey: requesterValue.publicKey });
    let profile: IdentityProfile | undefined;
    if (typeof value.profile === "string") {
        const profileBytes = decodeBase64Url(value.profile);
        try {
            if (profileBytes.length > MAX_PROFILE_BYTES) {
                throw new Error("Invalid persisted friend record");
            }
            profile = decodeProfilePayload(profileBytes);
        } finally {
            profileBytes.fill(0);
        }
    }
    const privateData =
        typeof value.privateData === "string" ? decodeBase64Url(value.privateData) : undefined;
    let keepPrivateData = false;
    try {
        if (
            (privateData !== undefined && privateData.length > MAX_PRIVATE_DATA_BYTES) ||
            (typeof value.peerResponseAddress === "string" &&
                (utf8Encode(value.peerResponseAddress).length === 0 ||
                    utf8Encode(value.peerResponseAddress).length > 4096)) ||
            (typeof value.localResponseAddress === "string" &&
                (utf8Encode(value.localResponseAddress).length === 0 ||
                    utf8Encode(value.localResponseAddress).length > 4096)) ||
            ((value.status === "pending-incoming" || value.status === "active") &&
                (profile === undefined || typeof value.peerResponseAddress !== "string")) ||
            (value.status === "pending-outgoing" &&
                (profile !== undefined ||
                    value.peerResponseAddress !== null ||
                    typeof value.localResponseAddress !== "string" ||
                    privateData !== undefined))
        ) {
            throw new Error("Invalid persisted friend record");
        }
        const record: FriendRecord = {
            identity,
            requester,
            status: value.status,
            requestId: value.requestId,
            previousRequestId: value.previousRequestId,
            nextRequestPredecessorId: value.nextRequestPredecessorId,
            ...(profile === undefined ? {} : { profile }),
            ...(typeof value.peerResponseAddress === "string"
                ? { peerResponseAddress: value.peerResponseAddress }
                : {}),
            ...(typeof value.localResponseAddress === "string"
                ? { localResponseAddress: value.localResponseAddress }
                : {}),
            ...(privateData === undefined ? {} : { privateData }),
            createdAt: value.createdAt,
            updatedAt: value.updatedAt,
        };
        keepPrivateData = true;
        return record;
    } finally {
        if (!keepPrivateData) {
            privateData?.fill(0);
        }
    }
}
