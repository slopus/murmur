import type {
    FriendControlEnvelope,
    FriendRecord,
    FriendRequestEnvelope,
    FriendResponseEnvelope,
    IdentityProfile,
} from "../../identity/index.js";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import type { MurmurFriend } from "../types.js";

/** Defensive profile copy used at facade and persistence boundaries. */
export function copyProfile(profile: IdentityProfile): IdentityProfile {
    return {
        name: profile.name,
        ...(profile.avatar === undefined ? {} : { avatar: profile.avatar.slice() }),
        ...(profile.metadata === undefined ? {} : { metadata: { ...profile.metadata } }),
    };
}

/** Decode and type-bind one strict encrypted friend envelope. */
export function decodeEnvelope(
    bytes: Uint8Array,
    expected: "friend-request" | "friend-response" | "friend-control",
): FriendRequestEnvelope | FriendResponseEnvelope | FriendControlEnvelope {
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new Error("Invalid encrypted friend envelope");
    }
    const envelope = decoded as Record<string, unknown>;
    if (envelope.type !== expected) {
        throw new Error("Unexpected encrypted friend envelope");
    }
    return envelope as unknown as
        | FriendRequestEnvelope
        | FriendResponseEnvelope
        | FriendControlEnvelope;
}

/** Encode one encrypted friend envelope for an exact relay event. */
export function encodeEnvelope(
    envelope: FriendRequestEnvelope | FriendResponseEnvelope | FriendControlEnvelope,
): Uint8Array {
    return utf8Encode(JSON.stringify(envelope));
}

/** Convert durable friend state to its defensive facade view. */
export function friendView(record: FriendRecord): MurmurFriend {
    return {
        identityKey: record.identity.publicKey.slice(),
        ...(record.profile === undefined ? {} : { profile: copyProfile(record.profile) }),
        status: record.status,
    };
}

/** Whether one error is a quarantinable authenticated friend-state conflict. */
export function friendStateError(error: unknown): boolean {
    if (!(error instanceof Error)) {
        return false;
    }
    return (
        error.name.startsWith("Friend") ||
        error.message.startsWith("Friend") ||
        error.message.startsWith("Cannot receive friendship") ||
        error.message.startsWith("Authenticated friend") ||
        error.message.includes("causal predecessor") ||
        error.message.includes("does not match durable outgoing")
    );
}
