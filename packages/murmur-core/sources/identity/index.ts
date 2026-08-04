import { zeroBytes } from "../utils/index.js";
import { encodeProfilePayload } from "./impl/profileCodec.js";
import type { IdentityProfile } from "./types.js";

export type {
    AcceptedFriendControl,
    CreateFriendRequestOptions,
    CreateFriendResponseOptions,
    FriendAcceptance,
    FriendChannelOptions,
    FriendControlEnvelope,
    FriendControlMessage,
    FriendControlRetention,
    FriendOutboxItem,
    FriendOutboxOutcome,
    FriendRequestOutboxItem,
    FriendRecord,
    FriendRequestEnvelope,
    FriendRequestInput,
    FriendResponseDecision,
    FriendResponseEnvelope,
    FriendResponseInput,
    FriendResponseOutboxItem,
    FriendStatus,
    IdentityProfile,
    OpenedFriendControl,
    OpenedFriendRequest,
    OpenedFriendResponse,
    PersistFriendControl,
    PreparedFriendResponse,
    SerializedPublicIdentity,
} from "./types.js";
export {
    deserializePublicIdentity,
    identityId,
    serializePublicIdentity,
} from "./impl/identityCodec.js";
export {
    createFriendRequest,
    createFriendResponse,
    openFriendRequest,
    openFriendResponse,
} from "./impl/friendProtocol.js";
export { FriendBook, FriendExchangeIdCollisionError } from "./friendBook.js";
export {
    acceptFriendControl,
    FriendChannel,
    FriendControlIdCollisionError,
} from "./friendChannel.js";

const MAX_PROFILE_BYTES = 1024 * 1024;

/** Validate a profile against the canonical clean-rewrite encoding and bound. */
export function validateIdentityProfile(profile: IdentityProfile): void {
    const bytes = encodeProfilePayload(profile);
    try {
        if (bytes.length > MAX_PROFILE_BYTES) {
            throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
        }
    } finally {
        zeroBytes(bytes);
    }
}
