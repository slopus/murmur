import type { IdentityPublicKey } from "../crypto/index.js";
import type { StoreTransaction } from "../storage/index.js";

/** Small authenticated profile controlled by its identity. */
export interface IdentityProfile {
    /** Human-readable display name. */
    readonly name: string;
    /** Optional opaque avatar bytes. */
    readonly avatar?: Uint8Array;
    /** Optional application-defined string metadata. */
    readonly metadata?: Readonly<Record<string, string>>;
}

/** The complete public wire representation of an identity. */
export interface SerializedPublicIdentity {
    readonly publicKey: string;
}

/** Encrypted first-contact request addressed to one identity inbox. */
export interface FriendRequestEnvelope {
    readonly version: 1;
    readonly type: "friend-request";
    readonly ephemeralPublicKey: string;
    readonly nonce: string;
    readonly ciphertext: string;
}

/** Authenticated request content recovered by its intended recipient. */
export interface OpenedFriendRequest {
    readonly id: string;
    readonly previousRequestId: string | null;
    readonly sender: IdentityPublicKey;
    readonly responseAddress: string;
    readonly profile: IdentityProfile;
    readonly privateData?: Uint8Array;
}

/** Decision returned for one authenticated friend request. */
export type FriendResponseDecision = "accepted" | "rejected";

/** Encrypted response addressed back to the request author. */
export interface FriendResponseEnvelope {
    readonly version: 1;
    readonly type: "friend-response";
    readonly ephemeralPublicKey: string;
    readonly nonce: string;
    readonly ciphertext: string;
}

/** Authenticated response content recovered by the original requester. */
export type OpenedFriendResponse =
    | {
          readonly id: string;
          readonly requestId: string;
          readonly responder: IdentityPublicKey;
          readonly decision: "accepted";
          readonly responseAddress: string;
          readonly profile: IdentityProfile;
          readonly privateData?: Uint8Array;
      }
    | {
          readonly id: string;
          readonly requestId: string;
          readonly responder: IdentityPublicKey;
          readonly decision: "rejected";
      };

/** Inputs signed and encrypted into a friend request. */
export interface FriendRequestInput {
    readonly id: string;
    readonly previousRequestId: string | null;
    readonly responseAddress: string;
    readonly profile: IdentityProfile;
    readonly privateData?: Uint8Array;
}

/** Inputs signed and encrypted into a friend response. */
export type FriendResponseInput =
    | {
          readonly id: string;
          readonly requestId: string;
          readonly decision: "accepted";
          readonly responseAddress: string;
          readonly profile: IdentityProfile;
          readonly privateData?: Uint8Array;
      }
    | {
          readonly id: string;
          readonly requestId: string;
          readonly decision: "rejected";
      };

/** Durable lifecycle state for one peer identity. */
export type FriendStatus = "pending-incoming" | "pending-outgoing" | "active" | "ended";

/** Durable friend state, including bootstrap routing and opaque private data. */
export interface FriendRecord {
    readonly identity: IdentityPublicKey;
    readonly requester: IdentityPublicKey;
    readonly status: FriendStatus;
    readonly requestId: string;
    readonly previousRequestId: string | null;
    readonly nextRequestPredecessorId: string | null;
    readonly profile?: IdentityProfile;
    readonly peerResponseAddress?: string;
    readonly localResponseAddress?: string;
    readonly privateData?: Uint8Array;
    readonly createdAt: number;
    readonly updatedAt: number;
}

/** Result of accepting an inbound request or response into durable state. */
export interface FriendAcceptance<RecordType extends FriendRecord = FriendRecord> {
    readonly status: "opened" | "duplicate" | "superseded";
    readonly record: RecordType;
}

/** A response plus the state transition committed before it is published. */
export interface PreparedFriendResponse {
    readonly outbox: FriendResponseOutboxItem;
    readonly record: FriendRecord;
}

/** Options for atomically preparing a friend request and its outbox item. */
export interface CreateFriendRequestOptions {
    readonly profile: IdentityProfile;
    readonly destination: string;
    readonly responseAddress: string;
    readonly privateData?: Uint8Array;
    readonly now?: number;
}

/** Deterministic/testable construction options for durable friendship state. */
export interface FriendBookOptions {
    readonly generateId?: () => string;
}

/** Options for accepting an inbound request and preparing its response. */
export type CreateFriendResponseOptions =
    | {
          readonly decision: "accepted";
          readonly profile: IdentityProfile;
          readonly responseAddress: string;
          readonly privateData?: Uint8Array;
          readonly now?: number;
      }
    | {
          readonly decision: "rejected";
          readonly now?: number;
      };

interface FriendOutboxItemBase {
    readonly id: string;
    readonly peer: IdentityPublicKey;
    readonly destination: string;
    readonly createdAt: number;
}

/** Exact durable outgoing friend request. */
export interface FriendRequestOutboxItem extends FriendOutboxItemBase {
    readonly kind: "request";
    readonly envelope: FriendRequestEnvelope;
}

/** Exact durable outgoing friend response. */
export interface FriendResponseOutboxItem extends FriendOutboxItemBase {
    readonly kind: "response";
    readonly envelope: FriendResponseEnvelope;
}

/** Durable semantic operation which a facade seals onto the friend channel. */
export interface FriendControlIntent {
    readonly type: "friendship-ended";
    readonly requestId: string;
}

/** Exact durable control intent awaiting friend-channel publication. */
export interface FriendControlIntentOutboxItem extends FriendOutboxItemBase {
    readonly kind: "control-intent";
    readonly destination: "friend-channel";
    readonly intent: FriendControlIntent;
}

/** Exact durable request/response publication retained by `FriendBook`. */
export type FriendOutboxItem =
    | FriendRequestOutboxItem
    | FriendResponseOutboxItem
    | FriendControlIntentOutboxItem;

/** Relay-neutral successful publication outcome accepted by outbox confirmation. */
export type FriendOutboxOutcome = "accepted" | "duplicate";

/** Retention requested for an opaque friend-control payload. */
export type FriendControlRetention =
    | { readonly kind: "durable" }
    | { readonly kind: "temporary"; readonly expiresAt: number };

/** Opaque control content sent on the non-MLS friend channel. */
export interface FriendControlMessage {
    readonly id: string;
    readonly sentAt: number;
    readonly retention: FriendControlRetention;
    readonly payload: Uint8Array;
}

/** Encrypted and identity-signed friend-control wire envelope. */
export interface FriendControlEnvelope {
    readonly version: 1;
    readonly type: "friend-control";
    readonly nonce: string;
    readonly ciphertext: string;
}

/** Injectable friend-channel clock, primarily for deterministic expiry handling. */
export interface FriendChannelOptions {
    readonly now?: () => number;
}

/** Authenticated control content recovered from a friend channel. */
export interface OpenedFriendControl {
    readonly sender: IdentityPublicKey;
    readonly message: FriendControlMessage;
}

/** Durable replay result for a friend-control envelope. */
export interface AcceptedFriendControl extends OpenedFriendControl {
    readonly status: "opened" | "duplicate";
}

/** Application persistence performed atomically with replay acceptance. */
export type PersistFriendControl = (
    transaction: StoreTransaction,
    opened: OpenedFriendControl,
) => Promise<void>;
