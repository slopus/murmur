import type {
    EncryptedFileDescriptor,
    IdentityPublicKeys,
    JsonValue,
    ReceivedEvent,
    StoreTransaction,
} from "@slopus/murmur";
import type { MlsKeyPackage, MlsKeyPackageBundle } from "../keyPackage/index.js";

/** Maximum UTF-8 bytes accepted for a Rig-owned opaque share identifier. */
export const MAX_SHARED_SESSION_SHARE_ID_BYTES = 128;
/** Maximum canonical JSON bytes accepted for one opaque transcript projection. */
export const MAX_SHARED_SESSION_ENTRY_BYTES = 768 * 1024;
/** Maximum UTF-8 bytes accepted for one authenticated friend post. */
export const MAX_SHARED_SESSION_POST_BYTES = 64 * 1024;
/** Maximum plaintext bytes in one encrypted history page. */
export const MAX_SHARED_SESSION_HISTORY_PAGE_BYTES = 4 * 1024 * 1024;
/** Maximum entries in one encrypted history page. */
export const MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES = 256;
/** Maximum page descriptors carried by one chained history offer. */
export const MAX_SHARED_SESSION_OFFER_PAGES = 256;
/** Maximum chained offer manifests retained while discovering history. */
export const MAX_SHARED_SESSION_HISTORY_OFFERS = 100_000;
/** Maximum active and ended member records retained for one share. */
export const MAX_SHARED_SESSION_MEMBERS = 256;
/** Maximum live entries retained durably while a member backfills history. */
export const MAX_SHARED_SESSION_PENDING_ENTRIES = 512;

/** Caller-supplied opaque owner transcript projection. */
export interface SharedSessionEntryInput {
    readonly shareSequence: number;
    readonly shareEventId: string;
    readonly timestamp: number;
    readonly payload: JsonValue;
}

/** Live owner append; Murmur mints UUIDv7 when `shareEventId` is omitted. */
export interface SharedSessionAppendInput {
    readonly shareSequence: number;
    readonly shareEventId?: string;
    readonly timestamp: number;
    readonly payload: JsonValue;
}

/** Authenticated owner transcript entry surfaced transactionally. */
export interface SharedSessionEntry extends SharedSessionEntryInput {
    readonly shareId: string;
    readonly contentHash: string;
}

/** Stable member grant controlled solely by the owner. */
export interface SharedSessionMemberGrant {
    readonly shareMemberId: string;
    readonly peerId: string;
    readonly grantEpoch: number;
    readonly status: "active" | "ended";
}

/** Transactional view of owner-authoritative share control state. */
export interface SharedSessionState {
    readonly shareId: string;
    readonly groupId: string;
    readonly ownerId: string;
    readonly stateSequence: number;
    readonly status: "active" | "stopped" | "terminated";
    readonly members: readonly SharedSessionMemberGrant[];
}

/** Authenticated friend text submitted through the shared MLS group. */
export interface SharedSessionPost {
    readonly shareId: string;
    readonly authenticatedPeerId: string;
    readonly shareMemberId: string;
    readonly grantEpoch: number;
    readonly postId: string;
    readonly timestamp: number;
    readonly text: string;
}

/** Reason all local replica rows and protocol secrets must be retired. */
export interface SharedSessionTermination {
    readonly shareId: string;
    readonly reason: "ended" | "removed" | "protocol-error";
    readonly error?: SharedSessionProtocolError;
}

/**
 * Required application hooks.
 *
 * Every hook runs inside the same `MurmurStore` transaction as the protocol
 * checkpoint, replay marker, and transport cursor which caused it.
 */
export interface SharedSessionCallbacks {
    persistEntry(transaction: StoreTransaction, entry: SharedSessionEntry): Promise<void>;
    persistState(transaction: StoreTransaction, state: SharedSessionState): Promise<void>;
    persistPost(transaction: StoreTransaction, post: SharedSessionPost): Promise<void>;
    terminate(transaction: StoreTransaction, termination: SharedSessionTermination): Promise<void>;
}

/** One bounded page supplied from Rig's authoritative transcript store. */
export interface SessionEntrySourcePage {
    readonly entries: readonly SharedSessionEntryInput[];
    readonly done: boolean;
}

/**
 * Pull-based authoritative history source.
 *
 * Murmur asks for at most the advertised entry/byte limits and never retains a
 * second plaintext transcript after a page is encrypted.
 */
export interface SessionEntrySource {
    readPage(options: {
        readonly afterSequence: number;
        readonly maximumEntries: number;
        readonly maximumBytes: number;
    }): Promise<SessionEntrySourcePage>;
}

/** One peer and authenticated one-use MLS KeyPackage to add. */
export interface SharedSessionInvitee {
    readonly identity: IdentityPublicKeys;
    readonly keyPackage: MlsKeyPackage;
}

/** Direct-message-sized invitation retained before its membership Commit. */
export interface SharedSessionInvitation {
    readonly recipient: IdentityPublicKeys;
    readonly deliveryId: string;
    readonly sentAt: number;
    readonly text: string;
}

/** Delivery boundary normally implemented with `DirectChat.sendText()`. */
export interface SharedSessionInvitationDelivery {
    deliver(invitation: SharedSessionInvitation): Promise<void>;
}

/** Result of a batch Add: one Commit, one state generation, many Welcomes. */
export interface SharedSessionInviteResult {
    readonly state: SharedSessionState;
    readonly invitations: readonly SharedSessionInvitation[];
}

/** Owner construction dependencies shared by create and load. */
export interface SharedSessionOwnerOptions {
    readonly identity: import("@slopus/murmur").IdentityKeyPair;
    readonly client: import("@slopus/murmur").MurmurClient;
    readonly store: import("@slopus/murmur").MurmurStore;
    readonly callbacks: SharedSessionCallbacks;
    readonly invitationDelivery: SharedSessionInvitationDelivery;
    readonly entrySource: SessionEntrySource;
    readonly now?: () => number;
}

/** Member construction dependencies shared by join and load. */
export interface SharedSessionMemberOptions {
    readonly identity: import("@slopus/murmur").IdentityKeyPair;
    readonly client: import("@slopus/murmur").MurmurClient;
    readonly store: import("@slopus/murmur").MurmurStore;
    readonly callbacks: SharedSessionCallbacks;
    readonly now?: () => number;
}

/** Inputs which atomically consume a local KeyPackage and adopt an invitation. */
export interface SharedSessionJoinOptions extends SharedSessionMemberOptions {
    readonly invitation: string;
    readonly keyPackageBundle: MlsKeyPackageBundle;
    readonly expectedOwner: IdentityPublicKeys;
}

/** Result of handling one existing client delivery. */
export type SharedSessionEventResult =
    | { readonly status: "unhandled"; readonly event: ReceivedEvent }
    | {
          readonly status:
              | "entry"
              | "post"
              | "state"
              | "duplicate"
              | "commit"
              | "removed"
              | "deferred"
              | "quarantined"
              | "terminated";
      };

/** Aggregate retry report which preserves independent failures. */
export interface SharedSessionRetryReport {
    readonly published: number;
    readonly historyPages: number;
    readonly failures: readonly Error[];
}

/** Encrypted page descriptor and authenticated sequence range. */
export interface SharedSessionHistoryPageDescriptor {
    readonly firstSequence: number;
    readonly lastSequence: number;
    readonly entryCount: number;
    readonly file: EncryptedFileDescriptor;
}

/** Typed authenticated protocol failure which permanently retires a replica. */
export class SharedSessionProtocolError extends Error {
    readonly code:
        | "content-collision"
        | "invalid-frame"
        | "owner-authorization"
        | "sequence-gap"
        | "unauthorized-commit"
        | "buffer-exhausted"
        | "grant-mismatch";

    constructor(code: SharedSessionProtocolError["code"], message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "SharedSessionProtocolError";
        this.code = code;
    }
}

/** A share ID is already durably bound to another group or owner. */
export class SharedSessionIdentityCollisionError extends Error {
    constructor() {
        super("Shared-session identity collides with durable state");
        this.name = "SharedSessionIdentityCollisionError";
    }
}

/** Same share sequence/event ID was authenticated with different content. */
export class SharedSessionEntryCollisionError extends SharedSessionProtocolError {
    constructor() {
        super("content-collision", "Shared-session entry identity collides with different content");
        this.name = "SharedSessionEntryCollisionError";
    }
}
