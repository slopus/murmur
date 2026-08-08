import type { InboxSyncResult } from "../delivery/index.js";
import type { DiscoveryBundle } from "../identity/discovery/index.js";
import type { StoreTransaction } from "../storage/index.js";

/** Stable public view of one local MLS session. */
export interface MurmurSession {
    readonly id: Uint8Array;
    readonly status: "creating" | "pending" | "active" | "removed";
    readonly descriptor: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly committer: Uint8Array;
    readonly bufferedEvents: number;
}

/** One opaque application event ready for application-owned durability. */
export interface MurmurSessionEvent {
    readonly sessionId: Uint8Array;
    readonly sender: Uint8Array;
    readonly bytes: Uint8Array;
}

/** One MLS-protected member proposal awaiting committer acceptance. */
export interface MurmurSessionProposal {
    readonly id: string;
    readonly type: "add" | "remove";
    readonly proposer: Uint8Array;
    readonly identity: Uint8Array;
}

/** Bounded session-list query. */
export interface MurmurSessionListOptions {
    readonly after?: string;
    readonly limit?: number;
}

/** One bounded page of local sessions. */
export interface MurmurSessionPage {
    readonly sessions: readonly MurmurSession[];
    readonly cursor: string | null;
}

/** Transactional application callback used while draining buffered events. */
export type MurmurSessionEventHandler = (
    transaction: StoreTransaction,
    event: MurmurSessionEvent,
) => Promise<void>;

/** Construction inputs for one new local session. */
export interface CreateMurmurSessionOptions {
    readonly descriptor: Uint8Array;
    /** At least one other member, making the initial MLS group two-or-more. */
    readonly members: readonly DiscoveryBundle[];
}

/** Stateful-session resource limits. */
export interface MurmurSessionLimits {
    readonly maximumPendingSessions?: number;
    readonly maximumBufferedEventsPerSession?: number;
    readonly maximumBufferedBytesPerSession?: number;
    /** Maximum members and therefore relay recipients in one session. */
    readonly maximumMembersPerSession?: number;
    /** Maximum encoded ciphertext accepted for one relay delivery. */
    readonly maximumDeliveryCiphertextBytes?: number;
    /** Maximum durable unpublished session deliveries. */
    readonly maximumOutboxes?: number;
}

/** One synchronization request for delivery, outbox, and proposal convergence. */
export interface MurmurSynchronizeOptions {
    readonly limit?: number;
    readonly waitMilliseconds?: number;
    readonly signal?: AbortSignal;
}

/** One durable session or publication diagnostic retained by Murmur. */
export interface MurmurSessionIssue {
    readonly id: string;
    readonly code: string;
    readonly sessionId?: Uint8Array;
    readonly kind?: "application" | "proposal" | "commit" | "bootstrap" | "session";
    readonly operationId?: string;
}

/** Observable result of one synchronization cycle. */
export interface MurmurSynchronizeResult {
    readonly inbox: InboxSyncResult;
    readonly published: number;
    readonly transientPublicationFailures: number;
    readonly terminalPublicationFailures: number;
    readonly pendingOutboxes: number;
    readonly issues: readonly MurmurSessionIssue[];
}
