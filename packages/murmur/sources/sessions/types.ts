import type { InboxSyncResult } from "../delivery/index.js";
import type {
    MurmurDeviceAdded,
    MurmurDeviceRosterEntry,
    MurmurDeviceRevoked,
    MurmurDormantDevice,
} from "../accounts/types.js";

/** Stable public view of one local MLS session. */
export interface MurmurSession {
    readonly id: Uint8Array;
    readonly status: "creating" | "pending" | "active" | "removed";
    readonly descriptor: Uint8Array;
    readonly members: readonly Uint8Array[];
    /** Immutable role owner account. */
    readonly owner: Uint8Array;
    /** Admin accounts, including the owner. */
    readonly admins: readonly Uint8Array[];
    /** Membership and role-assignment policies. */
    readonly policies: MurmurSessionPolicies;
    readonly bufferedEvents: number;
    /** True when this local session was recreated by continuity-reset convergence. */
    readonly reAdmission?: boolean;
}

/** Complete application-facing view of one session destroyed by an inbox reset. */
export interface MurmurResetSession {
    readonly id: Uint8Array;
    readonly status: MurmurSession["status"];
    readonly descriptor: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly owner: Uint8Array;
    readonly admins: readonly Uint8Array[];
    readonly policies: MurmurSessionPolicies;
}

/** Durable final event emitted before continuity-broken technical state is destroyed. */
export interface MurmurResetEvent {
    /** Stable identifier reused if the lifecycle callback must be retried. */
    readonly id: string;
    readonly reason: "inbox_continuity_lost";
    readonly generation: Uint8Array;
    readonly head: string | null;
    readonly headSequence: number;
    readonly sessions: readonly MurmurResetSession[];
}

/** Thrown after a reset is recorded, or after its one-time purge commits. */
export class MurmurResetRequiredError extends Error {
    readonly reset: MurmurResetEvent;
    readonly committed: boolean;

    constructor(reset: MurmurResetEvent, committed: boolean) {
        super(
            committed
                ? "Inbox continuity reset committed; session state was destroyed"
                : "Inbox continuity reset requires an onReset callback",
        );
        this.name = "MurmurResetRequiredError";
        this.reset = reset;
        this.committed = committed;
    }
}

/** Accounts permitted to send application events in one session epoch. */
export type MurmurSessionSendPolicy = "everyone" | "admins";

/** Owner-controlled policies for one role-managed session. */
export interface MurmurSessionPolicies {
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy: MurmurSessionSendPolicy;
}

/** Owner-controlled policy update. Omitted send policy keeps its current value. */
export interface MurmurSessionPolicyChanges {
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy?: MurmurSessionSendPolicy;
}

/** One opaque application update from the identity's ordered inbox. */
export interface MurmurUpdate {
    /** Stable relay event ID for application-level idempotency. */
    readonly id: string;
    readonly sessionId: Uint8Array;
    readonly sender: Uint8Array;
    readonly bytes: Uint8Array;
    /** Stable registered service owner, omitted for unowned sessions. */
    readonly service?: string;
}

/** Durable final lifecycle event for an owner-deleted session. */
export interface MurmurSessionDeletedEvent {
    /** Stable deletion delivery ID reused when a callback retries. */
    readonly id: string;
    readonly sessionId: Uint8Array;
    readonly owner: Uint8Array;
    readonly service: string;
}

/** Optional lifecycle configuration for the single identity-wide synchronization loop. */
export interface MurmurSyncOptions {
    /** Stops the persistent loop when aborted. Without it, sync runs until a fatal error. */
    readonly abort?: AbortSignal;
    /** Runs after one SSE connection completes its HTTP handshake. */
    readonly onConnected?: () => void | Promise<void>;
    /** Runs when that connection closes, before reconnect or final shutdown. */
    readonly onDisconnected?: (error?: unknown) => void | Promise<void>;
    /**
     * Receives the complete durable session snapshot after inbox continuity loss.
     *
     * Throwing leaves the reset pending and retries this same event. Resolving
     * authorizes Murmur's one-time technical-state purge.
     */
    readonly onReset?: (reset: MurmurResetEvent) => void | Promise<void>;
    /**
     * Runs for one ordered application-update batch.
     *
     * Murmur commits the whole batch after this hook resolves. Throwing or
     * omitting the hook leaves updates pending.
     */
    readonly onUpdates?: (updates: readonly MurmurUpdate[]) => void | Promise<void>;
    /** Runs when a device of this account is durably authorized. */
    readonly onDeviceAdded?: (devices: readonly MurmurDeviceAdded[]) => void | Promise<void>;
    /** Runs when a device of this account is durably revoked. */
    readonly onDeviceRevoked?: (devices: readonly MurmurDeviceRevoked[]) => void | Promise<void>;
    /** Runs with the refreshed owner roster after a connected relay reports a change. */
    readonly onDevicesChanged?: (
        devices: readonly MurmurDeviceRosterEntry[],
    ) => void | Promise<void>;
    /** Reports sibling devices silent for six months; revocation remains application-directed. */
    readonly onDeviceDormant?: (devices: readonly MurmurDormantDevice[]) => void | Promise<void>;
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

interface CreateMurmurSessionCommonOptions {
    readonly descriptor: Uint8Array;
    /** Stable registered service that immediately owns this locally created session. */
    readonly service?: string;
    /** Whether admins may grant admin to another member. Defaults to false. */
    readonly adminsAssignAdmins?: boolean;
    /** Whether any member may add a new member account. Defaults to false. */
    readonly anyoneCanAddMembers?: boolean;
    /** Who may send application events. Defaults to everyone. */
    readonly sendPolicy?: MurmurSessionSendPolicy;
}

/** Bare MLS admission material used until relay-directory claims are introduced. */
export interface MurmurSessionMember {
    readonly identity: Uint8Array;
    readonly keyPackage: Uint8Array;
}

/** One device-level prekey returned by an exact account directory claim. */
export interface MurmurClaimedSessionMember extends MurmurSessionMember {
    readonly device: Uint8Array;
    readonly resetGeneration: number;
    readonly source: "one_time" | "last_resort";
}

/** Ticket-authorized account claim accepted directly by session construction and Add. */
export interface MurmurAccountClaim {
    readonly identity: Uint8Array;
    readonly rosterRevision: number;
    readonly members: readonly MurmurClaimedSessionMember[];
}

/** Direct or directory-claimed admission material. */
export type MurmurSessionAdmission = MurmurSessionMember | MurmurAccountClaim;

/** Construction inputs for one new local session. */
export interface CreateMurmurSessionOptions extends CreateMurmurSessionCommonOptions {
    readonly members: readonly MurmurSessionAdmission[];
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

/** One synchronization request for delivery, outbox, and intent convergence. */
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
    readonly kind?: "application" | "commit" | "bootstrap" | "session";
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
