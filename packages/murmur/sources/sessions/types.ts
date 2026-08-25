import type { InboxSyncResult } from "../delivery/index.js";
import type { DiscoveryBundle } from "../identity/discovery/index.js";
import type {
    MurmurContactAdded,
    MurmurContactRemoved,
    MurmurContactRequested,
    MurmurContactUpdated,
} from "../contacts/types.js";
import type {
    MurmurContactRosterChanged,
    MurmurDeviceAdded,
    MurmurDeviceRevoked,
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
}

/** Owner-controlled policies for one role-managed session. */
export interface MurmurSessionPolicies {
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
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

/** Optional lifecycle configuration for the single identity-wide synchronization loop. */
export interface MurmurSyncOptions {
    /** Stops the persistent loop when aborted. Without it, sync runs until a fatal error. */
    readonly abort?: AbortSignal;
    /** Runs after one SSE connection completes its HTTP handshake. */
    readonly onConnected?: () => void | Promise<void>;
    /** Runs when that connection closes, before reconnect or final shutdown. */
    readonly onDisconnected?: (error?: unknown) => void | Promise<void>;
    /**
     * Runs for one ordered application-update batch.
     *
     * Murmur commits the whole batch after this hook resolves. Throwing or
     * omitting the hook leaves updates pending.
     */
    readonly onUpdates?: (updates: readonly MurmurUpdate[]) => void | Promise<void>;
    /** Runs for validated incoming contact requests in the same durable batch. */
    readonly onContactRequested?: (
        requests: readonly MurmurContactRequested[],
    ) => void | Promise<void>;
    /** Runs when mutual profile hellos establish confirmed contacts. */
    readonly onContactAdded?: (contacts: readonly MurmurContactAdded[]) => void | Promise<void>;
    /** Runs when an established contact publishes a newer authenticated profile. */
    readonly onContactUpdated?: (contacts: readonly MurmurContactUpdated[]) => void | Promise<void>;
    /** Runs when technical contact sessions are removed. */
    readonly onContactRemoved?: (contacts: readonly MurmurContactRemoved[]) => void | Promise<void>;
    /** Runs when a device of this account is durably authorized. */
    readonly onDeviceAdded?: (devices: readonly MurmurDeviceAdded[]) => void | Promise<void>;
    /** Runs when a device of this account is durably revoked. */
    readonly onDeviceRevoked?: (devices: readonly MurmurDeviceRevoked[]) => void | Promise<void>;
    /** Runs when an authenticated contact roster adds or revokes a device. */
    readonly onContactRosterChanged?: (
        changes: readonly MurmurContactRosterChanged[],
    ) => void | Promise<void>;
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
}

/** Construction inputs for one new local session. */
export type CreateMurmurSessionOptions =
    | (CreateMurmurSessionCommonOptions & {
          /** Confirmed contact identities admitted from their cached KeyPackages. */
          readonly contacts: readonly Uint8Array[];
          readonly members?: never;
      })
    | (CreateMurmurSessionCommonOptions & {
          /** Direct discovery material used by low-level bootstrap workflows. */
          readonly members: readonly DiscoveryBundle[];
          readonly contacts?: never;
      });

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
