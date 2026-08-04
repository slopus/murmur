import type { IdentityProfile } from "../identity/index.js";
import type { MurmurStore } from "../storage/index.js";
import type { RelayFetch } from "../transport/index.js";

/** Inputs for opening the single stateful Murmur facade. */
export interface MurmurOpenOptions {
    /** The one relay used by every friend and group stream. */
    readonly relay: string | URL;
    /** Application-owned transactional persistence. */
    readonly store: MurmurStore;
    /** Required only when the clean Murmur namespace is empty. */
    readonly initialProfile?: IdentityProfile;
    /** Optional browser-compatible fetch implementation. */
    readonly fetch?: RelayFetch;
}

/** Options for one explicit convergence boundary. */
export interface MurmurSyncOptions {
    /** Cancels outstanding relay work without discarding durable state. */
    readonly signal?: AbortSignal;
    /** Long-poll duration used only after immediate work becomes quiescent. */
    readonly waitMilliseconds?: number;
}

/** Durable lifecycle visible for one friend identity. */
export type MurmurFriendStatus = "pending-incoming" | "pending-outgoing" | "active" | "ended";

/** Defensive public view of one friend relationship. */
export interface MurmurFriend {
    /** The peer's single public Murmur identity key. */
    readonly identityKey: Uint8Array;
    /** Latest authenticated profile, when one has been received. */
    readonly profile?: IdentityProfile;
    /** Current durable relationship lifecycle. */
    readonly status: MurmurFriendStatus;
}

/** Non-constructible friend operations owned by a `Murmur` instance. */
export interface MurmurFriends {
    /** Queue an encrypted request to a public identity key. */
    request(identityKey: Uint8Array): Promise<void>;
    /** Accept one pending inbound request. */
    accept(identityKey: Uint8Array): Promise<void>;
    /** Reject one pending inbound request. */
    reject(identityKey: Uint8Array): Promise<void>;
    /** End a pending or active relationship. */
    end(identityKey: Uint8Array): Promise<void>;
    /** List every durable relationship in identity-key order. */
    list(): Promise<readonly MurmurFriend[]>;
    /** Read one relationship by public identity key. */
    get(identityKey: Uint8Array): Promise<MurmurFriend | undefined>;
}

/** Whether the local identity remains an active MLS member. */
export type MurmurGroupStatus = "active" | "removed";

/** Durable summary of one opaque MLS group stream. */
export interface MurmurGroup {
    /** Stable random MLS group identifier. */
    readonly id: Uint8Array;
    /** Application-defined opaque descriptor. */
    readonly descriptor: Uint8Array;
    /** Current authenticated member identity keys. */
    readonly members: readonly Uint8Array[];
    /** Current MLS epoch, or the last known epoch after removal. */
    readonly epoch: bigint;
    /** Local membership status. */
    readonly status: MurmurGroupStatus;
}

/** One authenticated opaque MLS application event. */
export interface MurmurGroupEvent {
    /** Stable relay order within this group stream. */
    readonly sequence: bigint;
    /** Authenticated MLS sender identity key. */
    readonly sender: Uint8Array;
    /** Application-defined opaque bytes. */
    readonly bytes: Uint8Array;
}

/** Paginated durable view of one group and its opaque events. */
export interface MurmurGroupPage {
    /** Current group summary. */
    readonly group: MurmurGroup;
    /** Events strictly after the requested sequence. */
    readonly events: readonly MurmurGroupEvent[];
    /** Sequence to use as `after` for the next page, when more events exist. */
    readonly nextAfter?: bigint;
}

/** Non-constructible group operations owned by a `Murmur` instance. */
export interface MurmurGroups {
    /**
     * Persist a one-member group and optionally queue active friends for
     * addition through ordinary MLS Commits.
     */
    create(descriptor: Uint8Array, members?: readonly Uint8Array[]): Promise<Uint8Array>;
    /** Queue one durable opaque MLS application event. */
    send(groupId: Uint8Array, bytes: Uint8Array): Promise<void>;
    /** Queue one active friend for an MLS Add transition. */
    add(groupId: Uint8Array, identityKey: Uint8Array): Promise<void>;
    /** Queue one current member for an MLS Remove transition. */
    remove(groupId: Uint8Array, identityKey: Uint8Array): Promise<void>;
    /** List every retained group in stable identifier order. */
    list(): Promise<readonly MurmurGroup[]>;
    /** Read one group and a bounded page of retained opaque events. */
    get(
        groupId: Uint8Array,
        options?: { readonly after?: bigint; readonly limit?: number },
    ): Promise<MurmurGroupPage | undefined>;
}
