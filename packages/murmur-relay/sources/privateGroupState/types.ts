/** Service-visible fixed authorization roles for opaque member entries. */
export type PrivateGroupRole = "owner" | "administrator" | "member";

/** One deterministic encrypted account entry and its fixed service-visible role. */
export interface PrivateGroupMemberEntry {
    readonly entry: Uint8Array;
    readonly role: PrivateGroupRole;
}

/** One client-authenticated encrypted canonical private-group revision. */
export interface PrivateGroupStateRecord {
    readonly version: 1;
    readonly opaqueGroupId: Uint8Array;
    readonly publicParameters: Uint8Array;
    readonly revision: number;
    readonly previousRevisionHash: Uint8Array | null;
    readonly members: readonly PrivateGroupMemberEntry[];
    readonly sealedState: Uint8Array;
    readonly revisionAuthenticator: Uint8Array;
}

/** A stored record together with its service-computed canonical digest. */
export interface StoredPrivateGroupStateRecord {
    readonly record: PrivateGroupStateRecord;
    readonly revisionHash: Uint8Array;
    /** Server-assigned canonical UUIDv7 version. */
    readonly canonicalVersion: string;
    /** Canonical UUIDv7 version this write replaced, or null for creation. */
    readonly replacesVersion: string | null;
    /** Winning relay Commit event once backend arbitration is enabled. */
    readonly commitEventId: string | null;
}

/** Operations bound into a one-use anonymous presentation challenge. */
export type PrivateGroupChallengeOperation = "create" | "access";

/** One service-generated, short-lived, one-use presentation challenge. */
export interface PrivateGroupPresentationChallenge {
    readonly opaqueGroupId: Uint8Array;
    readonly entry: Uint8Array;
    readonly role: PrivateGroupRole;
    readonly operation: PrivateGroupChallengeOperation;
    readonly replayNonce: Uint8Array;
    readonly context: Uint8Array;
    readonly expiresAt: number;
}

/** Anonymous bearer capability returned after a successful presentation. */
export interface PrivateGroupAccessToken {
    readonly bytes: Uint8Array;
    readonly expiresAt: number;
}

/** Blind credential and presentation operations supplied by the credential authority. */
export interface PrivateGroupCredentialAuthority {
    readonly publicParameters: Uint8Array;
    issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly expiresAt: number;
        readonly now: number;
        readonly context: Uint8Array;
    }): Uint8Array | Promise<Uint8Array>;
    validateGroupPublicParameters(
        publicParameters: Uint8Array,
        expectedOpaqueGroupId: Uint8Array,
    ): boolean;
    verifyPresentation(options: {
        readonly presentation: Uint8Array;
        readonly encryptedEntry: Uint8Array;
        readonly groupPublicParameters: Uint8Array;
        readonly expectedReplayNonce: Uint8Array;
        readonly context: Uint8Array;
        readonly now: number;
    }): number | null | Promise<number | null>;
}

/** Explicit storage and replay bounds for one service instance. */
export interface PrivateGroupStateLimits {
    readonly maximumGroups: number;
    readonly maximumRecordBytes: number;
    readonly maximumSealedStateBytes: number;
    readonly maximumMembersPerGroup: number;
    readonly maximumPendingChallenges: number;
}

/** Persistence operations required by the private-group state service. */
export interface PrivateGroupStateStore {
    create(
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
        now: number,
    ): StoredPrivateGroupStateRecord | Promise<StoredPrivateGroupStateRecord>;
    replace(
        replacesVersion: string,
        expectedRevisionHash: Uint8Array,
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
        now: number,
    ): StoredPrivateGroupStateRecord | Promise<StoredPrivateGroupStateRecord>;
    read(
        opaqueGroupId: Uint8Array,
    ):
        | StoredPrivateGroupStateRecord
        | undefined
        | Promise<StoredPrivateGroupStateRecord | undefined>;
    hasMember(
        opaqueGroupId: Uint8Array,
        entry: Uint8Array,
        role: PrivateGroupRole,
    ): boolean | Promise<boolean>;
    storeChallenge(
        challenge: PrivateGroupPresentationChallenge,
        maximumPendingChallenges: number,
        now: number,
    ): void | Promise<void>;
    consumeChallenge(
        replayNonce: Uint8Array,
        now: number,
    ):
        | PrivateGroupPresentationChallenge
        | undefined
        | Promise<PrivateGroupPresentationChallenge | undefined>;
    close(): void;
}

/** Service timing and persistence construction inputs. */
export interface PrivateGroupStateServiceOptions {
    readonly store: PrivateGroupStateStore;
    readonly credentialAuthority: PrivateGroupCredentialAuthority;
    readonly tokenSecret: Uint8Array;
    readonly now?: () => number;
    readonly credentialLifetimeMilliseconds?: number;
    readonly challengeLifetimeMilliseconds?: number;
    readonly tokenLifetimeMilliseconds?: number;
    readonly limits?: Partial<PrivateGroupStateLimits>;
}
