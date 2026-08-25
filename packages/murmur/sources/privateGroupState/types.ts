import type { AccountCredential } from "../privateGroups/index.js";
import type { MurmurSession } from "../sessions/index.js";

/** Fixed roles understood by the opaque state service. */
export type PrivateGroupRole = "owner" | "administrator" | "member";

/** One deterministic encrypted account entry and its service-visible fixed role. */
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

/** A service response carrying one canonical record and its canonical hash. */
export interface StoredPrivateGroupStateRecord {
    readonly record: PrivateGroupStateRecord;
    readonly revisionHash: Uint8Array;
}

/** One role assignment for a logical account in an authenticated MLS snapshot. */
export interface PrivateGroupAccountRole {
    readonly accountIdentifier: Uint8Array;
    readonly role: PrivateGroupRole;
}

/** Service-generated, short-lived presentation challenge. */
export interface PrivateGroupPresentationChallenge {
    readonly opaqueGroupId: Uint8Array;
    readonly entry: Uint8Array;
    readonly role: PrivateGroupRole;
    readonly operation: "create" | "access";
    readonly replayNonce: Uint8Array;
    readonly context: Uint8Array;
    readonly expiresAt: number;
}

/** Proof-derived anonymous access token. */
export interface PrivateGroupAccessToken {
    readonly bytes: Uint8Array;
    readonly expiresAt: number;
}

/** Byte-only transport implemented by the private-group state service. */
export interface PrivateGroupStateTransport {
    readonly credentialIssuerPublicParameters: Uint8Array;
    credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array;
    issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly authenticationContext: Uint8Array;
    }): Promise<Uint8Array>;
    createPresentationChallenge(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly entry: Uint8Array;
        readonly role: PrivateGroupRole;
        readonly operation: "create" | "access";
    }): Promise<PrivateGroupPresentationChallenge>;
    authenticatePresentation(options: {
        readonly challenge: PrivateGroupPresentationChallenge;
        readonly publicParameters: Uint8Array;
        readonly presentation: Uint8Array;
    }): Promise<PrivateGroupAccessToken>;
    createRecord(options: {
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord>;
    readRecord(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord>;
    replaceRecord(options: {
        readonly expectedRevision: number;
        readonly expectedRevisionHash: Uint8Array;
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord>;
}

/** Accepted and decrypted state returned to private-group feature code. */
export interface PrivateGroupAcceptedState {
    readonly record: StoredPrivateGroupStateRecord;
    readonly attributes: Uint8Array;
}

/** Client construction inputs at the private-group/account/session boundary. */
export interface PrivateGroupStateClientOptions {
    readonly accountIdentifier: Uint8Array;
    readonly groupMasterSecret: Uint8Array;
    readonly transport: PrivateGroupStateTransport;
    readonly now?: () => number;
    readonly trustedTip?: {
        readonly revision: number;
        readonly revisionHash: Uint8Array;
    };
}

/** Inputs shared by initial and successor canonical record construction. */
export interface PrivateGroupRecordContent {
    readonly attributes: Uint8Array;
    readonly session: Pick<
        MurmurSession,
        "id" | "status" | "descriptor" | "members" | "owner" | "admins" | "policies"
    >;
    readonly roles: readonly PrivateGroupAccountRole[];
}

/** Opaque credential retained only by the account client. */
export type PrivateGroupAccountCredential = AccountCredential;
