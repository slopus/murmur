import type { CredentialIssuerPublicParameters } from "../../privateGroups/index.js";
import {
    createCredentialIssuanceRequest,
    createEncryptedUid,
    createUidPresentation,
    decodeCredentialIssuanceResponse,
    decodeCredentialIssuerPublicParameters,
    derivePrivateGroupParameters,
    destroyCredentialIssuanceState,
    destroyPrivateGroupParameters,
    encodeCredentialIssuanceRequest,
    encodeEncryptedUid,
    encodePrivateGroupPublicParameters,
    encodeUidPresentation,
    finalizeCredentialIssuance,
    privateGroupPublicParameters,
    type PrivateGroupParameters,
} from "../../privateGroups/index.js";
import { encodeBase64Url, equalBytes, zeroBytes } from "../../utils/index.js";
import type {
    PrivateGroupAcceptedState,
    PrivateGroupAccessToken,
    PrivateGroupAccountCredential,
    PrivateGroupMemberEntry,
    PrivateGroupPresentationChallenge,
    PrivateGroupRecordContent,
    PrivateGroupRole,
    PrivateGroupStateClientOptions,
    PrivateGroupStateRecord,
    PrivateGroupStateTransport,
    StoredPrivateGroupStateRecord,
} from "../types.js";
import {
    createPrivateGroupStateRecord,
    openPrivateGroupStateRecord,
    privateGroupStateRecordHash,
} from "./recordCodec.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function isUuidV7(value: string): boolean {
    return UUID_V7.test(value);
}

/** Experimental private-group state client bound to one account and one group secret. */
export class PrivateGroupStateClient {
    readonly #accountIdentifier: Uint8Array;
    readonly #parameters: PrivateGroupParameters;
    readonly #publicParameters: Uint8Array;
    readonly #issuer: CredentialIssuerPublicParameters;
    readonly #transport: PrivateGroupStateTransport;
    readonly #now: () => number;
    #trustedCanonicalVersion: string | undefined;
    #trustedRevision: number | undefined;
    #trustedRevisionHash: Uint8Array | undefined;
    #closed = false;

    constructor(options: PrivateGroupStateClientOptions) {
        if (options.accountIdentifier.length !== 32) {
            throw new Error("Private-group account identifier must be 32 bytes");
        }
        this.#accountIdentifier = options.accountIdentifier.slice();
        this.#parameters = derivePrivateGroupParameters(options.groupMasterSecret);
        this.#publicParameters = encodePrivateGroupPublicParameters(
            privateGroupPublicParameters(this.#parameters),
        );
        this.#issuer = decodeCredentialIssuerPublicParameters(
            options.transport.credentialIssuerPublicParameters,
        );
        this.#transport = options.transport;
        this.#now = options.now ?? Date.now;
        if (options.trustedTip !== undefined) {
            if (
                !isUuidV7(options.trustedTip.canonicalVersion) ||
                !Number.isSafeInteger(options.trustedTip.revision) ||
                options.trustedTip.revision < 1 ||
                options.trustedTip.revisionHash.length !== 32
            ) {
                throw new Error("Invalid trusted private-group revision tip");
            }
            this.#trustedCanonicalVersion = options.trustedTip.canonicalVersion;
            this.#trustedRevision = options.trustedTip.revision;
            this.#trustedRevisionHash = options.trustedTip.revisionHash.slice();
        }
    }

    /** Defensive copy of this group's opaque service capability. */
    get opaqueGroupId(): Uint8Array {
        this.#assertOpen();
        return this.#parameters.opaqueGroupId.slice();
    }

    /** Deterministic group-scoped encrypted entry for this logical account. */
    get ownEncryptedEntry(): Uint8Array {
        this.#assertOpen();
        return encodeEncryptedUid(createEncryptedUid(this.#accountIdentifier, this.#parameters));
    }

    /** Current rollback-protected local tip, if this client has accepted one. */
    get trustedTip():
        | {
              readonly canonicalVersion: string;
              readonly revision: number;
              readonly revisionHash: Uint8Array;
          }
        | undefined {
        this.#assertOpen();
        return this.#trustedCanonicalVersion === undefined ||
            this.#trustedRevision === undefined ||
            this.#trustedRevisionHash === undefined
            ? undefined
            : {
                  canonicalVersion: this.#trustedCanonicalVersion,
                  revision: this.#trustedRevision,
                  revisionHash: this.#trustedRevisionHash.slice(),
              };
    }

    /** Blindly obtain one short-lived credential through the authenticated service boundary. */
    async obtainCredential(
        authenticationContext: Uint8Array,
    ): Promise<PrivateGroupAccountCredential> {
        this.#assertOpen();
        const context = this.#transport.credentialIssuanceContext(authenticationContext);
        const state = createCredentialIssuanceRequest(
            this.#accountIdentifier,
            this.#issuer,
            context,
        );
        try {
            const response = await this.#transport.issueCredential({
                authenticatedAccountIdentifier: this.#accountIdentifier,
                request: encodeCredentialIssuanceRequest(state.request),
                authenticationContext,
            });
            return finalizeCredentialIssuance({
                state,
                response: decodeCredentialIssuanceResponse(response),
                accountIdentifier: this.#accountIdentifier,
                parameters: this.#issuer,
                context,
            });
        } finally {
            destroyCredentialIssuanceState(state);
        }
    }

    /** Create the randomized presentation bytes for one exact service challenge. */
    createPresentation(
        credential: PrivateGroupAccountCredential,
        challenge: PrivateGroupPresentationChallenge,
    ): Uint8Array {
        this.#assertOpen();
        if (
            !equalBytes(challenge.opaqueGroupId, this.#parameters.opaqueGroupId) ||
            !equalBytes(challenge.entry, this.ownEncryptedEntry)
        ) {
            throw new Error("Private-group challenge does not name this account entry");
        }
        return encodeUidPresentation(
            createUidPresentation({
                credential,
                accountIdentifier: this.#accountIdentifier,
                encryptedUid: createEncryptedUid(this.#accountIdentifier, this.#parameters),
                group: this.#parameters,
                issuer: this.#issuer,
                replayNonce: challenge.replayNonce,
                context: challenge.context,
                now: this.#safeNow(),
            }),
        );
    }

    /** Prove anonymous membership and obtain an exact group/entry/role token. */
    async authorize(
        credential: PrivateGroupAccountCredential,
        role: PrivateGroupRole,
        operation: "create" | "access",
    ): Promise<PrivateGroupAccessToken> {
        this.#assertOpen();
        const challenge = await this.#transport.createPresentationChallenge({
            opaqueGroupId: this.#parameters.opaqueGroupId,
            entry: this.ownEncryptedEntry,
            role,
            operation,
        });
        return await this.#transport.authenticatePresentation({
            challenge,
            publicParameters: this.#publicParameters,
            presentation: this.createPresentation(credential, challenge),
        });
    }

    /** Build an authenticated revision-one record without publishing it. */
    buildInitialRecord(content: PrivateGroupRecordContent): PrivateGroupStateRecord {
        this.#assertOpen();
        return createPrivateGroupStateRecord({
            parameters: this.#parameters,
            publicParameters: this.#publicParameters,
            revision: 1,
            previousRevisionHash: null,
            members: this.#memberEntries(content),
            content,
        });
    }

    /** Build one authenticated direct child of a previously fetched canonical record. */
    buildSuccessorRecord(
        current: StoredPrivateGroupStateRecord,
        content: PrivateGroupRecordContent,
    ): PrivateGroupStateRecord {
        this.#assertOpen();
        if (
            !equalBytes(current.record.opaqueGroupId, this.#parameters.opaqueGroupId) ||
            !equalBytes(privateGroupStateRecordHash(current.record), current.revisionHash)
        ) {
            throw new Error("Cannot extend an invalid private-group revision");
        }
        if (
            this.#trustedCanonicalVersion !== current.canonicalVersion ||
            this.#trustedRevision !== current.record.revision ||
            this.#trustedRevisionHash === undefined ||
            !equalBytes(this.#trustedRevisionHash, current.revisionHash)
        ) {
            throw new Error("Cannot extend a private-group revision before accepting it");
        }
        return createPrivateGroupStateRecord({
            parameters: this.#parameters,
            publicParameters: this.#publicParameters,
            revision: current.record.revision + 1,
            previousRevisionHash: current.revisionHash,
            members: this.#memberEntries(content),
            content,
        });
    }

    /** Verify/decrypt a canonical response and advance the local rollback-protected tip. */
    acceptRecord(
        stored: StoredPrivateGroupStateRecord,
        content: Pick<PrivateGroupRecordContent, "session" | "roles">,
    ): PrivateGroupAcceptedState {
        this.#assertOpen();
        const expectedMembers = this.#memberEntries({
            attributes: new Uint8Array(),
            session: content.session,
            roles: content.roles,
        });
        const attributes = openPrivateGroupStateRecord({
            stored,
            parameters: this.#parameters,
            publicParameters: this.#publicParameters,
            expectedMembers,
            content: { session: content.session },
        });
        try {
            this.#acceptRevisionTip(stored);
            return { record: stored, attributes };
        } catch (error: unknown) {
            zeroBytes(attributes);
            throw error;
        }
    }

    /** Authorize creation, publish revision one, and accept the returned canonical tip. */
    async createGroup(
        credential: PrivateGroupAccountCredential,
        content: PrivateGroupRecordContent,
    ): Promise<PrivateGroupAcceptedState> {
        this.#assertOpen();
        const ownRole = this.#roleForOwnAccount(content);
        if (ownRole !== "owner") throw new Error("Private-group creator must have owner role");
        const token = await this.authorize(credential, ownRole, "create");
        const stored = await this.#transport.createRecord({
            record: this.buildInitialRecord(content),
            token: token.bytes,
        });
        return this.acceptRecord(stored, content);
    }

    /** Read, authenticate, decrypt, and MLS-bind the current canonical record. */
    async readGroup(
        token: PrivateGroupAccessToken,
        content: Pick<PrivateGroupRecordContent, "session" | "roles">,
    ): Promise<PrivateGroupAcceptedState> {
        this.#assertOpen();
        const stored = await this.#transport.readRecord({
            opaqueGroupId: this.#parameters.opaqueGroupId,
            token: token.bytes,
        });
        return this.acceptRecord(stored, content);
    }

    /** Publish and accept one direct canonical child after the matching MLS state exists. */
    async replaceGroup(
        token: PrivateGroupAccessToken,
        current: StoredPrivateGroupStateRecord,
        content: PrivateGroupRecordContent,
    ): Promise<PrivateGroupAcceptedState> {
        this.#assertOpen();
        const stored = await this.#transport.replaceRecord({
            replacesVersion: current.canonicalVersion,
            expectedRevisionHash: current.revisionHash,
            record: this.buildSuccessorRecord(current, content),
            token: token.bytes,
        });
        return this.acceptRecord(stored, content);
    }

    /** Destroy member-only group parameters and local account material. */
    close(): void {
        if (!this.#closed) {
            this.#closed = true;
            this.#accountIdentifier.fill(0);
            this.#publicParameters.fill(0);
            if (this.#trustedRevisionHash !== undefined) this.#trustedRevisionHash.fill(0);
            destroyPrivateGroupParameters(this.#parameters);
        }
    }

    #memberEntries(content: PrivateGroupRecordContent): readonly PrivateGroupMemberEntry[] {
        const roles = new Map<string, PrivateGroupRole>();
        for (const assignment of content.roles) {
            if (assignment.accountIdentifier.length !== 32) {
                throw new Error("Invalid private-group role account identifier");
            }
            const key = encodeBase64Url(assignment.accountIdentifier);
            if (roles.has(key)) throw new Error("Duplicate private-group account role");
            roles.set(key, assignment.role);
        }
        if (roles.size !== content.session.members.length) {
            throw new Error("Private-group roles must exactly cover MLS logical accounts");
        }
        const members: PrivateGroupMemberEntry[] = [];
        for (const accountIdentifier of content.session.members) {
            const accountRole = roles.get(encodeBase64Url(accountIdentifier));
            if (accountRole === undefined) {
                throw new Error("Private-group roles must exactly cover MLS logical accounts");
            }
            members.push({
                entry: encodeEncryptedUid(createEncryptedUid(accountIdentifier, this.#parameters)),
                role: accountRole,
            });
        }
        return members;
    }

    #roleForOwnAccount(content: PrivateGroupRecordContent): PrivateGroupRole {
        const matches = content.roles.filter((assignment) =>
            equalBytes(assignment.accountIdentifier, this.#accountIdentifier),
        );
        if (matches.length !== 1)
            throw new Error("Private-group roles do not name this account once");
        return matches[0]!.role;
    }

    #acceptRevisionTip(stored: StoredPrivateGroupStateRecord): void {
        if (
            !isUuidV7(stored.canonicalVersion) ||
            (stored.replacesVersion !== null && !isUuidV7(stored.replacesVersion)) ||
            (stored.commitEventId !== null && !isUuidV7(stored.commitEventId))
        ) {
            throw new Error("Invalid private-group canonical metadata");
        }
        const revision = stored.record.revision;
        const hash = stored.revisionHash;
        if (
            this.#trustedCanonicalVersion === undefined ||
            this.#trustedRevision === undefined ||
            this.#trustedRevisionHash === undefined
        ) {
            if (
                (revision === 1 && stored.replacesVersion !== null) ||
                (revision > 1 && stored.replacesVersion === null)
            ) {
                throw new Error("Invalid private-group canonical predecessor");
            }
            this.#trustedCanonicalVersion = stored.canonicalVersion;
            this.#trustedRevision = revision;
            this.#trustedRevisionHash = hash.slice();
            return;
        }
        const versionOrder = stored.canonicalVersion.localeCompare(this.#trustedCanonicalVersion);
        if (versionOrder < 0 || revision < this.#trustedRevision) {
            throw new Error("Private-group revision rollback detected");
        }
        if (versionOrder === 0) {
            if (
                revision !== this.#trustedRevision ||
                !equalBytes(hash, this.#trustedRevisionHash)
            ) {
                throw new Error("Private-group revision fork detected");
            }
            return;
        }
        if (revision !== this.#trustedRevision + 1) {
            throw new Error("Private-group revision gap detected");
        }
        if (
            stored.replacesVersion !== this.#trustedCanonicalVersion ||
            stored.record.previousRevisionHash === null ||
            !equalBytes(stored.record.previousRevisionHash, this.#trustedRevisionHash)
        ) {
            throw new Error("Private-group revision fork detected");
        }
        this.#trustedRevisionHash.fill(0);
        this.#trustedCanonicalVersion = stored.canonicalVersion;
        this.#trustedRevision = revision;
        this.#trustedRevisionHash = hash.slice();
    }

    #safeNow(): number {
        const now = this.#now();
        if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid client clock");
        return now;
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Private-group state client is closed");
    }
}
