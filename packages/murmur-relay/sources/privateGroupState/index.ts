import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { canonicalJson } from "../utils/canonicalJson.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { isUuidV7 } from "../utils/uuidV7.js";
import type {
    PrivateGroupChallengeOperation,
    PrivateGroupCredentialAuthority,
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateLimits,
    PrivateGroupStateRecord,
    PrivateGroupStateServiceOptions,
    StoredPrivateGroupStateRecord,
} from "./types.js";

export { SqlitePrivateGroupStateStore } from "./impl/privateGroupStateStoreSqlite.js";
export type { SqlitePrivateGroupStateStoreOptions } from "./impl/privateGroupStateStoreSqlite.js";
export { PostgresPrivateGroupStateStore } from "./impl/privateGroupStateStorePostgres.js";
export type {
    PrivateGroupAccessToken,
    PrivateGroupChallengeOperation,
    PrivateGroupCredentialAuthority,
    PrivateGroupMemberEntry,
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateLimits,
    PrivateGroupStateRecord,
    PrivateGroupStateServiceOptions,
    PrivateGroupStateStore,
    StoredPrivateGroupStateRecord,
} from "./types.js";

const DEFAULT_LIMITS: PrivateGroupStateLimits = {
    maximumGroups: 10_000,
    maximumRecordBytes: 1024 * 1024,
    maximumSealedStateBytes: 512 * 1024,
    maximumMembersPerGroup: 1024,
    maximumPendingChallenges: 10_000,
};
const DEFAULT_CREDENTIAL_LIFETIME = 5 * 60_000;
const DEFAULT_CHALLENGE_LIFETIME = 30_000;
const DEFAULT_TOKEN_LIFETIME = 60_000;

interface TokenClaims {
    readonly version: 1;
    readonly opaqueGroupId: Uint8Array;
    readonly entry: Uint8Array;
    readonly role: PrivateGroupRole;
    readonly expiresAt: number;
    readonly tokenId: Uint8Array;
}

function safePositive(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be positive`);
    return value;
}

function role(value: unknown): PrivateGroupRole {
    if (value !== "owner" && value !== "administrator" && value !== "member") {
        throw new Error("Invalid private-group role");
    }
    return value;
}

function validateBytes(value: Uint8Array, length: number | null, name: string): void {
    if (!(value instanceof Uint8Array) || (length !== null && value.length !== length)) {
        throw new Error(`Invalid ${name}`);
    }
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    const length = Math.min(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return left.length - right.length;
}

function recordValue(record: PrivateGroupStateRecord, includeAuthenticator: boolean): unknown {
    return {
        version: record.version,
        opaqueGroupId: encodeBase64Url(record.opaqueGroupId),
        publicParameters: encodeBase64Url(record.publicParameters),
        revision: record.revision,
        previousRevisionHash:
            record.previousRevisionHash === null
                ? null
                : encodeBase64Url(record.previousRevisionHash),
        members: record.members.map((member) => ({
            entry: encodeBase64Url(member.entry),
            role: member.role,
        })),
        sealedState: encodeBase64Url(record.sealedState),
        ...(includeAuthenticator
            ? { revisionAuthenticator: encodeBase64Url(record.revisionAuthenticator) }
            : {}),
    };
}

/** Canonically encode one service-visible private-group record. */
export function encodePrivateGroupStateRecord(record: PrivateGroupStateRecord): Uint8Array {
    return canonicalJson(recordValue(record, true));
}

/** Canonically encode a record before its member-only authenticator is attached. */
export function encodeUnsignedPrivateGroupStateRecord(record: PrivateGroupStateRecord): Uint8Array {
    return canonicalJson(recordValue(record, false));
}

/** Compute the service-visible canonical SHA-256 revision digest. */
export function privateGroupStateRecordHash(record: PrivateGroupStateRecord): Uint8Array {
    return sha256(encodePrivateGroupStateRecord(record));
}

function validateRecord(record: PrivateGroupStateRecord, limits: PrivateGroupStateLimits): void {
    if (record.version !== 1) throw new Error("Unsupported private-group record version");
    validateBytes(record.opaqueGroupId, 32, "opaque private-group ID");
    validateBytes(record.publicParameters, null, "private-group public parameters");
    validateBytes(record.sealedState, null, "private-group sealed state");
    validateBytes(record.revisionAuthenticator, 32, "private-group revision authenticator");
    if (!Number.isSafeInteger(record.revision) || record.revision < 1) {
        throw new Error("Invalid private-group revision");
    }
    if (record.previousRevisionHash !== null) {
        validateBytes(record.previousRevisionHash, 32, "previous private-group revision hash");
    }
    if (record.members.length < 1 || record.members.length > limits.maximumMembersPerGroup) {
        throw new Error("Private-group member count exceeds limits");
    }
    if (
        record.sealedState.length < 17 ||
        record.sealedState.length > limits.maximumSealedStateBytes
    ) {
        throw new Error("Private-group sealed state exceeds limits");
    }
    let previous: Uint8Array | undefined;
    for (const member of record.members) {
        validateBytes(member.entry, null, "private-group encrypted member entry");
        if (member.entry.length < 1 || member.entry.length > 1024) {
            throw new Error("Private-group encrypted member entry exceeds limits");
        }
        role(member.role);
        if (previous !== undefined && compareBytes(previous, member.entry) >= 0) {
            throw new Error("Private-group member entries must be unique and canonically ordered");
        }
        previous = member.entry;
    }
    if (!record.members.some((member) => member.role === "owner")) {
        throw new Error("Private group must retain at least one owner");
    }
    if (encodePrivateGroupStateRecord(record).length > limits.maximumRecordBytes) {
        throw new Error("Private-group record exceeds byte limit");
    }
}

function challengeContext(options: {
    readonly opaqueGroupId: Uint8Array;
    readonly entry: Uint8Array;
    readonly role: PrivateGroupRole;
    readonly operation: PrivateGroupChallengeOperation;
    readonly replayNonce: Uint8Array;
}): Uint8Array {
    return canonicalJson({
        domain: "murmur.private-group-state.presentation.v1",
        opaqueGroupId: encodeBase64Url(options.opaqueGroupId),
        entry: encodeBase64Url(options.entry),
        role: options.role,
        operation: options.operation,
        replayNonce: encodeBase64Url(options.replayNonce),
    });
}

function issuanceContext(authenticationContext: Uint8Array): Uint8Array {
    return canonicalJson({
        domain: "murmur.private-group-state.credential-issuance.v1",
        authenticationContext: encodeBase64Url(authenticationContext),
    });
}

function tokenPayload(claims: TokenClaims): Uint8Array {
    return canonicalJson({
        version: claims.version,
        opaqueGroupId: encodeBase64Url(claims.opaqueGroupId),
        entry: encodeBase64Url(claims.entry),
        role: claims.role,
        expiresAt: claims.expiresAt,
        tokenId: encodeBase64Url(claims.tokenId),
    });
}

function encodeToken(claims: TokenClaims, secret: Uint8Array): Uint8Array {
    const payload = tokenPayload(claims);
    return canonicalJson({
        payload: encodeBase64Url(payload),
        authenticator: encodeBase64Url(hmac(sha256, secret, payload)),
    });
}

function jsonObject(value: Uint8Array, name: string): Record<string, unknown> {
    let parsed: unknown;
    try {
        parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(value));
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error(`Invalid ${name}`);
    }
    return parsed as Record<string, unknown>;
}

function parseToken(value: Uint8Array, secret: Uint8Array): TokenClaims {
    const outer = jsonObject(value, "private-group access token");
    if (
        Object.keys(outer).sort().join(",") !== "authenticator,payload" ||
        typeof outer.payload !== "string" ||
        typeof outer.authenticator !== "string"
    ) {
        throw new Error("Invalid private-group access token");
    }
    const payload = decodeBase64Url(outer.payload);
    const authenticator = decodeBase64Url(outer.authenticator, 32);
    if (!equalBytes(authenticator, hmac(sha256, secret, payload))) {
        throw new Error("Invalid private-group access token");
    }
    const claims = jsonObject(payload, "private-group access token");
    if (
        Object.keys(claims).sort().join(",") !==
            "entry,expiresAt,opaqueGroupId,role,tokenId,version" ||
        claims.version !== 1 ||
        typeof claims.opaqueGroupId !== "string" ||
        typeof claims.entry !== "string" ||
        typeof claims.expiresAt !== "number" ||
        !Number.isSafeInteger(claims.expiresAt) ||
        typeof claims.tokenId !== "string"
    ) {
        throw new Error("Invalid private-group access token");
    }
    return {
        version: 1,
        opaqueGroupId: decodeBase64Url(claims.opaqueGroupId, 32),
        entry: decodeBase64Url(claims.entry),
        role: role(claims.role),
        expiresAt: claims.expiresAt,
        tokenId: decodeBase64Url(claims.tokenId, 16),
    };
}

/** Canonical private-group state service with anonymous proof-derived access. */
export class PrivateGroupStateService {
    readonly #store: PrivateGroupStateServiceOptions["store"];
    readonly #authority: PrivateGroupCredentialAuthority;
    readonly #tokenSecret: Uint8Array;
    readonly #now: () => number;
    readonly #credentialLifetime: number;
    readonly #challengeLifetime: number;
    readonly #tokenLifetime: number;
    readonly #limits: PrivateGroupStateLimits;
    #closed = false;

    constructor(options: PrivateGroupStateServiceOptions) {
        validateBytes(options.tokenSecret, 32, "private-group token secret");
        this.#store = options.store;
        this.#authority = options.credentialAuthority;
        this.#tokenSecret = options.tokenSecret.slice();
        this.#now = options.now ?? Date.now;
        this.#credentialLifetime = safePositive(
            options.credentialLifetimeMilliseconds ?? DEFAULT_CREDENTIAL_LIFETIME,
            "Credential lifetime",
        );
        this.#challengeLifetime = safePositive(
            options.challengeLifetimeMilliseconds ?? DEFAULT_CHALLENGE_LIFETIME,
            "Challenge lifetime",
        );
        this.#tokenLifetime = safePositive(
            options.tokenLifetimeMilliseconds ?? DEFAULT_TOKEN_LIFETIME,
            "Token lifetime",
        );
        this.#limits = this.#resolveLimits(options.limits);
    }

    /** Defensive copy of the credential issuer's public proof parameters. */
    get credentialIssuerPublicParameters(): Uint8Array {
        this.#assertOpen();
        return this.#authority.publicParameters.slice();
    }

    /** Derive the exact blind-issuance context bound to an authenticated session. */
    credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array {
        this.#assertOpen();
        if (authenticationContext.length < 1 || authenticationContext.length > 4096) {
            throw new Error("Invalid authenticated credential context");
        }
        return issuanceContext(authenticationContext);
    }

    /** Blind-issue a short-lived credential to an upstream-authenticated account. */
    async issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly authenticationContext: Uint8Array;
    }): Promise<Uint8Array> {
        this.#assertOpen();
        validateBytes(options.authenticatedAccountIdentifier, 32, "authenticated account ID");
        if (
            options.authenticationContext.length < 1 ||
            options.authenticationContext.length > 4096
        ) {
            throw new Error("Invalid authenticated credential context");
        }
        const now = this.#safeNow();
        const expiresAt = now + this.#credentialLifetime;
        if (!Number.isSafeInteger(expiresAt)) throw new Error("Credential expiry overflow");
        return await this.#authority.issueCredential({
            authenticatedAccountIdentifier: options.authenticatedAccountIdentifier,
            request: options.request,
            expiresAt,
            now,
            context: issuanceContext(options.authenticationContext),
        });
    }

    /** Allocate one bounded, one-use challenge for creation or ordinary access. */
    async createPresentationChallenge(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly entry: Uint8Array;
        readonly role: PrivateGroupRole;
        readonly operation: PrivateGroupChallengeOperation;
    }): Promise<PrivateGroupPresentationChallenge> {
        this.#assertOpen();
        validateBytes(options.opaqueGroupId, 32, "opaque private-group ID");
        validateBytes(options.entry, null, "private-group encrypted entry");
        role(options.role);
        if (options.operation === "create") {
            if (options.role !== "owner") throw new Error("Only an owner entry may create a group");
            if ((await this.#store.read(options.opaqueGroupId)) !== undefined) {
                throw new Error("Private group already exists");
            }
        } else if (options.operation === "access") {
            if (
                !(await this.#store.hasMember(options.opaqueGroupId, options.entry, options.role))
            ) {
                throw new Error("Opaque member entry is not authorized for this group and role");
            }
        } else {
            throw new Error("Invalid private-group challenge operation");
        }
        const now = this.#safeNow();
        const replayNonce = randomBytes(32);
        const challenge: PrivateGroupPresentationChallenge = {
            opaqueGroupId: options.opaqueGroupId.slice(),
            entry: options.entry.slice(),
            role: options.role,
            operation: options.operation,
            replayNonce,
            context: challengeContext({ ...options, replayNonce }),
            expiresAt: now + this.#challengeLifetime,
        };
        await this.#store.storeChallenge(challenge, this.#limits.maximumPendingChallenges, now);
        return challenge;
    }

    /** Consume and verify one randomized presentation, returning an anonymous scoped token. */
    async authenticatePresentation(options: {
        readonly challenge: PrivateGroupPresentationChallenge;
        readonly publicParameters: Uint8Array;
        readonly presentation: Uint8Array;
    }): Promise<{ readonly bytes: Uint8Array; readonly expiresAt: number }> {
        this.#assertOpen();
        const now = this.#safeNow();
        const stored = await this.#store.consumeChallenge(options.challenge.replayNonce, now);
        if (stored === undefined || !this.#sameChallenge(stored, options.challenge)) {
            throw new Error("Private-group presentation challenge is invalid or replayed");
        }
        if (stored.expiresAt <= now)
            throw new Error("Private-group presentation challenge expired");
        if (
            !this.#authority.validateGroupPublicParameters(
                options.publicParameters,
                stored.opaqueGroupId,
            )
        ) {
            throw new Error("Private-group public parameters do not match the opaque group");
        }
        if (
            stored.operation === "access" &&
            !(await this.#store.hasMember(stored.opaqueGroupId, stored.entry, stored.role))
        ) {
            throw new Error("Opaque member entry is no longer authorized");
        }
        if (
            stored.operation === "create" &&
            (await this.#store.read(stored.opaqueGroupId)) !== undefined
        ) {
            throw new Error("Private group already exists");
        }
        const credentialExpiry = await this.#authority.verifyPresentation({
            presentation: options.presentation,
            encryptedEntry: stored.entry,
            groupPublicParameters: options.publicParameters,
            expectedReplayNonce: stored.replayNonce,
            context: stored.context,
            now,
        });
        if (credentialExpiry === null || credentialExpiry <= now) {
            throw new Error("Invalid or expired private-group credential presentation");
        }
        const expiresAt = Math.min(credentialExpiry, now + this.#tokenLifetime);
        const claims: TokenClaims = {
            version: 1,
            opaqueGroupId: stored.opaqueGroupId,
            entry: stored.entry,
            role: stored.role,
            expiresAt,
            tokenId: randomBytes(16),
        };
        return { bytes: encodeToken(claims, this.#tokenSecret), expiresAt };
    }

    /** Create revision one using an owner-scoped proof-derived token. */
    async createRecord(options: {
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.#assertOpen();
        validateRecord(options.record, this.#limits);
        if (options.record.revision !== 1 || options.record.previousRevisionHash !== null) {
            throw new Error("Private-group creation must write revision one without a parent");
        }
        if (
            !this.#authority.validateGroupPublicParameters(
                options.record.publicParameters,
                options.record.opaqueGroupId,
            )
        ) {
            throw new Error("Private-group public parameters do not match the opaque group");
        }
        const claims = this.#authorize(options.token, options.record.opaqueGroupId);
        if (claims.role !== "owner") throw new Error("Private-group creation requires owner role");
        if (
            !options.record.members.some(
                (member) => member.role === claims.role && equalBytes(member.entry, claims.entry),
            )
        ) {
            throw new Error("Creating owner token does not name an owner in the record");
        }
        const raw = encodePrivateGroupStateRecord(options.record);
        const revisionHash = sha256(raw);
        return await this.#store.create(
            options.record,
            revisionHash,
            raw,
            this.#limits,
            this.#safeNow(),
        );
    }

    /** Read the current canonical encrypted revision using an exact member/role token. */
    async readRecord(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.#assertOpen();
        const claims = this.#authorize(options.token, options.opaqueGroupId);
        if (!(await this.#store.hasMember(options.opaqueGroupId, claims.entry, claims.role))) {
            throw new Error("Private-group token member entry is no longer authorized");
        }
        const stored = await this.#store.read(options.opaqueGroupId);
        if (stored === undefined) throw new Error("Unknown private group");
        return stored;
    }

    /** Atomically replace the canonical tip using an administrator or owner token. */
    async replaceRecord(options: {
        readonly replacesVersion: string;
        readonly expectedRevisionHash: Uint8Array;
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.#assertOpen();
        validateRecord(options.record, this.#limits);
        if (!isUuidV7(options.replacesVersion)) {
            throw new Error("Invalid replaced private-group canonical version");
        }
        validateBytes(options.expectedRevisionHash, 32, "expected private-group revision hash");
        const claims = this.#authorize(options.token, options.record.opaqueGroupId);
        if (claims.role !== "owner" && claims.role !== "administrator") {
            throw new Error("Private-group mutation requires owner or administrator role");
        }
        const current = await this.#store.read(options.record.opaqueGroupId);
        if (
            current === undefined ||
            !equalBytes(current.record.publicParameters, options.record.publicParameters)
        ) {
            throw new Error("Private-group public parameters cannot change");
        }
        const raw = encodePrivateGroupStateRecord(options.record);
        const revisionHash = sha256(raw);
        if (
            current.replacesVersion === options.replacesVersion &&
            equalBytes(current.revisionHash, revisionHash)
        ) {
            return current;
        }
        if (
            current.canonicalVersion !== options.replacesVersion ||
            options.record.revision !== current.record.revision + 1 ||
            options.record.previousRevisionHash === null ||
            !equalBytes(current.revisionHash, options.expectedRevisionHash) ||
            !equalBytes(options.record.previousRevisionHash, options.expectedRevisionHash)
        ) {
            throw new Error("Private-group mutation does not extend the expected version");
        }
        if (
            !(await this.#store.hasMember(options.record.opaqueGroupId, claims.entry, claims.role))
        ) {
            throw new Error("Private-group mutation token member is no longer authorized");
        }
        return await this.#store.replace(
            options.replacesVersion,
            options.expectedRevisionHash,
            options.record,
            revisionHash,
            raw,
            this.#limits,
            this.#safeNow(),
        );
    }

    /** Close the service, zero its token secret, and close its configured store. */
    close(): void {
        if (!this.#closed) {
            this.#closed = true;
            this.#tokenSecret.fill(0);
            this.#store.close();
        }
    }

    #authorize(token: Uint8Array, opaqueGroupId: Uint8Array): TokenClaims {
        const claims = parseToken(token, this.#tokenSecret);
        if (claims.expiresAt <= this.#safeNow())
            throw new Error("Private-group access token expired");
        if (!equalBytes(claims.opaqueGroupId, opaqueGroupId)) {
            throw new Error("Private-group access token has the wrong group scope");
        }
        return claims;
    }

    #sameChallenge(
        left: PrivateGroupPresentationChallenge,
        right: PrivateGroupPresentationChallenge,
    ): boolean {
        return (
            left.role === right.role &&
            left.operation === right.operation &&
            left.expiresAt === right.expiresAt &&
            equalBytes(left.opaqueGroupId, right.opaqueGroupId) &&
            equalBytes(left.entry, right.entry) &&
            equalBytes(left.replayNonce, right.replayNonce) &&
            equalBytes(left.context, right.context)
        );
    }

    #resolveLimits(limits: Partial<PrivateGroupStateLimits> | undefined): PrivateGroupStateLimits {
        return {
            maximumGroups: safePositive(
                limits?.maximumGroups ?? DEFAULT_LIMITS.maximumGroups,
                "Maximum groups",
            ),
            maximumRecordBytes: safePositive(
                limits?.maximumRecordBytes ?? DEFAULT_LIMITS.maximumRecordBytes,
                "Maximum record bytes",
            ),
            maximumSealedStateBytes: safePositive(
                limits?.maximumSealedStateBytes ?? DEFAULT_LIMITS.maximumSealedStateBytes,
                "Maximum sealed-state bytes",
            ),
            maximumMembersPerGroup: safePositive(
                limits?.maximumMembersPerGroup ?? DEFAULT_LIMITS.maximumMembersPerGroup,
                "Maximum group members",
            ),
            maximumPendingChallenges: safePositive(
                limits?.maximumPendingChallenges ?? DEFAULT_LIMITS.maximumPendingChallenges,
                "Maximum pending challenges",
            ),
        };
    }

    #safeNow(): number {
        const now = this.#now();
        if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid service clock");
        return now;
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Private-group state service is closed");
    }
}
