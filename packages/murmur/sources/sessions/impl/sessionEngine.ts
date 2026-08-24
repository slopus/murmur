import {
    DeliveryTransportError,
    InboxProcessor,
    MURMUR_INTERNAL_INBOX_HANDLER,
    TerminalInboxDeliveryError,
    createSignedDelivery,
    type DeliveryTransport,
    type InboxDelivery,
    type InboxStreamOptions,
    type InboxSyncResult,
} from "../../delivery/index.js";
import { openBox, sealBox, type IdentityKeyPair } from "../../crypto/index.js";
import type { DiscoveryBundle } from "../../identity/discovery/index.js";
import { verifyDiscoveryBundle } from "../../identity/discovery/index.js";
import {
    MlsEpochState,
    MlsLocalMemberRemovedError,
    authenticateMurmurMlsCredential,
    createMlsGroup,
    decodeMlsPrivateMessage,
    decodeMlsRatchetTree,
    decodeMlsTreeCommit,
    deserializeMlsKeyPackageBundle,
    destroyMlsKeyPackageBundle,
    encodeMlsRatchetTree,
    joinMlsGroupFromWelcome,
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
    type MlsEpochCommitProposal,
    type MlsKeyPackage,
} from "../../mls/index.js";
import type { MurmurStore, StoreTransaction } from "../../storage/index.js";
import {
    ROUTING_MARKER_PREFIX,
    decodeSessionRouting,
    decodeSessionOwner,
    encodeSessionRouting,
    encodeSessionOwner,
    routingMarkerKey,
    sessionOwnerKey,
    type SessionOwnerRecord,
} from "../../services/impl/serviceRecords.js";
import {
    canonicalJsonBytes,
    concatBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import type {
    CreateMurmurSessionOptions,
    MurmurSession,
    MurmurSessionIssue,
    MurmurSessionLimits,
    MurmurSessionListOptions,
    MurmurSessionPage,
    MurmurSessionProposal,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "../types.js";
import {
    decodeBootstrapFrame,
    decodeCommitterControl,
    decodePrivateFrame,
    decodeStoredProposal,
    encodeBootstrapCiphertext,
    encodeBootstrapFrame,
    encodeCommitterControl,
    encodePrivateCiphertext,
    encodePrivateFrame,
    encodeStoredProposal,
    openCommitCiphertext,
    parseSessionCiphertext,
    sealCommitCiphertext,
    type PrivateSessionFrame,
} from "./sessionFrames.js";
import {
    decodeBufferedEvent,
    decodeOutboxRecord,
    decodeSessionRecord,
    encodeBufferedEvent,
    encodeOutboxRecord,
    encodeSessionRecord,
    type SessionOutboxRecord,
    type SessionRecord,
} from "./sessionRecords.js";

const SESSION_STATE_PREFIX = "murmur/session-states/";
const SESSION_DATA_PREFIX = "murmur/session-data/";
const OUTBOX_PREFIX = "murmur/session-outbox/";
const OUTBOX_ORDER_PREFIX = "murmur/session-outbox-order/";
const OUTBOX_SEQUENCE_KEY = "murmur/session-outbox-sequence";
const KEY_PACKAGE_PREFIX = "murmur/key-packages/";
const KEY_PACKAGE_EXPIRY_PREFIX = "murmur/key-package-expiries/";
const KEY_PACKAGE_REUSABLE_PREFIX = "murmur/key-package-reusable/";
const REJECTED_PREFIX = "murmur/rejected-sessions/";
const QUARANTINE_PREFIX = "murmur/session-quarantine/";
const PENDING_SESSION_PREFIX = "murmur/pending-sessions/";
const USED_DISCOVERY_PREFIX = "murmur/used-discovery/";
const BOOTSTRAP_INDEX_PREFIX = "murmur/bootstrap-outboxes/";
const EPOCH_OUTBOX_INDEX_PREFIX = "murmur/epoch-outboxes/";
const POST_COMMIT_OUTBOX_INDEX_PREFIX = "murmur/post-commit-outboxes/";
const APPLICATION_UPDATE_PREFIX = "murmur/application-updates/";
const DEFAULT_MAXIMUM_PENDING = 64;
const DEFAULT_MAXIMUM_BUFFERED_EVENTS = 1_000;
const DEFAULT_MAXIMUM_BUFFERED_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAXIMUM_MEMBERS = 256;
const DEFAULT_MAXIMUM_CIPHERTEXT_BYTES = 1024 * 1024;
const MAXIMUM_KEY_PACKAGES = 8_192;
const DEFAULT_MAXIMUM_OUTBOXES = 1_000;
const MAXIMUM_REJECTED_SESSIONS = 256;
const MAXIMUM_USED_DISCOVERY = 1_024;
const MAXIMUM_PROPOSALS_PER_SESSION = 256;
const MAXIMUM_COMMIT_PROPOSALS = 64;
const SESSION_LIST_LIMIT = 256;
const MAXIMUM_UPDATE_BATCH_EVENTS = 256;
const OUTBOX_SCAN_ITEMS = 64;
const PREVIOUS_EPOCH_GRACE_MILLISECONDS = 5 * 60 * 1_000;
const PREVIOUS_EPOCH_MESSAGES = 64;
const DELIVERY_TTL_MILLISECONDS = 29 * 24 * 60 * 60 * 1_000;
const COMMIT_EXPORT_LABEL = "murmur session commit";
const COMMIT_EXPORT_CONTEXT = utf8Encode("murmur/session-commit/v1");

/** Internal immutable snapshot backing one identity-wide application batch. */
export interface PreparedUpdates {
    readonly keys: readonly string[];
    readonly routes: readonly PreparedSessionRoute[];
    readonly updates: readonly PreparedRoutedUpdate[];
    readonly exhausted: boolean;
}

/** One incoming session whose descriptor still needs an owner decision. */
export interface PreparedSessionRoute {
    readonly eventId: string;
    readonly key: string;
    readonly session: MurmurSession;
}

/** One buffered session update and its durable routing owner. */
export interface PreparedRoutedUpdate extends MurmurUpdate {
    readonly key: string;
    readonly owner: SessionOwnerRecord | undefined;
}

/** Durable owner decision for one prepared incoming session. */
export interface SessionRouteDecision {
    readonly key: string;
    readonly sessionId: Uint8Array;
    readonly owner: SessionOwnerRecord;
}

/** Authenticated public admission material supplied by the built-in contact layer. */
export interface SessionMemberMaterial {
    readonly identity: Uint8Array;
    readonly keyPackage: MlsKeyPackage;
    /** Present only for public discovery, whose one-use claim is tracked separately. */
    readonly discovery?: DiscoveryBundle;
}

function sessionId(value: Uint8Array): string {
    return encodeBase64Url(value);
}

function sessionEventTime(eventId: string): number {
    const value = Number.parseInt(`${eventId.slice(0, 8)}${eventId.slice(9, 13)}`, 16);
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("Invalid session event time");
    }
    return value;
}

function stateKey(id: Uint8Array): string {
    return `${SESSION_STATE_PREFIX}${sessionId(id)}`;
}

function bufferPrefix(id: Uint8Array): string {
    return `${SESSION_DATA_PREFIX}${sessionId(id)}/buffer/`;
}

function applicationUpdateKey(eventId: string): string {
    return `${APPLICATION_UPDATE_PREFIX}${eventId}`;
}

function proposalPrefix(id: Uint8Array): string {
    return `${SESSION_DATA_PREFIX}${sessionId(id)}/proposals/`;
}

function outboxKey(deliveryId: string): string {
    return `${OUTBOX_PREFIX}${deliveryId}`;
}

function outboxOrderKey(order: string, deliveryId: string): string {
    return `${OUTBOX_ORDER_PREFIX}${order}/${deliveryId}`;
}

function bootstrapIndexKey(parentCommitId: string, deliveryId: string): string {
    return `${BOOTSTRAP_INDEX_PREFIX}${parentCommitId}/${deliveryId}`;
}

function epochOutboxIndexKey(id: Uint8Array, deliveryId: string): string {
    return `${EPOCH_OUTBOX_INDEX_PREFIX}${sessionId(id)}/${deliveryId}`;
}

function postCommitOutboxIndexKey(parentCommitId: string, deliveryId: string): string {
    return `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${parentCommitId}/${deliveryId}`;
}

function keyPackageKey(reference: Uint8Array): string {
    return `${KEY_PACKAGE_PREFIX}${encodeBase64Url(reference)}`;
}

function keyPackageExpiryKey(reference: Uint8Array): string {
    return `${KEY_PACKAGE_EXPIRY_PREFIX}${encodeBase64Url(reference)}`;
}

function keyPackageReusableKey(reference: Uint8Array): string {
    return `${KEY_PACKAGE_REUSABLE_PREFIX}${encodeBase64Url(reference)}`;
}

function rejectedKey(id: Uint8Array): string {
    return `${REJECTED_PREFIX}${sessionId(id)}`;
}

function pendingKey(id: Uint8Array): string {
    return `${PENDING_SESSION_PREFIX}${sessionId(id)}`;
}

function usedDiscoveryKey(keyPackage: MlsKeyPackage): string {
    return `${USED_DISCOVERY_PREFIX}${encodeBase64Url(mlsKeyPackageReference(keyPackage))}`;
}

function usedDiscoveryExpiresAt(keyPackage: MlsKeyPackage): number {
    const expiresAt = (keyPackage.leafNode.notAfter + 1n) * 1_000n;
    if (expiresAt > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("Discovery KeyPackage lifetime is too large");
    }
    return Number(expiresAt);
}

function stateRepairIssueId(stagedCommitId: string, id: Uint8Array): string {
    return `${stagedCommitId}.${encodeBase64Url(id)}`;
}

function encodeIssue(
    code: string,
    session: Uint8Array | undefined,
    kind: MurmurSessionIssue["kind"],
    operationId: string | undefined,
): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        code,
        sessionId: session === undefined ? null : encodeBase64Url(session),
        kind: kind ?? null,
        operationId: operationId ?? null,
    });
}

function decodeIssue(id: string, bytes: Uint8Array): MurmurSessionIssue {
    const value = JSON.parse(utf8Decode(bytes)) as unknown;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid session issue");
    }
    const input = value as Record<string, unknown>;
    const fields = ["version", "code", "sessionId", "kind", "operationId"];
    if (
        input.version !== 1 ||
        typeof input.code !== "string" ||
        (input.sessionId !== null && typeof input.sessionId !== "string") ||
        (input.kind !== null &&
            input.kind !== "application" &&
            input.kind !== "proposal" &&
            input.kind !== "commit" &&
            input.kind !== "bootstrap" &&
            input.kind !== "session") ||
        (input.operationId !== null && typeof input.operationId !== "string") ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid session issue");
    }
    return {
        id,
        code: input.code,
        ...(input.sessionId === null
            ? {}
            : { sessionId: decodeBase64Url(input.sessionId as string) }),
        ...(input.kind === null ? {} : { kind: input.kind }),
        ...(input.operationId === null ? {} : { operationId: input.operationId as string }),
    };
}

function activeMembers(epoch: MlsEpochState): readonly Uint8Array[] {
    return epoch.memberSignatureKeys.flatMap((value) => (value === undefined ? [] : [value]));
}

function memberLeaf(epoch: MlsEpochState, identity: Uint8Array): number {
    const matches = epoch.memberSignatureKeys.flatMap((value, index) =>
        value !== undefined && equalBytes(value, identity) ? [index] : [],
    );
    if (matches.length !== 1) throw new Error("Session member is absent or ambiguous");
    return matches[0]!;
}

function exactRecipients(
    delivery: InboxDelivery["delivery"],
    members: readonly Uint8Array[],
): boolean {
    if (delivery.recipients.length !== members.length) return false;
    const expected = new Set(members.map(encodeBase64Url));
    return delivery.recipients.every((recipient) => expected.delete(encodeBase64Url(recipient)));
}

async function setAndZero(
    transaction: StoreTransaction,
    key: string,
    value: Uint8Array,
): Promise<void> {
    try {
        await transaction.set(key, value);
    } finally {
        zeroBytes(value);
    }
}

function restoreEpoch(identity: IdentityKeyPair, record: SessionRecord): MlsEpochState {
    return MlsEpochState.deserialize(record.epoch, {
        localSigningSecretKey: identity.secretKey,
        authenticateCredential: authenticateMurmurMlsCredential,
        minimumPersistenceGeneration: record.generation,
    });
}

function restorePreviousEpoch(
    identity: IdentityKeyPair,
    record: SessionRecord,
): MlsEpochState | undefined {
    if (
        record.previousEpoch === undefined ||
        record.previousGeneration === undefined ||
        record.previousEpochExpiresAt === undefined ||
        record.previousMessagesRemaining === undefined
    ) {
        return undefined;
    }
    return MlsEpochState.deserialize(record.previousEpoch, {
        localSigningSecretKey: identity.secretKey,
        authenticateCredential: authenticateMurmurMlsCredential,
        minimumPersistenceGeneration: record.previousGeneration,
    });
}

function publicSession(record: SessionRecord, epoch: MlsEpochState): MurmurSession {
    return {
        id: epoch.groupId,
        status: record.status,
        descriptor: record.descriptor.slice(),
        members: activeMembers(epoch),
        committer: record.committer.slice(),
        bufferedEvents: record.bufferedEvents,
    };
}

interface ResolvedLimits {
    readonly maximumPendingSessions: number;
    readonly maximumBufferedEventsPerSession: number;
    readonly maximumBufferedBytesPerSession: number;
    readonly maximumMembersPerSession: number;
    readonly maximumDeliveryCiphertextBytes: number;
    readonly maximumOutboxes: number;
}

interface PreparedAddition {
    readonly identity: Uint8Array;
    readonly keyPackage: MlsKeyPackage;
}

interface FlushOutboxResult {
    readonly publishedIds: ReadonlySet<string>;
    readonly transientFailureIds: ReadonlySet<string>;
    readonly terminalFailureIds: ReadonlySet<string>;
}

interface CorruptOutboxRecovery {
    readonly sessionId: Uint8Array;
    readonly kind: "bootstrap" | "commit";
    readonly operationId: string;
}

/** Internal stateful MLS/session coordinator. */
export class SessionEngine {
    readonly #identity: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #transport: DeliveryTransport;
    readonly #inbox: InboxProcessor;
    readonly #limits: ResolvedLimits;
    readonly #now: () => number;

    constructor(
        identity: IdentityKeyPair,
        store: MurmurStore,
        transport: DeliveryTransport,
        limits: MurmurSessionLimits = {},
        now: () => number = Date.now,
    ) {
        this.#identity = identity;
        this.#store = store;
        this.#transport = transport;
        this.#now = now;
        this.#limits = {
            maximumPendingSessions: limits.maximumPendingSessions ?? DEFAULT_MAXIMUM_PENDING,
            maximumBufferedEventsPerSession:
                limits.maximumBufferedEventsPerSession ?? DEFAULT_MAXIMUM_BUFFERED_EVENTS,
            maximumBufferedBytesPerSession:
                limits.maximumBufferedBytesPerSession ?? DEFAULT_MAXIMUM_BUFFERED_BYTES,
            maximumMembersPerSession: limits.maximumMembersPerSession ?? DEFAULT_MAXIMUM_MEMBERS,
            maximumDeliveryCiphertextBytes:
                limits.maximumDeliveryCiphertextBytes ?? DEFAULT_MAXIMUM_CIPHERTEXT_BYTES,
            maximumOutboxes: limits.maximumOutboxes ?? DEFAULT_MAXIMUM_OUTBOXES,
        };
        if (
            !Number.isSafeInteger(this.#limits.maximumPendingSessions) ||
            this.#limits.maximumPendingSessions < 1 ||
            this.#limits.maximumPendingSessions > 1_000 ||
            !Number.isSafeInteger(this.#limits.maximumBufferedEventsPerSession) ||
            this.#limits.maximumBufferedEventsPerSession < 1 ||
            this.#limits.maximumBufferedEventsPerSession > DEFAULT_MAXIMUM_BUFFERED_EVENTS ||
            !Number.isSafeInteger(this.#limits.maximumBufferedBytesPerSession) ||
            this.#limits.maximumBufferedBytesPerSession < 1 ||
            this.#limits.maximumBufferedBytesPerSession > DEFAULT_MAXIMUM_BUFFERED_BYTES ||
            !Number.isSafeInteger(this.#limits.maximumMembersPerSession) ||
            this.#limits.maximumMembersPerSession < 2 ||
            this.#limits.maximumMembersPerSession > DEFAULT_MAXIMUM_MEMBERS ||
            !Number.isSafeInteger(this.#limits.maximumDeliveryCiphertextBytes) ||
            this.#limits.maximumDeliveryCiphertextBytes < 1 ||
            this.#limits.maximumDeliveryCiphertextBytes > DEFAULT_MAXIMUM_CIPHERTEXT_BYTES ||
            !Number.isSafeInteger(this.#limits.maximumOutboxes) ||
            this.#limits.maximumOutboxes < 1 ||
            this.#limits.maximumOutboxes > DEFAULT_MAXIMUM_OUTBOXES
        ) {
            throw new Error("Invalid Murmur session limits");
        }
        this.#inbox = new InboxProcessor(
            { identity, store, transport },
            async (transaction, delivery) => this.#receive(transaction, delivery),
            { now },
            MURMUR_INTERNAL_INBOX_HANDLER,
        );
    }

    async storeKeyPackages(
        values: readonly {
            readonly reference: Uint8Array;
            readonly bytes: Uint8Array;
            readonly expiresAt: number;
            readonly reusable?: boolean;
        }[],
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const now = this.#now();
            await this.#pruneKeyPackages(transaction, now);
            const existing = new Map(
                await transaction.scan(KEY_PACKAGE_PREFIX, {
                    limit: MAXIMUM_KEY_PACKAGES + 1,
                }),
            );
            if (existing.size > MAXIMUM_KEY_PACKAGES) {
                for (const bytes of existing.values()) zeroBytes(bytes);
                throw new Error("Local KeyPackage capacity exceeded");
            }
            for (const bytes of existing.values()) zeroBytes(bytes);
            const newKeys = new Set<string>();
            for (const value of values) {
                if (
                    value.reference.length !== 32 ||
                    !Number.isSafeInteger(value.expiresAt) ||
                    value.expiresAt <= now
                ) {
                    throw new Error("Invalid local KeyPackage expiry");
                }
                const bundle = deserializeMlsKeyPackageBundle(value.bytes);
                try {
                    if (
                        !verifyMlsKeyPackage(bundle.keyPackage, Math.floor(now / 1_000)) ||
                        !equalBytes(mlsKeyPackageReference(bundle.keyPackage), value.reference) ||
                        BigInt(value.expiresAt) >
                            (bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n
                    ) {
                        throw new Error("Invalid local KeyPackage state");
                    }
                } finally {
                    destroyMlsKeyPackageBundle(bundle);
                }
                const key = keyPackageKey(value.reference);
                if (!existing.has(key)) newKeys.add(key);
            }
            if (existing.size + newKeys.size > MAXIMUM_KEY_PACKAGES) {
                throw new Error("Local KeyPackage capacity exceeded");
            }
            for (const value of values) {
                await transaction.set(keyPackageKey(value.reference), value.bytes);
                await setAndZero(
                    transaction,
                    keyPackageExpiryKey(value.reference),
                    utf8Encode(String(value.expiresAt).padStart(16, "0")),
                );
                if (value.reusable === true) {
                    await transaction.set(keyPackageReusableKey(value.reference), new Uint8Array());
                } else {
                    await transaction.delete(keyPackageReusableKey(value.reference));
                }
            }
        });
    }

    async deleteKeyPackages(references: readonly Uint8Array[]): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            for (const reference of references) {
                await transaction.delete(keyPackageKey(reference));
                await transaction.delete(keyPackageExpiryKey(reference));
                await transaction.delete(keyPackageReusableKey(reference));
            }
        });
    }

    async #pruneKeyPackages(transaction: StoreTransaction, now: number): Promise<void> {
        const packages = await transaction.scan(KEY_PACKAGE_PREFIX, {
            limit: MAXIMUM_KEY_PACKAGES + 1,
        });
        const expiries = await transaction.scan(KEY_PACKAGE_EXPIRY_PREFIX, {
            limit: MAXIMUM_KEY_PACKAGES + 1,
        });
        const reusable = await transaction.scan(KEY_PACKAGE_REUSABLE_PREFIX, {
            limit: MAXIMUM_KEY_PACKAGES + 1,
        });
        try {
            if (
                packages.size > MAXIMUM_KEY_PACKAGES ||
                expiries.size > MAXIMUM_KEY_PACKAGES ||
                reusable.size > MAXIMUM_KEY_PACKAGES
            ) {
                throw new Error("Local KeyPackage capacity exceeded");
            }
            const packageKeys = new Set(packages.keys());
            const active = new Set<string>();
            for (const [expiryKey, bytes] of expiries) {
                const suffix = expiryKey.slice(KEY_PACKAGE_EXPIRY_PREFIX.length);
                const packageKey = `${KEY_PACKAGE_PREFIX}${suffix}`;
                const encodedExpiry = utf8Decode(bytes);
                const expiresAt = /^\d{16}$/.test(encodedExpiry)
                    ? Number(encodedExpiry)
                    : Number.NaN;
                if (
                    !Number.isSafeInteger(expiresAt) ||
                    expiresAt <= now ||
                    !packageKeys.has(packageKey)
                ) {
                    await transaction.delete(expiryKey);
                    await transaction.delete(packageKey);
                    await transaction.delete(`${KEY_PACKAGE_REUSABLE_PREFIX}${suffix}`);
                } else {
                    try {
                        if (decodeBase64Url(suffix).length !== 32) {
                            throw new Error("Invalid KeyPackage reference");
                        }
                        active.add(packageKey);
                    } catch {
                        await transaction.delete(expiryKey);
                        await transaction.delete(packageKey);
                        await transaction.delete(`${KEY_PACKAGE_REUSABLE_PREFIX}${suffix}`);
                    }
                }
            }
            for (const packageKey of packageKeys) {
                if (!active.has(packageKey)) {
                    await transaction.delete(packageKey);
                    await transaction.delete(
                        `${KEY_PACKAGE_REUSABLE_PREFIX}${packageKey.slice(KEY_PACKAGE_PREFIX.length)}`,
                    );
                }
            }
            for (const reusableKey of reusable.keys()) {
                const suffix = reusableKey.slice(KEY_PACKAGE_REUSABLE_PREFIX.length);
                if (!active.has(`${KEY_PACKAGE_PREFIX}${suffix}`)) {
                    await transaction.delete(reusableKey);
                }
            }
        } finally {
            for (const bytes of packages.values()) zeroBytes(bytes);
            for (const bytes of expiries.values()) zeroBytes(bytes);
            for (const bytes of reusable.values()) zeroBytes(bytes);
        }
    }

    async #claimDiscovery(
        transaction: StoreTransaction,
        bundles: readonly DiscoveryBundle[],
    ): Promise<void> {
        const entries = await transaction.scan(USED_DISCOVERY_PREFIX, {
            limit: MAXIMUM_USED_DISCOVERY + 1,
        });
        const active = new Set<string>();
        try {
            for (const [key, value] of entries) {
                const encodedExpiry = utf8Decode(value);
                if (!/^\d{16}$/.test(encodedExpiry)) {
                    throw new Error("Invalid discovery claim");
                }
                if (Number(encodedExpiry) <= this.#now()) {
                    await transaction.delete(key);
                } else {
                    active.add(key);
                }
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
        const claims = bundles.map((bundle) => ({
            key: usedDiscoveryKey(bundle.keyPackages[0]!),
            expiresAt: usedDiscoveryExpiresAt(bundle.keyPackages[0]!),
        }));
        if (
            new Set(claims.map(({ key }) => key)).size !== claims.length ||
            claims.some(({ key }) => active.has(key))
        ) {
            throw new Error("Discovery KeyPackage was already used");
        }
        if (active.size + claims.length > MAXIMUM_USED_DISCOVERY) {
            throw new Error("Used discovery capacity exceeded");
        }
        for (const claim of claims) {
            await setAndZero(
                transaction,
                claim.key,
                utf8Encode(String(claim.expiresAt).padStart(16, "0")),
            );
        }
    }

    async create(
        options: Pick<CreateMurmurSessionOptions, "descriptor"> & {
            readonly members: readonly (DiscoveryBundle | SessionMemberMaterial)[];
        },
        owner?: SessionOwnerRecord,
        operation?: (transaction: StoreTransaction, id: Uint8Array) => Promise<void>,
    ): Promise<MurmurSession> {
        if (options.descriptor.length > 1024 * 1024) {
            throw new Error("Session descriptor is too large");
        }
        const members: SessionMemberMaterial[] = options.members.map((member) => {
            if ("keyPackage" in member) {
                return member;
            }
            if (
                member.keyPackages.length !== 1 ||
                !verifyDiscoveryBundle(member, { now: this.#now() })
            ) {
                throw new Error("Invalid session member discovery bundle");
            }
            return {
                identity: member.identityKey,
                keyPackage: member.keyPackages[0]!,
                discovery: member,
            };
        });
        if (members.length < 1) {
            throw new Error("A session requires at least two members");
        }
        if (members.length + 1 > this.#limits.maximumMembersPerSession) {
            throw new Error("Session membership exceeds the configured limit");
        }
        const memberIdentities = new Set<string>();
        for (const member of members) {
            if (
                member.identity.length !== 32 ||
                !verifyMlsKeyPackage(member.keyPackage, Math.floor(this.#now() / 1_000)) ||
                !equalBytes(member.keyPackage.leafNode.signatureKey, member.identity) ||
                !equalBytes(member.keyPackage.leafNode.credential.identity, member.identity)
            ) {
                throw new Error("Invalid session member KeyPackage");
            }
            const identity = encodeBase64Url(member.identity);
            if (
                equalBytes(member.identity, this.#identity.publicKey) ||
                memberIdentities.has(identity)
            ) {
                throw new Error("Session members must be distinct");
            }
            memberIdentities.add(identity);
        }
        const discoveryMembers = members
            .map((member) => member.discovery)
            .filter((member): member is DiscoveryBundle => member !== undefined);
        const discoveryClaims = discoveryMembers.map((member) =>
            usedDiscoveryKey(member.keyPackages[0]!),
        );
        const epoch = createMlsGroup(this.#identity);
        const id = epoch.groupId;
        let checkpoint: Uint8Array | undefined;
        try {
            checkpoint = epoch.serialize();
            const record: SessionRecord = {
                version: 1,
                status: "creating",
                descriptor: options.descriptor.slice(),
                committer: this.#identity.publicKey.slice(),
                epoch: checkpoint,
                generation: epoch.persistenceGeneration,
                bufferedEvents: 0,
                bufferedBytes: 0,
            };
            await this.#store.transaction(async (transaction) => {
                const existingState = await transaction.get(stateKey(id));
                if (existingState !== undefined) {
                    zeroBytes(existingState);
                    throw new Error("Session already exists");
                }
                await this.#claimDiscovery(transaction, discoveryMembers);
                await setAndZero(transaction, stateKey(id), encodeSessionRecord(record));
                if (owner !== undefined) {
                    await setAndZero(transaction, sessionOwnerKey(id), encodeSessionOwner(owner));
                }
                await operation?.(transaction, id);
            });
        } finally {
            epoch.destroy();
            if (checkpoint !== undefined) zeroBytes(checkpoint);
        }
        if (members.length > 0) {
            try {
                await this.#prepareCommit(
                    id,
                    members.map((member) => ({
                        identity: member.identity,
                        keyPackage: member.keyPackage,
                    })),
                    [],
                    [],
                );
            } catch (error: unknown) {
                await this.#store.transaction(async (transaction) => {
                    await this.#deleteSession(transaction, id);
                    for (const claim of discoveryClaims) {
                        await transaction.delete(claim);
                    }
                });
                throw error;
            }
        }
        return (await this.get(id))!;
    }

    async get(id: Uint8Array): Promise<MurmurSession | undefined> {
        const bytes = await this.#store.get(stateKey(id));
        if (bytes === undefined) return undefined;
        const record = decodeSessionRecord(bytes);
        const epoch = restoreEpoch(this.#identity, record);
        try {
            return publicSession(record, epoch);
        } finally {
            epoch.destroy();
            this.#zeroSessionRecord(record);
            zeroBytes(bytes);
        }
    }

    async list(options: MurmurSessionListOptions = {}): Promise<MurmurSessionPage> {
        const limit = options.limit ?? SESSION_LIST_LIMIT;
        if (
            !Number.isSafeInteger(limit) ||
            limit < 1 ||
            limit > SESSION_LIST_LIMIT ||
            (options.after !== undefined && !/^[A-Za-z0-9_-]+$/.test(options.after))
        ) {
            throw new Error("Invalid session-list options");
        }
        const entries = await this.#store.scan(SESSION_STATE_PREFIX, {
            ...(options.after === undefined
                ? {}
                : { after: `${SESSION_STATE_PREFIX}${options.after}` }),
            limit,
        });
        const result: MurmurSession[] = [];
        for (const [, bytes] of entries) {
            const record = decodeSessionRecord(bytes);
            const epoch = restoreEpoch(this.#identity, record);
            try {
                result.push(publicSession(record, epoch));
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
            }
        }
        const last = [...entries.keys()].at(-1);
        return {
            sessions: result,
            cursor:
                entries.size === limit && last !== undefined
                    ? last.slice(SESSION_STATE_PREFIX.length)
                    : null,
        };
    }

    async activate(id: Uint8Array): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await this.#activatePending(transaction, id);
            await this.#deleteRoutingMarkers(transaction, id);
        });
    }

    /** Activate one internally owned pending session after an explicit decision. */
    async activateOwned(id: Uint8Array, expectedOwner: "contact" | "service"): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner === undefined || owner.owner !== expectedOwner) {
                throw new Error("Session owner does not match");
            }
            await this.#activatePending(transaction, id);
        });
    }

    /** Destroy one internally owned session and retain its rejection marker. */
    async destroyOwned(
        id: Uint8Array,
        expectedOwner: "contact" | "service",
        operation?: (transaction: StoreTransaction) => Promise<void>,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner === undefined || owner.owner !== expectedOwner) {
                throw new Error("Session owner does not match");
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
            await operation?.(transaction);
        });
    }

    async ignore(id: Uint8Array): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const bytes = await transaction.get(stateKey(id));
            if (bytes === undefined) throw new Error("Unknown session");
            const record = decodeSessionRecord(bytes);
            try {
                if (record.status !== "pending") throw new Error("Session is not pending");
            } finally {
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
        });
    }

    async abandon(id: Uint8Array): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const bytes = await transaction.get(stateKey(id));
            if (bytes === undefined) throw new Error("Unknown session");
            const record = decodeSessionRecord(bytes);
            try {
                if (record.status !== "creating" && record.stagedCommitId === undefined) {
                    throw new Error("Session has no blocked membership operation");
                }
            } finally {
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
        });
    }

    async prepareUpdates(): Promise<PreparedUpdates> {
        return this.#store.transaction(async (transaction) => {
            type Candidate =
                | { readonly type: "route"; readonly eventId: string; readonly key: string }
                | {
                      readonly type: "update";
                      readonly eventId: string;
                      readonly key: string;
                      readonly sessionId: Uint8Array;
                  };
            const candidates: Candidate[] = [];
            const routePage = await transaction.scan(ROUTING_MARKER_PREFIX, {
                limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1,
            });
            try {
                for (const [key, bytes] of routePage) {
                    const eventId = key.slice(ROUTING_MARKER_PREFIX.length);
                    const marker = decodeSessionRouting(bytes);
                    const stateBytes = await transaction.get(stateKey(marker.sessionId));
                    if (stateBytes === undefined) {
                        await transaction.delete(key);
                        zeroBytes(marker.sessionId);
                        continue;
                    }
                    zeroBytes(stateBytes);
                    candidates.push({ type: "route", eventId, key });
                    zeroBytes(marker.sessionId);
                }
            } finally {
                for (const bytes of routePage.values()) zeroBytes(bytes);
            }
            const updatePage = await transaction.scan(APPLICATION_UPDATE_PREFIX, {
                limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1,
            });
            try {
                for (const [key, indexedSessionId] of updatePage) {
                    const eventId = key.slice(APPLICATION_UPDATE_PREFIX.length);
                    const bufferedBytes = await transaction.get(
                        `${bufferPrefix(indexedSessionId)}${eventId}`,
                    );
                    if (bufferedBytes === undefined) {
                        await transaction.delete(key);
                        continue;
                    }
                    zeroBytes(bufferedBytes);
                    candidates.push({
                        type: "update",
                        eventId,
                        key,
                        sessionId: indexedSessionId.slice(),
                    });
                }
            } finally {
                for (const bytes of updatePage.values()) zeroBytes(bytes);
            }
            candidates.sort((left, right) => left.eventId.localeCompare(right.eventId));
            const selected = candidates.slice(0, MAXIMUM_UPDATE_BATCH_EVENTS);
            const keys: string[] = [];
            const routes: PreparedSessionRoute[] = [];
            const updates: PreparedRoutedUpdate[] = [];
            try {
                for (const candidate of selected) {
                    if (candidate.type === "route") {
                        const markerBytes = await transaction.get(candidate.key);
                        if (markerBytes === undefined) continue;
                        const marker = decodeSessionRouting(markerBytes);
                        zeroBytes(markerBytes);
                        const stateBytes = await transaction.get(stateKey(marker.sessionId));
                        if (stateBytes === undefined) {
                            await transaction.delete(candidate.key);
                            zeroBytes(marker.sessionId);
                            continue;
                        }
                        const record = decodeSessionRecord(stateBytes);
                        const epoch = restoreEpoch(this.#identity, record);
                        try {
                            routes.push({
                                eventId: candidate.eventId,
                                key: candidate.key,
                                session: publicSession(record, epoch),
                            });
                        } finally {
                            epoch.destroy();
                            this.#zeroSessionRecord(record);
                            zeroBytes(stateBytes);
                            zeroBytes(marker.sessionId);
                        }
                        continue;
                    }
                    const bufferedBytes = await transaction.get(
                        `${bufferPrefix(candidate.sessionId)}${candidate.eventId}`,
                    );
                    if (bufferedBytes === undefined) {
                        await transaction.delete(candidate.key);
                        continue;
                    }
                    let buffered: ReturnType<typeof decodeBufferedEvent>;
                    try {
                        buffered = decodeBufferedEvent(bufferedBytes);
                    } finally {
                        zeroBytes(bufferedBytes);
                    }
                    keys.push(candidate.key);
                    updates.push({
                        id: candidate.eventId,
                        key: candidate.key,
                        sessionId: candidate.sessionId.slice(),
                        sender: buffered.sender,
                        bytes: buffered.bytes,
                        owner: await this.#sessionOwner(transaction, candidate.sessionId),
                    });
                }
                return {
                    keys,
                    routes,
                    updates,
                    exhausted:
                        candidates.length <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        routePage.size <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        updatePage.size <= MAXIMUM_UPDATE_BATCH_EVENTS,
                };
            } finally {
                for (const candidate of candidates) {
                    if (candidate.type === "update") zeroBytes(candidate.sessionId);
                }
            }
        });
    }

    async commitUpdates(
        prepared: PreparedUpdates,
        decisions: readonly SessionRouteDecision[] = [],
        consumedKeys: ReadonlySet<string> = new Set(prepared.keys),
        operation?: (transaction: StoreTransaction) => Promise<void>,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const changes = new Map<string, { id: Uint8Array; events: number; bytes: number }>();
            try {
                for (const decision of decisions) {
                    const markerBytes = await transaction.get(decision.key);
                    if (markerBytes === undefined) continue;
                    const marker = decodeSessionRouting(markerBytes);
                    try {
                        if (!equalBytes(marker.sessionId, decision.sessionId)) {
                            throw new Error("Prepared session route changed before commit");
                        }
                        if (decision.owner.owner === "ignored") {
                            await this.#deleteSession(transaction, decision.sessionId);
                            await this.#rejectSession(transaction, decision.sessionId);
                        } else {
                            await setAndZero(
                                transaction,
                                sessionOwnerKey(decision.sessionId),
                                encodeSessionOwner(decision.owner),
                            );
                            if (decision.owner.owner === "contact") {
                                await this.#indexBuffered(transaction, decision.sessionId);
                            } else {
                                await this.#activatePending(transaction, decision.sessionId);
                            }
                        }
                        await transaction.delete(decision.key);
                    } finally {
                        zeroBytes(marker.sessionId);
                        zeroBytes(markerBytes);
                    }
                }
                for (const key of prepared.keys) {
                    if (!consumedKeys.has(key)) continue;
                    const indexedSessionId = await transaction.get(key);
                    if (indexedSessionId === undefined) continue;
                    try {
                        const eventId = key.slice(APPLICATION_UPDATE_PREFIX.length);
                        const bufferedKey = `${bufferPrefix(indexedSessionId)}${eventId}`;
                        const bufferedBytes = await transaction.get(bufferedKey);
                        if (bufferedBytes === undefined) {
                            await transaction.delete(key);
                            continue;
                        }
                        let buffered: ReturnType<typeof decodeBufferedEvent> | undefined;
                        try {
                            buffered = decodeBufferedEvent(bufferedBytes);
                            const decoded = buffered;
                            const encodedId = sessionId(indexedSessionId);
                            const change = changes.get(encodedId) ?? {
                                id: indexedSessionId.slice(),
                                events: 0,
                                bytes: 0,
                            };
                            change.events += 1;
                            change.bytes += decoded.bytes.length;
                            changes.set(encodedId, change);
                            await transaction.delete(bufferedKey);
                            await transaction.delete(key);
                        } finally {
                            if (buffered !== undefined) {
                                zeroBytes(buffered.sender);
                                zeroBytes(buffered.bytes);
                            }
                            zeroBytes(bufferedBytes);
                        }
                    } finally {
                        zeroBytes(indexedSessionId);
                    }
                }
                for (const change of changes.values()) {
                    const stateBytes = await transaction.get(stateKey(change.id));
                    if (stateBytes === undefined) continue;
                    const record = decodeSessionRecord(stateBytes);
                    try {
                        if (
                            (record.status !== "active" &&
                                !(
                                    record.status === "pending" &&
                                    (await this.#sessionOwner(transaction, change.id))?.owner ===
                                        "contact"
                                )) ||
                            record.bufferedEvents < change.events ||
                            record.bufferedBytes < change.bytes
                        ) {
                            throw new Error("Invalid application update accounting");
                        }
                        await setAndZero(
                            transaction,
                            stateKey(change.id),
                            encodeSessionRecord({
                                ...record,
                                bufferedEvents: record.bufferedEvents - change.events,
                                bufferedBytes: record.bufferedBytes - change.bytes,
                            }),
                        );
                    } finally {
                        this.#zeroSessionRecord(record);
                        zeroBytes(stateBytes);
                    }
                }
                await operation?.(transaction);
            } finally {
                for (const change of changes.values()) {
                    zeroBytes(change.id);
                }
            }
        });
    }

    async send(id: Uint8Array, bytes: Uint8Array): Promise<string> {
        return this.#queuePrivate(id, { version: 1, type: "application", bytes }, "application");
    }

    /** Atomically queue one contact packet with its contact-state mutation. */
    async sendOwnedContact(
        id: Uint8Array,
        bytes: Uint8Array,
        operation: (transaction: StoreTransaction, deliveryId: string) => Promise<void>,
    ): Promise<string> {
        return this.#store.transaction(async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner?.owner !== "contact") throw new Error("Session owner does not match");
            const deliveryId = await this.#queuePrivate(
                id,
                { version: 1, type: "application", bytes },
                "application",
                transaction,
            );
            await operation(transaction, deliveryId);
            return deliveryId;
        });
    }

    /** Atomically queue one packet to each bounded active contact and mutate contact state. */
    async sendOwnedContacts(
        packets: readonly { readonly id: Uint8Array; readonly bytes: Uint8Array }[],
        operation: (transaction: StoreTransaction, deliveryIds: readonly string[]) => Promise<void>,
    ): Promise<readonly string[]> {
        if (packets.length > 256) throw new Error("Contact packet batch exceeds the contact bound");
        const sessionIds = packets.map(({ id }) => encodeBase64Url(id));
        if (new Set(sessionIds).size !== sessionIds.length) {
            throw new Error("Contact packet batch contains duplicate sessions");
        }
        return this.#store.transaction(async (transaction) => {
            const outboxCount = (
                await transaction.scan(OUTBOX_PREFIX, {
                    limit: this.#limits.maximumOutboxes,
                })
            ).size;
            if (outboxCount > this.#limits.maximumOutboxes - packets.length) {
                throw new Error("Local session outbox capacity exceeded");
            }
            for (const packet of packets) {
                const owner = await this.#sessionOwner(transaction, packet.id);
                if (owner?.owner !== "contact") throw new Error("Session owner does not match");
            }
            const deliveryIds: string[] = [];
            for (const packet of packets) {
                deliveryIds.push(
                    await this.#queuePrivate(
                        packet.id,
                        { version: 1, type: "application", bytes: packet.bytes },
                        "application",
                        transaction,
                    ),
                );
            }
            await operation(transaction, deliveryIds);
            return Object.freeze(deliveryIds);
        });
    }

    /** Atomically activate one contact request, queue hello, and persist its mutation. */
    async acceptOwnedContact(
        id: Uint8Array,
        bytes: Uint8Array,
        operation: (transaction: StoreTransaction, deliveryId: string) => Promise<void>,
    ): Promise<string> {
        return this.#store.transaction(async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner?.owner !== "contact") throw new Error("Session owner does not match");
            await this.#activatePending(transaction, id);
            const deliveryId = await this.#queuePrivate(
                id,
                { version: 1, type: "application", bytes },
                "application",
                transaction,
            );
            await operation(transaction, deliveryId);
            return deliveryId;
        });
    }

    async add(
        id: Uint8Array,
        input: DiscoveryBundle | SessionMemberMaterial,
        operation?: (transaction: StoreTransaction) => Promise<void>,
    ): Promise<void> {
        let member: SessionMemberMaterial;
        if ("keyPackage" in input) {
            member = input;
        } else {
            if (
                input.keyPackages.length !== 1 ||
                !verifyDiscoveryBundle(input, { now: this.#now() })
            ) {
                throw new Error("Invalid Add discovery bundle");
            }
            member = {
                identity: input.identityKey,
                keyPackage: input.keyPackages[0]!,
                discovery: input,
            };
        }
        if (
            member.identity.length !== 32 ||
            !verifyMlsKeyPackage(member.keyPackage, Math.floor(this.#now() / 1_000)) ||
            !equalBytes(member.keyPackage.leafNode.signatureKey, member.identity) ||
            !equalBytes(member.keyPackage.leafNode.credential.identity, member.identity)
        ) {
            throw new Error("Invalid Add KeyPackage");
        }
        await this.#store.transaction(async (transaction) => {
            const stateBytes = await transaction.get(stateKey(id));
            if (stateBytes === undefined) throw new Error("Unknown active session");
            const record = decodeSessionRecord(stateBytes);
            const epoch = restoreEpoch(this.#identity, record);
            let session: MurmurSession;
            try {
                session = publicSession(record, epoch);
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
            }
            if (session === undefined || session.status !== "active") {
                throw new Error("Unknown active session");
            }
            if (member.discovery !== undefined) {
                await this.#claimDiscovery(transaction, [member.discovery]);
            }
            await operation?.(transaction);
            if (equalBytes(session.committer, this.#identity.publicKey)) {
                await this.#prepareCommit(
                    id,
                    [{ identity: member.identity, keyPackage: member.keyPackage }],
                    [],
                    [],
                    undefined,
                    transaction,
                );
            } else {
                await this.#queuePrivate(
                    id,
                    { version: 1, type: "proposal_add", keyPackage: member.keyPackage },
                    "proposal",
                    transaction,
                );
            }
        });
    }

    async remove(id: Uint8Array, identity: Uint8Array): Promise<void> {
        const session = await this.get(id);
        if (session === undefined || session.status !== "active") {
            throw new Error("Unknown active session");
        }
        if (equalBytes(session.committer, this.#identity.publicKey)) {
            await this.#prepareCommit(id, [], [identity], []);
        } else {
            await this.#queuePrivate(
                id,
                { version: 1, type: "proposal_remove", identity },
                "proposal",
            );
        }
    }

    async transferCommitter(id: Uint8Array, identity: Uint8Array): Promise<void> {
        const session = await this.get(id);
        if (
            session === undefined ||
            session.status !== "active" ||
            !equalBytes(session.committer, this.#identity.publicKey)
        ) {
            throw new Error("Only the current committer may transfer its role");
        }
        await this.#prepareCommit(id, [], [], [], identity);
    }

    async proposals(id: Uint8Array): Promise<readonly MurmurSessionProposal[]> {
        const entries = await this.#store.scan(proposalPrefix(id), {
            limit: MAXIMUM_PROPOSALS_PER_SESSION,
        });
        return [...entries].map(([key, bytes]) => {
            try {
                const stored = decodeStoredProposal(bytes);
                const frame = stored.frame;
                return {
                    id: key.slice(proposalPrefix(id).length),
                    type: frame.type === "proposal_add" ? "add" : "remove",
                    proposer: stored.proposer,
                    identity:
                        frame.type === "proposal_add"
                            ? frame.keyPackage.leafNode.signatureKey.slice()
                            : frame.identity.slice(),
                };
            } finally {
                zeroBytes(bytes);
            }
        });
    }

    async acceptProposals(id: Uint8Array, proposalIds: readonly string[]): Promise<void> {
        if (
            proposalIds.length < 1 ||
            proposalIds.length > MAXIMUM_COMMIT_PROPOSALS ||
            new Set(proposalIds).size !== proposalIds.length
        ) {
            throw new Error("Invalid proposal selection");
        }
        await this.#store.transaction(async (transaction) => {
            const stateBytes = await transaction.get(stateKey(id));
            if (stateBytes === undefined) throw new Error("Unknown session");
            const record = decodeSessionRecord(stateBytes);
            const epoch = restoreEpoch(this.#identity, record);
            let session: MurmurSession;
            try {
                session = publicSession(record, epoch);
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
            }
            if (!equalBytes(session.committer, this.#identity.publicKey)) {
                throw new Error("Only the committer may accept proposals");
            }
            const additions: PreparedAddition[] = [];
            const removals: Uint8Array[] = [];
            const keys: string[] = [];
            const identities = new Set<string>();
            for (const proposalId of proposalIds) {
                const key = `${proposalPrefix(id)}${proposalId}`;
                const bytes = await transaction.get(key);
                if (bytes === undefined) throw new Error("Unknown session proposal");
                let frame: ReturnType<typeof decodeStoredProposal>["frame"];
                try {
                    frame = decodeStoredProposal(bytes).frame;
                } finally {
                    zeroBytes(bytes);
                }
                const identity =
                    frame.type === "proposal_add"
                        ? frame.keyPackage.leafNode.signatureKey
                        : frame.identity;
                const encodedIdentity = encodeBase64Url(identity);
                if (identities.has(encodedIdentity)) {
                    throw new Error("Conflicting proposal selection");
                }
                identities.add(encodedIdentity);
                if (frame.type === "proposal_add") {
                    if (!verifyMlsKeyPackage(frame.keyPackage, Math.floor(this.#now() / 1_000))) {
                        throw new Error("Selected Add proposal KeyPackage is no longer current");
                    }
                    if (session.members.some((member) => equalBytes(member, identity))) {
                        await transaction.delete(key);
                        continue;
                    }
                    additions.push({ identity, keyPackage: frame.keyPackage });
                } else {
                    if (
                        equalBytes(frame.identity, session.committer) ||
                        !session.members.some((member) => equalBytes(member, frame.identity))
                    ) {
                        await transaction.delete(key);
                        continue;
                    }
                    removals.push(frame.identity);
                }
                keys.push(key);
            }
            if (additions.length + removals.length === 0) return;
            await this.#prepareCommit(id, additions, removals, keys, undefined, transaction);
        });
    }

    async synchronize(options: MurmurSynchronizeOptions = {}): Promise<MurmurSynchronizeResult> {
        await this.#store.transaction((transaction) =>
            this.#pruneKeyPackages(transaction, this.#now()),
        );
        const before = await this.#flushOutboxes(options.signal);
        const inbox = await this.#inbox.synchronize(options);
        const after = await this.#flushOutboxes(options.signal);
        return this.#synchronizationResult(inbox, [before, after]);
    }

    streamInbox(options: InboxStreamOptions): AsyncIterable<InboxSyncResult> {
        return this.#inbox.stream(options);
    }

    async flush(signal?: AbortSignal): Promise<boolean> {
        await this.#store.transaction((transaction) =>
            this.#pruneKeyPackages(transaction, this.#now()),
        );
        return (await this.#flushOutboxes(signal)).transientFailureIds.size > 0;
    }

    async completeStreamEvent(
        inbox: InboxSyncResult,
        signal?: AbortSignal,
    ): Promise<MurmurSynchronizeResult> {
        return this.#synchronizationResult(inbox, [await this.#flushOutboxes(signal)]);
    }

    async #synchronizationResult(
        inbox: InboxSyncResult,
        publications: readonly FlushOutboxResult[],
    ): Promise<MurmurSynchronizeResult> {
        const pendingOutboxes = (
            await this.#store.scan(OUTBOX_PREFIX, {
                limit: this.#limits.maximumOutboxes,
            })
        ).size;
        const publishedIds = new Set(publications.flatMap(({ publishedIds }) => [...publishedIds]));
        const transientFailureIds = new Set(
            publications.flatMap(({ transientFailureIds }) => [...transientFailureIds]),
        );
        const terminalFailureIds = new Set(
            publications.flatMap(({ terminalFailureIds }) => [...terminalFailureIds]),
        );
        return {
            inbox,
            published: publishedIds.size,
            transientPublicationFailures: transientFailureIds.size,
            terminalPublicationFailures: terminalFailureIds.size,
            pendingOutboxes,
            issues: await this.issues(),
        };
    }

    async issues(): Promise<readonly MurmurSessionIssue[]> {
        const entries = await this.#store.scan(QUARANTINE_PREFIX, {
            limit: MAXIMUM_REJECTED_SESSIONS,
        });
        const result: MurmurSessionIssue[] = [];
        for (const [key, bytes] of entries) {
            try {
                result.push(decodeIssue(key.slice(QUARANTINE_PREFIX.length), bytes));
            } finally {
                zeroBytes(bytes);
            }
        }
        return result;
    }

    async #nextOutboxOrder(transaction: StoreTransaction): Promise<string> {
        const stored = await transaction.get(OUTBOX_SEQUENCE_KEY);
        let previous = 0n;
        if (stored !== undefined) {
            try {
                const value = utf8Decode(stored);
                if (!/^\d{32}$/.test(value)) {
                    throw new Error("Invalid session outbox sequence");
                }
                previous = BigInt(value);
            } finally {
                zeroBytes(stored);
            }
        }
        const next = previous + 1n;
        const order = next.toString().padStart(32, "0");
        if (order.length !== 32) throw new Error("Session outbox sequence exhausted");
        await setAndZero(transaction, OUTBOX_SEQUENCE_KEY, utf8Encode(order));
        return order;
    }

    async #queuePrivate(
        id: Uint8Array,
        frame: PrivateSessionFrame,
        kind: "application" | "proposal",
        existingTransaction?: StoreTransaction,
    ): Promise<string> {
        const queue = async (transaction: StoreTransaction): Promise<string> => {
            if (
                (
                    await transaction.scan(OUTBOX_PREFIX, {
                        limit: this.#limits.maximumOutboxes,
                    })
                ).size >= this.#limits.maximumOutboxes
            ) {
                throw new Error("Local session outbox capacity exceeded");
            }
            const bytes = await transaction.get(stateKey(id));
            if (bytes === undefined) throw new Error("Unknown session");
            const record = decodeSessionRecord(bytes);
            let parentCommitId: string | undefined;
            let parentBytes: Uint8Array | undefined;
            let parent: SessionOutboxRecord | undefined;
            let epoch: MlsEpochState | undefined;
            let applicationData: Uint8Array | undefined;
            let checkpoint: Uint8Array | undefined;
            try {
                if (record.status === "removed") throw new Error("Unknown session");
                if (record.stagedCommitId === undefined) {
                    if (record.status === "creating") {
                        throw new Error("Creating session is missing its staged epoch");
                    }
                    epoch = restoreEpoch(this.#identity, record);
                } else {
                    if (kind !== "application") {
                        throw new Error("Session cannot queue a proposal while committing");
                    }
                    parentCommitId = record.stagedCommitId;
                    parentBytes = await transaction.get(outboxKey(parentCommitId));
                    if (parentBytes === undefined) {
                        throw new Error("Session staged Commit is missing");
                    }
                    parent = decodeOutboxRecord(parentBytes);
                    if (
                        parent.kind !== "commit" ||
                        parent.stagedEpoch === undefined ||
                        parent.delivery.id !== parentCommitId ||
                        !equalBytes(parent.sessionId, id)
                    ) {
                        throw new Error("Session staged Commit is invalid");
                    }
                    epoch = MlsEpochState.deserialize(parent.stagedEpoch, {
                        localSigningSecretKey: this.#identity.secretKey,
                        authenticateCredential: authenticateMurmurMlsCredential,
                        minimumPersistenceGeneration: 0n,
                    });
                    const minimumGeneration = record.generation + 1n;
                    if (epoch.persistenceGeneration < minimumGeneration) {
                        epoch.rebasePersistenceGeneration(minimumGeneration);
                    }
                }
                const members = activeMembers(epoch);
                if (members.length > this.#limits.maximumMembersPerSession) {
                    throw new Error("Session exceeds the configured member limit");
                }
                if (
                    frame.type === "application" &&
                    (frame.bytes.length > 1024 * 1024 ||
                        frame.bytes.length >
                            Math.max(
                                0,
                                Math.floor((this.#limits.maximumDeliveryCiphertextBytes * 3) / 4) -
                                    512,
                            ))
                ) {
                    throw new Error("Session application payload exceeds the configured limit");
                }
                applicationData = encodePrivateFrame(frame);
                const message = epoch.seal(applicationData);
                const ciphertext = encodePrivateCiphertext(message);
                if (ciphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
                    throw new Error("Session delivery exceeds the configured ciphertext limit");
                }
                const now = this.#now();
                const delivery = createSignedDelivery(this.#identity, members, ciphertext, {
                    createdAt: now,
                    expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                });
                checkpoint = epoch.serialize();
                if (parent === undefined) {
                    await setAndZero(
                        transaction,
                        stateKey(id),
                        encodeSessionRecord({
                            ...record,
                            epoch: checkpoint,
                            generation: epoch.persistenceGeneration,
                        }),
                    );
                } else {
                    await setAndZero(
                        transaction,
                        outboxKey(parent.delivery.id),
                        encodeOutboxRecord({ ...parent, stagedEpoch: checkpoint }),
                    );
                }
                const order = await this.#nextOutboxOrder(transaction);
                await setAndZero(
                    transaction,
                    outboxKey(delivery.id),
                    encodeOutboxRecord({
                        version: 1,
                        kind,
                        order,
                        operationId: delivery.id,
                        sessionId: id,
                        delivery,
                        applicationData,
                        ...(parentCommitId === undefined ? {} : { parentCommitId }),
                    }),
                );
                await transaction.set(outboxOrderKey(order, delivery.id), new Uint8Array());
                if (parentCommitId === undefined) {
                    await transaction.set(epochOutboxIndexKey(id, delivery.id), new Uint8Array());
                } else {
                    await transaction.set(
                        postCommitOutboxIndexKey(parentCommitId, delivery.id),
                        new Uint8Array(),
                    );
                }
                return delivery.id;
            } finally {
                epoch?.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
                if (parent?.stagedEpoch !== undefined) zeroBytes(parent.stagedEpoch);
                if (parent?.applicationData !== undefined) zeroBytes(parent.applicationData);
                if (parentBytes !== undefined) zeroBytes(parentBytes);
                if (applicationData !== undefined) zeroBytes(applicationData);
                if (checkpoint !== undefined) zeroBytes(checkpoint);
            }
        };
        return existingTransaction === undefined
            ? this.#store.transaction(queue)
            : queue(existingTransaction);
    }

    async #prepareCommit(
        id: Uint8Array,
        additions: readonly PreparedAddition[],
        removals: readonly Uint8Array[],
        consumedProposalKeys: readonly string[],
        nextCommitter?: Uint8Array,
        existingTransaction?: StoreTransaction,
    ): Promise<void> {
        const prepare = async (transaction: StoreTransaction): Promise<void> => {
            const bytes = await transaction.get(stateKey(id));
            if (bytes === undefined) throw new Error("Unknown session");
            const record = decodeSessionRecord(bytes);
            if (
                (record.status !== "active" && record.status !== "creating") ||
                record.stagedCommitId !== undefined ||
                !equalBytes(record.committer, this.#identity.publicKey)
            ) {
                throw new Error("Only the idle epoch committer may create a Commit");
            }
            const epoch = restoreEpoch(this.#identity, record);
            let transition: ReturnType<MlsEpochState["prepareCommit"]> | undefined;
            let commitKey: Uint8Array | undefined;
            let stagedCheckpoint: Uint8Array | undefined;
            try {
                const members = activeMembers(epoch);
                const memberIds = new Set(members.map(encodeBase64Url));
                const additionIds = additions.map(({ identity }) => encodeBase64Url(identity));
                const removalIds = removals.map(encodeBase64Url);
                if (
                    new Set(additionIds).size !== additionIds.length ||
                    new Set(removalIds).size !== removalIds.length ||
                    additionIds.some((identity) => memberIds.has(identity)) ||
                    removalIds.some((identity) => !memberIds.has(identity))
                ) {
                    throw new Error("Invalid or conflicting session membership change");
                }
                const projectedMembers = members.length + additions.length - removals.length;
                if (
                    projectedMembers < 2 ||
                    projectedMembers > this.#limits.maximumMembersPerSession
                ) {
                    throw new Error("Session membership exceeds the configured limit");
                }
                const requiredOutboxes = 1 + additions.length;
                const outboxCount = (
                    await transaction.scan(OUTBOX_PREFIX, {
                        limit: this.#limits.maximumOutboxes,
                    })
                ).size;
                if (outboxCount > this.#limits.maximumOutboxes - requiredOutboxes) {
                    throw new Error("Local session outbox capacity exceeded");
                }
                const resolvedCommitter = nextCommitter ?? record.committer;
                memberLeaf(epoch, resolvedCommitter);
                if (removals.some((identity) => equalBytes(identity, resolvedCommitter))) {
                    throw new Error("Cannot remove the next epoch committer");
                }
                const proposals: MlsEpochCommitProposal[] = [
                    ...additions.map(
                        ({ keyPackage }): MlsEpochCommitProposal => ({
                            type: "add",
                            keyPackage,
                        }),
                    ),
                    ...removals.map(
                        (identity): MlsEpochCommitProposal => ({
                            type: "remove",
                            removed: memberLeaf(epoch, identity),
                        }),
                    ),
                ];
                commitKey = epoch.exportSecret(COMMIT_EXPORT_LABEL, COMMIT_EXPORT_CONTEXT, 32);
                const committerControl = encodeCommitterControl(resolvedCommitter);
                transition = epoch.prepareCommit(proposals, committerControl);
                const commitMessage = decodeMlsTreeCommit(transition.commit);
                const commitCiphertext = sealCommitCiphertext(commitKey, {
                    version: 1,
                    groupId: id,
                    epoch: epoch.context.epoch,
                    commit: transition.commit,
                    nextCommitter: resolvedCommitter,
                });
                if (commitCiphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
                    throw new Error("Session Commit exceeds the configured ciphertext limit");
                }
                const now = this.#now();
                const delivery = createSignedDelivery(this.#identity, members, commitCiphertext, {
                    createdAt: now,
                    expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                });
                stagedCheckpoint = transition.transition.serialize();
                const commitOrder = await this.#nextOutboxOrder(transaction);
                await setAndZero(
                    transaction,
                    stateKey(id),
                    encodeSessionRecord({ ...record, stagedCommitId: delivery.id }),
                );
                const bootstrapDeliveryIds: string[] = [];
                for (const addition of additions) {
                    if (transition.welcome === undefined) {
                        throw new Error("MLS Add Commit did not create a Welcome");
                    }
                    const bootstrap = encodeBootstrapFrame({
                        version: 1,
                        inviter: this.#identity.publicKey,
                        groupId: id,
                        descriptor: record.descriptor,
                        welcome: transition.welcome,
                        tree: encodeMlsRatchetTree(transition.tree),
                        confirmationTag: commitMessage.confirmationTag,
                        commit: transition.commit,
                        keyPackageReference: mlsKeyPackageReference(addition.keyPackage),
                        committer: resolvedCommitter,
                    });
                    try {
                        const box = sealBox(
                            { publicKey: addition.identity },
                            bootstrap,
                            concatBytes(this.#identity.publicKey, addition.identity),
                        );
                        const bootstrapCiphertext = encodeBootstrapCiphertext(box);
                        try {
                            if (
                                bootstrapCiphertext.length >
                                this.#limits.maximumDeliveryCiphertextBytes
                            ) {
                                throw new Error(
                                    "Session bootstrap exceeds the configured ciphertext limit",
                                );
                            }
                            const welcomeDelivery = createSignedDelivery(
                                this.#identity,
                                [addition.identity],
                                bootstrapCiphertext,
                                {
                                    createdAt: now,
                                    expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                                },
                            );
                            const bootstrapOrder = await this.#nextOutboxOrder(transaction);
                            await setAndZero(
                                transaction,
                                outboxKey(welcomeDelivery.id),
                                encodeOutboxRecord({
                                    version: 1,
                                    kind: "bootstrap",
                                    order: bootstrapOrder,
                                    operationId: delivery.id,
                                    sessionId: id,
                                    delivery: welcomeDelivery,
                                    parentCommitId: delivery.id,
                                }),
                            );
                            await transaction.set(
                                outboxOrderKey(bootstrapOrder, welcomeDelivery.id),
                                new Uint8Array(),
                            );
                            await transaction.set(
                                bootstrapIndexKey(delivery.id, welcomeDelivery.id),
                                new Uint8Array(),
                            );
                            bootstrapDeliveryIds.push(welcomeDelivery.id);
                        } finally {
                            zeroBytes(bootstrapCiphertext);
                            zeroBytes(box.ciphertext);
                        }
                    } finally {
                        zeroBytes(bootstrap);
                    }
                }
                await setAndZero(
                    transaction,
                    outboxKey(delivery.id),
                    encodeOutboxRecord({
                        version: 1,
                        kind: "commit",
                        order: commitOrder,
                        operationId: delivery.id,
                        sessionId: id,
                        delivery,
                        stagedEpoch: stagedCheckpoint,
                        nextCommitter: resolvedCommitter,
                        retainPreviousEpoch: removals.length === 0,
                        consumedProposalKeys,
                        bootstrapDeliveryIds,
                    }),
                );
                await transaction.set(outboxOrderKey(commitOrder, delivery.id), new Uint8Array());
            } finally {
                transition?.transition.cancel();
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
                if (commitKey !== undefined) zeroBytes(commitKey);
                if (stagedCheckpoint !== undefined) zeroBytes(stagedCheckpoint);
            }
        };
        if (existingTransaction === undefined) {
            await this.#store.transaction(prepare);
        } else {
            await prepare(existingTransaction);
        }
    }

    async #receive(transaction: StoreTransaction, queued: InboxDelivery): Promise<void> {
        if (queued.delivery.ciphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
            throw new TerminalInboxDeliveryError("session_ciphertext_too_large");
        }
        let wire: ReturnType<typeof parseSessionCiphertext>;
        try {
            wire = parseSessionCiphertext(queued.delivery.ciphertext);
        } catch {
            throw new TerminalInboxDeliveryError("malformed_session_ciphertext");
        }
        if (wire.kind === "bootstrap") {
            await this.#receiveBootstrap(transaction, queued, wire.box);
            return;
        }
        let id: Uint8Array;
        try {
            id =
                wire.kind === "commit"
                    ? wire.groupId
                    : decodeMlsPrivateMessage(wire.message).groupId;
        } catch {
            throw new TerminalInboxDeliveryError("malformed_private_message");
        }
        const ownOutboxBytes = await transaction.get(outboxKey(queued.delivery.id));
        if (
            ownOutboxBytes !== undefined &&
            equalBytes(queued.delivery.sender, this.#identity.publicKey)
        ) {
            try {
                await this.#receiveOwnEcho(transaction, queued, decodeOutboxRecord(ownOutboxBytes));
                return;
            } finally {
                zeroBytes(ownOutboxBytes);
            }
        }
        if (ownOutboxBytes !== undefined) zeroBytes(ownOutboxBytes);
        const stateBytes = await transaction.get(stateKey(id));
        if (stateBytes === undefined) throw new TerminalInboxDeliveryError("unknown_session");
        const record = decodeSessionRecord(stateBytes);
        try {
            if (wire.kind === "commit") {
                await this.#receiveCommit(transaction, queued, record, wire);
            } else {
                await this.#receivePrivate(transaction, queued, record, wire.message);
            }
        } finally {
            this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
        }
    }

    async #receiveBootstrap(
        transaction: StoreTransaction,
        queued: InboxDelivery,
        box: Parameters<typeof openBox>[1],
    ): Promise<void> {
        if (
            queued.delivery.recipients.length !== 1 ||
            !equalBytes(queued.delivery.recipients[0]!, this.#identity.publicKey)
        ) {
            throw new TerminalInboxDeliveryError("bootstrap_recipient_set");
        }
        let plaintext: Uint8Array;
        try {
            plaintext = openBox(
                this.#identity,
                box,
                concatBytes(queued.delivery.sender, this.#identity.publicKey),
            );
        } catch {
            throw new TerminalInboxDeliveryError("invalid_bootstrap_box");
        }
        try {
            let frame: ReturnType<typeof decodeBootstrapFrame>;
            try {
                frame = decodeBootstrapFrame(plaintext);
            } catch {
                throw new TerminalInboxDeliveryError("malformed_bootstrap");
            }
            const rejection = await transaction.get(rejectedKey(frame.groupId));
            const rejected = rejection !== undefined;
            if (rejection !== undefined) zeroBytes(rejection);
            if (!equalBytes(frame.inviter, queued.delivery.sender) || rejected) {
                throw new TerminalInboxDeliveryError("rejected_bootstrap");
            }
            const existingState = await transaction.get(stateKey(frame.groupId));
            if (existingState !== undefined) {
                zeroBytes(existingState);
                return;
            }
            const pending = await transaction.scan(PENDING_SESSION_PREFIX, {
                limit: this.#limits.maximumPendingSessions,
            });
            if (pending.size >= this.#limits.maximumPendingSessions) {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "pending_session_capacity",
                    frame.groupId,
                    "session",
                );
                return;
            }
            const bundleBytes = await transaction.get(keyPackageKey(frame.keyPackageReference));
            if (bundleBytes === undefined) {
                throw new TerminalInboxDeliveryError("unknown_key_package");
            }
            const reusableBytes = await transaction.get(
                keyPackageReusableKey(frame.keyPackageReference),
            );
            const reusable = reusableBytes !== undefined;
            if (reusableBytes !== undefined) zeroBytes(reusableBytes);
            let bundle: ReturnType<typeof deserializeMlsKeyPackageBundle>;
            try {
                bundle = deserializeMlsKeyPackageBundle(bundleBytes);
            } catch {
                throw new TerminalInboxDeliveryError("invalid_key_package_state");
            }
            let epoch: MlsEpochState | undefined;
            let checkpoint: Uint8Array | undefined;
            let protocolComplete = false;
            try {
                if (
                    !verifyMlsKeyPackage(
                        bundle.keyPackage,
                        Math.floor(queued.delivery.createdAt / 1_000),
                    ) ||
                    !equalBytes(
                        mlsKeyPackageReference(bundle.keyPackage),
                        frame.keyPackageReference,
                    )
                ) {
                    throw new Error("Bootstrap KeyPackage is stale or mismatched");
                }
                const commit = decodeMlsTreeCommit(frame.commit);
                if (
                    !equalBytes(commit.confirmationTag, frame.confirmationTag) ||
                    !equalBytes(decodeCommitterControl(commit.authenticatedData), frame.committer)
                ) {
                    throw new Error("Bootstrap Commit control mismatch");
                }
                const tree = decodeMlsRatchetTree(frame.tree, {
                    groupId: frame.groupId,
                    authenticateCredential: authenticateMurmurMlsCredential,
                });
                const commitSender = tree.nodes[commit.sender * 2];
                if (
                    commitSender?.type !== "leaf" ||
                    !equalBytes(commitSender.signatureKey, frame.inviter)
                ) {
                    throw new Error("Bootstrap Commit sender mismatch");
                }
                try {
                    epoch = joinMlsGroupFromWelcome({
                        identity: this.#identity,
                        inviter: { publicKey: frame.inviter },
                        groupId: frame.groupId,
                        welcome: frame.welcome,
                        tree,
                        keyPackageBundle: bundle,
                        expectedCommitConfirmationTag: frame.confirmationTag,
                    });
                } catch {
                    throw new TerminalInboxDeliveryError("invalid_mls_welcome");
                }
                if (!activeMembers(epoch).some((member) => equalBytes(member, frame.committer))) {
                    throw new Error("Bootstrap committer is not an MLS member");
                }
                if (activeMembers(epoch).length > this.#limits.maximumMembersPerSession) {
                    throw new Error("Bootstrap exceeds the configured member limit");
                }
                protocolComplete = true;
                checkpoint = epoch.serialize();
                await setAndZero(
                    transaction,
                    stateKey(frame.groupId),
                    encodeSessionRecord({
                        version: 1,
                        status: "pending",
                        descriptor: frame.descriptor,
                        committer: frame.committer,
                        epoch: checkpoint,
                        generation: epoch.persistenceGeneration,
                        bufferedEvents: 0,
                        bufferedBytes: 0,
                    }),
                );
                await transaction.set(pendingKey(frame.groupId), new Uint8Array());
                await setAndZero(
                    transaction,
                    routingMarkerKey(queued.eventId),
                    encodeSessionRouting({ version: 1, sessionId: frame.groupId }),
                );
                if (!reusable) {
                    await transaction.delete(keyPackageKey(frame.keyPackageReference));
                    await transaction.delete(keyPackageExpiryKey(frame.keyPackageReference));
                    await transaction.delete(keyPackageReusableKey(frame.keyPackageReference));
                }
            } catch (error: unknown) {
                if (error instanceof TerminalInboxDeliveryError || protocolComplete) throw error;
                throw new TerminalInboxDeliveryError("invalid_bootstrap");
            } finally {
                epoch?.destroy();
                destroyMlsKeyPackageBundle(bundle);
                if (checkpoint !== undefined) zeroBytes(checkpoint);
                zeroBytes(bundleBytes);
            }
        } finally {
            zeroBytes(plaintext);
        }
    }

    async #receiveOwnEcho(
        transaction: StoreTransaction,
        queued: InboxDelivery,
        outbox: SessionOutboxRecord,
    ): Promise<void> {
        const stateBytes = await transaction.get(stateKey(outbox.sessionId));
        if (stateBytes === undefined) throw new TerminalInboxDeliveryError("unknown_session");
        const record = decodeSessionRecord(stateBytes);
        try {
            if (outbox.kind === "commit") {
                if (
                    outbox.stagedEpoch === undefined ||
                    outbox.nextCommitter === undefined ||
                    record.stagedCommitId !== queued.delivery.id
                ) {
                    throw new TerminalInboxDeliveryError("invalid_commit_echo");
                }
                const next = MlsEpochState.deserialize(outbox.stagedEpoch, {
                    localSigningSecretKey: this.#identity.secretKey,
                    authenticateCredential: authenticateMurmurMlsCredential,
                    minimumPersistenceGeneration: 0n,
                });
                let checkpoint: Uint8Array | undefined;
                try {
                    const minimumGeneration = record.generation + 1n;
                    if (next.persistenceGeneration < minimumGeneration) {
                        next.rebasePersistenceGeneration(minimumGeneration);
                    }
                    const {
                        stagedCommitId: _stagedCommitId,
                        previousEpoch: _previousEpoch,
                        previousGeneration: _previousGeneration,
                        previousEpochExpiresAt: _previousEpochExpiresAt,
                        previousMessagesRemaining: _previousMessagesRemaining,
                        ...settled
                    } = record;
                    checkpoint = next.serialize();
                    await setAndZero(
                        transaction,
                        stateKey(outbox.sessionId),
                        encodeSessionRecord({
                            ...settled,
                            status: record.status === "creating" ? "active" : record.status,
                            committer: outbox.nextCommitter,
                            epoch: checkpoint,
                            generation: next.persistenceGeneration,
                            ...(outbox.retainPreviousEpoch === true
                                ? {
                                      previousEpoch: record.epoch,
                                      previousGeneration: record.generation,
                                      previousEpochExpiresAt:
                                          sessionEventTime(queued.eventId) +
                                          PREVIOUS_EPOCH_GRACE_MILLISECONDS,
                                      previousMessagesRemaining: PREVIOUS_EPOCH_MESSAGES,
                                  }
                                : {}),
                        }),
                    );
                    for (const key of outbox.consumedProposalKeys ?? []) {
                        await transaction.delete(key);
                    }
                    await this.#activatePostCommitOutboxes(
                        transaction,
                        queued.delivery.id,
                        outbox.sessionId,
                    );
                } finally {
                    next.destroy();
                    zeroBytes(outbox.stagedEpoch);
                    if (checkpoint !== undefined) zeroBytes(checkpoint);
                }
            } else if (outbox.kind === "application") {
                const frame = decodePrivateFrame(outbox.applicationData!);
                if (frame.type !== "application") {
                    throw new TerminalInboxDeliveryError("invalid_application_echo");
                }
                try {
                    await this.#buffer(
                        transaction,
                        outbox.sessionId,
                        record,
                        queued.eventId,
                        this.#identity.publicKey,
                        frame.bytes,
                    );
                } finally {
                    zeroBytes(frame.bytes);
                }
            }
            if (outbox.kind === "commit") {
                await this.#deletePrefix(
                    transaction,
                    `${BOOTSTRAP_INDEX_PREFIX}${queued.delivery.id}/`,
                );
            }
            await transaction.delete(outboxKey(queued.delivery.id));
            await transaction.delete(outboxOrderKey(outbox.order, queued.delivery.id));
            if (outbox.kind === "application" || outbox.kind === "proposal") {
                await transaction.delete(epochOutboxIndexKey(outbox.sessionId, queued.delivery.id));
                if (outbox.parentCommitId !== undefined) {
                    await transaction.delete(
                        postCommitOutboxIndexKey(outbox.parentCommitId, queued.delivery.id),
                    );
                }
            }
        } finally {
            this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
            if (outbox.stagedEpoch !== undefined) zeroBytes(outbox.stagedEpoch);
            if (outbox.applicationData !== undefined) zeroBytes(outbox.applicationData);
        }
    }

    async #receivePrivate(
        transaction: StoreTransaction,
        queued: InboxDelivery,
        record: SessionRecord,
        message: Uint8Array,
    ): Promise<void> {
        let header: ReturnType<typeof decodeMlsPrivateMessage>;
        try {
            header = decodeMlsPrivateMessage(message);
        } catch {
            throw new TerminalInboxDeliveryError("malformed_private_message");
        }
        const current = restoreEpoch(this.#identity, record);
        const previous =
            header.epoch === current.context.epoch
                ? undefined
                : restorePreviousEpoch(this.#identity, record);
        const epoch = header.epoch === current.context.epoch ? current : previous;
        if (epoch === undefined || header.epoch !== epoch.context.epoch) {
            current.destroy();
            previous?.destroy();
            throw new TerminalInboxDeliveryError("unknown_message_epoch");
        }
        const eventTime = sessionEventTime(queued.eventId);
        if (
            epoch === previous &&
            (record.previousEpochExpiresAt === undefined ||
                record.previousMessagesRemaining === undefined ||
                eventTime > record.previousEpochExpiresAt ||
                record.previousMessagesRemaining < 1)
        ) {
            current.destroy();
            previous.destroy();
            throw new TerminalInboxDeliveryError("previous_epoch_grace_expired");
        }
        try {
            if (!exactRecipients(queued.delivery, activeMembers(epoch))) {
                throw new TerminalInboxDeliveryError("member_recipient_set");
            }
            let opened: ReturnType<MlsEpochState["openWithCheckpoint"]>;
            try {
                opened = epoch.openWithCheckpoint(message);
            } catch {
                throw new TerminalInboxDeliveryError("invalid_private_message");
            }
            try {
                let updated: SessionRecord;
                if (epoch === current) {
                    updated = {
                        ...record,
                        epoch: opened.state,
                        generation: opened.persistenceGeneration,
                    };
                } else if ((record.previousMessagesRemaining ?? 0) <= 1) {
                    const {
                        previousEpoch: _previousEpoch,
                        previousGeneration: _previousGeneration,
                        previousEpochExpiresAt: _previousEpochExpiresAt,
                        previousMessagesRemaining: _previousMessagesRemaining,
                        ...withoutPrevious
                    } = record;
                    updated = withoutPrevious;
                } else {
                    updated = {
                        ...record,
                        previousEpoch: opened.state,
                        previousGeneration: opened.persistenceGeneration,
                        previousMessagesRemaining: record.previousMessagesRemaining! - 1,
                    };
                }
                await setAndZero(
                    transaction,
                    stateKey(epoch.groupId),
                    encodeSessionRecord(updated),
                );
                const sender = epoch.memberSignatureKeys[opened.message.sender];
                if (sender === undefined || !equalBytes(sender, queued.delivery.sender)) {
                    await this.#quarantine(transaction, queued.eventId, "sender_binding");
                    return;
                }
                let frame: ReturnType<typeof decodePrivateFrame>;
                try {
                    frame = decodePrivateFrame(opened.message.applicationData);
                } catch {
                    await this.#quarantine(
                        transaction,
                        queued.eventId,
                        "unsupported_private_frame",
                    );
                    return;
                }
                if (frame.type === "application") {
                    try {
                        await this.#buffer(
                            transaction,
                            epoch.groupId,
                            record,
                            queued.eventId,
                            sender,
                            frame.bytes,
                        );
                    } finally {
                        zeroBytes(frame.bytes);
                    }
                } else if (
                    epoch === current &&
                    equalBytes(record.committer, this.#identity.publicKey)
                ) {
                    if (!this.#validProposal(epoch, record, frame, queued.delivery.createdAt)) {
                        await this.#quarantine(transaction, queued.eventId, "invalid_proposal");
                        return;
                    }
                    const proposals = await transaction.scan(proposalPrefix(epoch.groupId), {
                        limit: MAXIMUM_PROPOSALS_PER_SESSION,
                    });
                    if (proposals.size >= MAXIMUM_PROPOSALS_PER_SESSION) {
                        await this.#quarantine(transaction, queued.eventId, "proposal_capacity");
                        return;
                    }
                    await setAndZero(
                        transaction,
                        `${proposalPrefix(epoch.groupId)}${queued.eventId}`,
                        encodeStoredProposal({ proposer: sender, frame }),
                    );
                }
            } finally {
                zeroBytes(opened.state);
                zeroBytes(opened.message.applicationData);
                zeroBytes(opened.message.authenticatedData);
            }
        } finally {
            current.destroy();
            if (previous !== undefined && previous !== current) previous.destroy();
            this.#zeroSessionRecord(record);
        }
    }

    async #receiveCommit(
        transaction: StoreTransaction,
        queued: InboxDelivery,
        record: SessionRecord,
        wire: Extract<ReturnType<typeof parseSessionCiphertext>, { kind: "commit" }>,
    ): Promise<void> {
        if (!equalBytes(record.committer, queued.delivery.sender)) {
            throw new TerminalInboxDeliveryError("unauthorized_committer");
        }
        const epoch = restoreEpoch(this.#identity, record);
        let key: Uint8Array | undefined;
        try {
            if (!exactRecipients(queued.delivery, activeMembers(epoch))) {
                throw new TerminalInboxDeliveryError("commit_recipient_set");
            }
            if (wire.epoch !== epoch.context.epoch) {
                throw new TerminalInboxDeliveryError("wrong_commit_epoch");
            }
            key = epoch.exportSecret(COMMIT_EXPORT_LABEL, COMMIT_EXPORT_CONTEXT, 32);
            let frame: ReturnType<typeof openCommitCiphertext>;
            let commit: ReturnType<typeof decodeMlsTreeCommit>;
            try {
                frame = openCommitCiphertext(key, wire);
                commit = decodeMlsTreeCommit(frame.commit);
            } catch {
                throw new TerminalInboxDeliveryError("invalid_commit_ciphertext");
            }
            const expectedSender = memberLeaf(epoch, record.committer);
            let committedNextCommitter: Uint8Array;
            try {
                committedNextCommitter = decodeCommitterControl(commit.authenticatedData);
            } catch {
                throw new TerminalInboxDeliveryError("committer_control");
            }
            if (
                commit.sender !== expectedSender ||
                !equalBytes(committedNextCommitter, frame.nextCommitter)
            ) {
                throw new TerminalInboxDeliveryError("committer_control");
            }
            let transition: ReturnType<MlsEpochState["applyCommit"]>;
            try {
                try {
                    transition = epoch.applyCommit(frame.commit);
                } catch (error: unknown) {
                    if (error instanceof MlsLocalMemberRemovedError) throw error;
                    throw new TerminalInboxDeliveryError("invalid_mls_commit");
                }
                if (transition.sender !== expectedSender) {
                    transition.cancel();
                    throw new TerminalInboxDeliveryError("committer_sender");
                }
            } catch (error: unknown) {
                if (error instanceof MlsLocalMemberRemovedError) {
                    await this.#deleteSession(transaction, frame.groupId);
                    await this.#rejectSession(transaction, frame.groupId);
                    return;
                }
                throw error;
            }
            let committed = false;
            let checkpoint: Uint8Array | undefined;
            try {
                const next = transition.commit();
                committed = true;
                try {
                    if (
                        !activeMembers(next).some((member) =>
                            equalBytes(member, frame.nextCommitter),
                        )
                    ) {
                        throw new TerminalInboxDeliveryError("next_committer_is_not_a_member");
                    }
                    const {
                        stagedCommitId: _stagedCommitId,
                        previousEpoch: _previousEpoch,
                        previousGeneration: _previousGeneration,
                        previousEpochExpiresAt: _previousEpochExpiresAt,
                        previousMessagesRemaining: _previousMessagesRemaining,
                        ...settled
                    } = record;
                    checkpoint = next.serialize();
                    await setAndZero(
                        transaction,
                        stateKey(frame.groupId),
                        encodeSessionRecord({
                            ...settled,
                            committer: frame.nextCommitter,
                            epoch: checkpoint,
                            generation: next.persistenceGeneration,
                            ...(commit.proposals.some((proposal) => proposal.type === "remove")
                                ? {}
                                : {
                                      previousEpoch: record.epoch,
                                      previousGeneration: record.generation,
                                      previousEpochExpiresAt:
                                          sessionEventTime(queued.eventId) +
                                          PREVIOUS_EPOCH_GRACE_MILLISECONDS,
                                      previousMessagesRemaining: PREVIOUS_EPOCH_MESSAGES,
                                  }),
                        }),
                    );
                } finally {
                    next.destroy();
                    if (checkpoint !== undefined) zeroBytes(checkpoint);
                }
            } catch (error: unknown) {
                if (!committed) transition.cancel();
                throw error;
            }
        } finally {
            if (key !== undefined) zeroBytes(key);
            this.#zeroSessionRecord(record);
        }
    }

    async #sessionOwner(
        transaction: StoreTransaction,
        id: Uint8Array,
    ): Promise<SessionOwnerRecord | undefined> {
        const bytes = await transaction.get(sessionOwnerKey(id));
        if (bytes === undefined) return undefined;
        try {
            return decodeSessionOwner(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #deleteRoutingMarkers(transaction: StoreTransaction, id: Uint8Array): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(ROUTING_MARKER_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const marker = decodeSessionRouting(bytes);
                try {
                    if (equalBytes(marker.sessionId, id)) {
                        await transaction.delete(key);
                    }
                } finally {
                    zeroBytes(marker.sessionId);
                    zeroBytes(bytes);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #indexBuffered(transaction: StoreTransaction, id: Uint8Array): Promise<void> {
        let after: string | undefined;
        const prefix = bufferPrefix(id);
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                await transaction.set(applicationUpdateKey(key.slice(prefix.length)), id);
                zeroBytes(bytes);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #activatePending(transaction: StoreTransaction, id: Uint8Array): Promise<void> {
        const stateBytes = await transaction.get(stateKey(id));
        if (stateBytes === undefined) throw new Error("Unknown session");
        const record = decodeSessionRecord(stateBytes);
        try {
            if (record.status !== "pending") throw new Error("Session is not pending");
            await this.#indexBuffered(transaction, id);
            await transaction.delete(pendingKey(id));
            await setAndZero(
                transaction,
                stateKey(id),
                encodeSessionRecord({ ...record, status: "active" }),
            );
        } finally {
            this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
        }
    }

    async #buffer(
        transaction: StoreTransaction,
        id: Uint8Array,
        record: SessionRecord,
        eventId: string,
        sender: Uint8Array,
        bytes: Uint8Array,
    ): Promise<void> {
        const nextEvents = record.bufferedEvents + 1;
        const nextBytes = record.bufferedBytes + bytes.length;
        if (
            nextEvents > this.#limits.maximumBufferedEventsPerSession ||
            nextBytes > this.#limits.maximumBufferedBytesPerSession
        ) {
            if (record.status === "pending") {
                await this.#deleteSession(transaction, id);
                await this.#rejectSession(transaction, id);
            } else {
                await this.#quarantine(transaction, eventId, "active_buffer_capacity");
            }
            return;
        }
        await setAndZero(
            transaction,
            `${bufferPrefix(id)}${eventId}`,
            encodeBufferedEvent({ version: 1, sender, bytes }),
        );
        const owner =
            record.status === "active" ? undefined : await this.#sessionOwner(transaction, id);
        if (record.status === "active" || owner?.owner === "contact") {
            await transaction.set(applicationUpdateKey(eventId), id);
        }
        const latestBytes = await transaction.get(stateKey(id));
        if (latestBytes === undefined) return;
        const latest = decodeSessionRecord(latestBytes);
        await setAndZero(
            transaction,
            stateKey(id),
            encodeSessionRecord({
                ...latest,
                bufferedEvents: nextEvents,
                bufferedBytes: nextBytes,
            }),
        );
        this.#zeroSessionRecord(latest);
        zeroBytes(latestBytes);
    }

    #validProposal(
        epoch: MlsEpochState,
        record: SessionRecord,
        frame: Exclude<PrivateSessionFrame, { type: "application" }>,
        deliveryCreatedAt: number,
    ): boolean {
        if (frame.type === "proposal_add") {
            return (
                verifyMlsKeyPackage(frame.keyPackage, Math.floor(deliveryCreatedAt / 1_000)) &&
                !activeMembers(epoch).some((member) =>
                    equalBytes(member, frame.keyPackage.leafNode.signatureKey),
                )
            );
        }
        try {
            memberLeaf(epoch, frame.identity);
            return !equalBytes(frame.identity, record.committer);
        } catch {
            return false;
        }
    }

    async #quarantine(
        transaction: StoreTransaction,
        eventId: string,
        code: string,
        session?: Uint8Array,
        kind?: MurmurSessionIssue["kind"],
        operationId?: string,
    ): Promise<void> {
        await setAndZero(
            transaction,
            `${QUARANTINE_PREFIX}${eventId}`,
            encodeIssue(code, session, kind, operationId),
        );
        const entries = await transaction.scan(QUARANTINE_PREFIX, {
            limit: MAXIMUM_REJECTED_SESSIONS + 1,
        });
        try {
            if (entries.size > MAXIMUM_REJECTED_SESSIONS) {
                const oldest = entries.keys().next().value;
                if (typeof oldest === "string") await transaction.delete(oldest);
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
    }

    async #flushOutboxes(signal?: AbortSignal): Promise<FlushOutboxResult> {
        const publishedIds = new Set<string>();
        const publishedCommitIds = new Set<string>();
        const transientFailureIds = new Set<string>();
        const terminalFailureIds = await this.#preflightMembershipOutboxes();
        const phases = ["bootstrap", "current", "commit", "post-commit"] as const;
        for (const phase of phases) {
            const blockedSessions = new Set<string>();
            let after: string | undefined;
            for (;;) {
                const page = await this.#store.scan(OUTBOX_ORDER_PREFIX, {
                    ...(after === undefined ? {} : { after }),
                    limit: OUTBOX_SCAN_ITEMS,
                });
                if (page.size === 0) break;
                for (const [orderKey, orderValue] of page) {
                    after = orderKey;
                    const deliveryId = orderKey.slice(orderKey.lastIndexOf("/") + 1);
                    const key = outboxKey(deliveryId);
                    const bytes = await this.#store.get(key);
                    if (bytes === undefined) {
                        zeroBytes(orderValue);
                        await this.#store.delete(orderKey);
                        continue;
                    }
                    let record: SessionOutboxRecord | undefined;
                    try {
                        try {
                            record = decodeOutboxRecord(bytes);
                        } catch {
                            await this.#handleCorruptOutbox(orderKey, deliveryId);
                            terminalFailureIds.add(deliveryId);
                            continue;
                        }
                        const decodedRecord = record;
                        const matchesPhase =
                            (phase === "bootstrap" && decodedRecord.kind === "bootstrap") ||
                            (phase === "current" &&
                                (decodedRecord.kind === "application" ||
                                    decodedRecord.kind === "proposal") &&
                                decodedRecord.parentCommitId === undefined) ||
                            (phase === "commit" && decodedRecord.kind === "commit") ||
                            (phase === "post-commit" &&
                                decodedRecord.kind === "application" &&
                                decodedRecord.parentCommitId !== undefined);
                        if (!matchesPhase) continue;
                        const encodedSessionId = sessionId(decodedRecord.sessionId);
                        if (
                            (decodedRecord.kind === "application" ||
                                decodedRecord.kind === "proposal") &&
                            blockedSessions.has(encodedSessionId)
                        ) {
                            continue;
                        }
                        if (decodedRecord.kind === "commit") {
                            const pendingEpoch = await this.#store.scan(
                                `${EPOCH_OUTBOX_INDEX_PREFIX}${sessionId(
                                    decodedRecord.sessionId,
                                )}/`,
                                { limit: 1 },
                            );
                            if (
                                !(await this.#membershipOperationReady(decodedRecord)) ||
                                pendingEpoch.size > 0
                            ) {
                                continue;
                            }
                        }
                        if (
                            phase === "post-commit" &&
                            !publishedCommitIds.has(decodedRecord.parentCommitId!)
                        ) {
                            continue;
                        }
                        if (decodedRecord.delivery.expiresAt <= this.#now()) {
                            if (
                                decodedRecord.kind === "commit" ||
                                decodedRecord.kind === "bootstrap"
                            ) {
                                await this.#refreshMembershipOutbox(key, decodedRecord);
                                transientFailureIds.add(decodedRecord.delivery.id);
                            } else {
                                await this.#discardTerminalOutbox(key, decodedRecord, "expired");
                                terminalFailureIds.add(decodedRecord.delivery.id);
                            }
                            continue;
                        }
                        try {
                            await this.#transport.publish(decodedRecord.delivery, signal);
                            publishedIds.add(decodedRecord.delivery.id);
                            if (decodedRecord.kind === "commit") {
                                publishedCommitIds.add(decodedRecord.delivery.id);
                            }
                            if (decodedRecord.kind === "bootstrap") {
                                await this.#store.transaction(async (transaction) => {
                                    await transaction.delete(key);
                                    await transaction.delete(orderKey);
                                    await transaction.set(
                                        bootstrapIndexKey(
                                            decodedRecord.parentCommitId!,
                                            decodedRecord.delivery.id,
                                        ),
                                        new Uint8Array([1]),
                                    );
                                });
                            }
                        } catch (error: unknown) {
                            if (
                                decodedRecord.kind === "commit" ||
                                decodedRecord.kind === "bootstrap"
                            ) {
                                await this.#store.transaction((transaction) =>
                                    this.#quarantine(
                                        transaction,
                                        decodedRecord.delivery.id,
                                        `blocked_${decodedRecord.kind}_${
                                            error instanceof DeliveryTransportError
                                                ? error.code
                                                : "transport"
                                        }`,
                                        decodedRecord.sessionId,
                                        decodedRecord.kind,
                                        decodedRecord.operationId,
                                    ),
                                );
                                transientFailureIds.add(decodedRecord.delivery.id);
                            } else if (
                                error instanceof DeliveryTransportError &&
                                error.status >= 400 &&
                                error.status < 500 &&
                                error.status !== 401 &&
                                error.status !== 429
                            ) {
                                await this.#discardTerminalOutbox(key, decodedRecord, error.code);
                                terminalFailureIds.add(decodedRecord.delivery.id);
                            } else {
                                transientFailureIds.add(decodedRecord.delivery.id);
                                blockedSessions.add(encodedSessionId);
                            }
                        }
                    } finally {
                        if (record?.stagedEpoch !== undefined) {
                            zeroBytes(record.stagedEpoch);
                        }
                        if (record?.applicationData !== undefined) {
                            zeroBytes(record.applicationData);
                        }
                        zeroBytes(bytes);
                        zeroBytes(orderValue);
                    }
                }
                if (page.size < OUTBOX_SCAN_ITEMS) break;
            }
        }
        return { publishedIds, transientFailureIds, terminalFailureIds };
    }

    async #preflightMembershipOutboxes(): Promise<Set<string>> {
        const terminalFailureIds = new Set<string>();
        const validCommitIds = new Set<string>();
        const corruptPrimaryIds = new Set<string>();
        let primaryAfter: string | undefined;
        for (;;) {
            const page = await this.#store.scan(OUTBOX_PREFIX, {
                ...(primaryAfter === undefined ? {} : { after: primaryAfter }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, pageBytes] of page) {
                primaryAfter = key;
                const deliveryId = key.slice(OUTBOX_PREFIX.length);
                const bytes = await this.#store.get(key);
                if (bytes === undefined) {
                    zeroBytes(pageBytes);
                    continue;
                }
                let record: SessionOutboxRecord | undefined;
                try {
                    try {
                        record = decodeOutboxRecord(bytes);
                    } catch {
                        corruptPrimaryIds.add(deliveryId);
                        continue;
                    }
                    if (record.kind !== "commit") continue;
                    if (await this.#validMembershipOperation(record)) {
                        validCommitIds.add(record.delivery.id);
                    } else {
                        await this.#store.transaction(async (transaction) => {
                            const recovery = await this.#cancelCorruptMembershipOperation(
                                transaction,
                                record!.delivery.id,
                                "commit",
                            );
                            await this.#quarantine(
                                transaction,
                                record!.delivery.id,
                                "corrupt_membership_operation",
                                recovery?.sessionId ?? record!.sessionId,
                                "commit",
                                record!.operationId,
                            );
                        });
                        terminalFailureIds.add(record.delivery.id);
                    }
                } finally {
                    if (record?.stagedEpoch !== undefined) zeroBytes(record.stagedEpoch);
                    if (record?.applicationData !== undefined) zeroBytes(record.applicationData);
                    zeroBytes(bytes);
                    zeroBytes(pageBytes);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        for (const deliveryId of corruptPrimaryIds) {
            const bytes = await this.#store.get(outboxKey(deliveryId));
            if (bytes === undefined) continue;
            zeroBytes(bytes);
            await this.#handleCorruptOutbox(undefined, deliveryId);
            terminalFailureIds.add(deliveryId);
        }
        await this.#reconcileMissingStagedCommits(terminalFailureIds);
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(OUTBOX_ORDER_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [orderKey, orderValue] of page) {
                after = orderKey;
                const deliveryId = orderKey.slice(orderKey.lastIndexOf("/") + 1);
                const bytes = await this.#store.get(outboxKey(deliveryId));
                if (bytes === undefined) {
                    zeroBytes(orderValue);
                    await this.#store.delete(orderKey);
                    continue;
                }
                let record: SessionOutboxRecord | undefined;
                try {
                    try {
                        record = decodeOutboxRecord(bytes);
                    } catch {
                        await this.#handleCorruptOutbox(orderKey, deliveryId);
                        terminalFailureIds.add(deliveryId);
                        continue;
                    }
                    if (
                        record.kind === "commit" &&
                        !validCommitIds.has(record.delivery.id) &&
                        !(await this.#validMembershipOperation(record))
                    ) {
                        await this.#store.transaction(async (transaction) => {
                            const recovery = await this.#cancelCorruptMembershipOperation(
                                transaction,
                                record!.delivery.id,
                                "commit",
                            );
                            await this.#quarantine(
                                transaction,
                                record!.delivery.id,
                                "corrupt_membership_operation",
                                recovery?.sessionId ?? record!.sessionId,
                                "commit",
                                record!.operationId,
                            );
                        });
                        terminalFailureIds.add(record.delivery.id);
                    } else if (record.kind === "commit") {
                        validCommitIds.add(record.delivery.id);
                    } else if (
                        record.kind === "bootstrap" &&
                        !validCommitIds.has(record.parentCommitId!)
                    ) {
                        const parentBytes = await this.#store.get(
                            outboxKey(record.parentCommitId!),
                        );
                        let parent: SessionOutboxRecord | undefined;
                        let valid = false;
                        if (parentBytes !== undefined) {
                            try {
                                parent = decodeOutboxRecord(parentBytes);
                                valid =
                                    parent.kind === "commit" &&
                                    (await this.#validMembershipOperation(parent));
                            } catch {
                                valid = false;
                            } finally {
                                if (parent?.stagedEpoch !== undefined) {
                                    zeroBytes(parent.stagedEpoch);
                                }
                                zeroBytes(parentBytes);
                            }
                        }
                        if (!valid) {
                            await this.#store.transaction(async (transaction) => {
                                const recovery = await this.#cancelCorruptMembershipOperation(
                                    transaction,
                                    record!.parentCommitId!,
                                    "bootstrap",
                                );
                                await this.#quarantine(
                                    transaction,
                                    record!.delivery.id,
                                    "corrupt_membership_operation",
                                    recovery?.sessionId ?? record!.sessionId,
                                    "bootstrap",
                                    record!.operationId,
                                );
                            });
                            terminalFailureIds.add(record.delivery.id);
                        } else {
                            validCommitIds.add(record.parentCommitId!);
                        }
                    }
                } finally {
                    if (record?.stagedEpoch !== undefined) zeroBytes(record.stagedEpoch);
                    if (record?.applicationData !== undefined) zeroBytes(record.applicationData);
                    zeroBytes(bytes);
                    zeroBytes(orderValue);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        return terminalFailureIds;
    }

    async #handleCorruptOutbox(orderKey: string | undefined, deliveryId: string): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await transaction.delete(outboxKey(deliveryId));
            if (orderKey !== undefined) await transaction.delete(orderKey);
            await this.#deleteIndexEntriesByDeliveryId(
                transaction,
                OUTBOX_ORDER_PREFIX,
                deliveryId,
            );
            const recovery = await this.#reconcileCorruptOutbox(transaction, deliveryId);
            await this.#quarantine(
                transaction,
                deliveryId,
                "corrupt_outbox",
                recovery?.sessionId,
                recovery?.kind,
                recovery?.operationId,
            );
        });
    }

    async #reconcileMissingStagedCommits(terminalFailureIds: Set<string>): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(SESSION_STATE_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: SESSION_LIST_LIMIT,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const id = decodeBase64Url(key.slice(SESSION_STATE_PREFIX.length));
                let record: SessionRecord | undefined;
                try {
                    try {
                        record = decodeSessionRecord(bytes);
                    } catch {
                        const issueId = encodeBase64Url(id);
                        await this.#store.transaction(async (transaction) => {
                            await this.#deleteSession(transaction, id);
                            await this.#quarantine(
                                transaction,
                                issueId,
                                "corrupt_session_state",
                                id,
                            );
                        });
                        terminalFailureIds.add(issueId);
                        continue;
                    }
                    if (record.stagedCommitId === undefined) continue;
                    const stagedCommitId = record.stagedCommitId;
                    const commitBytes = await this.#store.get(outboxKey(stagedCommitId));
                    if (commitBytes !== undefined) {
                        let commit: SessionOutboxRecord | undefined;
                        let matches = false;
                        try {
                            commit = decodeOutboxRecord(commitBytes);
                            matches =
                                commit.kind === "commit" &&
                                commit.delivery.id === stagedCommitId &&
                                equalBytes(commit.sessionId, id);
                        } catch {
                            matches = false;
                        } finally {
                            if (commit?.stagedEpoch !== undefined) zeroBytes(commit.stagedEpoch);
                            if (commit?.applicationData !== undefined) {
                                zeroBytes(commit.applicationData);
                            }
                            zeroBytes(commitBytes);
                        }
                        if (matches) continue;
                        const issueId = stateRepairIssueId(stagedCommitId, id);
                        await this.#store.transaction(async (transaction) => {
                            const recovery = await this.#clearStaleSessionReference(
                                transaction,
                                id,
                                stagedCommitId,
                            );
                            if (recovery !== undefined) {
                                await this.#quarantine(
                                    transaction,
                                    issueId,
                                    "stale_staged_commit",
                                    recovery.sessionId,
                                    "commit",
                                    stagedCommitId,
                                );
                            }
                        });
                        terminalFailureIds.add(issueId);
                        continue;
                    }
                    const issueId = stateRepairIssueId(stagedCommitId, id);
                    await this.#store.transaction(async (transaction) => {
                        const recovery = await this.#cancelCorruptMembershipOperation(
                            transaction,
                            stagedCommitId,
                            "commit",
                        );
                        if (recovery !== undefined) {
                            await this.#quarantine(
                                transaction,
                                issueId,
                                "missing_staged_commit",
                                recovery.sessionId,
                                "commit",
                                stagedCommitId,
                            );
                        }
                    });
                    terminalFailureIds.add(issueId);
                } finally {
                    if (record !== undefined) this.#zeroSessionRecord(record);
                    zeroBytes(bytes);
                }
            }
            if (page.size < SESSION_LIST_LIMIT) break;
        }
    }

    async #validMembershipOperation(record: SessionOutboxRecord): Promise<boolean> {
        if (record.kind !== "commit" || record.bootstrapDeliveryIds === undefined) return false;
        const stateBytes = await this.#store.get(stateKey(record.sessionId));
        if (stateBytes === undefined) return false;
        let state: SessionRecord | undefined;
        try {
            state = decodeSessionRecord(stateBytes);
            if (
                (state.status !== "active" && state.status !== "creating") ||
                state.stagedCommitId !== record.delivery.id
            ) {
                return false;
            }
        } catch {
            return false;
        } finally {
            if (state !== undefined) this.#zeroSessionRecord(state);
            zeroBytes(stateBytes);
        }
        const commitOrder = await this.#store.get(outboxOrderKey(record.order, record.delivery.id));
        if (commitOrder === undefined) return false;
        zeroBytes(commitOrder);
        const expected = new Set(record.bootstrapDeliveryIds);
        const entries = await this.#store.scan(`${BOOTSTRAP_INDEX_PREFIX}${record.delivery.id}/`, {
            limit: 257,
        });
        if (entries.size !== expected.size) {
            for (const value of entries.values()) zeroBytes(value);
            return false;
        }
        let valid = true;
        for (const [indexKey, indexValue] of entries) {
            const bootstrapId = indexKey.slice(indexKey.lastIndexOf("/") + 1);
            if (!expected.has(bootstrapId)) valid = false;
            if (indexValue.length === 1 && indexValue[0] === 1) {
                const stale = await this.#store.get(outboxKey(bootstrapId));
                if (stale !== undefined) {
                    valid = false;
                    zeroBytes(stale);
                }
            } else if (indexValue.length === 0) {
                const bootstrapBytes = await this.#store.get(outboxKey(bootstrapId));
                if (bootstrapBytes === undefined) {
                    valid = false;
                } else {
                    let bootstrap: SessionOutboxRecord | undefined;
                    try {
                        bootstrap = decodeOutboxRecord(bootstrapBytes);
                        if (
                            bootstrap.kind !== "bootstrap" ||
                            bootstrap.delivery.id !== bootstrapId ||
                            bootstrap.parentCommitId !== record.delivery.id ||
                            bootstrap.operationId !== record.operationId ||
                            !equalBytes(bootstrap.sessionId, record.sessionId)
                        ) {
                            valid = false;
                        }
                        const orderValue = await this.#store.get(
                            outboxOrderKey(bootstrap.order, bootstrapId),
                        );
                        if (orderValue === undefined) {
                            valid = false;
                        } else {
                            zeroBytes(orderValue);
                        }
                    } catch {
                        valid = false;
                    } finally {
                        if (bootstrap?.applicationData !== undefined) {
                            zeroBytes(bootstrap.applicationData);
                        }
                        if (bootstrap?.stagedEpoch !== undefined) {
                            zeroBytes(bootstrap.stagedEpoch);
                        }
                        zeroBytes(bootstrapBytes);
                    }
                }
            } else {
                valid = false;
            }
            zeroBytes(indexValue);
        }
        return valid;
    }

    async #membershipOperationReady(record: SessionOutboxRecord): Promise<boolean> {
        if (record.kind !== "commit" || record.bootstrapDeliveryIds === undefined) return false;
        const expected = new Set(record.bootstrapDeliveryIds);
        const entries = await this.#store.scan(`${BOOTSTRAP_INDEX_PREFIX}${record.delivery.id}/`, {
            limit: 257,
        });
        let ready = entries.size === expected.size;
        for (const [key, value] of entries) {
            const bootstrapId = key.slice(key.lastIndexOf("/") + 1);
            if (!expected.has(bootstrapId) || value.length !== 1 || value[0] !== 1) {
                ready = false;
            }
            zeroBytes(value);
        }
        return ready;
    }

    async #refreshMembershipOutbox(key: string, record: SessionOutboxRecord): Promise<void> {
        if (record.kind !== "commit" && record.kind !== "bootstrap") {
            throw new Error("Only membership outboxes can be refreshed");
        }
        const now = this.#now();
        const delivery = createSignedDelivery(
            this.#identity,
            record.delivery.recipients,
            record.delivery.ciphertext,
            {
                createdAt: now,
                expiresAt: now + DELIVERY_TTL_MILLISECONDS,
            },
        );
        await this.#store.transaction(async (transaction) => {
            await transaction.delete(key);
            await transaction.delete(outboxOrderKey(record.order, record.delivery.id));
            await setAndZero(
                transaction,
                outboxKey(delivery.id),
                encodeOutboxRecord({ ...record, delivery }),
            );
            await transaction.set(outboxOrderKey(record.order, delivery.id), new Uint8Array());
            if (record.kind === "bootstrap") {
                await transaction.delete(
                    bootstrapIndexKey(record.parentCommitId!, record.delivery.id),
                );
                await transaction.set(
                    bootstrapIndexKey(record.parentCommitId!, delivery.id),
                    new Uint8Array(),
                );
                const parentBytes = await transaction.get(outboxKey(record.parentCommitId!));
                if (parentBytes === undefined) throw new Error("Unknown bootstrap parent Commit");
                const parent = decodeOutboxRecord(parentBytes);
                try {
                    if (
                        parent.kind !== "commit" ||
                        parent.bootstrapDeliveryIds === undefined ||
                        !parent.bootstrapDeliveryIds.includes(record.delivery.id)
                    ) {
                        throw new Error("Invalid bootstrap parent Commit");
                    }
                    await setAndZero(
                        transaction,
                        outboxKey(parent.delivery.id),
                        encodeOutboxRecord({
                            ...parent,
                            bootstrapDeliveryIds: parent.bootstrapDeliveryIds.map((value) =>
                                value === record.delivery.id ? delivery.id : value,
                            ),
                        }),
                    );
                } finally {
                    if (parent.stagedEpoch !== undefined) zeroBytes(parent.stagedEpoch);
                    zeroBytes(parentBytes);
                }
            } else {
                const stateBytes = await transaction.get(stateKey(record.sessionId));
                if (stateBytes === undefined) throw new Error("Unknown staged session");
                const session = decodeSessionRecord(stateBytes);
                try {
                    if (session.stagedCommitId !== record.delivery.id) {
                        throw new Error("Staged Commit changed while refreshing");
                    }
                    await setAndZero(
                        transaction,
                        stateKey(record.sessionId),
                        encodeSessionRecord({ ...session, stagedCommitId: delivery.id }),
                    );
                    await this.#moveBootstrapIndexParent(
                        transaction,
                        record.delivery.id,
                        delivery.id,
                    );
                    await this.#movePostCommitIndexParent(
                        transaction,
                        record.delivery.id,
                        delivery.id,
                    );
                } finally {
                    this.#zeroSessionRecord(session);
                    zeroBytes(stateBytes);
                }
            }
            await this.#quarantine(
                transaction,
                record.delivery.id,
                `refreshed_${record.kind}_expiry`,
                record.sessionId,
                record.kind,
                record.operationId,
            );
        });
    }

    async #discardTerminalOutbox(
        key: string,
        record: SessionOutboxRecord,
        code: string,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await transaction.delete(key);
            await transaction.delete(outboxOrderKey(record.order, record.delivery.id));
            if (record.kind === "application" || record.kind === "proposal") {
                await transaction.delete(epochOutboxIndexKey(record.sessionId, record.delivery.id));
                if (record.parentCommitId !== undefined) {
                    await transaction.delete(
                        postCommitOutboxIndexKey(record.parentCommitId, record.delivery.id),
                    );
                }
            }
            await this.#quarantine(
                transaction,
                record.delivery.id,
                `outbox_${record.kind}_${code}`,
                record.sessionId,
                record.kind,
                record.operationId,
            );
        });
    }

    async #activatePostCommitOutboxes(
        transaction: StoreTransaction,
        commitId: string,
        id: Uint8Array,
    ): Promise<void> {
        const prefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(prefix.length);
                const bytes = await transaction.get(outboxKey(deliveryId));
                if (bytes === undefined) {
                    await transaction.delete(key);
                    zeroBytes(indexValue);
                    continue;
                }
                let dependent: SessionOutboxRecord | undefined;
                try {
                    dependent = decodeOutboxRecord(bytes);
                    if (
                        dependent.kind !== "application" ||
                        dependent.parentCommitId !== commitId ||
                        !equalBytes(dependent.sessionId, id)
                    ) {
                        throw new Error("Invalid post-Commit application outbox");
                    }
                    const { parentCommitId: _parentCommitId, ...activated } = dependent;
                    await setAndZero(
                        transaction,
                        outboxKey(deliveryId),
                        encodeOutboxRecord(activated),
                    );
                    await transaction.set(epochOutboxIndexKey(id, deliveryId), new Uint8Array());
                    await transaction.delete(key);
                } finally {
                    if (dependent?.stagedEpoch !== undefined) {
                        zeroBytes(dependent.stagedEpoch);
                    }
                    if (dependent?.applicationData !== undefined) {
                        zeroBytes(dependent.applicationData);
                    }
                    zeroBytes(bytes);
                    zeroBytes(indexValue);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deleteSession(transaction: StoreTransaction, id: Uint8Array): Promise<void> {
        let bufferedAfter: string | undefined;
        const bufferedPrefix = bufferPrefix(id);
        for (;;) {
            const page = await transaction.scan(bufferedPrefix, {
                ...(bufferedAfter === undefined ? {} : { after: bufferedAfter }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                bufferedAfter = key;
                await transaction.delete(applicationUpdateKey(key.slice(bufferedPrefix.length)));
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        await this.#deletePrefix(transaction, `${SESSION_DATA_PREFIX}${sessionId(id)}/`);
        await transaction.delete(stateKey(id));
        await transaction.delete(pendingKey(id));
        await transaction.delete(sessionOwnerKey(id));
        await this.#deleteRoutingMarkers(transaction, id);
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const outbox = decodeOutboxRecord(bytes);
                try {
                    if (equalBytes(outbox.sessionId, id)) {
                        await transaction.delete(key);
                        await transaction.delete(outboxOrderKey(outbox.order, outbox.delivery.id));
                        if (outbox.kind === "bootstrap") {
                            await transaction.delete(
                                bootstrapIndexKey(outbox.parentCommitId!, outbox.delivery.id),
                            );
                        } else if (outbox.kind === "commit") {
                            await this.#deletePrefix(
                                transaction,
                                `${BOOTSTRAP_INDEX_PREFIX}${outbox.delivery.id}/`,
                            );
                        } else if (outbox.parentCommitId !== undefined) {
                            await transaction.delete(
                                postCommitOutboxIndexKey(outbox.parentCommitId, outbox.delivery.id),
                            );
                        }
                    }
                } finally {
                    if (outbox.stagedEpoch !== undefined) {
                        zeroBytes(outbox.stagedEpoch);
                    }
                    if (outbox.applicationData !== undefined) {
                        zeroBytes(outbox.applicationData);
                    }
                    zeroBytes(bytes);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        await this.#deletePrefix(transaction, `${EPOCH_OUTBOX_INDEX_PREFIX}${sessionId(id)}/`);
    }

    async #deletePrefix(transaction: StoreTransaction, prefix: string): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                await transaction.delete(key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deleteIndexEntriesByDeliveryId(
        transaction: StoreTransaction,
        prefix: string,
        deliveryId: string,
    ): Promise<void> {
        const suffix = `/${deliveryId}`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                if (key.endsWith(suffix)) {
                    await transaction.delete(key);
                }
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #moveBootstrapIndexParent(
        transaction: StoreTransaction,
        previousCommitId: string,
        nextCommitId: string,
    ): Promise<void> {
        const previousPrefix = `${BOOTSTRAP_INDEX_PREFIX}${previousCommitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(previousPrefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                const bootstrapId = key.slice(previousPrefix.length);
                await transaction.set(bootstrapIndexKey(nextCommitId, bootstrapId), value);
                await transaction.delete(key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #movePostCommitIndexParent(
        transaction: StoreTransaction,
        previousCommitId: string,
        nextCommitId: string,
    ): Promise<void> {
        const previousPrefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${previousCommitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(previousPrefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(previousPrefix.length);
                const bytes = await transaction.get(outboxKey(deliveryId));
                if (bytes === undefined) {
                    await transaction.delete(key);
                    zeroBytes(indexValue);
                    continue;
                }
                const dependent = decodeOutboxRecord(bytes);
                try {
                    if (
                        dependent.kind !== "application" ||
                        dependent.parentCommitId !== previousCommitId
                    ) {
                        throw new Error("Invalid post-Commit outbox dependency");
                    }
                    await setAndZero(
                        transaction,
                        outboxKey(deliveryId),
                        encodeOutboxRecord({
                            ...dependent,
                            parentCommitId: nextCommitId,
                        }),
                    );
                    await transaction.set(
                        postCommitOutboxIndexKey(nextCommitId, deliveryId),
                        indexValue,
                    );
                    await transaction.delete(key);
                } finally {
                    if (dependent.stagedEpoch !== undefined) {
                        zeroBytes(dependent.stagedEpoch);
                    }
                    if (dependent.applicationData !== undefined) {
                        zeroBytes(dependent.applicationData);
                    }
                    zeroBytes(bytes);
                    zeroBytes(indexValue);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #reconcileCorruptOutbox(
        transaction: StoreTransaction,
        deliveryId: string,
    ): Promise<CorruptOutboxRecovery | undefined> {
        await this.#deleteIndexEntriesByDeliveryId(
            transaction,
            EPOCH_OUTBOX_INDEX_PREFIX,
            deliveryId,
        );
        await this.#deleteIndexEntriesByDeliveryId(
            transaction,
            POST_COMMIT_OUTBOX_INDEX_PREFIX,
            deliveryId,
        );
        const parentCommitIds = await this.#bootstrapParentCommitIds(transaction, deliveryId);
        let recovery: CorruptOutboxRecovery | undefined;
        for (const parentCommitId of parentCommitIds) {
            recovery ??= await this.#cancelCorruptMembershipOperation(
                transaction,
                parentCommitId,
                "bootstrap",
            );
        }
        recovery ??= await this.#cancelCorruptMembershipOperation(
            transaction,
            deliveryId,
            "commit",
        );
        await this.#deleteIndexEntriesByDeliveryId(transaction, BOOTSTRAP_INDEX_PREFIX, deliveryId);
        return recovery;
    }

    async #bootstrapParentCommitIds(
        transaction: StoreTransaction,
        deliveryId: string,
    ): Promise<ReadonlySet<string>> {
        const parents = new Set<string>();
        const suffix = `/${deliveryId}`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(BOOTSTRAP_INDEX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                if (key.endsWith(suffix)) {
                    parents.add(
                        key.slice(BOOTSTRAP_INDEX_PREFIX.length, key.length - suffix.length),
                    );
                }
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        after = undefined;
        for (;;) {
            const page = await transaction.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                let record: SessionOutboxRecord | undefined;
                try {
                    record = decodeOutboxRecord(value);
                    if (
                        record.kind === "commit" &&
                        record.bootstrapDeliveryIds?.includes(deliveryId) === true
                    ) {
                        parents.add(record.delivery.id);
                    }
                } catch {
                    // Another corrupt record is reconciled from its own order entry.
                } finally {
                    if (record?.stagedEpoch !== undefined) zeroBytes(record.stagedEpoch);
                    if (record?.applicationData !== undefined) zeroBytes(record.applicationData);
                    zeroBytes(value);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        return parents;
    }

    async #cancelCorruptMembershipOperation(
        transaction: StoreTransaction,
        commitId: string,
        kind: "bootstrap" | "commit",
    ): Promise<CorruptOutboxRecovery | undefined> {
        await this.#deleteMembershipOperationOutboxes(transaction, commitId);
        let matchedSessionId: Uint8Array | undefined;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(SESSION_STATE_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: SESSION_LIST_LIMIT,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                if (matchedSessionId === undefined) {
                    let record: SessionRecord | undefined;
                    try {
                        record = decodeSessionRecord(value);
                        if (record.stagedCommitId === commitId) {
                            matchedSessionId = decodeBase64Url(
                                key.slice(SESSION_STATE_PREFIX.length),
                            );
                        }
                    } catch {
                        // The state reconciliation pass handles corrupt session records.
                    } finally {
                        if (record !== undefined) this.#zeroSessionRecord(record);
                    }
                }
                zeroBytes(value);
            }
            if (matchedSessionId !== undefined || page.size < SESSION_LIST_LIMIT) break;
        }
        if (matchedSessionId === undefined) return undefined;

        const stateBytes = await transaction.get(stateKey(matchedSessionId));
        if (stateBytes === undefined) return undefined;
        let record: SessionRecord | undefined;
        try {
            try {
                record = decodeSessionRecord(stateBytes);
            } catch {
                await this.#deleteSession(transaction, matchedSessionId);
                return {
                    sessionId: matchedSessionId,
                    kind,
                    operationId: commitId,
                };
            }
            if (record.stagedCommitId !== commitId) return undefined;
            if (record.status === "creating") {
                await this.#deleteSession(transaction, matchedSessionId);
            } else {
                const unstaged = { ...record };
                delete unstaged.stagedCommitId;
                await setAndZero(
                    transaction,
                    stateKey(matchedSessionId),
                    encodeSessionRecord(unstaged),
                );
            }
            return {
                sessionId: matchedSessionId,
                kind,
                operationId: commitId,
            };
        } finally {
            if (record !== undefined) this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
        }
    }

    async #clearStaleSessionReference(
        transaction: StoreTransaction,
        id: Uint8Array,
        stagedCommitId: string,
    ): Promise<CorruptOutboxRecovery | undefined> {
        const bytes = await transaction.get(stateKey(id));
        if (bytes === undefined) return undefined;
        let record: SessionRecord | undefined;
        try {
            try {
                record = decodeSessionRecord(bytes);
            } catch {
                await this.#deleteSession(transaction, id);
                return {
                    sessionId: id,
                    kind: "commit",
                    operationId: stagedCommitId,
                };
            }
            if (record.stagedCommitId !== stagedCommitId) return undefined;
            if (record.status === "creating") {
                await this.#deleteSession(transaction, id);
            } else {
                const unstaged = { ...record };
                delete unstaged.stagedCommitId;
                await setAndZero(transaction, stateKey(id), encodeSessionRecord(unstaged));
            }
            return {
                sessionId: id,
                kind: "commit",
                operationId: stagedCommitId,
            };
        } finally {
            if (record !== undefined) this.#zeroSessionRecord(record);
            zeroBytes(bytes);
        }
    }

    async #deleteMembershipOperationOutboxes(
        transaction: StoreTransaction,
        commitId: string,
    ): Promise<void> {
        await transaction.delete(outboxKey(commitId));
        await this.#deleteIndexEntriesByDeliveryId(transaction, OUTBOX_ORDER_PREFIX, commitId);
        await this.#deletePostCommitOutboxes(transaction, commitId);
        const prefix = `${BOOTSTRAP_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                const bootstrapId = key.slice(prefix.length);
                await transaction.delete(outboxKey(bootstrapId));
                await this.#deleteIndexEntriesByDeliveryId(
                    transaction,
                    OUTBOX_ORDER_PREFIX,
                    bootstrapId,
                );
                await transaction.delete(key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deletePostCommitOutboxes(
        transaction: StoreTransaction,
        commitId: string,
    ): Promise<void> {
        const prefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await transaction.scan(prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(prefix.length);
                const bytes = await transaction.get(outboxKey(deliveryId));
                if (bytes !== undefined) {
                    let record: SessionOutboxRecord | undefined;
                    try {
                        record = decodeOutboxRecord(bytes);
                        await transaction.delete(outboxOrderKey(record.order, record.delivery.id));
                    } catch {
                        await this.#deleteIndexEntriesByDeliveryId(
                            transaction,
                            OUTBOX_ORDER_PREFIX,
                            deliveryId,
                        );
                    } finally {
                        if (record?.stagedEpoch !== undefined) {
                            zeroBytes(record.stagedEpoch);
                        }
                        if (record?.applicationData !== undefined) {
                            zeroBytes(record.applicationData);
                        }
                        zeroBytes(bytes);
                    }
                    await transaction.delete(outboxKey(deliveryId));
                }
                await transaction.delete(key);
                zeroBytes(indexValue);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    #zeroSessionRecord(record: SessionRecord): void {
        zeroBytes(record.epoch);
        if (record.previousEpoch !== undefined) zeroBytes(record.previousEpoch);
    }

    async #rejectSession(transaction: StoreTransaction, id: Uint8Array): Promise<void> {
        const key = rejectedKey(id);
        await setAndZero(transaction, key, utf8Encode(String(this.#now()).padStart(16, "0")));
        const entries = await transaction.scan(REJECTED_PREFIX, {
            limit: MAXIMUM_REJECTED_SESSIONS + 1,
        });
        try {
            if (entries.size > MAXIMUM_REJECTED_SESSIONS) {
                const evicted = [...entries]
                    .filter(([candidate]) => candidate !== key)
                    .sort((left, right) => {
                        const byTime = utf8Decode(left[1]).localeCompare(utf8Decode(right[1]));
                        return byTime === 0 ? left[0].localeCompare(right[0]) : byTime;
                    })[0]?.[0];
                if (evicted !== undefined) await transaction.delete(evicted);
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
    }
}
