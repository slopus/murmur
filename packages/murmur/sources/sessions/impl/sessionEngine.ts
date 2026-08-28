import {
    DeliveryTransportError,
    DeliveryStaleRosterError,
    InboxProcessor,
    MURMUR_INTERNAL_INBOX_HANDLER,
    TerminalInboxDeliveryError,
    createSignedDelivery,
    encodeSessionDeletionRequest,
    parseSignedDelivery,
    signedDeliveryToJson,
    verifySignedDelivery,
    type DeliveryTransport,
    type DeliveryAccountTarget,
    type DeliveryDeviceRoster,
    type DeliverySessionControl,
    type InboxDelivery,
    type InboxStreamOptions,
    type InboxSyncResult,
} from "../../delivery/index.js";
import { openBox, randomBytes, sealBox, type IdentityKeyPair } from "../../crypto/index.js";
import {
    accountConvergenceJobs,
    ACCOUNT_PEER_ROSTER_PREFIX,
    ACCOUNT_ROSTER_KEY,
    DIRECTORY_ONE_TIME_PREFIX,
    DIRECTORY_SPENT_PREFIX,
    decodeDirectorySpentNotification,
    deleteDirectoryPrekeyMarkers,
    decodeDeviceRosterMutation,
    isActiveDevice,
    observeDeviceRoster,
    parseDeviceRoster,
    serializeDeviceRoster,
    type AccountConvergenceJob,
} from "../../accounts/index.js";
import {
    MlsEpochState,
    MlsLocalMemberRemovedError,
    authenticateMurmurMlsCredential,
    createMlsGroup,
    decodeMlsKeyPackage,
    decodeMlsPrivateMessage,
    decodeMlsRatchetTree,
    decodeMlsTreeCommit,
    deserializeMlsKeyPackageBundle,
    destroyMlsKeyPackageBundle,
    encodeMlsRatchetTree,
    encodeMlsKeyPackage,
    joinMlsGroupFromWelcome,
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
    type MlsEpochCommitProposal,
    type MlsKeyPackage,
} from "../../mls/index.js";
import type { Context } from "@steve.kite/stdlib";

import type { MurmurStore } from "../../storage/index.js";
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
    MurmurSessionChangedEvent,
    MurmurSessionDeletedEvent,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "../types.js";
import { MurmurError } from "../types.js";
import {
    decodeBootstrapFrame,
    decodeSessionControl,
    decodePrivateFrame,
    encodeBootstrapCiphertext,
    encodeBootstrapFrame,
    encodeSessionControl,
    encodePrivateCiphertext,
    encodePrivateFrame,
    normalizeSessionRoles,
    openCommitCiphertext,
    parseSessionCiphertext,
    sealCommitCiphertext,
    sessionRolesEqual,
    type PrivateSessionFrame,
    type SessionRoles,
} from "./sessionFrames.js";
import {
    decodeBufferedEvent,
    decodeOutboxRecord,
    decodeSessionIntent,
    decodeSessionDeletedEvent,
    decodeSessionChangedEvent,
    decodeSessionDeletionOutbox,
    decodeSessionRecord,
    encodeBufferedEvent,
    encodeOutboxRecord,
    encodeSessionIntent,
    encodeSessionDeletedEvent,
    encodeSessionChangedEvent,
    encodeSessionDeletionOutbox,
    encodeSessionRecord,
    type SessionOutboxRecord,
    type SessionIntentRecord,
    type SessionRecord,
    type SessionChangedEventRecord,
} from "./sessionRecords.js";

const SESSION_STATE_PREFIX = "murmur/session-states/";
const SESSION_DATA_PREFIX = "murmur/session-data/";
const SESSION_INTENT_PREFIX = "murmur/session-intents/";
const OUTBOX_PREFIX = "murmur/session-outbox/";
const OUTBOX_ORDER_PREFIX = "murmur/session-outbox-order/";
const OUTBOX_SEQUENCE_KEY = "murmur/session-outbox-sequence";
const KEY_PACKAGE_PREFIX = "murmur/key-packages/";
const KEY_PACKAGE_EXPIRY_PREFIX = "murmur/key-package-expiries/";
const KEY_PACKAGE_REUSABLE_PREFIX = "murmur/key-package-reusable/";
const USED_KEY_PACKAGE_PREFIX = "murmur/used-key-packages/";
const REJECTED_PREFIX = "murmur/rejected-sessions/";
const QUARANTINE_PREFIX = "murmur/session-quarantine/";
const PENDING_SESSION_PREFIX = "murmur/pending-sessions/";
const PENDING_MEMBERSHIP_CONTROL_PREFIX = "murmur/pending-membership-controls/";
const BOOTSTRAP_INDEX_PREFIX = "murmur/bootstrap-outboxes/";
const ADMISSION_BARRIER_PREFIX = "murmur/admission-barriers/";
const EPOCH_OUTBOX_INDEX_PREFIX = "murmur/epoch-outboxes/";
const POST_COMMIT_OUTBOX_INDEX_PREFIX = "murmur/post-commit-outboxes/";
const APPLICATION_UPDATE_PREFIX = "murmur/application-updates/";
const SERVICE_UPDATE_DELIVERED_PREFIX = "murmur/service-update-delivered/";
const SESSION_DELETION_OUTBOX_PREFIX = "murmur/session-deletion-outboxes/";
const SESSION_DELETED_EVENT_PREFIX = "murmur/session-deleted-events/";
const SESSION_CHANGED_EVENT_PREFIX = "murmur/session-changed-events/";

const AUTOMATIC_ISSUE_CODES = new Set([
    "corrupt_application_update",
    "corrupt_application_update_index",
    "corrupt_membership_operation",
    "corrupt_outbox",
    "corrupt_service_update_receipt",
    "corrupt_session_changed_event",
    "corrupt_session_changed_event_index",
    "corrupt_session_intent",
    "corrupt_session_route",
    "corrupt_session_state",
    "orphaned_application_update_index",
    "orphaned_session_changed_event",
    "orphaned_session_changed_event_index",
    "orphaned_session_route",
    "refreshed_application_expiry",
    "refreshed_bootstrap_expiry",
    "refreshed_commit_expiry",
]);
const SESSION_CHANGED_EVENT_INDEX_PREFIX = "murmur/session-changed-event-index/";
const SESSION_RETAINED_DESCRIPTOR_PREFIX = "murmur/session-retained-descriptors/";
const RESET_READMISSION_PREFIX = "murmur/reset/v1/re-admissions/";
const ACCOUNT_DEVICE_ACTIVITY_PREFIX = "murmur/accounts/v1/device-activity/";
const ACCOUNT_CONVERGENCE_COMPLETION_PREFIX = "murmur/accounts/v1/convergence-complete/";
const DEFAULT_MAXIMUM_PENDING = 64;
const DEFAULT_MAXIMUM_BUFFERED_EVENTS = 1_000;
const DEFAULT_MAXIMUM_BUFFERED_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAXIMUM_MEMBERS = 256;
const DEFAULT_MAXIMUM_CIPHERTEXT_BYTES = 1024 * 1024;
const MAXIMUM_KEY_PACKAGES = 8_192;
const MAXIMUM_USED_KEY_PACKAGES = 1_024;
const DEFAULT_MAXIMUM_OUTBOXES = 1_000;
const MAXIMUM_REJECTED_SESSIONS = 256;
const MAXIMUM_SESSION_INTENTS = 256;
const SESSION_LIST_LIMIT = 256;
const MAXIMUM_UPDATE_BATCH_EVENTS = 256;
const OUTBOX_SCAN_ITEMS = 64;
const PREVIOUS_EPOCH_GRACE_MILLISECONDS = 5 * 60 * 1_000;
const PREVIOUS_EPOCH_MESSAGES = 64;
const DELIVERY_RETENTION_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;
const DELIVERY_TTL_MILLISECONDS = DELIVERY_RETENTION_MILLISECONDS - 5 * 60 * 1_000;
const COMMIT_EXPORT_LABEL = "murmur session commit";
const COMMIT_EXPORT_CONTEXT = utf8Encode("murmur/session-commit/v1");
const RELAY_EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAXIMUM_PENDING_RELAY_EFFECTS = 1_000;

/** Internal immutable snapshot backing one identity-wide application batch. */
export interface PreparedUpdates {
    readonly keys: readonly string[];
    readonly routes: readonly PreparedSessionRoute[];
    readonly updates: readonly PreparedRoutedUpdate[];
    readonly deletions: readonly PreparedSessionDeletion[];
    readonly sessionChanges: readonly PreparedSessionChange[];
    readonly exhausted: boolean;
}

export interface PreparedSessionChange extends MurmurSessionChangedEvent {
    readonly key: string;
    readonly indexKey: string;
}

export interface PreparedSessionDeletion extends MurmurSessionDeletedEvent {
    readonly key: string;
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

/** Authenticated public admission material supplied to the session engine. */
export interface SessionMemberMaterial {
    readonly identity: Uint8Array;
    readonly keyPackage: MlsKeyPackage;
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

function serviceUpdateDeliveredKey(eventId: string): string {
    return `${SERVICE_UPDATE_DELIVERED_PREFIX}${eventId}`;
}

function sessionDeletionOutboxKey(deliveryId: string): string {
    return `${SESSION_DELETION_OUTBOX_PREFIX}${deliveryId}`;
}

function sessionDeletedEventKey(deliveryId: string): string {
    return `${SESSION_DELETED_EVENT_PREFIX}${deliveryId}`;
}

function sessionChangedEventPrefix(id: Uint8Array): string {
    return `${SESSION_CHANGED_EVENT_PREFIX}${sessionId(id)}/`;
}

function sessionChangedEventKey(id: Uint8Array, eventId: string): string {
    return `${sessionChangedEventPrefix(id)}${eventId}`;
}

function sessionChangedEventIndexKey(eventId: string, id: Uint8Array): string {
    return `${SESSION_CHANGED_EVENT_INDEX_PREFIX}${eventId}/${sessionId(id)}`;
}

function sessionRetainedDescriptorKey(id: Uint8Array): string {
    return `${SESSION_RETAINED_DESCRIPTOR_PREFIX}${sessionId(id)}`;
}

function intentKey(intentId: string): string {
    return `${SESSION_INTENT_PREFIX}${intentId}`;
}

function outboxKey(deliveryId: string): string {
    return `${OUTBOX_PREFIX}${deliveryId}`;
}

function accountDeviceActivityKey(device: Uint8Array): string {
    return `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(device)}`;
}

function accountConvergenceCompletionPrefix(key: string): string {
    return `${ACCOUNT_CONVERGENCE_COMPLETION_PREFIX}${encodeBase64Url(utf8Encode(key))}/`;
}

function accountConvergenceCompletionKey(key: string, id: Uint8Array): string {
    return `${accountConvergenceCompletionPrefix(key)}${sessionId(id)}`;
}

function outboxOrderKey(order: string, deliveryId: string): string {
    return `${OUTBOX_ORDER_PREFIX}${order}/${deliveryId}`;
}

function bootstrapIndexKey(parentCommitId: string, deliveryId: string): string {
    return `${BOOTSTRAP_INDEX_PREFIX}${parentCommitId}/${deliveryId}`;
}

function admissionBarrierKey(id: Uint8Array): string {
    return `${ADMISSION_BARRIER_PREFIX}${sessionId(id)}`;
}

function encodeAdmissionBarrier(sender: Uint8Array): Uint8Array {
    if (sender.length !== 32) throw new Error("Invalid admission barrier");
    return sender.slice();
}

function decodeAdmissionBarrier(value: Uint8Array): Uint8Array {
    if (value.length !== 32) throw new Error("Invalid admission barrier");
    return value.slice();
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

function pendingMembershipControlKey(id: Uint8Array): string {
    return `${PENDING_MEMBERSHIP_CONTROL_PREFIX}${sessionId(id)}`;
}

function usedKeyPackageKey(keyPackage: MlsKeyPackage): string {
    return `${USED_KEY_PACKAGE_PREFIX}${encodeBase64Url(mlsKeyPackageReference(keyPackage))}`;
}

function usedKeyPackageExpiresAt(keyPackage: MlsKeyPackage): number {
    const expiresAt = (keyPackage.leafNode.notAfter + 1n) * 1_000n;
    if (expiresAt > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("KeyPackage lifetime is too large");
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
            input.kind !== "commit" &&
            input.kind !== "bootstrap" &&
            input.kind !== "session") ||
        (input.operationId !== null && typeof input.operationId !== "string") ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid session issue");
    }
    const automatic = AUTOMATIC_ISSUE_CODES.has(input.code);
    return {
        id,
        code: input.code,
        severity: automatic ? "warning" : "error",
        recovery: automatic ? "automatic" : "inspect",
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

function memberAccount(epoch: MlsEpochState, leaf: number): Uint8Array {
    const signatureKey = epoch.memberSignatureKeys[leaf];
    const credential = epoch.memberCredentialIdentities[leaf];
    if (signatureKey === undefined || credential === undefined) {
        throw new Error("Session member is absent");
    }
    if (credential.length !== 32) throw new Error("Invalid session account credential");
    return credential;
}

function activeAccounts(epoch: MlsEpochState): readonly Uint8Array[] {
    const accounts = new Map<string, Uint8Array>();
    for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
        if (epoch.memberSignatureKeys[leaf] === undefined) continue;
        const account = memberAccount(epoch, leaf);
        accounts.set(encodeBase64Url(account), account);
    }
    return [...accounts.values()];
}

function deliverySessionRoles(
    roles: SessionRoles,
): Extract<DeliverySessionControl, { type: "create" | "commit" }>["roles"] {
    return {
        owner: roles.owner,
        admins: roles.admins,
        adminsAssignAdmins: roles.adminsAssignAdmins,
        anyoneCanAddMembers: roles.anyoneCanAddMembers,
        sendPolicy: roles.sendPolicy,
    };
}

function sameIdentitySet(left: readonly Uint8Array[], right: readonly Uint8Array[]): boolean {
    const values = new Set(left.map(encodeBase64Url));
    return (
        values.size === right.length && right.every((value) => values.has(encodeBase64Url(value)))
    );
}

function deliverySessionRolesEqual(
    left: Extract<DeliverySessionControl, { type: "create" | "commit" }>["roles"],
    right: SessionRoles,
): boolean {
    return (
        equalBytes(left.owner, right.owner) &&
        sameIdentitySet(left.admins, right.admins) &&
        left.adminsAssignAdmins === right.adminsAssignAdmins &&
        left.anyoneCanAddMembers === right.anyoneCanAddMembers &&
        left.sendPolicy === right.sendPolicy
    );
}

function sessionChangesEqual(
    left: readonly Extract<DeliverySessionControl, { type: "commit" }>["changes"][number][],
    right: readonly Extract<DeliverySessionControl, { type: "commit" }>["changes"][number][],
): boolean {
    const encoded = (change: (typeof left)[number]): string =>
        `${change.type}:${encodeBase64Url(change.accountKey)}:${encodeBase64Url(change.deviceKey)}`;
    const values = new Set(left.map(encoded));
    return values.size === right.length && right.every((change) => values.has(encoded(change)));
}

function keyPackageAccount(keyPackage: MlsKeyPackage): Uint8Array {
    const credential = keyPackage.leafNode.credential.identity;
    if (credential.length !== 32) throw new Error("Invalid session account credential");
    return credential.slice();
}

function isSessionAdmin(roles: SessionRoles, account: Uint8Array): boolean {
    return (
        equalBytes(roles.owner, account) || roles.admins.some((admin) => equalBytes(admin, account))
    );
}

function accountLeaves(epoch: MlsEpochState, account: Uint8Array): readonly number[] {
    const leaves: number[] = [];
    for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
        if (
            epoch.memberSignatureKeys[leaf] !== undefined &&
            equalBytes(memberAccount(epoch, leaf), account)
        ) {
            leaves.push(leaf);
        }
    }
    return leaves;
}

function removalGeneration(record: SessionRecord, account: Uint8Array): number {
    return (
        record.removalGenerations.find((value) => equalBytes(value.account, account))?.generation ??
        0
    );
}

function incrementRemovalGenerations(
    record: SessionRecord,
    removedAccounts: readonly Uint8Array[],
): readonly { readonly account: Uint8Array; readonly generation: number }[] {
    const values = new Map(
        record.removalGenerations.map((value) => [
            encodeBase64Url(value.account),
            { account: value.account.slice(), generation: value.generation },
        ]),
    );
    for (const account of removedAccounts) {
        const key = encodeBase64Url(account);
        const current = values.get(key);
        const generation = (current?.generation ?? 0) + 1;
        if (!Number.isSafeInteger(generation)) throw new Error("Removal generation exhausted");
        values.set(key, { account: account.slice(), generation });
    }
    return [...values.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, value]) => value);
}

function memberLeaf(epoch: MlsEpochState, identity: Uint8Array): number {
    const matches = epoch.memberSignatureKeys.flatMap((value, index) =>
        value !== undefined && equalBytes(value, identity) ? [index] : [],
    );
    if (matches.length !== 1) throw new Error("Session member is absent or ambiguous");
    return matches[0]!;
}

async function setAndZero(
    store: MurmurStore,
    ctx: Context,
    key: string,
    value: Uint8Array,
): Promise<void> {
    try {
        await store.set(ctx, key, value);
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
    const roles = record.roles;
    return {
        id: epoch.groupId,
        status: record.status,
        descriptor: record.descriptor.slice(),
        members: activeAccounts(epoch),
        owner: roles.owner.slice(),
        admins: [roles.owner.slice(), ...roles.admins.map((admin) => admin.slice())],
        policies: {
            adminsAssignAdmins: roles.adminsAssignAdmins,
            anyoneCanAddMembers: roles.anyoneCanAddMembers,
            sendPolicy: roles.sendPolicy,
        },
        bufferedEvents: record.bufferedEvents,
        ...(record.reAdmission === true ? { reAdmission: true } : {}),
    };
}

function sessionMembersAfterCommit(
    epoch: MlsEpochState,
    proposals: readonly MlsEpochCommitProposal[],
): readonly Uint8Array[] {
    const counts = new Map<string, { account: Uint8Array; devices: number }>();
    for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
        if (epoch.memberSignatureKeys[leaf] === undefined) continue;
        const account = memberAccount(epoch, leaf);
        const key = encodeBase64Url(account);
        const current = counts.get(key);
        counts.set(key, { account, devices: (current?.devices ?? 0) + 1 });
    }
    for (const proposal of proposals) {
        if (proposal.type === "add") {
            const account = keyPackageAccount(proposal.keyPackage);
            const key = encodeBase64Url(account);
            const current = counts.get(key);
            counts.set(key, { account, devices: (current?.devices ?? 0) + 1 });
            continue;
        }
        const account = memberAccount(epoch, proposal.removed);
        const key = encodeBase64Url(account);
        const current = counts.get(key);
        if (current === undefined || current.devices < 1) {
            throw new Error("Invalid session Commit membership");
        }
        if (current.devices === 1) counts.delete(key);
        else counts.set(key, { account: current.account, devices: current.devices - 1 });
    }
    return [...counts.values()].map(({ account }) => account.slice());
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
    readonly #accountIdentity: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #transport: DeliveryTransport;
    readonly #inbox: InboxProcessor;
    readonly #limits: ResolvedLimits;
    readonly #now: () => number;
    #credentialIdentity: Uint8Array;
    #accountKey: Uint8Array;
    #issueVersion = 0;

    constructor(
        identity: IdentityKeyPair,
        store: MurmurStore,
        transport: DeliveryTransport,
        limits: MurmurSessionLimits = {},
        now: () => number = Date.now,
        credentialIdentity: Uint8Array = identity.publicKey,
        accountIdentity: IdentityKeyPair = identity,
    ) {
        this.#identity = identity;
        this.#accountIdentity = accountIdentity;
        this.#store = store;
        this.#transport = transport;
        this.#now = now;
        this.#credentialIdentity = credentialIdentity.slice();
        if (
            credentialIdentity.length !== 32 ||
            !equalBytes(credentialIdentity, accountIdentity.publicKey)
        ) {
            throw new Error("Invalid account credential");
        }
        this.#accountKey = credentialIdentity.slice();
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
            throw new MurmurError("invalid_configuration", "Invalid Murmur session limits");
        }
        this.#inbox = new InboxProcessor(
            { identity, store, transport },
            async (ctx, _store, delivery) => {
                const before = await this.#pendingRelayEffectCount(ctx);
                await this.#receive(ctx, delivery);
                const after = await this.#pendingRelayEffectCount(ctx);
                return after > MAXIMUM_PENDING_RELAY_EFFECTS && after > before
                    ? "deferred"
                    : undefined;
            },
            { now },
            MURMUR_INTERNAL_INBOX_HANDLER,
        );
    }

    /** Stable account key represented by this device's MLS credential. */
    get accountKey(): Uint8Array {
        return this.#accountKey.slice();
    }

    /** In-memory change token for the durable issue set. */
    get issueVersion(): number {
        return this.#issueVersion;
    }

    async #pendingRelayEffectCount(transaction: Context): Promise<number> {
        let count = 0;
        for (const prefix of [
            ROUTING_MARKER_PREFIX,
            APPLICATION_UPDATE_PREFIX,
            SESSION_CHANGED_EVENT_INDEX_PREFIX,
        ]) {
            const page = await this.#store.scan(transaction, prefix, {
                limit: MAXIMUM_PENDING_RELAY_EFFECTS + 1,
            });
            count += page.size;
            for (const value of page.values()) zeroBytes(value);
        }
        return count;
    }

    async #targetAccounts(
        ctx: Context,
        epoch: MlsEpochState,
        additionalAccounts: readonly Uint8Array[] = [],
    ): Promise<readonly DeliveryAccountTarget[]> {
        if (
            this.#transport.readDeviceRoster === undefined ||
            this.#transport.mutateDeviceRoster === undefined
        ) {
            return [];
        }
        const targets: DeliveryAccountTarget[] = [];
        const accounts = new Map(
            [...activeAccounts(epoch), ...additionalAccounts].map((accountKey) => [
                encodeBase64Url(accountKey),
                accountKey,
            ]),
        );
        for (const accountKey of accounts.values()) {
            const key = equalBytes(accountKey, this.#accountKey)
                ? ACCOUNT_ROSTER_KEY
                : `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(accountKey)}`;
            const bytes = await this.#store.get(ctx, key);
            let rosterRevision = 0;
            try {
                if (bytes !== undefined) {
                    const roster = parseDeviceRoster(bytes);
                    if (equalBytes(roster.accountKey, accountKey)) {
                        rosterRevision = roster.revision;
                    }
                } else {
                    const roster = await this.#transport.readDeviceRoster(ctx, accountKey);
                    if (roster !== undefined) {
                        rosterRevision = roster.revision;
                        const rosterBytes = serializeDeviceRoster(roster);
                        try {
                            await observeDeviceRoster(
                                ctx,
                                this.#store,
                                this.#accountKey,
                                `lookup-${roster.revision}`,
                                rosterBytes,
                            );
                        } finally {
                            zeroBytes(rosterBytes);
                        }
                    }
                }
            } finally {
                if (bytes !== undefined) zeroBytes(bytes);
            }
            targets.push({ accountKey: accountKey.slice(), rosterRevision });
        }
        return targets;
    }

    async storeKeyPackages(
        ctx: Context,
        values: readonly {
            readonly reference: Uint8Array;
            readonly bytes: Uint8Array;
            readonly expiresAt: number;
            readonly reusable?: boolean;
        }[],
    ): Promise<void> {
        await this.#store.tx(ctx, (transaction) =>
            this.storeKeyPackagesInTransaction(transaction, values),
        );
    }

    /** @internal Store reset KeyPackages atomically with a caller-owned state transition. */
    async storeKeyPackagesInTransaction(
        transaction: Context,
        values: readonly {
            readonly reference: Uint8Array;
            readonly bytes: Uint8Array;
            readonly expiresAt: number;
            readonly reusable?: boolean;
        }[],
    ): Promise<void> {
        const now = this.#now();
        await this.#pruneKeyPackages(transaction, now);
        const existing = new Map(
            await this.#store.scan(transaction, KEY_PACKAGE_PREFIX, {
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
                    BigInt(value.expiresAt) > (bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n
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
            await this.#store.set(transaction, keyPackageKey(value.reference), value.bytes);
            await setAndZero(
                this.#store,
                transaction,
                keyPackageExpiryKey(value.reference),
                utf8Encode(String(value.expiresAt).padStart(16, "0")),
            );
            if (value.reusable === true) {
                await this.#store.set(
                    transaction,
                    keyPackageReusableKey(value.reference),
                    new Uint8Array(),
                );
            } else {
                await this.#store.delete(transaction, keyPackageReusableKey(value.reference));
            }
        }
    }

    /** @internal Commit a post-loss inbox baseline inside the reset purge transaction. */
    async adoptInboxBaselineInTransaction(
        transaction: Context,
        generation: Uint8Array,
        head: string | null,
        headSequence: number,
    ): Promise<void> {
        await this.#inbox.adoptBaselineInTransaction(transaction, generation, head, headSequence);
    }

    /** @internal Retry the remote half of a committed post-loss baseline adoption. */
    async acknowledgeInboxBaseline(
        ctx: Context,
        head: string | null,
        signal?: AbortSignal,
    ): Promise<void> {
        await this.#inbox.acknowledgeBaseline(ctx, head, signal);
    }

    async deleteKeyPackages(ctx: Context, references: readonly Uint8Array[]): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            for (const reference of references) {
                await this.#store.delete(transaction, keyPackageKey(reference));
                await this.#store.delete(transaction, keyPackageExpiryKey(reference));
                await this.#store.delete(transaction, keyPackageReusableKey(reference));
                await deleteDirectoryPrekeyMarkers(transaction, this.#store, reference);
            }
        });
    }

    async #pruneKeyPackages(transaction: Context, now: number): Promise<void> {
        const packages = await this.#store.scan(transaction, KEY_PACKAGE_PREFIX, {
            limit: MAXIMUM_KEY_PACKAGES + 1,
        });
        const expiries = await this.#store.scan(transaction, KEY_PACKAGE_EXPIRY_PREFIX, {
            limit: MAXIMUM_KEY_PACKAGES + 1,
        });
        const reusable = await this.#store.scan(transaction, KEY_PACKAGE_REUSABLE_PREFIX, {
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
                    await this.#store.delete(transaction, expiryKey);
                    await this.#store.delete(transaction, packageKey);
                    await this.#store.delete(
                        transaction,
                        `${KEY_PACKAGE_REUSABLE_PREFIX}${suffix}`,
                    );
                    try {
                        await deleteDirectoryPrekeyMarkers(
                            transaction,
                            this.#store,
                            decodeBase64Url(suffix),
                        );
                    } catch {
                        // The malformed suffix is already being removed from private state.
                    }
                } else {
                    try {
                        if (decodeBase64Url(suffix).length !== 32) {
                            throw new Error("Invalid KeyPackage reference");
                        }
                        active.add(packageKey);
                    } catch {
                        await this.#store.delete(transaction, expiryKey);
                        await this.#store.delete(transaction, packageKey);
                        await this.#store.delete(
                            transaction,
                            `${KEY_PACKAGE_REUSABLE_PREFIX}${suffix}`,
                        );
                    }
                }
            }
            for (const packageKey of packageKeys) {
                if (!active.has(packageKey)) {
                    await this.#store.delete(transaction, packageKey);
                    await this.#store.delete(
                        transaction,
                        `${KEY_PACKAGE_REUSABLE_PREFIX}${packageKey.slice(KEY_PACKAGE_PREFIX.length)}`,
                    );
                }
            }
            for (const reusableKey of reusable.keys()) {
                const suffix = reusableKey.slice(KEY_PACKAGE_REUSABLE_PREFIX.length);
                if (!active.has(`${KEY_PACKAGE_PREFIX}${suffix}`)) {
                    await this.#store.delete(transaction, reusableKey);
                }
            }
        } finally {
            for (const bytes of packages.values()) zeroBytes(bytes);
            for (const bytes of expiries.values()) zeroBytes(bytes);
            for (const bytes of reusable.values()) zeroBytes(bytes);
        }
    }

    async #claimKeyPackages(
        transaction: Context,
        members: readonly SessionMemberMaterial[],
    ): Promise<readonly string[]> {
        const entries = await this.#store.scan(transaction, USED_KEY_PACKAGE_PREFIX, {
            limit: MAXIMUM_USED_KEY_PACKAGES + 1,
        });
        const active = new Set<string>();
        try {
            for (const [key, value] of entries) {
                const encodedExpiry = utf8Decode(value);
                if (!/^\d{16}$/.test(encodedExpiry)) {
                    throw new Error("Invalid used KeyPackage record");
                }
                if (Number(encodedExpiry) <= this.#now()) {
                    await this.#store.delete(transaction, key);
                } else {
                    active.add(key);
                }
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
        const claims = members.map((member) => ({
            key: usedKeyPackageKey(member.keyPackage),
            expiresAt: usedKeyPackageExpiresAt(member.keyPackage),
        }));
        if (
            new Set(claims.map(({ key }) => key)).size !== claims.length ||
            claims.some(({ key }) => active.has(key))
        ) {
            throw new Error("KeyPackage was already used");
        }
        if (active.size + claims.length > MAXIMUM_USED_KEY_PACKAGES) {
            throw new Error("Used KeyPackage capacity exceeded");
        }
        for (const claim of claims) {
            await setAndZero(
                this.#store,
                transaction,
                claim.key,
                utf8Encode(String(claim.expiresAt).padStart(16, "0")),
            );
        }
        return claims.map(({ key }) => key);
    }

    async create(
        ctx: Context,
        options: Pick<
            CreateMurmurSessionOptions,
            "descriptor" | "adminsAssignAdmins" | "anyoneCanAddMembers" | "sendPolicy"
        > & {
            readonly members: readonly SessionMemberMaterial[];
        },
        owner?: SessionOwnerRecord,
        operation?: (transaction: Context, id: Uint8Array) => Promise<void>,
    ): Promise<MurmurSession> {
        if (options.descriptor.length > 1024 * 1024) {
            throw new MurmurError("invalid_argument", "Session descriptor is too large");
        }
        const members = options.members;
        if (members.length < 1) {
            throw new MurmurError("invalid_argument", "A session requires at least two members");
        }
        if (members.length + 1 > this.#limits.maximumMembersPerSession) {
            throw new MurmurError(
                "resource_exhausted",
                "Session membership exceeds the configured limit",
            );
        }
        const memberIdentities = new Set<string>();
        for (const member of members) {
            if (
                member.identity.length !== 32 ||
                !verifyMlsKeyPackage(member.keyPackage, Math.floor(this.#now() / 1_000)) ||
                !equalBytes(member.keyPackage.leafNode.signatureKey, member.identity)
            ) {
                throw new MurmurError("invalid_argument", "Invalid session member KeyPackage");
            }
            const identity = encodeBase64Url(member.identity);
            if (
                equalBytes(member.identity, this.#identity.publicKey) ||
                memberIdentities.has(identity)
            ) {
                throw new MurmurError("invalid_argument", "Session members must be distinct");
            }
            memberIdentities.add(identity);
        }
        const epoch = createMlsGroup(this.#identity, {
            credentialIdentity: this.#credentialIdentity,
        });
        const id = epoch.groupId;
        const claimKeys = members.map((member) => usedKeyPackageKey(member.keyPackage));
        const roles = normalizeSessionRoles({
            owner: this.#accountKey,
            admins: [],
            adminsAssignAdmins: options.adminsAssignAdmins ?? false,
            anyoneCanAddMembers: options.anyoneCanAddMembers ?? false,
            sendPolicy: options.sendPolicy ?? "everyone",
        });
        let checkpoint: Uint8Array | undefined;
        try {
            checkpoint = epoch.serialize();
            const record: SessionRecord = {
                version: 2,
                status: "creating",
                descriptor: options.descriptor.slice(),
                epoch: checkpoint,
                generation: epoch.persistenceGeneration,
                bufferedEvents: 0,
                bufferedBytes: 0,
                roles,
                removalGenerations: [],
            };
            await this.#store.tx(ctx, async (transaction) => {
                const existingState = await this.#store.get(transaction, stateKey(id));
                if (existingState !== undefined) {
                    zeroBytes(existingState);
                    throw new MurmurError("already_exists", "Session already exists");
                }
                await this.#claimKeyPackages(transaction, members);
                await setAndZero(
                    this.#store,
                    transaction,
                    stateKey(id),
                    encodeSessionRecord(record),
                );
                if (owner !== undefined) {
                    await setAndZero(
                        this.#store,
                        transaction,
                        sessionOwnerKey(id),
                        encodeSessionOwner(owner),
                    );
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
                    ctx,
                    id,
                    members.map((member) => ({
                        identity: member.identity,
                        keyPackage: member.keyPackage,
                    })),
                    [],
                    roles,
                );
            } catch (error: unknown) {
                await this.#store.tx(ctx, async (transaction) => {
                    await this.#deleteSession(transaction, id);
                    for (const claimKey of claimKeys)
                        await this.#store.delete(transaction, claimKey);
                });
                throw error;
            }
        }
        return (await this.get(ctx, id))!;
    }

    async get(ctx: Context, id: Uint8Array): Promise<MurmurSession | undefined> {
        const bytes = await this.#store.get(ctx, stateKey(id));
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

    async list(ctx: Context, options: MurmurSessionListOptions = {}): Promise<MurmurSessionPage> {
        const limit = options.limit ?? SESSION_LIST_LIMIT;
        if (
            !Number.isSafeInteger(limit) ||
            limit < 1 ||
            limit > SESSION_LIST_LIMIT ||
            (options.after !== undefined && !/^[A-Za-z0-9_-]+$/.test(options.after))
        ) {
            throw new MurmurError("invalid_argument", "Invalid session-list options");
        }
        const entries = await this.#store.scan(ctx, SESSION_STATE_PREFIX, {
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

    async activate(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            await setAndZero(
                this.#store,
                transaction,
                sessionOwnerKey(id),
                encodeSessionOwner({ version: 1, owner: "account" }),
            );
            await this.#activatePending(transaction, id);
            await this.#deleteRoutingMarkers(transaction, id);
        });
    }

    /** Activate one internally owned pending session after an explicit decision. */
    async activateOwned(
        ctx: Context,
        id: Uint8Array,
        expectedOwner: "service" | "account",
    ): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner === undefined || owner.owner !== expectedOwner) {
                throw new Error("Session owner does not match");
            }
            await this.#activatePending(transaction, id);
        });
    }

    /** Destroy one internally owned session and retain its rejection marker. */
    async destroyOwned(
        ctx: Context,
        id: Uint8Array,
        expectedOwner: "service",
        operation?: (transaction: Context) => Promise<void>,
    ): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const owner = await this.#sessionOwner(transaction, id);
            if (owner === undefined || owner.owner !== expectedOwner) {
                throw new Error("Session owner does not match");
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
            await operation?.(transaction);
        });
    }

    async ignore(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const bytes = await this.#store.get(transaction, stateKey(id));
            if (bytes === undefined) throw new MurmurError("not_found", "Unknown session");
            const record = decodeSessionRecord(bytes);
            try {
                if (record.status !== "pending") {
                    throw new MurmurError("invalid_state", "Session is not pending");
                }
            } finally {
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
        });
    }

    async abandon(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const bytes = await this.#store.get(transaction, stateKey(id));
            if (bytes === undefined) throw new MurmurError("not_found", "Unknown session");
            const record = decodeSessionRecord(bytes);
            const barrier = await this.#store.get(transaction, admissionBarrierKey(id));
            try {
                if (
                    record.status !== "creating" &&
                    record.stagedCommitId === undefined &&
                    barrier === undefined &&
                    (await this.#readyBootstrapParentForSession(transaction, id)) === undefined
                ) {
                    throw new MurmurError(
                        "invalid_state",
                        "Session has no blocked membership operation",
                    );
                }
            } finally {
                this.#zeroSessionRecord(record);
                zeroBytes(bytes);
                if (barrier !== undefined) zeroBytes(barrier);
            }
            await this.#deleteSession(transaction, id);
            await this.#rejectSession(transaction, id);
        });
    }

    /** Durably emit a final MLS notice and terminally destroy an owner-held session. */
    async delete(ctx: Context, id: Uint8Array): Promise<string> {
        return this.#store.tx(ctx, async (transaction) => {
            const stateBytes = await this.#store.get(transaction, stateKey(id));
            if (stateBytes === undefined) {
                throw new MurmurError("not_found", "Unknown active session");
            }
            const record = decodeSessionRecord(stateBytes);
            let outboxBytes: Uint8Array | undefined;
            let requestBody: Uint8Array | undefined;
            try {
                if (!equalBytes(record.roles.owner, this.#accountKey)) {
                    throw new MurmurError(
                        "permission_denied",
                        "Only the session owner may delete the session",
                    );
                }
                if (this.#transport.deleteSession === undefined) {
                    throw new MurmurError(
                        "unsupported",
                        "Delivery transport does not support session deletion",
                    );
                }
                if (
                    record.status !== "active" ||
                    record.stagedCommitId !== undefined ||
                    (await this.#readyBootstrapParentForSession(transaction, id)) !== undefined
                ) {
                    throw new MurmurError(
                        "busy",
                        "Session deletion requires an idle active session",
                    );
                }
                const owner = await this.#sessionOwner(transaction, id);
                const noticeId = await this.#queuePrivate(
                    transaction,
                    id,
                    { version: 1, type: "delete" },
                    "application",
                    transaction,
                );
                outboxBytes = await this.#store.get(transaction, outboxKey(noticeId));
                if (outboxBytes === undefined) throw new Error("Missing session deletion notice");
                const outbox = decodeOutboxRecord(outboxBytes);
                try {
                    if (
                        outbox.kind !== "application" ||
                        outbox.parentCommitId !== undefined ||
                        !equalBytes(outbox.sessionId, id)
                    ) {
                        throw new Error("Invalid session deletion notice");
                    }
                    requestBody = encodeSessionDeletionRequest(id);
                    const now = this.#now();
                    const request = createSignedDelivery(this.#accountIdentity, [], requestBody, {
                        createdAt: now,
                        expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                        senderAccount: this.#accountKey,
                    });
                    await setAndZero(
                        this.#store,
                        transaction,
                        sessionDeletionOutboxKey(noticeId),
                        encodeSessionDeletionOutbox({
                            version: 1,
                            sessionId: id,
                            request,
                            notice: outbox.delivery,
                        }),
                    );
                    if (owner?.owner === "service") {
                        await setAndZero(
                            this.#store,
                            transaction,
                            sessionDeletedEventKey(noticeId),
                            encodeSessionDeletedEvent({
                                version: 1,
                                id: noticeId,
                                sessionId: id,
                                owner: record.roles.owner,
                                serviceId: owner.serviceId,
                            }),
                        );
                    }
                    await this.#store.delete(transaction, outboxKey(noticeId));
                    await this.#store.delete(transaction, outboxOrderKey(outbox.order, noticeId));
                    await this.#store.delete(transaction, epochOutboxIndexKey(id, noticeId));
                    await this.#deleteSession(transaction, id);
                    return noticeId;
                } finally {
                    if (outbox.applicationData !== undefined) zeroBytes(outbox.applicationData);
                    if (outbox.stagedEpoch !== undefined) zeroBytes(outbox.stagedEpoch);
                }
            } finally {
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
                if (outboxBytes !== undefined) zeroBytes(outboxBytes);
                if (requestBody !== undefined) zeroBytes(requestBody);
            }
        });
    }

    async prepareUpdates(ctx: Context): Promise<PreparedUpdates> {
        return this.#store.tx(ctx, async (transaction) => {
            type Candidate =
                | {
                      readonly type: "route";
                      readonly eventId: string;
                      readonly key: string;
                      readonly sessionId: Uint8Array;
                  }
                | {
                      readonly type: "update";
                      readonly eventId: string;
                      readonly key: string;
                      readonly sessionId: Uint8Array;
                  }
                | {
                      readonly type: "session-change";
                      readonly eventId: string;
                      readonly key: string;
                      readonly sessionId: Uint8Array;
                  };
            const candidates: Candidate[] = [];
            const routePage = await this.#store.scan(transaction, ROUTING_MARKER_PREFIX, {
                limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1,
            });
            try {
                for (const [key, bytes] of routePage) {
                    const eventId = key.slice(ROUTING_MARKER_PREFIX.length);
                    let marker: ReturnType<typeof decodeSessionRouting>;
                    try {
                        marker = decodeSessionRouting(bytes);
                    } catch {
                        await this.#store.delete(transaction, key);
                        await this.#quarantine(
                            transaction,
                            RELAY_EVENT_ID.test(eventId) ? eventId : "route-index",
                            "corrupt_session_route",
                            undefined,
                            "session",
                        );
                        continue;
                    }
                    if (!RELAY_EVENT_ID.test(eventId)) {
                        await this.#store.delete(transaction, key);
                        await this.#quarantine(
                            transaction,
                            "route-index",
                            "corrupt_session_route",
                            marker.sessionId,
                            "session",
                        );
                        zeroBytes(marker.sessionId);
                        continue;
                    }
                    const stateBytes = await this.#store.get(
                        transaction,
                        stateKey(marker.sessionId),
                    );
                    if (stateBytes === undefined) {
                        await this.#store.delete(transaction, key);
                        await this.#quarantine(
                            transaction,
                            eventId,
                            "orphaned_session_route",
                            marker.sessionId,
                            "session",
                        );
                        zeroBytes(marker.sessionId);
                        continue;
                    }
                    zeroBytes(stateBytes);
                    candidates.push({
                        type: "route",
                        eventId,
                        key,
                        sessionId: marker.sessionId.slice(),
                    });
                    zeroBytes(marker.sessionId);
                }
            } finally {
                for (const bytes of routePage.values()) zeroBytes(bytes);
            }
            const updatePage = await this.#store.scan(transaction, APPLICATION_UPDATE_PREFIX, {
                limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1,
            });
            try {
                for (const [key, indexedSessionId] of updatePage) {
                    const eventId = key.slice(APPLICATION_UPDATE_PREFIX.length);
                    if (
                        indexedSessionId.length !== 32 ||
                        !RELAY_EVENT_ID.test(eventId) ||
                        key !== applicationUpdateKey(eventId)
                    ) {
                        await this.#store.delete(transaction, key);
                        if (RELAY_EVENT_ID.test(eventId)) {
                            await this.#store.delete(
                                transaction,
                                serviceUpdateDeliveredKey(eventId),
                            );
                        }
                        await this.#quarantine(
                            transaction,
                            RELAY_EVENT_ID.test(eventId) ? eventId : "application-update-index",
                            "corrupt_application_update_index",
                            indexedSessionId.length === 32 ? indexedSessionId : undefined,
                            "session",
                        );
                        continue;
                    }
                    const bufferedBytes = await this.#store.get(
                        transaction,
                        `${bufferPrefix(indexedSessionId)}${eventId}`,
                    );
                    if (bufferedBytes === undefined) {
                        await this.#store.delete(transaction, key);
                        await this.#store.delete(transaction, serviceUpdateDeliveredKey(eventId));
                        await this.#quarantine(
                            transaction,
                            eventId,
                            "orphaned_application_update_index",
                            indexedSessionId,
                            "session",
                        );
                        await this.#repairBufferedAccounting(transaction, indexedSessionId);
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
            const deletionPage = await this.#store.scan(transaction, SESSION_DELETED_EVENT_PREFIX, {
                limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1,
            });
            const sessionChangeIndexPage = await this.#store.scan(
                transaction,
                SESSION_CHANGED_EVENT_INDEX_PREFIX,
                { limit: MAXIMUM_UPDATE_BATCH_EVENTS + 1 },
            );
            for (const [key, indexedSessionId] of sessionChangeIndexPage) {
                const suffix = key.slice(SESSION_CHANGED_EVENT_INDEX_PREFIX.length);
                const separator = suffix.indexOf("/");
                const eventId = separator < 0 ? "" : suffix.slice(0, separator);
                let keySessionId: Uint8Array | undefined;
                try {
                    keySessionId =
                        separator < 0 ? undefined : decodeBase64Url(suffix.slice(separator + 1));
                } catch {
                    keySessionId = undefined;
                }
                if (
                    keySessionId === undefined ||
                    keySessionId.length !== 32 ||
                    indexedSessionId.length !== 32 ||
                    !RELAY_EVENT_ID.test(eventId) ||
                    key !== sessionChangedEventIndexKey(eventId, keySessionId) ||
                    !equalBytes(indexedSessionId, keySessionId)
                ) {
                    await this.#store.delete(transaction, key);
                    if (
                        keySessionId !== undefined &&
                        keySessionId.length === 32 &&
                        RELAY_EVENT_ID.test(eventId) &&
                        key === sessionChangedEventIndexKey(eventId, keySessionId)
                    ) {
                        await this.#store.delete(
                            transaction,
                            sessionChangedEventKey(keySessionId, eventId),
                        );
                    }
                    await this.#quarantine(
                        transaction,
                        "session-change-index",
                        "corrupt_session_changed_event_index",
                        keySessionId?.length === 32
                            ? keySessionId
                            : indexedSessionId.length === 32
                              ? indexedSessionId
                              : undefined,
                        "session",
                    );
                    if (keySessionId !== undefined) zeroBytes(keySessionId);
                    continue;
                }
                zeroBytes(keySessionId);
                const recordBytes = await this.#store.get(
                    transaction,
                    sessionChangedEventKey(indexedSessionId, eventId),
                );
                if (recordBytes === undefined) {
                    await this.#store.delete(transaction, key);
                    await this.#quarantine(
                        transaction,
                        eventId,
                        "orphaned_session_changed_event_index",
                        indexedSessionId,
                        "session",
                    );
                    continue;
                }
                zeroBytes(recordBytes);
                candidates.push({
                    type: "session-change",
                    eventId,
                    key,
                    sessionId: indexedSessionId.slice(),
                });
            }
            candidates.sort((left, right) => left.eventId.localeCompare(right.eventId));
            const selected = candidates.slice(0, MAXIMUM_UPDATE_BATCH_EVENTS);
            const keys: string[] = [];
            const routes: PreparedSessionRoute[] = [];
            const updates: PreparedRoutedUpdate[] = [];
            const deletions: PreparedSessionDeletion[] = [];
            const sessionChanges: PreparedSessionChange[] = [];
            try {
                for (const candidate of selected) {
                    if (candidate.type === "route") {
                        const markerBytes = await this.#store.get(transaction, candidate.key);
                        if (markerBytes === undefined) continue;
                        const marker = decodeSessionRouting(markerBytes);
                        zeroBytes(markerBytes);
                        const stateBytes = await this.#store.get(
                            transaction,
                            stateKey(marker.sessionId),
                        );
                        if (stateBytes === undefined) {
                            await this.#store.delete(transaction, candidate.key);
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
                    if (candidate.type === "session-change") {
                        const recordKey = sessionChangedEventKey(
                            candidate.sessionId,
                            candidate.eventId,
                        );
                        const bytes = await this.#store.get(transaction, recordKey);
                        if (bytes === undefined) {
                            await this.#store.delete(transaction, candidate.key);
                            continue;
                        }
                        let event: ReturnType<typeof decodeSessionChangedEvent>;
                        try {
                            event = decodeSessionChangedEvent(bytes);
                        } catch {
                            await this.#store.delete(transaction, recordKey);
                            await this.#store.delete(transaction, candidate.key);
                            await this.#quarantine(
                                transaction,
                                `session-change-${sessionId(candidate.sessionId)}`,
                                "corrupt_session_changed_event",
                                candidate.sessionId,
                                "session",
                            );
                            continue;
                        } finally {
                            zeroBytes(bytes);
                        }
                        if (!equalBytes(event.sessionId, candidate.sessionId)) {
                            await this.#store.delete(transaction, recordKey);
                            await this.#store.delete(transaction, candidate.key);
                            await this.#quarantine(
                                transaction,
                                event.id,
                                "corrupt_session_changed_event",
                                candidate.sessionId,
                                "session",
                            );
                            this.#zeroSessionChangedRecord(event);
                            continue;
                        }
                        if (event.id !== candidate.eventId) {
                            await this.#store.delete(transaction, recordKey);
                            await this.#store.delete(transaction, candidate.key);
                            await this.#quarantine(
                                transaction,
                                candidate.eventId,
                                "corrupt_session_changed_event",
                                candidate.sessionId,
                                "session",
                            );
                            this.#zeroSessionChangedRecord(event);
                            continue;
                        }
                        if (event.serviceId === undefined) {
                            const owner = await this.#sessionOwner(transaction, event.sessionId);
                            if (owner?.owner === "service") {
                                event = { ...event, serviceId: owner.serviceId };
                                await setAndZero(
                                    this.#store,
                                    transaction,
                                    recordKey,
                                    encodeSessionChangedEvent(event),
                                );
                            } else if (owner?.owner === "account") {
                                // Application-owned lifecycle records intentionally omit serviceId.
                            } else if (
                                candidates.some(
                                    (other) =>
                                        other.type === "route" &&
                                        equalBytes(other.sessionId, event.sessionId),
                                )
                            ) {
                                this.#zeroSessionChangedRecord(event);
                                continue;
                            } else {
                                await this.#store.delete(transaction, recordKey);
                                await this.#store.delete(transaction, candidate.key);
                                await this.#quarantine(
                                    transaction,
                                    event.id,
                                    "orphaned_session_changed_event",
                                    event.sessionId,
                                    "session",
                                );
                                this.#zeroSessionChangedRecord(event);
                                continue;
                            }
                        }
                        let descriptor = event.descriptor;
                        if (event.status === "active") {
                            let stateBytes = await this.#store.get(
                                transaction,
                                stateKey(event.sessionId),
                            );
                            if (stateBytes === undefined) {
                                stateBytes = await this.#store.get(
                                    transaction,
                                    sessionRetainedDescriptorKey(event.sessionId),
                                );
                                if (stateBytes === undefined) {
                                    await this.#store.delete(transaction, recordKey);
                                    await this.#store.delete(transaction, candidate.key);
                                    await this.#quarantine(
                                        transaction,
                                        event.id,
                                        "orphaned_session_changed_event",
                                        candidate.sessionId,
                                        "session",
                                    );
                                    this.#zeroSessionChangedRecord(event);
                                    continue;
                                }
                                descriptor = stateBytes.slice();
                                zeroBytes(stateBytes);
                            } else {
                                const record = decodeSessionRecord(stateBytes);
                                try {
                                    descriptor = record.descriptor.slice();
                                } finally {
                                    this.#zeroSessionRecord(record);
                                    zeroBytes(stateBytes);
                                }
                            }
                        }
                        sessionChanges.push({
                            key: recordKey,
                            indexKey: candidate.key,
                            id: event.id,
                            ...(event.serviceId === undefined ? {} : { service: event.serviceId }),
                            sessionId: event.sessionId,
                            status: event.status,
                            descriptor: descriptor!,
                            members: event.members,
                            owner: event.roles.owner,
                            admins: [event.roles.owner.slice(), ...event.roles.admins],
                            policies: {
                                adminsAssignAdmins: event.roles.adminsAssignAdmins,
                                anyoneCanAddMembers: event.roles.anyoneCanAddMembers,
                                sendPolicy: event.roles.sendPolicy,
                            },
                            ...(event.reAdmission === true ? { reAdmission: true } : {}),
                        });
                        continue;
                    }
                    const bufferedBytes = await this.#store.get(
                        transaction,
                        `${bufferPrefix(candidate.sessionId)}${candidate.eventId}`,
                    );
                    if (bufferedBytes === undefined) {
                        await this.#store.delete(transaction, candidate.key);
                        await this.#repairBufferedAccounting(transaction, candidate.sessionId);
                        continue;
                    }
                    let buffered: ReturnType<typeof decodeBufferedEvent> | undefined;
                    try {
                        try {
                            buffered = decodeBufferedEvent(bufferedBytes);
                        } catch {
                            await this.#store.delete(
                                transaction,
                                `${bufferPrefix(candidate.sessionId)}${candidate.eventId}`,
                            );
                            await this.#store.delete(transaction, candidate.key);
                            await this.#store.delete(
                                transaction,
                                serviceUpdateDeliveredKey(candidate.eventId),
                            );
                            await this.#quarantine(
                                transaction,
                                candidate.eventId,
                                "corrupt_application_update",
                                candidate.sessionId,
                                "session",
                            );
                            await this.#repairBufferedAccounting(transaction, candidate.sessionId);
                            continue;
                        }
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
                for (const [key, bytes] of [...deletionPage].slice(
                    0,
                    MAXIMUM_UPDATE_BATCH_EVENTS,
                )) {
                    const event = decodeSessionDeletedEvent(bytes);
                    if (event.serviceId === undefined) {
                        await this.#store.delete(transaction, key);
                        zeroBytes(event.sessionId);
                        zeroBytes(event.owner);
                        continue;
                    }
                    deletions.push({
                        key,
                        id: event.id,
                        sessionId: event.sessionId,
                        owner: event.owner,
                        service: event.serviceId,
                    });
                }
                return {
                    keys,
                    routes,
                    updates,
                    deletions,
                    sessionChanges,
                    exhausted:
                        candidates.length <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        routePage.size <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        updatePage.size <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        deletionPage.size <= MAXIMUM_UPDATE_BATCH_EVENTS &&
                        sessionChangeIndexPage.size <= MAXIMUM_UPDATE_BATCH_EVENTS,
                };
            } finally {
                for (const candidate of candidates) {
                    if (
                        candidate.type === "route" ||
                        candidate.type === "update" ||
                        candidate.type === "session-change"
                    ) {
                        zeroBytes(candidate.sessionId);
                    }
                }
                for (const bytes of deletionPage.values()) zeroBytes(bytes);
                for (const bytes of sessionChangeIndexPage.values()) zeroBytes(bytes);
            }
        });
    }

    async serviceUpdateDelivered(ctx: Context, eventId: string): Promise<boolean> {
        return this.#store.tx(ctx, async (transaction) => {
            const bytes = await this.#store.get(transaction, serviceUpdateDeliveredKey(eventId));
            if (bytes === undefined) return false;
            try {
                if (bytes.length === 0) return true;
                const sessionIdValue = await this.#store.get(
                    transaction,
                    applicationUpdateKey(eventId),
                );
                try {
                    await this.#store.delete(transaction, serviceUpdateDeliveredKey(eventId));
                    await this.#quarantine(
                        transaction,
                        eventId,
                        "corrupt_service_update_receipt",
                        sessionIdValue?.length === 32 ? sessionIdValue : undefined,
                        "application",
                    );
                } finally {
                    if (sessionIdValue !== undefined) zeroBytes(sessionIdValue);
                }
                return false;
            } finally {
                zeroBytes(bytes);
            }
        });
    }

    async markServiceUpdateDelivered(ctx: Context, eventId: string): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const indexedSession = await this.#store.get(
                transaction,
                applicationUpdateKey(eventId),
            );
            if (indexedSession === undefined) return;
            zeroBytes(indexedSession);
            await this.#store.set(
                transaction,
                serviceUpdateDeliveredKey(eventId),
                new Uint8Array(),
            );
        });
    }

    async commitUpdates(
        ctx: Context,
        prepared: PreparedUpdates,
        decisions: readonly SessionRouteDecision[] = [],
        consumedKeys: ReadonlySet<string> = new Set(prepared.keys),
        consumedDeletionKeys: ReadonlySet<string> = new Set(
            prepared.deletions.map((deletion) => deletion.key),
        ),
        consumedSessionChangeKeys: ReadonlySet<string> = new Set(
            prepared.sessionChanges.map((change) => change.key),
        ),
        operation?: (transaction: Context) => Promise<void>,
    ): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            const changes = new Map<string, { id: Uint8Array; events: number; bytes: number }>();
            try {
                for (const decision of decisions) {
                    const markerBytes = await this.#store.get(transaction, decision.key);
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
                                this.#store,
                                transaction,
                                sessionOwnerKey(decision.sessionId),
                                encodeSessionOwner(decision.owner),
                            );
                            if (decision.owner.owner === "service") {
                                await this.#assignSessionChangedService(
                                    transaction,
                                    decision.sessionId,
                                    decision.owner.serviceId,
                                );
                            }
                            await this.#activatePending(transaction, decision.sessionId);
                        }
                        await this.#store.delete(transaction, decision.key);
                    } finally {
                        zeroBytes(marker.sessionId);
                        zeroBytes(markerBytes);
                    }
                }
                for (const key of prepared.keys) {
                    if (!consumedKeys.has(key)) continue;
                    const indexedSessionId = await this.#store.get(transaction, key);
                    if (indexedSessionId === undefined) continue;
                    try {
                        const eventId = key.slice(APPLICATION_UPDATE_PREFIX.length);
                        const bufferedKey = `${bufferPrefix(indexedSessionId)}${eventId}`;
                        const bufferedBytes = await this.#store.get(transaction, bufferedKey);
                        if (bufferedBytes === undefined) {
                            await this.#store.delete(transaction, key);
                            await this.#store.delete(
                                transaction,
                                serviceUpdateDeliveredKey(eventId),
                            );
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
                            await this.#store.delete(transaction, bufferedKey);
                            await this.#store.delete(transaction, key);
                            await this.#store.delete(
                                transaction,
                                serviceUpdateDeliveredKey(eventId),
                            );
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
                    const stateBytes = await this.#store.get(transaction, stateKey(change.id));
                    if (stateBytes === undefined) continue;
                    const record = decodeSessionRecord(stateBytes);
                    try {
                        if (
                            record.status !== "active" ||
                            record.bufferedEvents < change.events ||
                            record.bufferedBytes < change.bytes
                        ) {
                            throw new Error("Invalid application update accounting");
                        }
                        await setAndZero(
                            this.#store,
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
                for (const key of consumedDeletionKeys) await this.#store.delete(transaction, key);
                for (const change of prepared.sessionChanges) {
                    if (!consumedSessionChangeKeys.has(change.key)) continue;
                    await this.#store.delete(transaction, change.key);
                    await this.#store.delete(transaction, change.indexKey);
                    if (change.status === "removed") {
                        await this.#deleteBufferedSessionUpdates(transaction, change.sessionId);
                        await this.#store.delete(transaction, sessionOwnerKey(change.sessionId));
                        await this.#store.delete(
                            transaction,
                            sessionRetainedDescriptorKey(change.sessionId),
                        );
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

    async send(ctx: Context, id: Uint8Array, bytes: Uint8Array): Promise<string> {
        return this.#queuePrivate(
            ctx,
            id,
            { version: 1, type: "application", bytes },
            "application",
        );
    }

    async add(
        ctx: Context,
        id: Uint8Array,
        member: SessionMemberMaterial,
        operation?: (transaction: Context) => Promise<void>,
    ): Promise<void> {
        if (
            member.identity.length !== 32 ||
            !verifyMlsKeyPackage(member.keyPackage, Math.floor(this.#now() / 1_000)) ||
            !equalBytes(member.keyPackage.leafNode.signatureKey, member.identity)
        ) {
            throw new MurmurError("invalid_argument", "Invalid Add KeyPackage");
        }
        const account = keyPackageAccount(member.keyPackage);
        const encodedKeyPackage = encodeMlsKeyPackage(member.keyPackage);
        await this.#store.tx(ctx, async (transaction) => {
            const stateBytes = await this.#store.get(transaction, stateKey(id));
            if (stateBytes === undefined) {
                throw new MurmurError("not_found", "Unknown active session");
            }
            const record = decodeSessionRecord(stateBytes);
            const epoch = restoreEpoch(this.#identity, record);
            try {
                if (record.status !== "active") {
                    throw new MurmurError("not_found", "Unknown active session");
                }
                if (
                    !isSessionAdmin(record.roles, this.#accountKey) &&
                    !record.roles.anyoneCanAddMembers
                ) {
                    throw new MurmurError(
                        "permission_denied",
                        "The local account may not add session members",
                    );
                }
                await this.#claimKeyPackages(transaction, [member]);
                await operation?.(transaction);
                await this.#queueSessionIntent(transaction, {
                    version: 1,
                    kind: "add",
                    sessionId: id.slice(),
                    account: account.slice(),
                    device: member.identity.slice(),
                    keyPackage: encodedKeyPackage.slice(),
                    removalGeneration: removalGeneration(record, account),
                });
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
            }
        });
        zeroBytes(account);
        zeroBytes(encodedKeyPackage);
    }

    async remove(ctx: Context, id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#queueAccountIntent(ctx, id, "remove", account);
    }

    async grantAdmin(ctx: Context, id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#queueAccountIntent(ctx, id, "grant_admin", account);
    }

    async revokeAdmin(ctx: Context, id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#queueAccountIntent(ctx, id, "revoke_admin", account);
    }

    async leave(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#queueAccountIntent(ctx, id, "leave", this.#accountKey);
    }

    async setPolicies(
        ctx: Context,
        id: Uint8Array,
        policies: {
            readonly adminsAssignAdmins?: boolean;
            readonly anyoneCanAddMembers?: boolean;
            readonly sendPolicy?: "everyone" | "admins";
        },
    ): Promise<void> {
        if (
            (policies.adminsAssignAdmins !== undefined &&
                typeof policies.adminsAssignAdmins !== "boolean") ||
            (policies.anyoneCanAddMembers !== undefined &&
                typeof policies.anyoneCanAddMembers !== "boolean") ||
            (policies.sendPolicy !== undefined &&
                policies.sendPolicy !== "everyone" &&
                policies.sendPolicy !== "admins")
        ) {
            throw new MurmurError("invalid_argument", "Invalid session policies");
        }
        if (
            policies.adminsAssignAdmins === undefined &&
            policies.anyoneCanAddMembers === undefined &&
            policies.sendPolicy === undefined
        ) {
            throw new MurmurError("invalid_argument", "Session policy change is empty");
        }
        await this.#store.tx(ctx, async (transaction) => {
            const stateBytes = await this.#store.get(transaction, stateKey(id));
            if (stateBytes === undefined) {
                throw new MurmurError("not_found", "Unknown active session");
            }
            const record = decodeSessionRecord(stateBytes);
            const epoch = restoreEpoch(this.#identity, record);
            try {
                if (record.status !== "active") {
                    throw new MurmurError("not_found", "Unknown active session");
                }
                if (!equalBytes(record.roles.owner, this.#accountKey)) {
                    throw new MurmurError(
                        "permission_denied",
                        "Only the session owner may change policies",
                    );
                }
                await this.#queueSessionIntent(transaction, {
                    version: 1,
                    kind: "set_policies",
                    sessionId: id.slice(),
                    adminsAssignAdmins:
                        policies.adminsAssignAdmins ?? record.roles.adminsAssignAdmins,
                    anyoneCanAddMembers:
                        policies.anyoneCanAddMembers ?? record.roles.anyoneCanAddMembers,
                    sendPolicy: policies.sendPolicy ?? record.roles.sendPolicy,
                });
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
            }
        });
    }

    async #queueAccountIntent(
        ctx: Context,
        id: Uint8Array,
        kind: "remove" | "grant_admin" | "revoke_admin" | "leave",
        account: Uint8Array,
    ): Promise<void> {
        if (account.length !== 32) {
            throw new MurmurError("invalid_argument", "Invalid session account");
        }
        await this.#store.tx(ctx, async (transaction) => {
            const stateBytes = await this.#store.get(transaction, stateKey(id));
            if (stateBytes === undefined) {
                throw new MurmurError("not_found", "Unknown active session");
            }
            const record = decodeSessionRecord(stateBytes);
            const epoch = restoreEpoch(this.#identity, record);
            try {
                if (record.status !== "active") {
                    throw new MurmurError("not_found", "Unknown active session");
                }
                const owner = equalBytes(record.roles.owner, this.#accountKey);
                const admin = isSessionAdmin(record.roles, this.#accountKey);
                if (kind === "remove") {
                    if (equalBytes(account, record.roles.owner)) {
                        throw new MurmurError(
                            "permission_denied",
                            "The session owner cannot be removed",
                        );
                    }
                    if (!equalBytes(account, this.#accountKey) && !admin) {
                        throw new MurmurError(
                            "permission_denied",
                            "Only an admin may remove another account",
                        );
                    }
                } else if (kind === "leave") {
                    if (owner) {
                        throw new MurmurError(
                            "permission_denied",
                            "The session owner cannot leave",
                        );
                    }
                } else if (kind === "grant_admin") {
                    if (!owner && !(admin && record.roles.adminsAssignAdmins)) {
                        throw new MurmurError(
                            "permission_denied",
                            "The local account may not grant admin",
                        );
                    }
                    if (accountLeaves(epoch, account).length === 0) {
                        throw new MurmurError(
                            "invalid_argument",
                            "An admin must be a current session member",
                        );
                    }
                } else {
                    if (!owner) {
                        throw new MurmurError(
                            "permission_denied",
                            "Only the session owner may revoke admin",
                        );
                    }
                    if (equalBytes(account, record.roles.owner)) {
                        throw new MurmurError(
                            "permission_denied",
                            "The session owner cannot be demoted",
                        );
                    }
                }
                await this.#queueSessionIntent(transaction, {
                    version: 1,
                    kind,
                    sessionId: id.slice(),
                    account: account.slice(),
                });
            } finally {
                epoch.destroy();
                this.#zeroSessionRecord(record);
                zeroBytes(stateBytes);
            }
        });
    }

    async #queueSessionIntent(transaction: Context, intent: SessionIntentRecord): Promise<string> {
        const current = await this.#store.scan(transaction, SESSION_INTENT_PREFIX, {
            limit: MAXIMUM_SESSION_INTENTS,
        });
        if (current.size >= MAXIMUM_SESSION_INTENTS) {
            throw new MurmurError("resource_exhausted", "Session intent capacity exceeded");
        }
        const id = encodeBase64Url(randomBytes(24));
        await setAndZero(this.#store, transaction, intentKey(id), encodeSessionIntent(intent));
        return id;
    }

    /** Converge durable public membership and role intents one Commit at a time. */
    async convergeIntents(ctx: Context): Promise<boolean> {
        let retry = false;
        const entries = await this.#store.scan(ctx, SESSION_INTENT_PREFIX, {
            limit: MAXIMUM_SESSION_INTENTS,
        });
        for (const [key, bytes] of entries) {
            const intentId = key.slice(SESSION_INTENT_PREFIX.length);
            let intent: SessionIntentRecord;
            try {
                intent = decodeSessionIntent(bytes);
            } catch {
                await this.#store.tx(ctx, async (transaction) => {
                    await this.#store.delete(transaction, key);
                    await this.#quarantine(transaction, intentId, "corrupt_session_intent");
                });
                zeroBytes(bytes);
                continue;
            }
            try {
                const completed = await this.#store.tx(ctx, async (transaction) => {
                    const stateBytes = await this.#store.get(
                        transaction,
                        stateKey(intent.sessionId),
                    );
                    if (stateBytes === undefined) {
                        await this.#store.delete(transaction, key);
                        await this.#quarantine(
                            transaction,
                            intentId,
                            "intent_unknown_session",
                            intent.sessionId,
                            "session",
                            intentId,
                        );
                        return true;
                    }
                    const record = decodeSessionRecord(stateBytes);
                    const epoch = restoreEpoch(this.#identity, record);
                    try {
                        if (record.status !== "active") return false;
                        if (record.stagedCommitId !== undefined) return false;
                        if (intent.kind === "leave") {
                            await this.#queuePrivate(
                                transaction,
                                intent.sessionId,
                                { version: 1, type: "leave" },
                                "application",
                                transaction,
                            );
                            await this.#store.delete(transaction, key);
                            return true;
                        }
                        const accounts = activeAccounts(epoch);
                        const accountPresent = (account: Uint8Array): boolean =>
                            accounts.some((member) => equalBytes(member, account));
                        const terminalizeAuthorizationLoss = async (): Promise<true> => {
                            await this.#store.delete(transaction, key);
                            await this.#quarantine(
                                transaction,
                                intentId,
                                "intent_authorization_lost",
                                intent.sessionId,
                                "session",
                                intentId,
                            );
                            return true;
                        };
                        let additions: readonly PreparedAddition[] = [];
                        let removals: readonly Uint8Array[] = [];
                        let roles = record.roles;
                        if (intent.kind === "add") {
                            if (accountPresent(intent.account)) {
                                await this.#store.delete(transaction, key);
                                return true;
                            }
                            if (
                                !isSessionAdmin(record.roles, this.#accountKey) &&
                                !record.roles.anyoneCanAddMembers
                            ) {
                                return terminalizeAuthorizationLoss();
                            }
                            if (
                                removalGeneration(record, intent.account) !==
                                intent.removalGeneration
                            ) {
                                await this.#store.delete(transaction, key);
                                await this.#quarantine(
                                    transaction,
                                    intentId,
                                    "add_intent_removal_generation_advanced",
                                    intent.sessionId,
                                    "session",
                                    intentId,
                                );
                                return true;
                            }
                            const keyPackage = decodeMlsKeyPackage(intent.keyPackage);
                            if (
                                !verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000)) ||
                                !equalBytes(keyPackage.leafNode.signatureKey, intent.device) ||
                                !equalBytes(keyPackageAccount(keyPackage), intent.account)
                            ) {
                                await this.#store.delete(transaction, key);
                                await this.#quarantine(
                                    transaction,
                                    intentId,
                                    "add_intent_key_package_expired",
                                    intent.sessionId,
                                    "session",
                                    intentId,
                                );
                                return true;
                            }
                            additions = [{ identity: intent.device, keyPackage }];
                        } else if (intent.kind === "remove") {
                            if (!accountPresent(intent.account)) {
                                await this.#store.delete(transaction, key);
                                return true;
                            }
                            if (
                                !equalBytes(intent.account, this.#accountKey) &&
                                !isSessionAdmin(record.roles, this.#accountKey)
                            ) {
                                return terminalizeAuthorizationLoss();
                            }
                            removals = accountLeaves(epoch, intent.account).map((leaf) =>
                                epoch.memberSignatureKeys[leaf]!.slice(),
                            );
                            if (
                                record.roles.admins.some((admin) =>
                                    equalBytes(admin, intent.account),
                                )
                            ) {
                                roles = normalizeSessionRoles({
                                    ...record.roles,
                                    admins: record.roles.admins.filter(
                                        (admin) => !equalBytes(admin, intent.account),
                                    ),
                                });
                            }
                        } else if (intent.kind === "grant_admin") {
                            if (
                                isSessionAdmin(record.roles, intent.account) ||
                                !accountPresent(intent.account)
                            ) {
                                await this.#store.delete(transaction, key);
                                return true;
                            }
                            if (
                                !equalBytes(record.roles.owner, this.#accountKey) &&
                                !(
                                    isSessionAdmin(record.roles, this.#accountKey) &&
                                    record.roles.adminsAssignAdmins
                                )
                            ) {
                                return terminalizeAuthorizationLoss();
                            }
                            roles = normalizeSessionRoles({
                                ...record.roles,
                                admins: [...record.roles.admins, intent.account],
                            });
                        } else if (intent.kind === "revoke_admin") {
                            if (
                                !record.roles.admins.some((admin) =>
                                    equalBytes(admin, intent.account),
                                )
                            ) {
                                await this.#store.delete(transaction, key);
                                return true;
                            }
                            if (!equalBytes(record.roles.owner, this.#accountKey)) {
                                return terminalizeAuthorizationLoss();
                            }
                            roles = normalizeSessionRoles({
                                ...record.roles,
                                admins: record.roles.admins.filter(
                                    (admin) => !equalBytes(admin, intent.account),
                                ),
                            });
                        } else if (intent.kind === "set_policies") {
                            roles = normalizeSessionRoles({
                                ...record.roles,
                                adminsAssignAdmins: intent.adminsAssignAdmins,
                                anyoneCanAddMembers: intent.anyoneCanAddMembers,
                                sendPolicy: intent.sendPolicy,
                            });
                            if (sessionRolesEqual(roles, record.roles)) {
                                await this.#store.delete(transaction, key);
                                return true;
                            }
                            if (!equalBytes(record.roles.owner, this.#accountKey)) {
                                return terminalizeAuthorizationLoss();
                            }
                        } else {
                            throw new Error("Unsupported session intent");
                        }
                        await this.#prepareCommit(
                            transaction,
                            intent.sessionId,
                            additions,
                            removals,
                            roles,
                            intentId,
                            transaction,
                        );
                        return false;
                    } finally {
                        epoch.destroy();
                        this.#zeroSessionRecord(record);
                        zeroBytes(stateBytes);
                    }
                });
                if (!completed) retry = true;
            } catch {
                retry = true;
            } finally {
                if (intent.kind === "add") zeroBytes(intent.keyPackage);
                zeroBytes(intent.sessionId);
                if (intent.kind !== "set_policies") zeroBytes(intent.account);
                zeroBytes(bytes);
            }
        }
        return retry;
    }

    async synchronize(
        ctx: Context,
        options: MurmurSynchronizeOptions = {},
    ): Promise<MurmurSynchronizeResult> {
        await this.#store.tx(ctx, (transaction) =>
            this.#pruneKeyPackages(transaction, this.#now()),
        );
        await this.convergeAccounts(ctx);
        await this.#flushDeletionOutboxes(ctx, options.signal);
        const before = await this.#flushOutboxes(ctx, options.signal);
        const inbox = await this.#inbox.synchronize(ctx, options);
        await this.convergeAccounts(ctx);
        await this.convergeIntents(ctx);
        await this.#flushDeletionOutboxes(ctx, options.signal);
        const after = await this.#flushOutboxes(ctx, options.signal);
        return this.#synchronizationResult(ctx, inbox, [before, after]);
    }

    streamInbox(ctx: Context, options: InboxStreamOptions): AsyncIterable<InboxSyncResult> {
        return this.#inbox.stream(ctx, options);
    }

    async flush(ctx: Context, signal?: AbortSignal): Promise<boolean> {
        await this.#store.tx(ctx, (transaction) =>
            this.#pruneKeyPackages(transaction, this.#now()),
        );
        const accountRetry = await this.convergeAccounts(ctx);
        const intentRetry = await this.convergeIntents(ctx);
        const deletionRetry = await this.#flushDeletionOutboxes(ctx, signal);
        const outboxRetry = (await this.#flushOutboxes(ctx, signal)).transientFailureIds.size > 0;
        return deletionRetry || outboxRetry || accountRetry || intentRetry;
    }

    async #flushDeletionOutboxes(ctx: Context, signal?: AbortSignal): Promise<boolean> {
        const entries = await this.#store.scan(ctx, SESSION_DELETION_OUTBOX_PREFIX, {
            limit: OUTBOX_SCAN_ITEMS,
        });
        let retry = entries.size >= OUTBOX_SCAN_ITEMS;
        for (const [key, bytes] of entries) {
            let record: ReturnType<typeof decodeSessionDeletionOutbox> | undefined;
            try {
                record = decodeSessionDeletionOutbox(bytes);
                if (this.#transport.deleteSession === undefined) {
                    retry = true;
                    continue;
                }
                const now = this.#now();
                const request = createSignedDelivery(
                    this.#accountIdentity,
                    [],
                    record.request.ciphertext,
                    {
                        id: record.request.id,
                        createdAt: now,
                        expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                        senderAccount: this.#accountKey,
                    },
                );
                let notice = record.notice;
                if (notice.expiresAt <= now) {
                    notice = createSignedDelivery(
                        this.#identity,
                        record.notice.recipients,
                        record.notice.ciphertext,
                        {
                            id: record.notice.id,
                            createdAt: now,
                            expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                            senderAccount: this.#accountKey,
                            targetAccounts: record.notice.targetAccounts,
                            ...(record.notice.ownerAccount === null
                                ? {}
                                : {
                                      ownerAccount: record.notice.ownerAccount,
                                      sessionId: record.notice.sessionId!,
                                  }),
                        },
                    );
                }
                await setAndZero(
                    this.#store,
                    ctx,
                    key,
                    encodeSessionDeletionOutbox({ ...record, request, notice }),
                );
                try {
                    await this.#transport.deleteSession(ctx, request, signal);
                } catch (error: unknown) {
                    if (!(error instanceof DeliveryTransportError && error.code === "replay")) {
                        retry = true;
                        continue;
                    }
                }
                try {
                    await this.#transport.publish(ctx, notice, signal);
                    await this.#store.delete(ctx, key);
                } catch {
                    retry = true;
                }
            } catch {
                retry = true;
            } finally {
                if (record !== undefined) {
                    zeroBytes(record.sessionId);
                    zeroBytes(record.request.ciphertext);
                    zeroBytes(record.notice.ciphertext);
                }
                zeroBytes(bytes);
            }
        }
        return retry;
    }

    /**
     * Drive every queued authenticated roster change into each matching session.
     *
     * A job adds, removes, or atomically replaces one account device. Any authorized current member
     * stages the direct Commit, and the durable job remains until an adopted
     * epoch proves that the requested roster state has converged.
     */
    async convergeAccounts(ctx: Context): Promise<boolean> {
        let retry = false;
        for (const job of await accountConvergenceJobs(ctx, this.#store)) {
            let complete = true;
            try {
                let after: string | undefined;
                for (;;) {
                    const page = await this.#store.scan(ctx, SESSION_STATE_PREFIX, {
                        ...(after === undefined ? {} : { after }),
                        limit: SESSION_LIST_LIMIT,
                    });
                    if (page.size === 0) break;
                    for (const [key, bytes] of page) {
                        after = key;
                        let record: SessionRecord;
                        try {
                            record = decodeSessionRecord(bytes);
                        } catch {
                            zeroBytes(bytes);
                            continue;
                        }
                        try {
                            if (!(await this.#convergeSession(ctx, job, record))) complete = false;
                        } catch {
                            complete = false;
                        } finally {
                            this.#zeroSessionRecord(record);
                            zeroBytes(bytes);
                        }
                    }
                    if (page.size < SESSION_LIST_LIMIT) break;
                }
                if (complete) {
                    await this.#store.tx(ctx, async (transaction) => {
                        await this.#store.delete(transaction, job.key);
                        await this.#deletePrefix(
                            transaction,
                            accountConvergenceCompletionPrefix(job.key),
                        );
                    });
                } else retry = true;
            } finally {
                zeroBytes(job.account);
                zeroBytes(job.device);
                if (job.keyPackage !== undefined) zeroBytes(job.keyPackage);
            }
        }
        return retry;
    }

    /** Apply one roster convergence job to one session; false requests a retry. */
    async #convergeSession(
        ctx: Context,
        job: AccountConvergenceJob,
        record: SessionRecord,
    ): Promise<boolean> {
        if (record.status === "removed") return true;
        if (job.dependsOn !== undefined) {
            const dependency = await this.#store.get(ctx, job.dependsOn);
            if (dependency !== undefined) {
                zeroBytes(dependency);
                return false;
            }
        }
        const adding = job.change === "added" || job.change === "reset_add";
        const removing = job.change === "revoked" || job.change === "reset_remove";
        const deviceCurrentlyAllowed = await this.#deviceAllowedByObservedRoster(
            ctx,
            job.account,
            job.device,
        );
        if (
            (job.change === "added" && !deviceCurrentlyAllowed) ||
            (job.change === "revoked" && deviceCurrentlyAllowed) ||
            (job.change === "reset_add" && !deviceCurrentlyAllowed) ||
            (!adding && !removing)
        ) {
            return true;
        }
        const epoch = restoreEpoch(this.#identity, record);
        try {
            const completion = await this.#store.get(
                ctx,
                accountConvergenceCompletionKey(job.key, epoch.groupId),
            );
            if (completion !== undefined) {
                zeroBytes(completion);
                return true;
            }
            let accountPresent = false;
            let devicePresent = false;
            for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
                const signatureKey = epoch.memberSignatureKeys[leaf];
                if (signatureKey === undefined) continue;
                if (equalBytes(memberAccount(epoch, leaf), job.account)) accountPresent = true;
                if (equalBytes(signatureKey, job.device)) devicePresent = true;
            }
            if (!accountPresent) return true;
            if (
                (job.change === "added" && devicePresent) ||
                (job.change === "revoked" && !devicePresent) ||
                (job.change === "reset_remove" && !devicePresent)
            ) {
                return true;
            }
            if (record.status !== "active") return false;
            const id = epoch.groupId;
            if (record.stagedCommitId !== undefined) return false;
            if (
                !equalBytes(job.account, this.#accountKey) &&
                !isSessionAdmin(record.roles, this.#accountKey) &&
                !adding
            ) {
                return false;
            }
            if (adding) {
                const keyPackage = decodeMlsKeyPackage(job.keyPackage!);
                if (!verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000))) {
                    return true;
                }
                await this.#prepareCommit(
                    ctx,
                    id,
                    [{ identity: job.device.slice(), keyPackage }],
                    job.change === "reset_add" && devicePresent ? [job.device.slice()] : [],
                    record.roles,
                    undefined,
                    undefined,
                    job.change === "reset_add" ? job.key : undefined,
                );
            } else {
                if (equalBytes(job.device, this.#identity.publicKey)) return false;
                await this.#prepareCommit(ctx, id, [], [job.device.slice()], record.roles);
            }
            return false;
        } finally {
            epoch.destroy();
        }
    }

    async completeStreamEvent(
        ctx: Context,
        inbox: InboxSyncResult,
        signal?: AbortSignal,
    ): Promise<MurmurSynchronizeResult> {
        await this.convergeAccounts(ctx);
        await this.convergeIntents(ctx);
        return this.#synchronizationResult(ctx, inbox, [await this.#flushOutboxes(ctx, signal)]);
    }

    async #synchronizationResult(
        ctx: Context,
        inbox: InboxSyncResult,
        publications: readonly FlushOutboxResult[],
    ): Promise<MurmurSynchronizeResult> {
        const pendingOutboxes = (
            await this.#store.scan(ctx, OUTBOX_PREFIX, {
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
            issues: await this.issues(ctx),
        };
    }

    async issues(ctx: Context): Promise<readonly MurmurSessionIssue[]> {
        const entries = await this.#store.scan(ctx, QUARANTINE_PREFIX, {
            limit: MAXIMUM_REJECTED_SESSIONS,
        });
        const result: MurmurSessionIssue[] = [];
        for (const [key, bytes] of entries) {
            try {
                try {
                    result.push(decodeIssue(key.slice(QUARANTINE_PREFIX.length), bytes));
                } catch {
                    await this.#store.delete(ctx, key);
                    this.#issueVersion += 1;
                }
            } finally {
                zeroBytes(bytes);
            }
        }
        return result;
    }

    async #nextOutboxOrder(transaction: Context): Promise<string> {
        const stored = await this.#store.get(transaction, OUTBOX_SEQUENCE_KEY);
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
        await setAndZero(this.#store, transaction, OUTBOX_SEQUENCE_KEY, utf8Encode(order));
        return order;
    }

    async #queuePrivate(
        ctx: Context,
        id: Uint8Array,
        frame: PrivateSessionFrame,
        kind: "application",
        existingTransaction?: Context,
    ): Promise<string> {
        const queue = async (transaction: Context): Promise<string> => {
            if (
                (
                    await this.#store.scan(transaction, OUTBOX_PREFIX, {
                        limit: this.#limits.maximumOutboxes,
                    })
                ).size >= this.#limits.maximumOutboxes
            ) {
                throw new MurmurError(
                    "resource_exhausted",
                    "Local session outbox capacity exceeded",
                );
            }
            const bytes = await this.#store.get(transaction, stateKey(id));
            if (bytes === undefined) throw new MurmurError("not_found", "Unknown session");
            const record = decodeSessionRecord(bytes);
            let parentCommitId: string | undefined;
            let parentBytes: Uint8Array | undefined;
            let parent: SessionOutboxRecord | undefined;
            let epoch: MlsEpochState | undefined;
            let applicationData: Uint8Array | undefined;
            let checkpoint: Uint8Array | undefined;
            try {
                if (record.status === "removed") {
                    throw new MurmurError("not_found", "Unknown session");
                }
                if (record.stagedCommitId === undefined) {
                    if (record.status === "creating") {
                        throw new Error("Creating session is missing its staged epoch");
                    }
                    parentCommitId = await this.#readyBootstrapParentForSession(transaction, id);
                    epoch = restoreEpoch(this.#identity, record);
                } else {
                    parentCommitId = record.stagedCommitId;
                    parentBytes = await this.#store.get(transaction, outboxKey(parentCommitId));
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
                const roles = parent?.roles ?? record.roles;
                if (
                    frame.type === "application" &&
                    roles.sendPolicy === "admins" &&
                    !isSessionAdmin(roles, this.#accountKey)
                ) {
                    throw new MurmurError(
                        "permission_denied",
                        "The local account may not send session events",
                    );
                }
                const members = activeMembers(epoch);
                if (members.length > this.#limits.maximumMembersPerSession) {
                    throw new MurmurError(
                        "resource_exhausted",
                        "Session exceeds the configured member limit",
                    );
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
                    throw new MurmurError(
                        "resource_exhausted",
                        "Session application payload exceeds the configured limit",
                    );
                }
                applicationData = encodePrivateFrame(frame);
                const message = epoch.seal(applicationData);
                const ciphertext = encodePrivateCiphertext(message);
                if (ciphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
                    throw new MurmurError(
                        "resource_exhausted",
                        "Session delivery exceeds the configured ciphertext limit",
                    );
                }
                const now = this.#now();
                const direct = frame.type === "delete";
                const delivery = createSignedDelivery(
                    this.#identity,
                    direct ? members : [],
                    ciphertext,
                    {
                        createdAt: now,
                        expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                        senderAccount: this.#accountKey,
                        ownerAccount: roles.owner,
                        sessionId: id,
                        ...(direct
                            ? { targetAccounts: await this.#targetAccounts(transaction, epoch) }
                            : {
                                  sessionControl: {
                                      version: 1,
                                      type: "message",
                                      epoch: epoch.context.epoch,
                                      content:
                                          frame.type === "application" ? "application" : "protocol",
                                      coveredDevices: members,
                                  } as const,
                              }),
                    },
                );
                checkpoint = epoch.serialize();
                if (parent === undefined) {
                    await setAndZero(
                        this.#store,
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
                        this.#store,
                        transaction,
                        outboxKey(parent.delivery.id),
                        encodeOutboxRecord({ ...parent, stagedEpoch: checkpoint }),
                    );
                }
                const order = await this.#nextOutboxOrder(transaction);
                await setAndZero(
                    this.#store,
                    transaction,
                    outboxKey(delivery.id),
                    encodeOutboxRecord({
                        version: 2,
                        kind,
                        order,
                        operationId: delivery.id,
                        sessionId: id,
                        delivery,
                        applicationData,
                        ...(parentCommitId === undefined ? {} : { parentCommitId }),
                    }),
                );
                await this.#store.set(
                    transaction,
                    outboxOrderKey(order, delivery.id),
                    new Uint8Array(),
                );
                if (parentCommitId === undefined) {
                    await this.#store.set(
                        transaction,
                        epochOutboxIndexKey(id, delivery.id),
                        new Uint8Array(),
                    );
                } else {
                    await this.#store.set(
                        transaction,
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
            ? this.#store.tx(ctx, queue)
            : queue(existingTransaction);
    }

    async #deviceAllowedByObservedRoster(
        ctx: Context,
        account: Uint8Array,
        device: Uint8Array,
    ): Promise<boolean> {
        const key = equalBytes(account, this.#accountKey)
            ? ACCOUNT_ROSTER_KEY
            : `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(account)}`;
        const stored = await this.#store.get(ctx, key);
        if (stored === undefined) return true;
        try {
            const roster = parseDeviceRoster(stored);
            return equalBytes(roster.accountKey, account) && isActiveDevice(roster, device);
        } catch {
            return false;
        } finally {
            zeroBytes(stored);
        }
    }

    /** Deterministically authorize one Commit against the role state it extends. */
    async #validRoleCommit(
        transaction: Context,
        epoch: MlsEpochState,
        currentRoles: SessionRoles,
        nextRoles: SessionRoles,
        commit: ReturnType<typeof decodeMlsTreeCommit>,
        createdAt: number = this.#now(),
    ): Promise<boolean> {
        try {
            const control = decodeSessionControl(commit.authenticatedData);
            if (
                commit.sender < 0 ||
                commit.sender >= epoch.memberSignatureKeys.length ||
                epoch.memberSignatureKeys[commit.sender] === undefined ||
                !equalBytes(control.roles.owner, nextRoles.owner) ||
                !sessionRolesEqual(control.roles, nextRoles) ||
                !equalBytes(currentRoles.owner, nextRoles.owner)
            ) {
                return false;
            }
            const senderAccount = memberAccount(epoch, commit.sender);
            const senderAdmin = isSessionAdmin(currentRoles, senderAccount);
            const counts = new Map<string, { account: Uint8Array; devices: number }>();
            for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
                if (epoch.memberSignatureKeys[leaf] === undefined) continue;
                const account = memberAccount(epoch, leaf);
                const key = encodeBase64Url(account);
                const current = counts.get(key);
                counts.set(key, {
                    account,
                    devices: (current?.devices ?? 0) + 1,
                });
            }
            const removedAccounts = new Set<string>();
            for (const proposal of commit.proposals) {
                if (proposal.type === "add") {
                    if (!verifyMlsKeyPackage(proposal.keyPackage, Math.floor(createdAt / 1_000))) {
                        return false;
                    }
                    const account = keyPackageAccount(proposal.keyPackage);
                    const device = proposal.keyPackage.leafNode.signatureKey;
                    if (
                        !(await this.#deviceAllowedByObservedRoster(transaction, account, device))
                    ) {
                        return false;
                    }
                    const key = encodeBase64Url(account);
                    const current = counts.get(key);
                    if (current === undefined) {
                        if (!senderAdmin && !currentRoles.anyoneCanAddMembers) return false;
                        counts.set(key, { account, devices: 1 });
                    } else {
                        counts.set(key, { account: current.account, devices: current.devices + 1 });
                    }
                } else {
                    const signatureKey = epoch.memberSignatureKeys[proposal.removed];
                    if (signatureKey === undefined) return false;
                    const account = memberAccount(epoch, proposal.removed);
                    const key = encodeBase64Url(account);
                    const current = counts.get(key);
                    if (current === undefined || current.devices < 1) return false;
                    if (current.devices === 1) {
                        if (equalBytes(account, currentRoles.owner)) return false;
                        if (!senderAdmin && !equalBytes(senderAccount, account)) return false;
                        counts.delete(key);
                        removedAccounts.add(key);
                    } else {
                        if (!senderAdmin && !equalBytes(senderAccount, account)) return false;
                        counts.set(key, { account: current.account, devices: current.devices - 1 });
                    }
                }
            }
            if (!counts.has(encodeBase64Url(currentRoles.owner))) return false;
            if (nextRoles.admins.some((admin) => !counts.has(encodeBase64Url(admin)))) {
                return false;
            }
            const currentAdmins = new Map(
                currentRoles.admins.map((admin) => [encodeBase64Url(admin), admin]),
            );
            const nextAdmins = new Map(
                nextRoles.admins.map((admin) => [encodeBase64Url(admin), admin]),
            );
            const granted = [...nextAdmins].filter(([key]) => !currentAdmins.has(key));
            const revoked = [...currentAdmins].filter(([key]) => !nextAdmins.has(key));
            if (
                granted.length > 0 &&
                !equalBytes(senderAccount, currentRoles.owner) &&
                !(senderAdmin && currentRoles.adminsAssignAdmins)
            ) {
                return false;
            }
            if (
                revoked.some(
                    ([key]) =>
                        !equalBytes(senderAccount, currentRoles.owner) &&
                        !(
                            removedAccounts.has(key) &&
                            equalBytes(currentAdmins.get(key)!, senderAccount)
                        ),
                )
            ) {
                return false;
            }
            if (
                (currentRoles.adminsAssignAdmins !== nextRoles.adminsAssignAdmins ||
                    currentRoles.anyoneCanAddMembers !== nextRoles.anyoneCanAddMembers ||
                    currentRoles.sendPolicy !== nextRoles.sendPolicy) &&
                !equalBytes(senderAccount, currentRoles.owner)
            ) {
                return false;
            }
            return true;
        } catch {
            return false;
        }
    }

    async #prepareCommit(
        ctx: Context,
        id: Uint8Array,
        additions: readonly PreparedAddition[],
        removals: readonly Uint8Array[],
        roles: SessionRoles,
        operationId?: string,
        existingTransaction?: Context,
        accountConvergenceKey?: string,
    ): Promise<void> {
        const prepare = async (transaction: Context): Promise<void> => {
            const bytes = await this.#store.get(transaction, stateKey(id));
            if (bytes === undefined) throw new MurmurError("not_found", "Unknown session");
            const record = decodeSessionRecord(bytes);
            if (
                (record.status !== "active" && record.status !== "creating") ||
                record.stagedCommitId !== undefined
            ) {
                throw new MurmurError("busy", "Only an idle session may create a Commit");
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
                    additionIds.some(
                        (identity) => memberIds.has(identity) && !removalIds.includes(identity),
                    ) ||
                    removalIds.some((identity) => !memberIds.has(identity))
                ) {
                    throw new MurmurError(
                        "invalid_argument",
                        "Invalid or conflicting session membership change",
                    );
                }
                const projectedMembers = members.length + additions.length - removals.length;
                if (
                    projectedMembers < 1 ||
                    projectedMembers > this.#limits.maximumMembersPerSession
                ) {
                    throw new MurmurError(
                        "resource_exhausted",
                        "Session membership exceeds the configured limit",
                    );
                }
                const requiredOutboxes = 1 + additions.length + (additions.length > 0 ? 1 : 0);
                const outboxCount = (
                    await this.#store.scan(transaction, OUTBOX_PREFIX, {
                        limit: this.#limits.maximumOutboxes,
                    })
                ).size;
                if (outboxCount > this.#limits.maximumOutboxes - requiredOutboxes) {
                    throw new MurmurError(
                        "resource_exhausted",
                        "Local session outbox capacity exceeded",
                    );
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
                const now = this.#now();
                commitKey = epoch.exportSecret(COMMIT_EXPORT_LABEL, COMMIT_EXPORT_CONTEXT, 32);
                const nextRoles = normalizeSessionRoles(roles);
                transition = epoch.prepareCommit(
                    proposals,
                    encodeSessionControl({
                        roles: nextRoles,
                    }),
                );
                const commitMessage = decodeMlsTreeCommit(transition.commit);
                if (
                    !(await this.#validRoleCommit(
                        transaction,
                        epoch,
                        record.roles,
                        nextRoles,
                        commitMessage,
                        now,
                    ))
                ) {
                    throw new MurmurError("permission_denied", "Unauthorized session Commit");
                }
                const commitCiphertext = sealCommitCiphertext(commitKey, {
                    version: 1,
                    groupId: id,
                    epoch: epoch.context.epoch,
                    commit: transition.commit,
                    roles: nextRoles,
                });
                if (commitCiphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
                    throw new MurmurError(
                        "resource_exhausted",
                        "Session Commit exceeds the configured ciphertext limit",
                    );
                }
                stagedCheckpoint = transition.transition.serialize();
                const preview = MlsEpochState.deserialize(stagedCheckpoint, {
                    localSigningSecretKey: this.#identity.secretKey,
                    authenticateCredential: authenticateMurmurMlsCredential,
                    minimumPersistenceGeneration: 0n,
                });
                let nextMembers: readonly Uint8Array[];
                let nextAccounts: readonly Uint8Array[];
                try {
                    nextMembers = activeMembers(preview).map((member) => member.slice());
                    nextAccounts = activeAccounts(preview).map((account) => account.slice());
                } finally {
                    preview.destroy();
                }
                const changes = [
                    ...additions.map((addition) => ({
                        type: "add" as const,
                        accountKey: keyPackageAccount(addition.keyPackage),
                        deviceKey: addition.identity,
                    })),
                    ...removals.map((device) => ({
                        type: "remove" as const,
                        accountKey: memberAccount(epoch, memberLeaf(epoch, device)),
                        deviceKey: device,
                    })),
                ];
                const sessionControl: DeliverySessionControl =
                    record.status === "creating"
                        ? {
                              version: 1,
                              type: "create",
                              epoch: epoch.context.epoch,
                              members: nextAccounts,
                              roles: deliverySessionRoles(nextRoles),
                              coveredDevices: nextMembers,
                          }
                        : {
                              version: 1,
                              type: "commit",
                              epoch: epoch.context.epoch,
                              members: nextAccounts,
                              roles: deliverySessionRoles(nextRoles),
                              changes,
                              coveredDevices: nextMembers,
                          };
                const delivery = createSignedDelivery(this.#identity, [], commitCiphertext, {
                    createdAt: now,
                    expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                    senderAccount: this.#accountKey,
                    ownerAccount: nextRoles.owner,
                    sessionId: id,
                    sessionControl,
                });
                const commitOrder = await this.#nextOutboxOrder(transaction);
                await setAndZero(
                    this.#store,
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
                        roles: nextRoles,
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
                                    senderAccount: this.#accountKey,
                                    ownerAccount: nextRoles.owner,
                                    sessionId: id,
                                },
                            );
                            const bootstrapOrder = await this.#nextOutboxOrder(transaction);
                            await setAndZero(
                                this.#store,
                                transaction,
                                outboxKey(welcomeDelivery.id),
                                encodeOutboxRecord({
                                    version: 2,
                                    kind: "bootstrap",
                                    order: bootstrapOrder,
                                    operationId: operationId ?? delivery.id,
                                    sessionId: id,
                                    delivery: welcomeDelivery,
                                    parentCommitId: delivery.id,
                                }),
                            );
                            await this.#store.set(
                                transaction,
                                outboxOrderKey(bootstrapOrder, welcomeDelivery.id),
                                new Uint8Array(),
                            );
                            await this.#store.set(
                                transaction,
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
                    this.#store,
                    transaction,
                    outboxKey(delivery.id),
                    encodeOutboxRecord({
                        version: 2,
                        kind: "commit",
                        order: commitOrder,
                        operationId: operationId ?? delivery.id,
                        sessionId: id,
                        delivery,
                        stagedEpoch: stagedCheckpoint,
                        retainPreviousEpoch: removals.length === 0,
                        bootstrapDeliveryIds,
                        roles: nextRoles,
                        ...(accountConvergenceKey === undefined ? {} : { accountConvergenceKey }),
                    }),
                );
                await this.#store.set(
                    transaction,
                    outboxOrderKey(commitOrder, delivery.id),
                    new Uint8Array(),
                );
                await this.#attachCoverageBlockedOutboxes(transaction, id, delivery.id);
                if (additions.length > 0) {
                    await this.#queuePrivate(
                        transaction,
                        id,
                        { version: 1, type: "welcome_complete" },
                        "application",
                        transaction,
                    );
                }
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
            await this.#store.tx(ctx, prepare);
        } else {
            await prepare(existingTransaction);
        }
    }

    async #receive(transaction: Context, queued: InboxDelivery): Promise<void> {
        if (queued.delivery.ciphertext.length > this.#limits.maximumDeliveryCiphertextBytes) {
            throw new TerminalInboxDeliveryError("session_ciphertext_too_large");
        }
        await this.#store.set(
            transaction,
            accountDeviceActivityKey(queued.delivery.sender),
            utf8Encode(String(queued.delivery.createdAt).padStart(16, "0")),
        );
        try {
            const reference = decodeDirectorySpentNotification(queued.delivery.ciphertext);
            if (!equalBytes(queued.delivery.sender, this.#identity.publicKey)) {
                throw new TerminalInboxDeliveryError("foreign_spent_prekey_notification");
            }
            const metadata = await this.#store.get(
                transaction,
                `${DIRECTORY_ONE_TIME_PREFIX}${encodeBase64Url(reference)}`,
            );
            if (metadata === undefined) {
                throw new TerminalInboxDeliveryError("unknown_spent_prekey");
            }
            zeroBytes(metadata);
            await this.#store.set(
                transaction,
                `${DIRECTORY_SPENT_PREFIX}${encodeBase64Url(reference)}`,
                utf8Encode("pending"),
            );
            return;
        } catch (error: unknown) {
            if (error instanceof TerminalInboxDeliveryError) throw error;
        }
        try {
            decodeDeviceRosterMutation(queued.delivery.ciphertext);
            if (!equalBytes(queued.delivery.sender, this.#accountKey)) {
                throw new TerminalInboxDeliveryError("foreign_roster_mutation");
            }
            return;
        } catch (error: unknown) {
            if (error instanceof TerminalInboxDeliveryError) throw error;
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
        const ownOutboxBytes = await this.#store.get(transaction, outboxKey(queued.delivery.id));
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
        const stateBytes = await this.#store.get(transaction, stateKey(id));
        if (stateBytes === undefined) {
            const visible = queued.delivery.sessionControl;
            if (
                wire.kind !== "commit" ||
                visible === null ||
                (visible.type !== "create" && visible.type !== "commit") ||
                visible.epoch !== wire.epoch ||
                queued.delivery.sessionId === null ||
                !equalBytes(queued.delivery.sessionId, wire.groupId) ||
                queued.delivery.ownerAccount === null ||
                !equalBytes(queued.delivery.ownerAccount, visible.roles.owner)
            ) {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "visible_session_metadata_mismatch",
                    id,
                    "commit",
                );
                return;
            }
            const controlKey = pendingMembershipControlKey(id);
            const existing = await this.#store.get(transaction, controlKey);
            if (existing === undefined) {
                const controls = await this.#store.scan(
                    transaction,
                    PENDING_MEMBERSHIP_CONTROL_PREFIX,
                    {
                        limit: this.#limits.maximumPendingSessions,
                    },
                );
                try {
                    if (controls.size >= this.#limits.maximumPendingSessions) {
                        await this.#quarantine(
                            transaction,
                            queued.eventId,
                            "pending_session_capacity",
                            id,
                            "session",
                        );
                        return;
                    }
                } finally {
                    for (const value of controls.values()) zeroBytes(value);
                }
            } else {
                zeroBytes(existing);
            }
            await setAndZero(
                this.#store,
                transaction,
                controlKey,
                canonicalJsonBytes(signedDeliveryToJson(queued.delivery) as never),
            );
            return;
        }
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
        transaction: Context,
        queued: InboxDelivery,
        box: Parameters<typeof openBox>[1],
    ): Promise<void> {
        if (
            queued.delivery.sessionControl !== null ||
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
        let frame: ReturnType<typeof decodeBootstrapFrame> | undefined;
        try {
            let commit: ReturnType<typeof decodeMlsTreeCommit>;
            try {
                frame = decodeBootstrapFrame(plaintext);
                commit = decodeMlsTreeCommit(frame.commit);
            } catch {
                throw new TerminalInboxDeliveryError("malformed_bootstrap");
            }
            const rejection = await this.#store.get(transaction, rejectedKey(frame.groupId));
            const rejected = rejection !== undefined;
            if (rejection !== undefined) zeroBytes(rejection);
            if (!equalBytes(frame.inviter, queued.delivery.sender) || rejected) {
                throw new TerminalInboxDeliveryError("rejected_bootstrap");
            }
            const existingState = await this.#store.get(transaction, stateKey(frame.groupId));
            if (existingState !== undefined) {
                zeroBytes(existingState);
                return;
            }
            const pending = await this.#store.scan(transaction, PENDING_SESSION_PREFIX, {
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
            const bundleBytes = await this.#store.get(
                transaction,
                keyPackageKey(frame.keyPackageReference),
            );
            if (bundleBytes === undefined) {
                throw new TerminalInboxDeliveryError("unknown_key_package");
            }
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
                const control = decodeSessionControl(commit.authenticatedData);
                if (
                    !equalBytes(commit.confirmationTag, frame.confirmationTag) ||
                    !sessionRolesEqual(control.roles, frame.roles)
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
                if (activeMembers(epoch).length > this.#limits.maximumMembersPerSession) {
                    throw new Error("Bootstrap exceeds the configured member limit");
                }
                const accounts = activeAccounts(epoch);
                const frameRoles = frame.roles;
                if (
                    !accounts.some((account) => equalBytes(account, frameRoles.owner)) ||
                    frameRoles.admins.some(
                        (admin) => !accounts.some((account) => equalBytes(account, admin)),
                    )
                ) {
                    throw new Error("Bootstrap roles name absent accounts");
                }
                const senderAccount = memberAccount(epoch, commit.sender);
                const addedAccounts = new Map<string, number>();
                for (const proposal of commit.proposals) {
                    if (proposal.type !== "add") continue;
                    const account = encodeBase64Url(keyPackageAccount(proposal.keyPackage));
                    addedAccounts.set(account, (addedAccounts.get(account) ?? 0) + 1);
                }
                const postCommitAccounts = new Map<string, number>();
                for (let leaf = 0; leaf < epoch.memberSignatureKeys.length; leaf += 1) {
                    if (epoch.memberSignatureKeys[leaf] === undefined) continue;
                    const account = encodeBase64Url(memberAccount(epoch, leaf));
                    postCommitAccounts.set(account, (postCommitAccounts.get(account) ?? 0) + 1);
                }
                const introducesAccount = [...addedAccounts].some(
                    ([account, additions]) => (postCommitAccounts.get(account) ?? 0) <= additions,
                );
                if (
                    !isSessionAdmin(frame.roles, senderAccount) &&
                    !frame.roles.anyoneCanAddMembers &&
                    introducesAccount
                ) {
                    throw new Error("Bootstrap sender may not add a member");
                }
                const visibleBytes = await this.#store.get(
                    transaction,
                    pendingMembershipControlKey(frame.groupId),
                );
                let visibleMatches = false;
                if (visibleBytes !== undefined) {
                    try {
                        const membershipDelivery = parseSignedDelivery(
                            JSON.parse(utf8Decode(visibleBytes)) as unknown,
                        );
                        const visible = membershipDelivery.sessionControl;
                        visibleMatches =
                            verifySignedDelivery(membershipDelivery) &&
                            visible !== null &&
                            (visible.type === "create" || visible.type === "commit") &&
                            visible.epoch + 1n === epoch.context.epoch &&
                            membershipDelivery.sessionId !== null &&
                            equalBytes(membershipDelivery.sessionId, frame.groupId) &&
                            membershipDelivery.ownerAccount !== null &&
                            equalBytes(membershipDelivery.ownerAccount, frame.roles.owner) &&
                            equalBytes(membershipDelivery.sender, frame.inviter) &&
                            equalBytes(membershipDelivery.senderAccount, senderAccount) &&
                            queued.delivery.sessionId !== null &&
                            equalBytes(queued.delivery.sessionId, frame.groupId) &&
                            queued.delivery.ownerAccount !== null &&
                            equalBytes(queued.delivery.ownerAccount, frame.roles.owner) &&
                            equalBytes(queued.delivery.senderAccount, senderAccount) &&
                            deliverySessionRolesEqual(visible.roles, frame.roles) &&
                            sameIdentitySet(visible.members, accounts) &&
                            sameIdentitySet(visible.coveredDevices, activeMembers(epoch));
                    } catch {
                        visibleMatches = false;
                    } finally {
                        zeroBytes(visibleBytes);
                    }
                }
                if (!visibleMatches) {
                    await this.#store.delete(
                        transaction,
                        pendingMembershipControlKey(frame.groupId),
                    );
                    await this.#quarantine(
                        transaction,
                        queued.eventId,
                        "visible_session_metadata_mismatch",
                        frame.groupId,
                        "bootstrap",
                    );
                    return;
                }
                await this.#store.delete(transaction, pendingMembershipControlKey(frame.groupId));
                protocolComplete = true;
                checkpoint = epoch.serialize();
                const reAdmissionKey = `${RESET_READMISSION_PREFIX}${sessionId(frame.groupId)}`;
                const reAdmissionDescriptor = await this.#store.get(transaction, reAdmissionKey);
                const reAdmission =
                    reAdmissionDescriptor !== undefined &&
                    equalBytes(reAdmissionDescriptor, frame.descriptor);
                if (reAdmissionDescriptor !== undefined) zeroBytes(reAdmissionDescriptor);
                if (reAdmission) await this.#store.delete(transaction, reAdmissionKey);
                const pendingRecord: SessionRecord = {
                    version: 2,
                    status: "pending",
                    descriptor: frame.descriptor,
                    epoch: checkpoint,
                    generation: epoch.persistenceGeneration,
                    bufferedEvents: 0,
                    bufferedBytes: 0,
                    roles: frame.roles,
                    removalGenerations: [],
                    bootstrapKeyPackageReference: frame.keyPackageReference,
                    ...(reAdmission ? { reAdmission: true } : {}),
                };
                await setAndZero(
                    this.#store,
                    transaction,
                    stateKey(frame.groupId),
                    encodeSessionRecord(pendingRecord),
                );
                await setAndZero(
                    this.#store,
                    transaction,
                    admissionBarrierKey(frame.groupId),
                    encodeAdmissionBarrier(frame.inviter),
                );
                await this.#store.set(transaction, pendingKey(frame.groupId), new Uint8Array());
                await setAndZero(
                    this.#store,
                    transaction,
                    routingMarkerKey(queued.eventId),
                    encodeSessionRouting({ version: 1, sessionId: frame.groupId }),
                );
                await this.#recordSessionChanged(
                    transaction,
                    queued.eventId,
                    frame.groupId,
                    pendingRecord,
                    accounts,
                    "active",
                );
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
        transaction: Context,
        queued: InboxDelivery,
        outbox: SessionOutboxRecord,
    ): Promise<void> {
        const stateBytes = await this.#store.get(transaction, stateKey(outbox.sessionId));
        if (stateBytes === undefined) throw new TerminalInboxDeliveryError("unknown_session");
        const record = decodeSessionRecord(stateBytes);
        try {
            if (outbox.kind === "commit") {
                if (
                    outbox.stagedEpoch === undefined ||
                    outbox.roles === undefined ||
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
                    const nextAccounts = new Set(activeAccounts(next).map(encodeBase64Url));
                    const current = restoreEpoch(this.#identity, record);
                    let removedAccounts: readonly Uint8Array[];
                    try {
                        removedAccounts = activeAccounts(current).filter(
                            (account) => !nextAccounts.has(encodeBase64Url(account)),
                        );
                    } finally {
                        current.destroy();
                    }
                    const {
                        stagedCommitId: _stagedCommitId,
                        previousEpoch: _previousEpoch,
                        previousGeneration: _previousGeneration,
                        previousEpochExpiresAt: _previousEpochExpiresAt,
                        previousMessagesRemaining: _previousMessagesRemaining,
                        previousRoles: _previousRoles,
                        ...settled
                    } = record;
                    checkpoint = next.serialize();
                    const nextRecord: SessionRecord = {
                        ...settled,
                        status: record.status === "creating" ? "active" : record.status,
                        roles: outbox.roles,
                        removalGenerations: incrementRemovalGenerations(record, removedAccounts),
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
                                  previousRoles: record.roles,
                              }
                            : {}),
                    };
                    await setAndZero(
                        this.#store,
                        transaction,
                        stateKey(outbox.sessionId),
                        encodeSessionRecord(nextRecord),
                    );
                    if (nextRecord.status === "active") {
                        await this.#recordSessionChanged(
                            transaction,
                            queued.eventId,
                            outbox.sessionId,
                            nextRecord,
                            activeAccounts(next),
                            "active",
                        );
                    }
                    await this.#store.delete(transaction, intentKey(outbox.operationId));
                    if (outbox.accountConvergenceKey !== undefined) {
                        await this.#store.set(
                            transaction,
                            accountConvergenceCompletionKey(
                                outbox.accountConvergenceKey,
                                outbox.sessionId,
                            ),
                            new Uint8Array(),
                        );
                    }
                    if ((outbox.bootstrapDeliveryIds?.length ?? 0) > 0) {
                        await setAndZero(
                            this.#store,
                            transaction,
                            admissionBarrierKey(outbox.sessionId),
                            encodeAdmissionBarrier(this.#identity.publicKey),
                        );
                    }
                    await this.#activateBootstrapOutboxes(
                        transaction,
                        queued.delivery.id,
                        outbox.sessionId,
                        outbox.bootstrapDeliveryIds,
                    );
                } finally {
                    next.destroy();
                    zeroBytes(outbox.stagedEpoch);
                    if (checkpoint !== undefined) zeroBytes(checkpoint);
                }
            } else if (outbox.kind === "application") {
                const frame = decodePrivateFrame(outbox.applicationData!);
                if (frame.type === "application") {
                    try {
                        await this.#buffer(
                            transaction,
                            outbox.sessionId,
                            record,
                            queued.eventId,
                            this.#accountKey,
                            frame.bytes,
                        );
                    } finally {
                        zeroBytes(frame.bytes);
                    }
                } else if (frame.type === "welcome_complete") {
                    await this.#completeAdmissionBarrier(
                        transaction,
                        outbox.sessionId,
                        this.#identity.publicKey,
                    );
                }
            }
            await this.#store.delete(transaction, outboxKey(queued.delivery.id));
            await this.#store.delete(transaction, outboxOrderKey(outbox.order, queued.delivery.id));
            if (outbox.kind === "application") {
                await this.#store.delete(
                    transaction,
                    epochOutboxIndexKey(outbox.sessionId, queued.delivery.id),
                );
                if (outbox.parentCommitId !== undefined) {
                    await this.#store.delete(
                        transaction,
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
        transaction: Context,
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
                        previousRoles: _previousRoles,
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
                    this.#store,
                    transaction,
                    stateKey(epoch.groupId),
                    encodeSessionRecord(updated),
                );
                const senderDevice = epoch.memberSignatureKeys[opened.message.sender];
                if (
                    senderDevice === undefined ||
                    !equalBytes(senderDevice, queued.delivery.sender)
                ) {
                    await this.#quarantine(transaction, queued.eventId, "sender_binding");
                    return;
                }
                const senderAccount = memberAccount(epoch, opened.message.sender);
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
                const visible = queued.delivery.sessionControl;
                const expectedContent = frame.type === "application" ? "application" : "protocol";
                if (
                    frame.type !== "delete" &&
                    (visible === null ||
                        visible.type !== "message" ||
                        visible.epoch !== epoch.context.epoch ||
                        visible.content !== expectedContent ||
                        queued.delivery.sessionId === null ||
                        !equalBytes(queued.delivery.sessionId, epoch.groupId) ||
                        queued.delivery.ownerAccount === null ||
                        !equalBytes(
                            queued.delivery.ownerAccount,
                            epoch === current ? record.roles.owner : record.previousRoles!.owner,
                        ) ||
                        !equalBytes(queued.delivery.senderAccount, senderAccount) ||
                        !sameIdentitySet(visible.coveredDevices, activeMembers(epoch)))
                ) {
                    await this.#quarantine(
                        transaction,
                        queued.eventId,
                        "visible_session_metadata_mismatch",
                        epoch.groupId,
                        frame.type === "application" ? "application" : "session",
                    );
                    if (frame.type === "application") zeroBytes(frame.bytes);
                    return;
                }
                if (frame.type === "application") {
                    const epochRoles = epoch === current ? record.roles : record.previousRoles!;
                    if (
                        (epoch !== current &&
                            !activeAccounts(current).some((account) =>
                                equalBytes(account, senderAccount),
                            )) ||
                        (epochRoles.sendPolicy === "admins" &&
                            !isSessionAdmin(epochRoles, senderAccount))
                    ) {
                        await this.#quarantine(
                            transaction,
                            queued.eventId,
                            "unauthorized_application_sender",
                            epoch.groupId,
                            "application",
                        );
                        return;
                    }
                    try {
                        await this.#buffer(
                            transaction,
                            epoch.groupId,
                            record,
                            queued.eventId,
                            senderAccount,
                            frame.bytes,
                        );
                    } finally {
                        zeroBytes(frame.bytes);
                    }
                } else if (frame.type === "delete") {
                    if (visible !== null) {
                        await this.#quarantine(
                            transaction,
                            queued.eventId,
                            "visible_session_metadata_mismatch",
                            epoch.groupId,
                            "session",
                        );
                        return;
                    }
                    const epochRoles = epoch === current ? record.roles : record.previousRoles!;
                    if (!equalBytes(senderAccount, epochRoles.owner)) {
                        await this.#quarantine(
                            transaction,
                            queued.eventId,
                            "unauthorized_session_deletion",
                            epoch.groupId,
                            "session",
                        );
                        return;
                    }
                    const owner = await this.#sessionOwner(transaction, epoch.groupId);
                    if (owner?.owner === "service") {
                        await setAndZero(
                            this.#store,
                            transaction,
                            sessionDeletedEventKey(queued.delivery.id),
                            encodeSessionDeletedEvent({
                                version: 1,
                                id: queued.delivery.id,
                                sessionId: epoch.groupId,
                                owner: epochRoles.owner,
                                serviceId: owner.serviceId,
                            }),
                        );
                    }
                    await this.#deleteSession(transaction, epoch.groupId);
                } else if (frame.type === "leave") {
                    const account = memberAccount(epoch, opened.message.sender);
                    if (
                        !equalBytes(account, record.roles.owner) &&
                        !equalBytes(account, this.#accountKey) &&
                        isSessionAdmin(record.roles, this.#accountKey)
                    ) {
                        await this.#queueSessionIntent(transaction, {
                            version: 1,
                            kind: "remove",
                            sessionId: epoch.groupId,
                            account,
                        });
                    }
                } else if (frame.type === "welcome_complete") {
                    await this.#completeAdmissionBarrier(transaction, epoch.groupId, senderDevice);
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
        transaction: Context,
        queued: InboxDelivery,
        record: SessionRecord,
        wire: Extract<ReturnType<typeof parseSessionCiphertext>, { kind: "commit" }>,
    ): Promise<void> {
        const epoch = restoreEpoch(this.#identity, record);
        let key: Uint8Array | undefined;
        let frame: ReturnType<typeof openCommitCiphertext> | undefined;
        let expectedMembers: readonly Uint8Array[] | undefined;
        try {
            if (wire.epoch !== epoch.context.epoch) {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "stale_commit_epoch",
                    wire.groupId,
                    "commit",
                );
                return;
            }
            key = epoch.exportSecret(COMMIT_EXPORT_LABEL, COMMIT_EXPORT_CONTEXT, 32);
            let commit: ReturnType<typeof decodeMlsTreeCommit>;
            try {
                frame = openCommitCiphertext(key, wire);
                commit = decodeMlsTreeCommit(frame.commit);
            } catch {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "invalid_commit_ciphertext",
                    wire.groupId,
                    "commit",
                );
                return;
            }
            const expectedSender = epoch.memberSignatureKeys[commit.sender];
            const expectedSenderAccount =
                expectedSender === undefined ? undefined : memberAccount(epoch, commit.sender);
            const visible = queued.delivery.sessionControl;
            let controlMatches = false;
            try {
                const control = decodeSessionControl(commit.authenticatedData);
                controlMatches = sessionRolesEqual(control.roles, frame.roles);
            } catch {
                controlMatches = false;
            }
            if (
                expectedSender === undefined ||
                expectedSenderAccount === undefined ||
                !equalBytes(expectedSender, queued.delivery.sender) ||
                !equalBytes(expectedSenderAccount, queued.delivery.senderAccount) ||
                visible === null ||
                visible.type !== "commit" ||
                visible.epoch !== wire.epoch ||
                queued.delivery.sessionId === null ||
                !equalBytes(queued.delivery.sessionId, wire.groupId) ||
                queued.delivery.ownerAccount === null ||
                !equalBytes(queued.delivery.ownerAccount, record.roles.owner) ||
                !controlMatches ||
                !(await this.#validRoleCommit(
                    transaction,
                    epoch,
                    record.roles,
                    frame.roles,
                    commit,
                    queued.delivery.createdAt,
                ))
            ) {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "unauthorized_commit",
                    wire.groupId,
                    "commit",
                );
                return;
            }
            const currentAccounts = activeAccounts(epoch).map((account) => account.slice());
            const changes = commit.proposals.map((proposal) =>
                proposal.type === "add"
                    ? {
                          type: "add" as const,
                          accountKey: keyPackageAccount(proposal.keyPackage),
                          deviceKey: proposal.keyPackage.leafNode.signatureKey,
                      }
                    : {
                          type: "remove" as const,
                          accountKey: memberAccount(epoch, proposal.removed),
                          deviceKey: epoch.memberSignatureKeys[proposal.removed]!,
                      },
            );
            const projectedMembers =
                activeMembers(epoch).length +
                commit.proposals.reduce(
                    (total, proposal) => total + (proposal.type === "add" ? 1 : -1),
                    0,
                );
            if (projectedMembers < 1 || projectedMembers > this.#limits.maximumMembersPerSession) {
                await this.#quarantine(
                    transaction,
                    queued.eventId,
                    "session_member_capacity",
                    wire.groupId,
                    "commit",
                );
                return;
            }
            expectedMembers = sessionMembersAfterCommit(epoch, commit.proposals);
            let transition: ReturnType<MlsEpochState["applyCommit"]>;
            try {
                try {
                    transition = epoch.applyCommit(frame.commit);
                } catch (error: unknown) {
                    if (error instanceof MlsLocalMemberRemovedError) throw error;
                    await this.#quarantine(
                        transaction,
                        queued.eventId,
                        "invalid_mls_commit",
                        wire.groupId,
                        "commit",
                    );
                    return;
                }
                if (transition.sender !== commit.sender) {
                    transition.cancel();
                    await this.#quarantine(
                        transaction,
                        queued.eventId,
                        "commit_sender",
                        wire.groupId,
                        "commit",
                    );
                    return;
                }
            } catch (error: unknown) {
                if (error instanceof MlsLocalMemberRemovedError) {
                    const owner = await this.#sessionOwner(transaction, frame.groupId);
                    if (owner?.owner === "service" || owner?.owner === "account") {
                        await this.#store.set(
                            transaction,
                            sessionRetainedDescriptorKey(frame.groupId),
                            record.descriptor,
                        );
                        await this.#deleteSession(transaction, frame.groupId, true);
                        await this.#recordSessionChanged(
                            transaction,
                            queued.eventId,
                            frame.groupId,
                            { ...record, roles: frame.roles },
                            expectedMembers!,
                            "removed",
                            owner.owner === "service" ? owner.serviceId : undefined,
                        );
                    } else {
                        await this.#deleteSession(transaction, frame.groupId);
                    }
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
                        visible === null ||
                        visible.type !== "commit" ||
                        !deliverySessionRolesEqual(visible.roles, frame.roles) ||
                        !sameIdentitySet(visible.members, activeAccounts(next)) ||
                        !sameIdentitySet(visible.coveredDevices, activeMembers(next)) ||
                        !sessionChangesEqual(visible.changes, changes)
                    ) {
                        await this.#quarantine(
                            transaction,
                            queued.eventId,
                            "visible_session_metadata_mismatch",
                            wire.groupId,
                            "commit",
                        );
                        return;
                    }
                    const nextAccounts = new Set(activeAccounts(next).map(encodeBase64Url));
                    const removedAccounts = currentAccounts.filter(
                        (account) => !nextAccounts.has(encodeBase64Url(account)),
                    );
                    if (record.stagedCommitId !== undefined) {
                        await this.#cancelLosingCommitAndReencrypt(
                            transaction,
                            record.stagedCommitId,
                            wire.groupId,
                            next,
                        );
                    }
                    const {
                        stagedCommitId: _stagedCommitId,
                        previousEpoch: _previousEpoch,
                        previousGeneration: _previousGeneration,
                        previousEpochExpiresAt: _previousEpochExpiresAt,
                        previousMessagesRemaining: _previousMessagesRemaining,
                        previousRoles: _previousRoles,
                        ...settled
                    } = record;
                    checkpoint = next.serialize();
                    const nextRecord: SessionRecord = {
                        ...settled,
                        roles: frame.roles,
                        removalGenerations: incrementRemovalGenerations(record, removedAccounts),
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
                                  previousRoles: record.roles,
                              }),
                    };
                    await setAndZero(
                        this.#store,
                        transaction,
                        stateKey(frame.groupId),
                        encodeSessionRecord(nextRecord),
                    );
                    await this.#recordSessionChanged(
                        transaction,
                        queued.eventId,
                        frame.groupId,
                        nextRecord,
                        activeAccounts(next),
                        "active",
                    );
                    if (commit.proposals.some((proposal) => proposal.type === "add")) {
                        await setAndZero(
                            this.#store,
                            transaction,
                            admissionBarrierKey(frame.groupId),
                            encodeAdmissionBarrier(queued.delivery.sender),
                        );
                    }
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
            if (expectedMembers !== undefined) {
                for (const member of expectedMembers) zeroBytes(member);
            }
            this.#zeroSessionRecord(record);
        }
    }

    async #cancelLosingCommitAndReencrypt(
        transaction: Context,
        commitId: string,
        id: Uint8Array,
        next: MlsEpochState,
    ): Promise<void> {
        const prefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [indexKey, indexValue] of page) {
                after = indexKey;
                const previousId = indexKey.slice(prefix.length);
                const bytes = await this.#store.get(transaction, outboxKey(previousId));
                if (bytes === undefined) {
                    await this.#store.delete(transaction, indexKey);
                    zeroBytes(indexValue);
                    continue;
                }
                const dependent = decodeOutboxRecord(bytes);
                try {
                    if (
                        dependent.kind !== "application" ||
                        dependent.applicationData === undefined ||
                        dependent.parentCommitId !== commitId ||
                        !equalBytes(dependent.sessionId, id)
                    ) {
                        throw new Error("Invalid losing-Commit application outbox");
                    }
                    const frame = decodePrivateFrame(dependent.applicationData);
                    try {
                        if (frame.type === "welcome_complete") {
                            await this.#store.delete(transaction, outboxKey(previousId));
                            await this.#store.delete(
                                transaction,
                                outboxOrderKey(dependent.order, dependent.delivery.id),
                            );
                            await this.#store.delete(transaction, indexKey);
                            continue;
                        }
                    } finally {
                        if (frame.type === "application") zeroBytes(frame.bytes);
                    }
                    const message = next.seal(dependent.applicationData);
                    const ciphertext = encodePrivateCiphertext(message);
                    const now = this.#now();
                    const delivery = createSignedDelivery(this.#identity, [], ciphertext, {
                        createdAt: now,
                        expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                        senderAccount: this.#accountKey,
                        ...(dependent.delivery.ownerAccount === null
                            ? {}
                            : {
                                  ownerAccount: dependent.delivery.ownerAccount,
                                  sessionId: dependent.delivery.sessionId!,
                                  sessionControl: {
                                      version: 1,
                                      type: "message",
                                      epoch: next.context.epoch,
                                      content: "application",
                                      coveredDevices: activeMembers(next),
                                  } as const,
                              }),
                    });
                    await this.#store.delete(transaction, outboxKey(previousId));
                    await this.#store.delete(
                        transaction,
                        outboxOrderKey(dependent.order, dependent.delivery.id),
                    );
                    await this.#store.delete(transaction, indexKey);
                    await setAndZero(
                        this.#store,
                        transaction,
                        outboxKey(delivery.id),
                        encodeOutboxRecord({
                            version: 2,
                            kind: "application",
                            order: dependent.order,
                            operationId: dependent.operationId,
                            sessionId: id,
                            delivery,
                            applicationData: dependent.applicationData,
                        }),
                    );
                    await this.#store.set(
                        transaction,
                        outboxOrderKey(dependent.order, delivery.id),
                        new Uint8Array(),
                    );
                    await this.#store.set(
                        transaction,
                        epochOutboxIndexKey(id, delivery.id),
                        new Uint8Array(),
                    );
                } finally {
                    if (dependent.applicationData !== undefined) {
                        zeroBytes(dependent.applicationData);
                    }
                    zeroBytes(bytes);
                    zeroBytes(indexValue);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        const commitBytes = await this.#store.get(transaction, outboxKey(commitId));
        if (commitBytes !== undefined) {
            const commitOutbox = decodeOutboxRecord(commitBytes);
            try {
                await this.#store.delete(transaction, outboxKey(commitId));
                await this.#store.delete(transaction, outboxOrderKey(commitOutbox.order, commitId));
            } finally {
                if (commitOutbox.stagedEpoch !== undefined) zeroBytes(commitOutbox.stagedEpoch);
                zeroBytes(commitBytes);
            }
        }
        const bootstrapPrefix = `${BOOTSTRAP_INDEX_PREFIX}${commitId}/`;
        const bootstraps = await this.#store.scan(transaction, bootstrapPrefix, { limit: 257 });
        for (const [indexKey, indexValue] of bootstraps) {
            const bootstrapId = indexKey.slice(bootstrapPrefix.length);
            const bytes = await this.#store.get(transaction, outboxKey(bootstrapId));
            if (bytes !== undefined) {
                const bootstrap = decodeOutboxRecord(bytes);
                await this.#store.delete(transaction, outboxOrderKey(bootstrap.order, bootstrapId));
                zeroBytes(bytes);
            }
            await this.#store.delete(transaction, outboxKey(bootstrapId));
            await this.#store.delete(transaction, indexKey);
            zeroBytes(indexValue);
        }
    }

    async #attachCoverageBlockedOutboxes(
        transaction: Context,
        id: Uint8Array,
        commitId: string,
    ): Promise<void> {
        const commitBytes = await this.#store.get(transaction, outboxKey(commitId));
        if (commitBytes === undefined) throw new Error("Missing staged coverage Commit");
        const commit = decodeOutboxRecord(commitBytes);
        if (commit.kind !== "commit" || commit.stagedEpoch === undefined) {
            zeroBytes(commitBytes);
            throw new Error("Invalid staged coverage Commit");
        }
        const epoch = MlsEpochState.deserialize(commit.stagedEpoch, {
            localSigningSecretKey: this.#identity.secretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            minimumPersistenceGeneration: 0n,
        });
        let changed = false;
        let checkpoint: Uint8Array | undefined;
        try {
            const prefix = `${EPOCH_OUTBOX_INDEX_PREFIX}${sessionId(id)}/`;
            const entries = await this.#store.scan(transaction, prefix, {
                limit: this.#limits.maximumOutboxes,
            });
            for (const [indexKey, indexValue] of entries) {
                const previousId = indexKey.slice(prefix.length);
                const bytes = await this.#store.get(transaction, outboxKey(previousId));
                if (bytes === undefined) {
                    await this.#store.delete(transaction, indexKey);
                    zeroBytes(indexValue);
                    continue;
                }
                const record = decodeOutboxRecord(bytes);
                try {
                    if (
                        record.kind !== "application" ||
                        record.coverageBlocked !== true ||
                        record.applicationData === undefined ||
                        !equalBytes(record.sessionId, id)
                    ) {
                        continue;
                    }
                    const frame = decodePrivateFrame(record.applicationData);
                    try {
                        if (frame.type !== "application") {
                            throw new Error("Only application outboxes may await epoch coverage");
                        }
                    } finally {
                        if (frame.type === "application") zeroBytes(frame.bytes);
                    }
                    const ciphertext = encodePrivateCiphertext(epoch.seal(record.applicationData));
                    const now = this.#now();
                    const delivery = createSignedDelivery(this.#identity, [], ciphertext, {
                        createdAt: now,
                        expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                        senderAccount: this.#accountKey,
                        ownerAccount: record.delivery.ownerAccount!,
                        sessionId: id,
                        sessionControl: {
                            version: 1,
                            type: "message",
                            epoch: epoch.context.epoch,
                            content: "application",
                            coveredDevices: activeMembers(epoch),
                        },
                    });
                    const {
                        coverageBlocked: _coverageBlocked,
                        parentCommitId: _parentCommitId,
                        ...rest
                    } = record;
                    await this.#store.delete(transaction, outboxKey(previousId));
                    await this.#store.delete(transaction, outboxOrderKey(record.order, previousId));
                    await this.#store.delete(transaction, indexKey);
                    await setAndZero(
                        this.#store,
                        transaction,
                        outboxKey(delivery.id),
                        encodeOutboxRecord({ ...rest, delivery, parentCommitId: commitId }),
                    );
                    await this.#store.set(
                        transaction,
                        outboxOrderKey(record.order, delivery.id),
                        new Uint8Array(),
                    );
                    await this.#store.set(
                        transaction,
                        postCommitOutboxIndexKey(commitId, delivery.id),
                        new Uint8Array(),
                    );
                    changed = true;
                } finally {
                    if (record.applicationData !== undefined) zeroBytes(record.applicationData);
                    zeroBytes(bytes);
                    zeroBytes(indexValue);
                }
            }
            if (changed) {
                checkpoint = epoch.serialize();
                await setAndZero(
                    this.#store,
                    transaction,
                    outboxKey(commitId),
                    encodeOutboxRecord({ ...commit, stagedEpoch: checkpoint }),
                );
            }
        } finally {
            epoch.destroy();
            zeroBytes(commit.stagedEpoch);
            zeroBytes(commitBytes);
            if (checkpoint !== undefined) zeroBytes(checkpoint);
        }
    }

    async #sessionOwner(
        transaction: Context,
        id: Uint8Array,
    ): Promise<SessionOwnerRecord | undefined> {
        const bytes = await this.#store.get(transaction, sessionOwnerKey(id));
        if (bytes === undefined) return undefined;
        try {
            return decodeSessionOwner(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #recordSessionChanged(
        transaction: Context,
        eventId: string,
        sessionIdValue: Uint8Array,
        record: SessionRecord,
        members: readonly Uint8Array[],
        status: "active" | "removed",
        serviceId?: string,
    ): Promise<void> {
        const owner =
            serviceId === undefined
                ? await this.#sessionOwner(transaction, sessionIdValue)
                : undefined;
        const resolvedServiceId =
            serviceId ?? (owner?.owner === "service" ? owner.serviceId : undefined);
        if (
            resolvedServiceId === undefined &&
            owner?.owner !== "account" &&
            record.status !== "pending"
        ) {
            return;
        }
        if (members.length < 1 || members.length > this.#limits.maximumMembersPerSession) {
            await this.#quarantine(
                transaction,
                eventId,
                "session_changed_member_capacity",
                sessionIdValue,
                "session",
            );
            return;
        }
        const encoded = encodeSessionChangedEvent({
            version: 1,
            id: eventId,
            ...(resolvedServiceId === undefined ? {} : { serviceId: resolvedServiceId }),
            sessionId: sessionIdValue,
            status,
            ...(status === "removed" ? { descriptor: record.descriptor } : {}),
            members,
            roles: record.roles,
            ...(record.reAdmission === true ? { reAdmission: true } : {}),
        });
        try {
            await setAndZero(
                this.#store,
                transaction,
                sessionChangedEventKey(sessionIdValue, eventId),
                encoded,
            );
            await this.#store.set(
                transaction,
                sessionChangedEventIndexKey(eventId, sessionIdValue),
                sessionIdValue,
            );
        } finally {
            zeroBytes(encoded);
        }
    }

    async #assignSessionChangedService(
        transaction: Context,
        id: Uint8Array,
        serviceIdValue: string,
    ): Promise<void> {
        let after: string | undefined;
        const prefix = sessionChangedEventPrefix(id);
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const eventId = key.slice(prefix.length);
                let record: ReturnType<typeof decodeSessionChangedEvent> | undefined;
                try {
                    try {
                        record = decodeSessionChangedEvent(bytes);
                    } catch {
                        await this.#store.delete(transaction, key);
                        if (RELAY_EVENT_ID.test(eventId)) {
                            await this.#store.delete(
                                transaction,
                                sessionChangedEventIndexKey(eventId, id),
                            );
                        }
                        await this.#quarantine(
                            transaction,
                            RELAY_EVENT_ID.test(eventId) ? eventId : "session-change-route",
                            "corrupt_session_changed_event",
                            id,
                            "session",
                        );
                        continue;
                    }
                    if (record.serviceId !== undefined && record.serviceId !== serviceIdValue) {
                        throw new Error("Pending session lifecycle owner changed");
                    }
                    if (record.serviceId === undefined) {
                        await setAndZero(
                            this.#store,
                            transaction,
                            key,
                            encodeSessionChangedEvent({ ...record, serviceId: serviceIdValue }),
                        );
                    }
                } finally {
                    if (record !== undefined) this.#zeroSessionChangedRecord(record);
                    zeroBytes(bytes);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deleteRoutingMarkers(transaction: Context, id: Uint8Array): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, ROUTING_MARKER_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const marker = decodeSessionRouting(bytes);
                try {
                    if (equalBytes(marker.sessionId, id)) {
                        await this.#store.delete(transaction, key);
                    }
                } finally {
                    zeroBytes(marker.sessionId);
                    zeroBytes(bytes);
                }
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #activatePending(transaction: Context, id: Uint8Array): Promise<void> {
        const stateBytes = await this.#store.get(transaction, stateKey(id));
        if (stateBytes === undefined) throw new MurmurError("not_found", "Unknown session");
        const record = decodeSessionRecord(stateBytes);
        try {
            if (record.status !== "pending") {
                throw new MurmurError("invalid_state", "Session is not pending");
            }
            await this.#store.delete(transaction, pendingKey(id));
            if (record.bootstrapKeyPackageReference !== undefined) {
                const reusable = await this.#store.get(
                    transaction,
                    keyPackageReusableKey(record.bootstrapKeyPackageReference),
                );
                if (reusable === undefined) {
                    await this.#store.delete(
                        transaction,
                        keyPackageKey(record.bootstrapKeyPackageReference),
                    );
                    await this.#store.delete(
                        transaction,
                        keyPackageExpiryKey(record.bootstrapKeyPackageReference),
                    );
                    await deleteDirectoryPrekeyMarkers(
                        transaction,
                        this.#store,
                        record.bootstrapKeyPackageReference,
                    );
                } else {
                    zeroBytes(reusable);
                }
            }
            const { bootstrapKeyPackageReference: _bootstrapKeyPackageReference, ...active } =
                record;
            await setAndZero(
                this.#store,
                transaction,
                stateKey(id),
                encodeSessionRecord({ ...active, status: "active" }),
            );
        } finally {
            this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
        }
    }

    async #buffer(
        transaction: Context,
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
            this.#store,
            transaction,
            `${bufferPrefix(id)}${eventId}`,
            encodeBufferedEvent({ version: 1, sender, bytes }),
        );
        if (record.status === "active" || record.status === "pending") {
            await this.#store.set(transaction, applicationUpdateKey(eventId), id);
        }
        const latestBytes = await this.#store.get(transaction, stateKey(id));
        if (latestBytes === undefined) return;
        const latest = decodeSessionRecord(latestBytes);
        await setAndZero(
            this.#store,
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

    async #repairBufferedAccounting(transaction: Context, id: Uint8Array): Promise<void> {
        const prefix = bufferPrefix(id);
        const page = await this.#store.scan(transaction, prefix, {
            limit: this.#limits.maximumBufferedEventsPerSession + 1,
        });
        let events = 0;
        let bytesCount = 0;
        for (const [key, bytes] of page) {
            const eventId = key.slice(prefix.length);
            let buffered: ReturnType<typeof decodeBufferedEvent> | undefined;
            try {
                try {
                    buffered = decodeBufferedEvent(bytes);
                } catch {
                    await this.#store.delete(transaction, key);
                    await this.#store.delete(transaction, applicationUpdateKey(eventId));
                    await this.#store.delete(transaction, serviceUpdateDeliveredKey(eventId));
                    await this.#quarantine(
                        transaction,
                        RELAY_EVENT_ID.test(eventId) ? eventId : "application-update",
                        "corrupt_application_update",
                        id,
                        "session",
                    );
                    continue;
                }
                if (
                    events >= this.#limits.maximumBufferedEventsPerSession ||
                    bytesCount + buffered.bytes.length > this.#limits.maximumBufferedBytesPerSession
                ) {
                    await this.#store.delete(transaction, key);
                    await this.#store.delete(transaction, applicationUpdateKey(eventId));
                    await this.#store.delete(transaction, serviceUpdateDeliveredKey(eventId));
                    await this.#quarantine(
                        transaction,
                        RELAY_EVENT_ID.test(eventId) ? eventId : "application-update",
                        "active_buffer_capacity",
                        id,
                        "session",
                    );
                    continue;
                }
                events += 1;
                bytesCount += buffered.bytes.length;
            } finally {
                if (buffered !== undefined) {
                    zeroBytes(buffered.sender);
                    zeroBytes(buffered.bytes);
                }
                zeroBytes(bytes);
            }
        }
        const stateBytes = await this.#store.get(transaction, stateKey(id));
        if (stateBytes === undefined) return;
        const record = decodeSessionRecord(stateBytes);
        try {
            if (record.bufferedEvents === events && record.bufferedBytes === bytesCount) return;
            await setAndZero(
                this.#store,
                transaction,
                stateKey(id),
                encodeSessionRecord({
                    ...record,
                    bufferedEvents: events,
                    bufferedBytes: bytesCount,
                }),
            );
        } finally {
            this.#zeroSessionRecord(record);
            zeroBytes(stateBytes);
        }
    }

    async #quarantine(
        transaction: Context,
        eventId: string,
        code: string,
        session?: Uint8Array,
        kind?: MurmurSessionIssue["kind"],
        operationId?: string,
    ): Promise<void> {
        await setAndZero(
            this.#store,
            transaction,
            `${QUARANTINE_PREFIX}${eventId}`,
            encodeIssue(code, session, kind, operationId),
        );
        const entries = await this.#store.scan(transaction, QUARANTINE_PREFIX, {
            limit: MAXIMUM_REJECTED_SESSIONS + 1,
        });
        try {
            if (entries.size > MAXIMUM_REJECTED_SESSIONS) {
                const oldest = entries.keys().next().value;
                if (typeof oldest === "string") await this.#store.delete(transaction, oldest);
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
        this.#issueVersion += 1;
    }

    async #flushOutboxes(ctx: Context, signal?: AbortSignal): Promise<FlushOutboxResult> {
        const publishedIds = new Set<string>();
        const transientFailureIds = new Set<string>();
        const terminalFailureIds = await this.#preflightMembershipOutboxes(ctx);
        const phases = ["current", "commit", "bootstrap", "completion"] as const;
        for (const phase of phases) {
            const blockedSessions = new Set<string>();
            let after: string | undefined;
            for (;;) {
                const page = await this.#store.scan(ctx, OUTBOX_ORDER_PREFIX, {
                    ...(after === undefined ? {} : { after }),
                    limit: OUTBOX_SCAN_ITEMS,
                });
                if (page.size === 0) break;
                for (const [orderKey, orderValue] of page) {
                    after = orderKey;
                    const deliveryId = orderKey.slice(orderKey.lastIndexOf("/") + 1);
                    const key = outboxKey(deliveryId);
                    const bytes = await this.#store.get(ctx, key);
                    if (bytes === undefined) {
                        zeroBytes(orderValue);
                        await this.#store.delete(ctx, orderKey);
                        continue;
                    }
                    let record: SessionOutboxRecord | undefined;
                    try {
                        try {
                            record = decodeOutboxRecord(bytes);
                        } catch {
                            await this.#handleCorruptOutbox(ctx, orderKey, deliveryId);
                            terminalFailureIds.add(deliveryId);
                            continue;
                        }
                        const decodedRecord = record;
                        const welcomeComplete = this.#isWelcomeCompleteOutbox(decodedRecord);
                        const matchesPhase =
                            (phase === "bootstrap" && decodedRecord.kind === "bootstrap") ||
                            (phase === "current" &&
                                decodedRecord.kind === "application" &&
                                decodedRecord.parentCommitId === undefined &&
                                decodedRecord.coverageBlocked !== true &&
                                !welcomeComplete) ||
                            (phase === "commit" && decodedRecord.kind === "commit") ||
                            (phase === "completion" &&
                                welcomeComplete &&
                                decodedRecord.parentCommitId === undefined);
                        if (!matchesPhase) continue;
                        const encodedSessionId = sessionId(decodedRecord.sessionId);
                        if (
                            decodedRecord.kind === "application" &&
                            blockedSessions.has(encodedSessionId)
                        ) {
                            continue;
                        }
                        if (decodedRecord.kind === "commit") {
                            await this.#store.tx(ctx, (transaction) =>
                                this.#attachCoverageBlockedOutboxes(
                                    transaction,
                                    decodedRecord.sessionId,
                                    decodedRecord.delivery.id,
                                ),
                            );
                            const pendingEpoch = await this.#store.scan(
                                ctx,
                                `${EPOCH_OUTBOX_INDEX_PREFIX}${sessionId(
                                    decodedRecord.sessionId,
                                )}/`,
                                { limit: 1 },
                            );
                            if (
                                pendingEpoch.size > 0 ||
                                (await this.#admissionBarrierPending(
                                    ctx,
                                    decodedRecord.sessionId,
                                )) ||
                                (await this.#hasReadyBootstrapForSession(
                                    ctx,
                                    decodedRecord.sessionId,
                                ))
                            ) {
                                continue;
                            }
                        }
                        if (
                            decodedRecord.kind === "bootstrap" &&
                            !(await this.#bootstrapReady(ctx, decodedRecord))
                        ) {
                            continue;
                        }
                        if (decodedRecord.delivery.expiresAt <= this.#now()) {
                            if (
                                decodedRecord.kind === "commit" ||
                                decodedRecord.kind === "bootstrap"
                            ) {
                                await this.#refreshMembershipOutbox(ctx, key, decodedRecord);
                                transientFailureIds.add(decodedRecord.delivery.id);
                            } else {
                                await this.#discardTerminalOutbox(
                                    ctx,
                                    key,
                                    decodedRecord,
                                    "expired",
                                );
                                terminalFailureIds.add(decodedRecord.delivery.id);
                            }
                            continue;
                        }
                        try {
                            await this.#transport.publish(ctx, decodedRecord.delivery, signal);
                            publishedIds.add(decodedRecord.delivery.id);
                            if (decodedRecord.kind === "bootstrap") {
                                await this.#store.tx(ctx, async (transaction) => {
                                    await this.#store.delete(transaction, key);
                                    await this.#store.delete(transaction, orderKey);
                                    await this.#store.delete(
                                        transaction,
                                        bootstrapIndexKey(
                                            decodedRecord.parentCommitId!,
                                            decodedRecord.delivery.id,
                                        ),
                                    );
                                    const remaining = await this.#store.scan(
                                        transaction,
                                        `${BOOTSTRAP_INDEX_PREFIX}${decodedRecord.parentCommitId!}/`,
                                        { limit: 1 },
                                    );
                                    try {
                                        if (remaining.size === 0) {
                                            await this.#activatePostCommitOutboxes(
                                                transaction,
                                                decodedRecord.parentCommitId!,
                                                decodedRecord.sessionId,
                                            );
                                        }
                                    } finally {
                                        for (const value of remaining.values()) zeroBytes(value);
                                    }
                                });
                            }
                        } catch (error: unknown) {
                            if (error instanceof DeliveryStaleRosterError) {
                                await this.#store.tx(ctx, async (transaction) => {
                                    for (const roster of error.rosters) {
                                        const rosterBytes = serializeDeviceRoster(roster);
                                        try {
                                            await observeDeviceRoster(
                                                transaction,
                                                this.#store,
                                                this.#accountKey,
                                                `stale-${decodedRecord.delivery.id}-${encodeBase64Url(roster.accountKey)}`,
                                                rosterBytes,
                                            );
                                        } finally {
                                            zeroBytes(rosterBytes);
                                        }
                                    }
                                });
                                if (
                                    error.code === "stale_epoch_coverage" &&
                                    decodedRecord.kind === "application"
                                ) {
                                    await this.#store.tx(ctx, (transaction) =>
                                        setAndZero(
                                            this.#store,
                                            transaction,
                                            key,
                                            encodeOutboxRecord({
                                                ...decodedRecord,
                                                coverageBlocked: true,
                                            }),
                                        ),
                                    );
                                } else if (error.code === "stale_roster") {
                                    await this.#refreshStaleRosterOutbox(
                                        ctx,
                                        key,
                                        decodedRecord,
                                        error.rosters,
                                    );
                                }
                                transientFailureIds.add(decodedRecord.delivery.id);
                                blockedSessions.add(encodedSessionId);
                                continue;
                            }
                            if (
                                decodedRecord.kind === "commit" &&
                                error instanceof DeliveryTransportError &&
                                ((error.status === 409 && error.code === "stale_session_epoch") ||
                                    (error.status === 403 && error.code === "session_unauthorized"))
                            ) {
                                // The relay has already accepted a competing Commit or applied
                                // state that can invalidate this candidate. Keep the candidate and
                                // its dependent sends durable until the authenticated queue echo
                                // arrives; receiveCommit then cancels it, re-encrypts the sends,
                                // and leaves the membership intent available for re-authorization.
                                transientFailureIds.add(decodedRecord.delivery.id);
                                blockedSessions.add(encodedSessionId);
                                continue;
                            }
                            if (
                                decodedRecord.kind === "commit" ||
                                decodedRecord.kind === "bootstrap"
                            ) {
                                await this.#store.tx(ctx, (transaction) =>
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
                                await this.#discardTerminalOutbox(
                                    ctx,
                                    key,
                                    decodedRecord,
                                    error.code,
                                );
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

    #isWelcomeCompleteOutbox(record: SessionOutboxRecord): boolean {
        if (record.kind !== "application" || record.applicationData === undefined) return false;
        let frame: PrivateSessionFrame | undefined;
        try {
            frame = decodePrivateFrame(record.applicationData);
            return frame.type === "welcome_complete";
        } catch {
            return false;
        } finally {
            if (frame?.type === "application") zeroBytes(frame.bytes);
        }
    }

    async #preflightMembershipOutboxes(ctx: Context): Promise<Set<string>> {
        const terminalFailureIds = new Set<string>();
        const validCommitIds = new Set<string>();
        const corruptPrimaryIds = new Set<string>();
        let primaryAfter: string | undefined;
        for (;;) {
            const page = await this.#store.scan(ctx, OUTBOX_PREFIX, {
                ...(primaryAfter === undefined ? {} : { after: primaryAfter }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, pageBytes] of page) {
                primaryAfter = key;
                const deliveryId = key.slice(OUTBOX_PREFIX.length);
                const bytes = await this.#store.get(ctx, key);
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
                    if (await this.#validMembershipOperation(ctx, record)) {
                        validCommitIds.add(record.delivery.id);
                    } else {
                        await this.#store.tx(ctx, async (transaction) => {
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
            const bytes = await this.#store.get(ctx, outboxKey(deliveryId));
            if (bytes === undefined) continue;
            zeroBytes(bytes);
            await this.#handleCorruptOutbox(ctx, undefined, deliveryId);
            terminalFailureIds.add(deliveryId);
        }
        await this.#reconcileMissingStagedCommits(ctx, terminalFailureIds);
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(ctx, OUTBOX_ORDER_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [orderKey, orderValue] of page) {
                after = orderKey;
                const deliveryId = orderKey.slice(orderKey.lastIndexOf("/") + 1);
                const bytes = await this.#store.get(ctx, outboxKey(deliveryId));
                if (bytes === undefined) {
                    zeroBytes(orderValue);
                    await this.#store.delete(ctx, orderKey);
                    continue;
                }
                let record: SessionOutboxRecord | undefined;
                try {
                    try {
                        record = decodeOutboxRecord(bytes);
                    } catch {
                        await this.#handleCorruptOutbox(ctx, orderKey, deliveryId);
                        terminalFailureIds.add(deliveryId);
                        continue;
                    }
                    if (
                        record.kind === "commit" &&
                        !validCommitIds.has(record.delivery.id) &&
                        !(await this.#validMembershipOperation(ctx, record))
                    ) {
                        await this.#store.tx(ctx, async (transaction) => {
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
                            ctx,
                            outboxKey(record.parentCommitId!),
                        );
                        let parent: SessionOutboxRecord | undefined;
                        let valid = false;
                        if (parentBytes !== undefined) {
                            try {
                                parent = decodeOutboxRecord(parentBytes);
                                valid =
                                    parent.kind === "commit" &&
                                    (await this.#validMembershipOperation(ctx, parent));
                            } catch {
                                valid = false;
                            } finally {
                                if (parent?.stagedEpoch !== undefined) {
                                    zeroBytes(parent.stagedEpoch);
                                }
                                zeroBytes(parentBytes);
                            }
                        } else {
                            valid = await this.#validAdoptedBootstrap(ctx, record);
                        }
                        if (!valid) {
                            await this.#store.tx(ctx, async (transaction) => {
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

    async #handleCorruptOutbox(
        ctx: Context,
        orderKey: string | undefined,
        deliveryId: string,
    ): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            await this.#store.delete(transaction, outboxKey(deliveryId));
            if (orderKey !== undefined) await this.#store.delete(transaction, orderKey);
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

    async #reconcileMissingStagedCommits(
        ctx: Context,
        terminalFailureIds: Set<string>,
    ): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(ctx, SESSION_STATE_PREFIX, {
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
                        await this.#store.tx(ctx, async (transaction) => {
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
                    const commitBytes = await this.#store.get(ctx, outboxKey(stagedCommitId));
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
                        await this.#store.tx(ctx, async (transaction) => {
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
                    await this.#store.tx(ctx, async (transaction) => {
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

    async #validMembershipOperation(ctx: Context, record: SessionOutboxRecord): Promise<boolean> {
        if (record.kind !== "commit" || record.bootstrapDeliveryIds === undefined) return false;
        const stateBytes = await this.#store.get(ctx, stateKey(record.sessionId));
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
        const commitOrder = await this.#store.get(
            ctx,
            outboxOrderKey(record.order, record.delivery.id),
        );
        if (commitOrder === undefined) return false;
        zeroBytes(commitOrder);
        const expected = new Set(record.bootstrapDeliveryIds);
        const entries = await this.#store.scan(
            ctx,
            `${BOOTSTRAP_INDEX_PREFIX}${record.delivery.id}/`,
            {
                limit: 257,
            },
        );
        if (entries.size !== expected.size) {
            for (const value of entries.values()) zeroBytes(value);
            return false;
        }
        let valid = true;
        for (const [indexKey, indexValue] of entries) {
            const bootstrapId = indexKey.slice(indexKey.lastIndexOf("/") + 1);
            if (!expected.has(bootstrapId)) valid = false;
            if (indexValue.length === 0) {
                const bootstrapBytes = await this.#store.get(ctx, outboxKey(bootstrapId));
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
                            ctx,
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

    async #validAdoptedBootstrap(ctx: Context, record: SessionOutboxRecord): Promise<boolean> {
        if (record.kind !== "bootstrap" || record.parentCommitId === undefined) return false;
        const parent = await this.#store.get(ctx, outboxKey(record.parentCommitId));
        if (parent !== undefined) {
            zeroBytes(parent);
            return false;
        }
        const stateBytes = await this.#store.get(ctx, stateKey(record.sessionId));
        if (stateBytes === undefined) return false;
        let state: SessionRecord | undefined;
        try {
            state = decodeSessionRecord(stateBytes);
            if (state.status !== "active") return false;
        } catch {
            return false;
        } finally {
            if (state !== undefined) this.#zeroSessionRecord(state);
            zeroBytes(stateBytes);
        }
        const order = await this.#store.get(ctx, outboxOrderKey(record.order, record.delivery.id));
        if (order === undefined) return false;
        zeroBytes(order);
        const marker = await this.#store.get(
            ctx,
            bootstrapIndexKey(record.parentCommitId, record.delivery.id),
        );
        if (marker === undefined) return false;
        try {
            return marker.length === 1 && marker[0] === 1;
        } finally {
            zeroBytes(marker);
        }
    }

    async #bootstrapReady(ctx: Context, record: SessionOutboxRecord): Promise<boolean> {
        if (record.kind !== "bootstrap" || record.parentCommitId === undefined) return false;
        const marker = await this.#store.get(
            ctx,
            bootstrapIndexKey(record.parentCommitId, record.delivery.id),
        );
        if (marker === undefined) return false;
        try {
            return marker.length === 1 && marker[0] === 1;
        } finally {
            zeroBytes(marker);
        }
    }

    async #readyBootstrapParentForSession(
        ctx: Context,
        id: Uint8Array,
    ): Promise<string | undefined> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(ctx, BOOTSTRAP_INDEX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) return undefined;
            let matchedParent: string | undefined;
            for (const [key, marker] of page) {
                after = key;
                try {
                    if (marker.length !== 1 || marker[0] !== 1) continue;
                    const bootstrapId = key.slice(key.lastIndexOf("/") + 1);
                    const bytes = await this.#store.get(ctx, outboxKey(bootstrapId));
                    if (bytes === undefined) continue;
                    let bootstrap: SessionOutboxRecord | undefined;
                    try {
                        bootstrap = decodeOutboxRecord(bytes);
                        if (bootstrap.kind === "bootstrap" && equalBytes(bootstrap.sessionId, id)) {
                            matchedParent = bootstrap.parentCommitId;
                        }
                    } finally {
                        if (bootstrap?.stagedEpoch !== undefined) {
                            zeroBytes(bootstrap.stagedEpoch);
                        }
                        if (bootstrap?.applicationData !== undefined) {
                            zeroBytes(bootstrap.applicationData);
                        }
                        zeroBytes(bytes);
                    }
                } finally {
                    zeroBytes(marker);
                }
            }
            if (matchedParent !== undefined) return matchedParent;
            if (page.size < OUTBOX_SCAN_ITEMS) return undefined;
        }
    }

    async #hasReadyBootstrapForSession(ctx: Context, id: Uint8Array): Promise<boolean> {
        return (await this.#readyBootstrapParentForSession(ctx, id)) !== undefined;
    }

    async #admissionBarrierPending(ctx: Context, id: Uint8Array): Promise<boolean> {
        const barrier = await this.#store.get(ctx, admissionBarrierKey(id));
        if (barrier === undefined) return false;
        zeroBytes(barrier);
        return true;
    }

    async #refreshStaleRosterOutbox(
        ctx: Context,
        key: string,
        record: SessionOutboxRecord,
        rosters: readonly DeliveryDeviceRoster[],
    ): Promise<void> {
        const targets = new Map(
            record.delivery.targetAccounts.map((target) => [
                encodeBase64Url(target.accountKey),
                target,
            ]),
        );
        for (const roster of rosters) {
            const encodedAccount = encodeBase64Url(roster.accountKey);
            if (!targets.has(encodedAccount)) continue;
            targets.set(encodedAccount, {
                accountKey: roster.accountKey,
                rosterRevision: roster.revision,
            });
        }
        const recipients = new Map<string, Uint8Array>();
        let completeRosters = true;
        for (const target of targets.values()) {
            const rosterKey = equalBytes(target.accountKey, this.#accountKey)
                ? ACCOUNT_ROSTER_KEY
                : `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(target.accountKey)}`;
            const bytes = await this.#store.get(ctx, rosterKey);
            try {
                if (bytes === undefined) {
                    completeRosters = false;
                    continue;
                }
                const roster = parseDeviceRoster(bytes);
                if (
                    !equalBytes(roster.accountKey, target.accountKey) ||
                    roster.revision !== target.rosterRevision
                ) {
                    completeRosters = false;
                    continue;
                }
                for (const device of roster.devices) {
                    recipients.set(encodeBase64Url(device.deviceKey), device.deviceKey);
                }
            } finally {
                if (bytes !== undefined) zeroBytes(bytes);
            }
        }
        if (!completeRosters) {
            for (const recipient of record.delivery.recipients) {
                recipients.set(encodeBase64Url(recipient), recipient);
            }
        }
        const now = this.#now();
        const delivery = createSignedDelivery(
            this.#identity,
            [...recipients.values()],
            record.delivery.ciphertext,
            {
                createdAt: now,
                expiresAt: now + DELIVERY_TTL_MILLISECONDS,
                senderAccount: this.#accountKey,
                targetAccounts: [...targets.values()],
                ...(record.delivery.ownerAccount === null
                    ? {}
                    : {
                          ownerAccount: record.delivery.ownerAccount,
                          sessionId: record.delivery.sessionId!,
                          ...(record.delivery.sessionControl === null
                              ? {}
                              : { sessionControl: record.delivery.sessionControl }),
                      }),
            },
        );
        await this.#store.tx(ctx, async (transaction) => {
            await this.#store.delete(transaction, key);
            await this.#store.delete(transaction, outboxOrderKey(record.order, record.delivery.id));
            await setAndZero(
                this.#store,
                transaction,
                outboxKey(delivery.id),
                encodeOutboxRecord({ ...record, delivery }),
            );
            await this.#store.set(
                transaction,
                outboxOrderKey(record.order, delivery.id),
                new Uint8Array(),
            );
            if (record.kind === "application") {
                await this.#store.delete(
                    transaction,
                    epochOutboxIndexKey(record.sessionId, record.delivery.id),
                );
                if (record.parentCommitId === undefined) {
                    await this.#store.set(
                        transaction,
                        epochOutboxIndexKey(record.sessionId, delivery.id),
                        new Uint8Array(),
                    );
                } else {
                    await this.#store.delete(
                        transaction,
                        postCommitOutboxIndexKey(record.parentCommitId, record.delivery.id),
                    );
                    await this.#store.set(
                        transaction,
                        postCommitOutboxIndexKey(record.parentCommitId, delivery.id),
                        new Uint8Array(),
                    );
                }
            } else if (record.kind === "bootstrap") {
                const markerKey = bootstrapIndexKey(record.parentCommitId!, record.delivery.id);
                const marker = await this.#store.get(transaction, markerKey);
                if (marker === undefined) throw new Error("Unknown bootstrap outbox");
                try {
                    await this.#store.delete(transaction, markerKey);
                    await this.#store.set(
                        transaction,
                        bootstrapIndexKey(record.parentCommitId!, delivery.id),
                        marker,
                    );
                } finally {
                    zeroBytes(marker);
                }
            } else {
                const stateBytes = await this.#store.get(transaction, stateKey(record.sessionId));
                if (stateBytes === undefined) throw new Error("Unknown staged session");
                const session = decodeSessionRecord(stateBytes);
                try {
                    if (session.stagedCommitId !== record.delivery.id) {
                        throw new Error("Staged Commit changed while refreshing");
                    }
                    await setAndZero(
                        this.#store,
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
        });
    }

    async #refreshMembershipOutbox(
        ctx: Context,
        key: string,
        record: SessionOutboxRecord,
    ): Promise<void> {
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
                senderAccount: this.#accountKey,
                targetAccounts: record.delivery.targetAccounts,
                ...(record.delivery.ownerAccount === null
                    ? {}
                    : {
                          ownerAccount: record.delivery.ownerAccount,
                          sessionId: record.delivery.sessionId!,
                          ...(record.delivery.sessionControl === null
                              ? {}
                              : { sessionControl: record.delivery.sessionControl }),
                      }),
            },
        );
        await this.#store.tx(ctx, async (transaction) => {
            await this.#store.delete(transaction, key);
            await this.#store.delete(transaction, outboxOrderKey(record.order, record.delivery.id));
            await setAndZero(
                this.#store,
                transaction,
                outboxKey(delivery.id),
                encodeOutboxRecord({ ...record, delivery }),
            );
            await this.#store.set(
                transaction,
                outboxOrderKey(record.order, delivery.id),
                new Uint8Array(),
            );
            if (record.kind === "bootstrap") {
                const markerKey = bootstrapIndexKey(record.parentCommitId!, record.delivery.id);
                const marker = await this.#store.get(transaction, markerKey);
                if (marker === undefined || marker.length !== 1 || marker[0] !== 1) {
                    if (marker !== undefined) zeroBytes(marker);
                    throw new Error("Only an adopted bootstrap may be refreshed");
                }
                await this.#store.delete(transaction, markerKey);
                await this.#store.set(
                    transaction,
                    bootstrapIndexKey(record.parentCommitId!, delivery.id),
                    new Uint8Array([1]),
                );
                zeroBytes(marker);
            } else {
                const stateBytes = await this.#store.get(transaction, stateKey(record.sessionId));
                if (stateBytes === undefined) throw new Error("Unknown staged session");
                const session = decodeSessionRecord(stateBytes);
                try {
                    if (session.stagedCommitId !== record.delivery.id) {
                        throw new Error("Staged Commit changed while refreshing");
                    }
                    await setAndZero(
                        this.#store,
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
        ctx: Context,
        key: string,
        record: SessionOutboxRecord,
        code: string,
    ): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            await this.#store.delete(transaction, key);
            await this.#store.delete(transaction, outboxOrderKey(record.order, record.delivery.id));
            if (record.kind === "application") {
                await this.#store.delete(
                    transaction,
                    epochOutboxIndexKey(record.sessionId, record.delivery.id),
                );
                if (record.parentCommitId !== undefined) {
                    await this.#store.delete(
                        transaction,
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

    async #completeAdmissionBarrier(
        transaction: Context,
        id: Uint8Array,
        sender: Uint8Array,
    ): Promise<void> {
        const key = admissionBarrierKey(id);
        const bytes = await this.#store.get(transaction, key);
        if (bytes === undefined) {
            throw new TerminalInboxDeliveryError("unexpected_welcome_complete");
        }
        const expectedSender = decodeAdmissionBarrier(bytes);
        try {
            if (!equalBytes(expectedSender, sender)) {
                throw new TerminalInboxDeliveryError("invalid_welcome_complete");
            }
            await this.#store.delete(transaction, key);
        } finally {
            zeroBytes(expectedSender);
            zeroBytes(bytes);
        }
    }

    async #activateBootstrapOutboxes(
        transaction: Context,
        commitId: string,
        id: Uint8Array,
        bootstrapDeliveryIds: readonly string[] | undefined,
    ): Promise<void> {
        if (bootstrapDeliveryIds === undefined) {
            throw new TerminalInboxDeliveryError("invalid_commit_echo");
        }
        const expected = new Set(bootstrapDeliveryIds);
        const prefix = `${BOOTSTRAP_INDEX_PREFIX}${commitId}/`;
        const entries = await this.#store.scan(transaction, prefix, { limit: 257 });
        try {
            if (entries.size !== expected.size) {
                throw new TerminalInboxDeliveryError("invalid_commit_echo");
            }
            for (const [key, marker] of entries) {
                const bootstrapId = key.slice(prefix.length);
                if (!expected.has(bootstrapId) || marker.length !== 0) {
                    throw new TerminalInboxDeliveryError("invalid_commit_echo");
                }
                const bytes = await this.#store.get(transaction, outboxKey(bootstrapId));
                if (bytes === undefined) {
                    throw new TerminalInboxDeliveryError("invalid_commit_echo");
                }
                let bootstrap: SessionOutboxRecord | undefined;
                try {
                    bootstrap = decodeOutboxRecord(bytes);
                    if (
                        bootstrap.kind !== "bootstrap" ||
                        bootstrap.parentCommitId !== commitId ||
                        !equalBytes(bootstrap.sessionId, id)
                    ) {
                        throw new TerminalInboxDeliveryError("invalid_commit_echo");
                    }
                    await this.#store.set(transaction, key, new Uint8Array([1]));
                } finally {
                    if (bootstrap?.stagedEpoch !== undefined) {
                        zeroBytes(bootstrap.stagedEpoch);
                    }
                    if (bootstrap?.applicationData !== undefined) {
                        zeroBytes(bootstrap.applicationData);
                    }
                    zeroBytes(bytes);
                }
            }
            if (entries.size === 0) {
                await this.#activatePostCommitOutboxes(transaction, commitId, id);
            }
        } finally {
            for (const marker of entries.values()) zeroBytes(marker);
        }
    }

    async #activatePostCommitOutboxes(
        transaction: Context,
        commitId: string,
        id: Uint8Array,
    ): Promise<void> {
        const prefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(prefix.length);
                const bytes = await this.#store.get(transaction, outboxKey(deliveryId));
                if (bytes === undefined) {
                    await this.#store.delete(transaction, key);
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
                        this.#store,
                        transaction,
                        outboxKey(deliveryId),
                        encodeOutboxRecord(activated),
                    );
                    await this.#store.set(
                        transaction,
                        epochOutboxIndexKey(id, deliveryId),
                        new Uint8Array(),
                    );
                    await this.#store.delete(transaction, key);
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

    async #deleteSessionChangedEvents(transaction: Context, id: Uint8Array): Promise<void> {
        const prefix = sessionChangedEventPrefix(id);
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const eventId = key.slice(prefix.length);
                await this.#store.delete(transaction, sessionChangedEventIndexKey(eventId, id));
                zeroBytes(bytes);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        await this.#deletePrefix(transaction, prefix);
    }

    async #deleteBufferedSessionUpdates(transaction: Context, id: Uint8Array): Promise<void> {
        let bufferedAfter: string | undefined;
        const bufferedPrefix = bufferPrefix(id);
        for (;;) {
            const page = await this.#store.scan(transaction, bufferedPrefix, {
                ...(bufferedAfter === undefined ? {} : { after: bufferedAfter }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                bufferedAfter = key;
                const eventId = key.slice(bufferedPrefix.length);
                await this.#store.delete(transaction, applicationUpdateKey(eventId));
                await this.#store.delete(transaction, serviceUpdateDeliveredKey(eventId));
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
        await this.#deletePrefix(transaction, `${SESSION_DATA_PREFIX}${sessionId(id)}/`);
    }

    async #deleteSession(
        transaction: Context,
        id: Uint8Array,
        preserveApplicationDelivery = false,
    ): Promise<void> {
        if (!preserveApplicationDelivery) {
            await this.#deleteSessionChangedEvents(transaction, id);
        }
        if (!preserveApplicationDelivery) {
            await this.#deleteBufferedSessionUpdates(transaction, id);
        }
        await this.#store.delete(transaction, stateKey(id));
        await this.#store.delete(transaction, pendingKey(id));
        await this.#store.delete(transaction, pendingMembershipControlKey(id));
        await this.#store.delete(transaction, admissionBarrierKey(id));
        if (!preserveApplicationDelivery) {
            await this.#store.delete(transaction, sessionOwnerKey(id));
            await this.#store.delete(transaction, sessionRetainedDescriptorKey(id));
        }
        await this.#deleteRoutingMarkers(transaction, id);
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                const outbox = decodeOutboxRecord(bytes);
                try {
                    if (equalBytes(outbox.sessionId, id)) {
                        await this.#store.delete(transaction, key);
                        await this.#store.delete(
                            transaction,
                            outboxOrderKey(outbox.order, outbox.delivery.id),
                        );
                        if (outbox.kind === "bootstrap") {
                            await this.#store.delete(
                                transaction,
                                bootstrapIndexKey(outbox.parentCommitId!, outbox.delivery.id),
                            );
                        } else if (outbox.kind === "commit") {
                            await this.#deletePrefix(
                                transaction,
                                `${BOOTSTRAP_INDEX_PREFIX}${outbox.delivery.id}/`,
                            );
                        } else if (outbox.parentCommitId !== undefined) {
                            await this.#store.delete(
                                transaction,
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
        const intents = await this.#store.scan(transaction, SESSION_INTENT_PREFIX, {
            limit: MAXIMUM_SESSION_INTENTS,
        });
        for (const [key, bytes] of intents) {
            try {
                const intent = decodeSessionIntent(bytes);
                try {
                    if (equalBytes(intent.sessionId, id))
                        await this.#store.delete(transaction, key);
                } finally {
                    zeroBytes(intent.sessionId);
                    if (intent.kind !== "set_policies") zeroBytes(intent.account);
                    if (intent.kind === "add") zeroBytes(intent.keyPackage);
                }
            } catch {
                // Corrupt intents are reconciled by the intent convergence pass.
            } finally {
                zeroBytes(bytes);
            }
        }
    }

    async #deletePrefix(transaction: Context, prefix: string): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                await this.#store.delete(transaction, key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deleteIndexEntriesByDeliveryId(
        transaction: Context,
        prefix: string,
        deliveryId: string,
    ): Promise<void> {
        const suffix = `/${deliveryId}`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                if (key.endsWith(suffix)) {
                    await this.#store.delete(transaction, key);
                }
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #moveBootstrapIndexParent(
        transaction: Context,
        previousCommitId: string,
        nextCommitId: string,
    ): Promise<void> {
        const previousPrefix = `${BOOTSTRAP_INDEX_PREFIX}${previousCommitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, previousPrefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                const bootstrapId = key.slice(previousPrefix.length);
                if (value.length !== 0) {
                    zeroBytes(value);
                    throw new Error("An adopted bootstrap parent Commit cannot be refreshed");
                }
                const bytes = await this.#store.get(transaction, outboxKey(bootstrapId));
                if (bytes === undefined) {
                    zeroBytes(value);
                    throw new Error("Missing bootstrap while refreshing its parent Commit");
                }
                const bootstrap = decodeOutboxRecord(bytes);
                try {
                    if (
                        bootstrap.kind !== "bootstrap" ||
                        bootstrap.parentCommitId !== previousCommitId
                    ) {
                        throw new Error("Invalid bootstrap parent Commit");
                    }
                    await setAndZero(
                        this.#store,
                        transaction,
                        outboxKey(bootstrapId),
                        encodeOutboxRecord({
                            ...bootstrap,
                            parentCommitId: nextCommitId,
                        }),
                    );
                } finally {
                    if (bootstrap.stagedEpoch !== undefined) zeroBytes(bootstrap.stagedEpoch);
                    if (bootstrap.applicationData !== undefined) {
                        zeroBytes(bootstrap.applicationData);
                    }
                    zeroBytes(bytes);
                }
                await this.#store.set(
                    transaction,
                    bootstrapIndexKey(nextCommitId, bootstrapId),
                    value,
                );
                await this.#store.delete(transaction, key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #movePostCommitIndexParent(
        transaction: Context,
        previousCommitId: string,
        nextCommitId: string,
    ): Promise<void> {
        const previousPrefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${previousCommitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, previousPrefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(previousPrefix.length);
                const bytes = await this.#store.get(transaction, outboxKey(deliveryId));
                if (bytes === undefined) {
                    await this.#store.delete(transaction, key);
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
                        this.#store,
                        transaction,
                        outboxKey(deliveryId),
                        encodeOutboxRecord({
                            ...dependent,
                            parentCommitId: nextCommitId,
                        }),
                    );
                    await this.#store.set(
                        transaction,
                        postCommitOutboxIndexKey(nextCommitId, deliveryId),
                        indexValue,
                    );
                    await this.#store.delete(transaction, key);
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
        transaction: Context,
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
        transaction: Context,
        deliveryId: string,
    ): Promise<ReadonlySet<string>> {
        const parents = new Set<string>();
        const suffix = `/${deliveryId}`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, BOOTSTRAP_INDEX_PREFIX, {
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
            const page = await this.#store.scan(transaction, OUTBOX_PREFIX, {
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
        transaction: Context,
        commitId: string,
        kind: "bootstrap" | "commit",
    ): Promise<CorruptOutboxRecovery | undefined> {
        await this.#deleteMembershipOperationOutboxes(transaction, commitId);
        let matchedSessionId: Uint8Array | undefined;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, SESSION_STATE_PREFIX, {
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

        const stateBytes = await this.#store.get(transaction, stateKey(matchedSessionId));
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
                    this.#store,
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
        transaction: Context,
        id: Uint8Array,
        stagedCommitId: string,
    ): Promise<CorruptOutboxRecovery | undefined> {
        const bytes = await this.#store.get(transaction, stateKey(id));
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
                await setAndZero(
                    this.#store,
                    transaction,
                    stateKey(id),
                    encodeSessionRecord(unstaged),
                );
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
        transaction: Context,
        commitId: string,
    ): Promise<void> {
        await this.#store.delete(transaction, outboxKey(commitId));
        await this.#deleteIndexEntriesByDeliveryId(transaction, OUTBOX_ORDER_PREFIX, commitId);
        await this.#deletePostCommitOutboxes(transaction, commitId);
        const prefix = `${BOOTSTRAP_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, value] of page) {
                after = key;
                const bootstrapId = key.slice(prefix.length);
                await this.#store.delete(transaction, outboxKey(bootstrapId));
                await this.#deleteIndexEntriesByDeliveryId(
                    transaction,
                    OUTBOX_ORDER_PREFIX,
                    bootstrapId,
                );
                await this.#store.delete(transaction, key);
                zeroBytes(value);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    async #deletePostCommitOutboxes(transaction: Context, commitId: string): Promise<void> {
        const prefix = `${POST_COMMIT_OUTBOX_INDEX_PREFIX}${commitId}/`;
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(transaction, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: OUTBOX_SCAN_ITEMS,
            });
            if (page.size === 0) break;
            for (const [key, indexValue] of page) {
                after = key;
                const deliveryId = key.slice(prefix.length);
                const bytes = await this.#store.get(transaction, outboxKey(deliveryId));
                if (bytes !== undefined) {
                    let record: SessionOutboxRecord | undefined;
                    try {
                        record = decodeOutboxRecord(bytes);
                        await this.#store.delete(
                            transaction,
                            outboxOrderKey(record.order, record.delivery.id),
                        );
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
                    await this.#store.delete(transaction, outboxKey(deliveryId));
                }
                await this.#store.delete(transaction, key);
                zeroBytes(indexValue);
            }
            if (page.size < OUTBOX_SCAN_ITEMS) break;
        }
    }

    #zeroSessionRecord(record: SessionRecord): void {
        zeroBytes(record.epoch);
        if (record.previousEpoch !== undefined) zeroBytes(record.previousEpoch);
    }

    #zeroSessionChangedRecord(record: SessionChangedEventRecord): void {
        zeroBytes(record.sessionId);
        if (record.descriptor !== undefined) zeroBytes(record.descriptor);
        for (const member of record.members) zeroBytes(member);
        zeroBytes(record.roles.owner);
        for (const admin of record.roles.admins) zeroBytes(admin);
    }

    async #rejectSession(transaction: Context, id: Uint8Array): Promise<void> {
        await this.#store.delete(transaction, pendingMembershipControlKey(id));
        const key = rejectedKey(id);
        await setAndZero(
            this.#store,
            transaction,
            key,
            utf8Encode(String(this.#now()).padStart(16, "0")),
        );
        const entries = await this.#store.scan(transaction, REJECTED_PREFIX, {
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
                if (evicted !== undefined) await this.#store.delete(transaction, evicted);
            }
        } finally {
            for (const value of entries.values()) zeroBytes(value);
        }
    }
}
