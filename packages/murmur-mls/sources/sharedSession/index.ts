import {
    canonicalJsonBytes,
    createRelayEvent,
    decodeBase64Url,
    decryptFile,
    encodeBase64Url,
    encryptFile,
    equalBytes,
    hashBytes,
    identityId,
    randomBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
    type DirectChat,
    type IdentityKeyPair,
    type IdentityPublicKeys,
    type MurmurClient,
    type MurmurStore,
    type PublishResult,
    type ReceivedEvent,
    type SignedRelayEvent,
    type StoreTransaction,
} from "@slopus/murmur";
import { decodeMlsTreeCommit } from "../commit/index.js";
import { MlsEpochState } from "../epoch/index.js";
import {
    authenticateMurmurMlsCredential,
    createMlsGroup,
    joinMlsGroupFromWelcome,
} from "../group/index.js";
import {
    MlsGroupChannel,
    type PreparedMlsGroupApplication,
    type PreparedMlsGroupCommit,
} from "../groupChannel/index.js";
import { mlsKeyPackageReference, verifyMlsKeyPackage } from "../keyPackage/index.js";
import { decodeMlsPrivateMessage } from "../privateMessage/index.js";
import { decodeMlsRatchetTree, encodeMlsRatchetTree } from "../ratchetTree/index.js";
import {
    decodeDurableSharedSessionOutbox,
    decodeDurableSharedSessionRecord,
    encodeDurableSharedSessionOutbox,
    encodeDurableSharedSessionRecord,
    type DurableSharedSessionHistory,
    type DurableSharedSessionOutbox,
    type DurableSharedSessionRecord,
} from "./impl/durableCodec.js";
import {
    createSharedSessionEntry,
    decodeSharedSessionFrame,
    decodeSharedSessionHistoryOffer,
    decodeSharedSessionHistoryPage,
    decodeSharedSessionInvitation,
    encodeSharedSessionHistoryOffer,
    encodeSharedSessionHistoryPage,
    encodeSharedSessionInvitation,
    encodeSharedSessionOwnerEntryFrame,
    encodeSharedSessionOwnerStateFrame,
    encodeSharedSessionPostFrame,
    validateSharedSessionShareId,
    type SharedSessionHistoryOffer,
} from "./impl/frameCodec.js";
import {
    MAX_SHARED_SESSION_HISTORY_PAGE_BYTES,
    MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES,
    MAX_SHARED_SESSION_MEMBERS,
    MAX_SHARED_SESSION_OFFER_PAGES,
    MAX_SHARED_SESSION_PENDING_ENTRIES,
    SharedSessionEntryCollisionError,
    SharedSessionIdentityCollisionError,
    SharedSessionProtocolError,
    type SessionEntrySource,
    type SharedSessionCallbacks,
    type SharedSessionAppendInput,
    type SharedSessionEntry,
    type SharedSessionEntryInput,
    type SharedSessionEventResult,
    type SharedSessionHistoryPageDescriptor,
    type SharedSessionInvitation,
    type SharedSessionInvitationDelivery,
    type SharedSessionInvitee,
    type SharedSessionInviteResult,
    type SharedSessionJoinOptions,
    type SharedSessionMemberGrant,
    type SharedSessionMemberOptions,
    type SharedSessionOwnerOptions,
    type SharedSessionPost,
    type SharedSessionRetryReport,
    type SharedSessionState,
} from "./types.js";

export type {
    SessionEntrySource,
    SessionEntrySourcePage,
    SharedSessionCallbacks,
    SharedSessionAppendInput,
    SharedSessionEntry,
    SharedSessionEntryInput,
    SharedSessionEventResult,
    SharedSessionHistoryPageDescriptor,
    SharedSessionInvitation,
    SharedSessionInvitationDelivery,
    SharedSessionInvitee,
    SharedSessionInviteResult,
    SharedSessionJoinOptions,
    SharedSessionMemberGrant,
    SharedSessionMemberOptions,
    SharedSessionOwnerOptions,
    SharedSessionPost,
    SharedSessionRetryReport,
    SharedSessionState,
    SharedSessionTermination,
} from "./types.js";
export {
    MAX_SHARED_SESSION_ENTRY_BYTES,
    MAX_SHARED_SESSION_HISTORY_PAGE_BYTES,
    MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES,
    MAX_SHARED_SESSION_MEMBERS,
    MAX_SHARED_SESSION_OFFER_PAGES,
    MAX_SHARED_SESSION_PENDING_ENTRIES,
    MAX_SHARED_SESSION_POST_BYTES,
    MAX_SHARED_SESSION_SHARE_ID_BYTES,
    SharedSessionEntryCollisionError,
    SharedSessionIdentityCollisionError,
    SharedSessionProtocolError,
} from "./types.js";
export {
    contentHashForPayload,
    decodeSharedSessionInvitation,
    validateSharedSessionEventId,
    validateSharedSessionShareId,
} from "./impl/frameCodec.js";

const SESSION_PREFIX = "shared-session/v1";
const MAXIMUM_HISTORY_OFFERS = 100_000;

type PendingPrepared =
    | {
          readonly kind: "application";
          readonly prepared: PreparedMlsGroupApplication;
          phase: "persisted" | "ambiguous";
      }
    | {
          readonly kind: "commit";
          readonly prepared: PreparedMlsGroupCommit;
          phase: "persisted" | "ambiguous";
      };

function shareKeyId(shareId: string): string {
    return encodeBase64Url(hashBytes(utf8Encode(shareId)));
}

function recordKey(localId: string, shareId: string): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/record`;
}

function sessionPrefix(localId: string, shareId: string): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/`;
}

function terminalKey(localId: string, shareId: string): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/terminal`;
}

function bindingKey(localId: string, shareId: string): string {
    return `shared-session-binding/v1/${localId}/${shareKeyId(shareId)}`;
}

function bindingBytes(
    state: Pick<SharedSessionState, "shareId" | "groupId" | "ownerId">,
): Uint8Array {
    return canonicalJsonBytes({
        groupId: state.groupId,
        ownerId: state.ownerId,
        shareId: state.shareId,
        version: 1,
    });
}

function validateBinding(
    bytes: Uint8Array,
    state: Pick<SharedSessionState, "shareId" | "groupId" | "ownerId">,
): void {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new SharedSessionIdentityCollisionError();
    }
    if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed) ||
        (parsed as Record<string, unknown>).version !== 1 ||
        (parsed as Record<string, unknown>).shareId !== state.shareId ||
        (parsed as Record<string, unknown>).groupId !== state.groupId ||
        (parsed as Record<string, unknown>).ownerId !== state.ownerId ||
        !equalBytes(bindingBytes(state), bytes)
    ) {
        throw new SharedSessionIdentityCollisionError();
    }
}

function outboxPrefix(localId: string, shareId: string): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/outbox/`;
}

function outboxKey(localId: string, shareId: string, order: number, identifier: string): string {
    return `${outboxPrefix(localId, shareId)}${order.toString().padStart(4, "0")}/${identifier}`;
}

function historyOfferKey(localId: string, shareId: string, index: number): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/history-offer/${index
        .toString()
        .padStart(8, "0")}`;
}

function entrySequenceKey(localId: string, shareId: string, sequence: number): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/entry-sequence/${sequence
        .toString()
        .padStart(16, "0")}`;
}

function entryEventKey(localId: string, shareId: string, eventId: string): string {
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/entry-event/${eventId}`;
}

function postKey(
    localId: string,
    shareId: string,
    peerId: string,
    grantEpoch: number,
    postId: string,
): string {
    const digest = hashBytes(
        canonicalJsonBytes({
            context: "murmur/shared-session/post-replay/v1",
            grantEpoch,
            peerId,
            postId,
            shareId,
        }),
    );
    return `${SESSION_PREFIX}/${localId}/${shareKeyId(shareId)}/post/${encodeBase64Url(digest)}`;
}

function includeFingerprint(
    values: readonly Uint8Array[],
    fingerprint: Uint8Array,
): readonly Uint8Array[] {
    const id = encodeBase64Url(fingerprint);
    return values.some((value) => encodeBase64Url(value) === id)
        ? values
        : [...values, fingerprint.slice()];
}

function copyIdentity(identity: IdentityPublicKeys): IdentityPublicKeys {
    return {
        signingKey: identity.signingKey.slice(),
        encryptionKey: identity.encryptionKey.slice(),
    };
}

function copyGrant(grant: SharedSessionMemberGrant): SharedSessionMemberGrant {
    return { ...grant };
}

function copyState(state: SharedSessionState): SharedSessionState {
    return {
        ...state,
        members: state.members.map(copyGrant),
    };
}

function uuidV7(now: number): string {
    if (!Number.isSafeInteger(now) || now < 0 || now > 0xffff_ffff_ffff) {
        throw new Error("UUIDv7 timestamp is outside its 48-bit range");
    }
    const bytes = randomBytes(16);
    let timestamp = now;
    for (let index = 5; index >= 0; index -= 1) {
        bytes[index] = timestamp & 0xff;
        timestamp = Math.floor(timestamp / 256);
    }
    bytes[6] = 0x70 | ((bytes[6] ?? 0) & 0x0f);
    bytes[8] = 0x80 | ((bytes[8] ?? 0) & 0x3f);
    const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
        16,
        20,
    )}-${hex.slice(20)}`;
}

function randomOpaqueId(bytes: number): string {
    return encodeBase64Url(randomBytes(bytes));
}

function exactPublisher(
    client: MurmurClient,
    event: SignedRelayEvent,
): {
    publish(topic: string, payload: Uint8Array): Promise<PublishResult>;
    subscribe(topic: string): Promise<void>;
} {
    return {
        publish: async (topic, payload) => {
            if (topic !== event.topic || !equalBytes(payload, event.payload)) {
                throw new Error("Prepared shared-session event changed before publication");
            }
            return client.publishEvent(event);
        },
        subscribe: async (topic) => client.subscribe(topic),
    };
}

function eventMarker(entry: SharedSessionEntry): Uint8Array {
    return canonicalJsonBytes({
        contentHash: entry.contentHash,
        shareEventId: entry.shareEventId,
        shareSequence: entry.shareSequence,
    });
}

async function persistEntryReplay(
    transaction: StoreTransaction,
    localId: string,
    entry: SharedSessionEntry,
): Promise<"new" | "duplicate"> {
    const marker = eventMarker(entry);
    const sequenceKey = entrySequenceKey(localId, entry.shareId, entry.shareSequence);
    const eventKey = entryEventKey(localId, entry.shareId, entry.shareEventId);
    const [sequenceValue, eventValue] = await Promise.all([
        transaction.get(sequenceKey),
        transaction.get(eventKey),
    ]);
    if (sequenceValue !== undefined || eventValue !== undefined) {
        if (
            sequenceValue === undefined ||
            eventValue === undefined ||
            !equalBytes(sequenceValue, marker) ||
            !equalBytes(eventValue, marker)
        ) {
            throw new SharedSessionEntryCollisionError();
        }
        return "duplicate";
    }
    await transaction.set(sequenceKey, marker);
    await transaction.set(eventKey, marker);
    return "new";
}

function sameGroupAndShare(
    record: DurableSharedSessionRecord,
    frame: { readonly groupId: string; readonly shareId: string },
): boolean {
    return (
        frame.shareId === record.state.shareId &&
        frame.groupId === encodeBase64Url(decodeBase64Url(record.state.groupId))
    );
}

/**
 * Build the standard invitation delivery adapter on top of DirectChat's
 * canonical retryable text path.
 */
export function sharedSessionDirectChatDelivery(
    directChat: Pick<DirectChat, "sendText">,
): SharedSessionInvitationDelivery {
    return {
        deliver: async (invitation) => {
            await directChat.sendText(invitation.recipient, invitation.text, {
                id: invitation.deliveryId,
                sentAt: invitation.sentAt,
            });
        },
    };
}

abstract class SharedSessionBase {
    readonly #identity: IdentityKeyPair;
    readonly #client: MurmurClient;
    readonly #store: MurmurStore;
    readonly #callbacks: SharedSessionCallbacks;
    readonly #now: () => number;
    readonly #localId: string;
    readonly #recordKey: string;
    readonly #pending = new Map<string, PendingPrepared>();
    protected channel: MlsGroupChannel;
    protected record: DurableSharedSessionRecord;
    #destroyed = false;

    protected constructor(
        options: SharedSessionMemberOptions,
        record: DurableSharedSessionRecord,
        channel: MlsGroupChannel,
    ) {
        this.#identity = options.identity;
        this.#client = options.client;
        this.#store = options.store;
        this.#callbacks = options.callbacks;
        this.#now = options.now ?? Date.now;
        this.#localId = identityId(options.identity);
        this.#recordKey = recordKey(this.#localId, record.state.shareId);
        this.record = record;
        this.channel = channel;
    }

    /** Rig-owned opaque share identity. */
    get shareId(): string {
        return this.record.state.shareId;
    }

    /** Stable MLS group identifier serialized at the public boundary. */
    get groupId(): string {
        return this.record.state.groupId;
    }

    /** Defensive owner-authoritative state view. */
    get state(): SharedSessionState {
        return copyState(this.record.state);
    }

    protected get identity(): IdentityKeyPair {
        return this.#identity;
    }

    protected get client(): MurmurClient {
        return this.#client;
    }

    protected get store(): MurmurStore {
        return this.#store;
    }

    protected get callbacks(): SharedSessionCallbacks {
        return this.#callbacks;
    }

    protected get localId(): string {
        return this.#localId;
    }

    protected now(): number {
        return this.#now();
    }

    protected ensureActive(): void {
        if (this.#destroyed || this.record.internalStatus !== "active") {
            throw new Error("Shared session is terminal or stopping");
        }
    }

    protected async saveRecord(
        transaction: StoreTransaction,
        record: DurableSharedSessionRecord,
    ): Promise<void> {
        await transaction.set(this.#recordKey, encodeDurableSharedSessionRecord(record));
    }

    protected registerPending(eventId: string, pending: PendingPrepared): void {
        this.#pending.set(eventId, pending);
    }

    protected async publishPrepared(
        key: string,
        event: SignedRelayEvent,
        pending: PendingPrepared,
    ): Promise<void> {
        try {
            const result = await pending.prepared.publish(exactPublisher(this.#client, event));
            if (pending.kind === "commit") {
                pending.prepared.adopt();
            }
            await this.#store.delete(key);
            this.#pending.delete(event.id);
            void result;
        } catch (error: unknown) {
            pending.phase = "ambiguous";
            throw error;
        }
    }

    protected async prepareApplication(
        applicationData: Uint8Array,
        operation: (
            transaction: StoreTransaction,
            record: DurableSharedSessionRecord,
        ) => Promise<DurableSharedSessionRecord>,
    ): Promise<void> {
        this.ensureActive();
        await this.assertNoOutbox();
        const prepared = this.channel.prepareSend(applicationData);
        let checkpoint: Uint8Array | undefined;
        let persisted = false;
        try {
            checkpoint = prepared.serializeEpoch();
            const event = createRelayEvent(this.#identity, this.channel.topic, prepared.payload);
            const key = outboxKey(this.#localId, this.shareId, 2, event.id);
            const next = await this.#store.transaction(async (transaction) => {
                const base: DurableSharedSessionRecord = {
                    ...this.record,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedApplicationFingerprints: includeFingerprint(
                        this.channel.appliedApplicationFingerprints,
                        prepared.fingerprint,
                    ),
                };
                const updated = await operation(transaction, base);
                await this.saveRecord(transaction, updated);
                await transaction.set(
                    key,
                    encodeDurableSharedSessionOutbox({
                        kind: "application",
                        shareId: this.shareId,
                        event,
                    }),
                );
                return updated;
            });
            persisted = true;
            this.record = next;
            prepared.markPersisted();
            const pending: PendingPrepared = {
                kind: "application",
                prepared,
                phase: "persisted",
            };
            this.registerPending(event.id, pending);
            await this.publishPrepared(key, event, pending);
        } catch (error: unknown) {
            if (!persisted) {
                prepared.cancel();
            }
            throw error;
        } finally {
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
        }
    }

    protected async prepareCommit(
        proposals: Parameters<MlsGroupChannel["prepareCommit"]>[0],
        operation: (
            transaction: StoreTransaction,
            prepared: PreparedMlsGroupCommit,
            next: DurableSharedSessionRecord,
            commitEvent: SignedRelayEvent,
        ) => Promise<DurableSharedSessionRecord>,
        deferPublication: boolean = false,
    ): Promise<void> {
        await this.assertNoOutbox();
        const prepared = this.channel.prepareCommit(proposals);
        let checkpoint: Uint8Array | undefined;
        let persisted = false;
        try {
            checkpoint = prepared.serializeNextEpoch();
            const event = createRelayEvent(this.#identity, this.channel.topic, prepared.payload);
            const key = outboxKey(this.#localId, this.shareId, 1, event.id);
            const next = await this.#store.transaction(async (transaction) => {
                const base: DurableSharedSessionRecord = {
                    ...this.record,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedCommitFingerprints: includeFingerprint(
                        this.channel.appliedCommitFingerprints,
                        prepared.fingerprint,
                    ),
                };
                const updated = await operation(transaction, prepared, base, event);
                await this.saveRecord(transaction, updated);
                await transaction.set(
                    key,
                    encodeDurableSharedSessionOutbox({
                        kind: "commit",
                        shareId: this.shareId,
                        event,
                    }),
                );
                return updated;
            });
            persisted = true;
            this.record = next;
            prepared.markPersisted();
            const pending: PendingPrepared = {
                kind: "commit",
                prepared,
                phase: "persisted",
            };
            this.registerPending(event.id, pending);
            if (!deferPublication) {
                await this.publishPrepared(key, event, pending);
            }
        } catch (error: unknown) {
            if (!persisted) {
                prepared.cancel();
            }
            throw error;
        } finally {
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
        }
    }

    protected async assertNoOutbox(): Promise<void> {
        const records = await this.#store.list(outboxPrefix(this.#localId, this.shareId));
        if (records.size > 0) {
            throw new Error("Shared session has an unresolved durable publication");
        }
    }

    /** Subscribe this existing Murmur client to the session's stable MLS topic. */
    async subscribe(): Promise<void> {
        await this.channel.subscribe(this.#client);
    }

    /**
     * Retry exact invitation/application/Commit outboxes and one history blob.
     *
     * Records are ordered so every invitation is delivered before its batch
     * Commit. One history blob is fetched and committed per call.
     */
    async retry(): Promise<SharedSessionRetryReport> {
        const failures: Error[] = [];
        let published = 0;
        let historyPages = 0;
        const entries = await this.#store.list(outboxPrefix(this.#localId, this.shareId));
        for (const [key, bytes] of [...entries].sort(([left], [right]) =>
            left.localeCompare(right),
        )) {
            let outbox: DurableSharedSessionOutbox;
            try {
                outbox = decodeDurableSharedSessionOutbox(bytes);
            } finally {
                zeroBytes(bytes);
            }
            try {
                if (outbox.kind === "invitation") {
                    await this.deliverInvitation(outbox.invitation);
                    await this.#store.delete(key);
                    published += 1;
                    continue;
                }
                const pending = this.#pending.get(outbox.event.id);
                if (pending !== undefined) {
                    if (pending.phase === "persisted") {
                        await pending.prepared.publish(exactPublisher(this.#client, outbox.event));
                    } else {
                        const result = await this.#client.publishEvent(outbox.event);
                        pending.prepared.confirmPublished(result);
                    }
                    if (pending.kind === "commit") {
                        pending.prepared.adopt();
                    }
                    this.#pending.delete(outbox.event.id);
                } else {
                    await this.#client.publishEvent(outbox.event);
                }
                await this.#store.delete(key);
                published += 1;
            } catch (error: unknown) {
                failures.push(error instanceof Error ? error : new Error(String(error)));
                break;
            }
        }
        if (failures.length === 0 && this.record.history !== undefined) {
            try {
                historyPages += await this.retryHistory();
            } catch (error: unknown) {
                failures.push(error instanceof Error ? error : new Error(String(error)));
            }
        }
        return { published, historyPages, failures };
    }

    protected async deliverInvitation(_invitation: SharedSessionInvitation): Promise<void> {
        throw new Error("Members cannot deliver shared-session invitations");
    }

    protected async retryHistory(): Promise<number> {
        const history = this.record.history;
        if (history === undefined) {
            return 0;
        }
        if (history.discovery !== undefined) {
            if (history.offerCount >= MAXIMUM_HISTORY_OFFERS) {
                throw new SharedSessionProtocolError(
                    "buffer-exhausted",
                    "Shared-session history offer chain is too long",
                );
            }
            const blob = await this.#client.getBlob(
                history.discovery.blobId,
                history.discovery.plaintextBytes + 16,
            );
            if (blob === undefined) {
                throw new Error("Shared-session history offer blob is unavailable");
            }
            const plaintext = decryptFile(history.discovery, blob);
            let offer: SharedSessionHistoryOffer;
            try {
                offer = decodeSharedSessionHistoryOffer(plaintext);
            } finally {
                zeroBytes(plaintext);
                zeroBytes(blob.bytes);
            }
            if (
                offer.shareId !== this.shareId ||
                offer.groupId !== this.groupId ||
                offer.throughSequence < history.highestSequence
            ) {
                throw new SharedSessionProtocolError(
                    "invalid-frame",
                    "Shared-session history offer binding mismatch",
                );
            }
            const index = history.offerCount;
            const nextHistory: DurableSharedSessionHistory = {
                ...history,
                ...(offer.previous === undefined
                    ? { processOffer: index }
                    : { discovery: offer.previous }),
                offerCount: index + 1,
            };
            if (offer.previous === undefined) {
                delete (nextHistory as { discovery?: unknown }).discovery;
            }
            const nextRecord = { ...this.record, history: nextHistory };
            await this.#store.transaction(async (transaction) => {
                await transaction.set(
                    historyOfferKey(this.#localId, this.shareId, index),
                    encodeSharedSessionHistoryOffer(offer),
                );
                await this.saveRecord(transaction, nextRecord);
            });
            this.record = nextRecord;
            return 0;
        }
        if (history.processOffer !== undefined) {
            const offerKey = historyOfferKey(this.#localId, this.shareId, history.processOffer);
            const bytes = await this.#store.get(offerKey);
            if (bytes === undefined) {
                throw new Error("Shared-session durable history offer disappeared");
            }
            let offer: SharedSessionHistoryOffer;
            try {
                offer = decodeSharedSessionHistoryOffer(bytes);
            } finally {
                zeroBytes(bytes);
            }
            const page = offer.pages[history.pageIndex];
            if (page === undefined) {
                const nextIndex = history.processOffer - 1;
                const nextHistory: DurableSharedSessionHistory = {
                    ...history,
                    pageIndex: 0,
                    ...(nextIndex < 0 ? {} : { processOffer: nextIndex }),
                };
                if (nextIndex < 0) {
                    delete (nextHistory as { processOffer?: unknown }).processOffer;
                }
                const nextRecord = { ...this.record, history: nextHistory };
                await this.#store.transaction(async (transaction) => {
                    await transaction.delete(offerKey);
                    await this.saveRecord(transaction, nextRecord);
                });
                this.record = nextRecord;
                return 0;
            }
            const blob = await this.#client.getBlob(
                page.file.blobId,
                page.file.plaintextBytes + 16,
            );
            if (blob === undefined) {
                throw new Error("Shared-session history page blob is unavailable");
            }
            const plaintext = decryptFile(page.file, blob);
            let pageEntries: readonly SharedSessionEntry[];
            try {
                pageEntries = decodeSharedSessionHistoryPage(plaintext);
            } finally {
                zeroBytes(plaintext);
                zeroBytes(blob.bytes);
            }
            if (
                pageEntries.length !== page.entryCount ||
                pageEntries[0]?.shareSequence !== page.firstSequence ||
                pageEntries.at(-1)?.shareSequence !== page.lastSequence ||
                page.firstSequence !== history.highestSequence + 1 ||
                pageEntries.some((entry) => entry.shareId !== this.shareId)
            ) {
                throw new SharedSessionProtocolError(
                    "sequence-gap",
                    "Shared-session history page is not the next contiguous page",
                );
            }
            const nextHistory: DurableSharedSessionHistory = {
                ...history,
                pageIndex: history.pageIndex + 1,
                highestSequence: page.lastSequence,
            };
            const nextRecord = {
                ...this.record,
                maximumSequence: Math.max(this.record.maximumSequence, page.lastSequence),
                history: nextHistory,
            };
            await this.#store.transaction(async (transaction) => {
                for (const entry of pageEntries) {
                    if ((await persistEntryReplay(transaction, this.#localId, entry)) === "new") {
                        await this.#callbacks.persistEntry(transaction, entry);
                    }
                }
                await this.saveRecord(transaction, nextRecord);
            });
            this.record = nextRecord;
            return 1;
        }
        if (history.pendingEntries.length > 0) {
            const sorted = [...history.pendingEntries].sort(
                (left, right) => left.shareSequence - right.shareSequence,
            );
            const first = sorted[0]!;
            if (first.shareSequence !== history.highestSequence + 1) {
                throw new SharedSessionProtocolError(
                    "sequence-gap",
                    "Shared-session live tail does not meet completed history",
                );
            }
            const nextHistory = {
                ...history,
                highestSequence: first.shareSequence,
                pendingEntries: sorted.slice(1),
            };
            const nextRecord = {
                ...this.record,
                maximumSequence: Math.max(this.record.maximumSequence, first.shareSequence),
                history: nextHistory,
            };
            await this.#store.transaction(async (transaction) => {
                if ((await persistEntryReplay(transaction, this.#localId, first)) === "new") {
                    await this.#callbacks.persistEntry(transaction, first);
                }
                await this.saveRecord(transaction, nextRecord);
            });
            this.record = nextRecord;
            return 1;
        }
        const nextRecord = { ...this.record };
        delete (nextRecord as { history?: unknown }).history;
        await this.#store.transaction(async (transaction) => {
            await this.saveRecord(transaction, nextRecord);
        });
        this.record = nextRecord;
        return 0;
    }

    /** Apply one event already read by the application's existing client. */
    async handleEvent(received: ReceivedEvent): Promise<SharedSessionEventResult> {
        if (received.event.topic !== this.channel.topic) {
            return { status: "unhandled", event: received };
        }
        if (this.#destroyed) {
            return { status: "terminated" };
        }
        try {
            const privateMessage = decodeMlsPrivateMessage(received.event.payload);
            if (privateMessage.epoch < this.channel.epoch) {
                await this.#store.transaction(received.advanceCursor);
                return { status: "duplicate" };
            }
        } catch {
            // Commit or malformed payload; the channel performs full validation.
        }
        if (this.isCommit(received.event.payload)) {
            const commit = decodeMlsTreeCommit(received.event.payload);
            let author: ReturnType<MlsGroupChannel["parseCommitAuthor"]>;
            try {
                author = this.channel.parseCommitAuthor(received.event.payload);
            } catch {
                author = { sender: -1, signingKey: new Uint8Array() };
            }
            if (!equalBytes(author.signingKey, this.record.owner.signingKey)) {
                // Parsing is intentionally not authorization. Authentication
                // happens inside `channel.handle()` before the ACL below.
                author = { sender: -1, signingKey: new Uint8Array() };
            }
            if (
                commit.epoch < this.channel.epoch &&
                equalBytes(author.signingKey, this.record.owner.signingKey)
            ) {
                await this.#store.transaction(received.advanceCursor);
                return { status: "duplicate" };
            }
        }
        if (
            this.record.history !== undefined &&
            this.record.history.pendingEntries.length >= MAX_SHARED_SESSION_PENDING_ENTRIES &&
            !this.isCommit(received.event.payload)
        ) {
            return { status: "deferred" };
        }
        const handled = this.channel.handle(received);
        if (handled === undefined) {
            return { status: "unhandled", event: received };
        }
        if (handled.status === "deferred") {
            return { status: "deferred" };
        }
        if (handled.status === "applied" || handled.status === "application-applied") {
            await this.#store.transaction(handled.advanceCursor);
            return { status: "duplicate" };
        }
        if (handled.status === "removed") {
            if (!equalBytes(handled.committer.signingKey, this.record.owner.signingKey)) {
                handled.cancel();
                const error = new SharedSessionProtocolError(
                    "unauthorized-commit",
                    "A non-owner attempted a shared-session MLS Commit",
                );
                await this.terminate(received, "protocol-error", error);
                return { status: "terminated" };
            }
            await this.#store.transaction(async (transaction) => {
                await this.#callbacks.terminate(transaction, {
                    shareId: this.shareId,
                    reason: "removed",
                });
                await this.deleteProtocolRows(transaction);
                await handled.advanceCursor(transaction);
                await this.#client.retireTopicCursors(transaction, this.channel.topic);
            });
            handled.markPersisted();
            this.#client.unsubscribe(this.channel.topic);
            this.#destroyed = true;
            return { status: "removed" };
        }
        if (handled.status === "commit") {
            if (!equalBytes(handled.committer.signingKey, this.record.owner.signingKey)) {
                handled.cancel();
                const error = new SharedSessionProtocolError(
                    "unauthorized-commit",
                    "A non-owner attempted a shared-session MLS Commit",
                );
                await this.terminate(received, "protocol-error", error);
                return { status: "terminated" };
            }
            const checkpoint = handled.serializeNextEpoch();
            const next: DurableSharedSessionRecord = {
                ...this.record,
                epochState: checkpoint,
                persistenceGeneration: handled.persistenceGeneration,
                appliedCommitFingerprints: includeFingerprint(
                    this.channel.appliedCommitFingerprints,
                    handled.fingerprint,
                ),
            };
            try {
                await this.#store.transaction(async (transaction) => {
                    await this.saveRecord(transaction, next);
                    await handled.advanceCursor(transaction);
                });
                this.record = next;
                handled.markPersisted();
                handled.adopt();
            } finally {
                zeroBytes(checkpoint);
            }
            return { status: "commit" };
        }
        const checkpoint = handled.serializeEpoch();
        let resultStatus: SharedSessionEventResult["status"] = "duplicate";
        let terminateAfter = false;
        let ownerAuthored = false;
        try {
            const senderKey = this.channel.memberSignatureKeys[handled.message.sender];
            if (senderKey === undefined) {
                throw new SharedSessionProtocolError(
                    "invalid-frame",
                    "Shared-session frame sender is not an active MLS member",
                );
            }
            ownerAuthored = equalBytes(senderKey, this.record.owner.signingKey);
            let frame: ReturnType<typeof decodeSharedSessionFrame>;
            try {
                frame = decodeSharedSessionFrame(
                    handled.message.applicationData,
                    this.record.owner,
                );
            } catch (error: unknown) {
                if (
                    error instanceof SharedSessionProtocolError &&
                    !equalBytes(senderKey, this.record.owner.signingKey)
                ) {
                    const next: DurableSharedSessionRecord = {
                        ...this.record,
                        epochState: checkpoint,
                        persistenceGeneration: handled.persistenceGeneration,
                        appliedApplicationFingerprints: includeFingerprint(
                            this.channel.appliedApplicationFingerprints,
                            handled.fingerprint,
                        ),
                    };
                    await this.#store.transaction(async (transaction) => {
                        await this.saveRecord(transaction, next);
                        await handled.advanceCursor(transaction);
                    });
                    this.record = next;
                    handled.markPersisted();
                    return { status: "quarantined" };
                }
                throw error;
            }
            if (!sameGroupAndShare(this.record, frame)) {
                throw new SharedSessionProtocolError(
                    "invalid-frame",
                    "Shared-session frame binding mismatch",
                );
            }
            let next: DurableSharedSessionRecord = {
                ...this.record,
                epochState: checkpoint,
                persistenceGeneration: handled.persistenceGeneration,
                appliedApplicationFingerprints: includeFingerprint(
                    this.channel.appliedApplicationFingerprints,
                    handled.fingerprint,
                ),
            };
            await this.#store.transaction(async (transaction) => {
                if (frame.kind === "entry") {
                    if (!equalBytes(senderKey, this.record.owner.signingKey)) {
                        throw new SharedSessionProtocolError(
                            "owner-authorization",
                            "A non-owner sent a shared-session entry",
                        );
                    }
                    const history = next.history;
                    if (
                        history !== undefined &&
                        (history.discovery !== undefined ||
                            history.processOffer !== undefined ||
                            history.pendingEntries.length > 0) &&
                        frame.entry.shareSequence > history.highestSequence
                    ) {
                        const duplicate = history.pendingEntries.find(
                            (entry) =>
                                entry.shareSequence === frame.entry.shareSequence ||
                                entry.shareEventId === frame.entry.shareEventId,
                        );
                        if (
                            duplicate !== undefined &&
                            (duplicate.contentHash !== frame.entry.contentHash ||
                                duplicate.shareEventId !== frame.entry.shareEventId ||
                                duplicate.shareSequence !== frame.entry.shareSequence)
                        ) {
                            throw new SharedSessionEntryCollisionError();
                        }
                        next = {
                            ...next,
                            maximumSequence: Math.max(
                                next.maximumSequence,
                                frame.entry.shareSequence,
                            ),
                            history: {
                                ...history,
                                pendingEntries:
                                    duplicate === undefined
                                        ? [...history.pendingEntries, frame.entry]
                                        : history.pendingEntries,
                            },
                        };
                        resultStatus = duplicate === undefined ? "entry" : "duplicate";
                    } else {
                        const replay = await persistEntryReplay(
                            transaction,
                            this.#localId,
                            frame.entry,
                        );
                        if (replay === "new") {
                            if (frame.entry.shareSequence !== next.maximumSequence + 1) {
                                throw new SharedSessionProtocolError(
                                    "sequence-gap",
                                    "Shared-session live entry is not gapless",
                                );
                            }
                            await this.#callbacks.persistEntry(transaction, frame.entry);
                            next = {
                                ...next,
                                maximumSequence: frame.entry.shareSequence,
                            };
                            resultStatus = "entry";
                        }
                    }
                } else if (frame.kind === "state") {
                    if (!equalBytes(senderKey, this.record.owner.signingKey)) {
                        throw new SharedSessionProtocolError(
                            "owner-authorization",
                            "A non-owner sent shared-session state",
                        );
                    }
                    if (frame.state.stateSequence > next.state.stateSequence) {
                        next = {
                            ...next,
                            state: copyState(frame.state),
                            internalStatus:
                                frame.state.status === "active"
                                    ? next.internalStatus
                                    : frame.state.status,
                        };
                        await this.#callbacks.persistState(transaction, frame.state);
                        resultStatus = "state";
                    }
                    const localGrant = frame.state.members.find(
                        (grant) => grant.peerId === this.#localId,
                    );
                    const currentGrant = next.state.members.find(
                        (grant) => grant.peerId === this.#localId,
                    );
                    if (
                        this.record.role === "member" &&
                        localGrant?.status === "ended" &&
                        currentGrant !== undefined &&
                        localGrant.shareMemberId === currentGrant.shareMemberId &&
                        localGrant.grantEpoch >= currentGrant.grantEpoch
                    ) {
                        await this.#callbacks.terminate(transaction, {
                            shareId: this.shareId,
                            reason: "ended",
                        });
                        terminateAfter = true;
                        resultStatus = "terminated";
                    }
                } else {
                    if (equalBytes(senderKey, this.record.owner.signingKey)) {
                        resultStatus = "quarantined";
                    } else {
                        const peerId = identityId({ signingKey: senderKey });
                        const grant = next.state.members.find(
                            (member) =>
                                member.peerId === peerId &&
                                member.status === "active" &&
                                member.grantEpoch === frame.grantEpoch,
                        );
                        if (grant === undefined) {
                            resultStatus = "quarantined";
                        } else if (next.role === "owner") {
                            const post: SharedSessionPost = {
                                shareId: this.shareId,
                                authenticatedPeerId: peerId,
                                shareMemberId: grant.shareMemberId,
                                grantEpoch: grant.grantEpoch,
                                postId: frame.postId,
                                timestamp: frame.timestamp,
                                text: frame.text,
                            };
                            const key = postKey(
                                this.#localId,
                                this.shareId,
                                peerId,
                                grant.grantEpoch,
                                frame.postId,
                            );
                            const fingerprint = hashBytes(handled.message.applicationData);
                            const existing = await transaction.get(key);
                            if (existing !== undefined && !equalBytes(existing, fingerprint)) {
                                resultStatus = "quarantined";
                            } else if (existing === undefined) {
                                await this.#callbacks.persistPost(transaction, post);
                                await transaction.set(key, fingerprint);
                                resultStatus = "post";
                            }
                        }
                    }
                }
                if (!terminateAfter) {
                    await this.saveRecord(transaction, next);
                } else {
                    await this.deleteProtocolRows(transaction);
                }
                await handled.advanceCursor(transaction);
                if (terminateAfter) {
                    await this.#client.retireTopicCursors(transaction, this.channel.topic);
                }
            });
            this.record = next;
            handled.markPersisted();
            if (terminateAfter) {
                this.#client.unsubscribe(this.channel.topic);
                this.channel.destroy();
                this.#destroyed = true;
            }
            return { status: resultStatus };
        } catch (error: unknown) {
            if (error instanceof SharedSessionProtocolError) {
                if (!ownerAuthored) {
                    const next: DurableSharedSessionRecord = {
                        ...this.record,
                        epochState: checkpoint,
                        persistenceGeneration: handled.persistenceGeneration,
                        appliedApplicationFingerprints: includeFingerprint(
                            this.channel.appliedApplicationFingerprints,
                            handled.fingerprint,
                        ),
                    };
                    await this.#store.transaction(async (transaction) => {
                        await this.saveRecord(transaction, next);
                        await handled.advanceCursor(transaction);
                    });
                    this.record = next;
                    handled.markPersisted();
                    return { status: "quarantined" };
                }
                await this.terminate(received, "protocol-error", error, handled);
                return { status: "terminated" };
            }
            throw error;
        } finally {
            zeroBytes(checkpoint);
            zeroBytes(handled.message.applicationData);
            zeroBytes(handled.message.authenticatedData);
        }
    }

    protected isCommit(payload: Uint8Array): boolean {
        try {
            decodeMlsTreeCommit(payload);
            return true;
        } catch {
            return false;
        }
    }

    protected async terminate(
        received: ReceivedEvent,
        reason: "protocol-error",
        error: SharedSessionProtocolError,
        opened?: Extract<
            NonNullable<ReturnType<MlsGroupChannel["handle"]>>,
            { readonly status: "opened" }
        >,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await this.#callbacks.terminate(transaction, {
                shareId: this.shareId,
                reason,
                error,
            });
            await this.deleteProtocolRows(transaction);
            await (opened?.advanceCursor ?? received.advanceCursor)(transaction);
            await this.#client.retireTopicCursors(transaction, this.channel.topic);
        });
        opened?.markPersisted();
        this.#client.unsubscribe(this.channel.topic);
        this.channel.destroy();
        this.#destroyed = true;
    }

    protected retireInMemory(): void {
        this.#client.unsubscribe(this.channel.topic);
        this.channel.destroy();
        this.#destroyed = true;
    }

    private async deleteProtocolRows(transaction: StoreTransaction): Promise<void> {
        const rows = await transaction.list(sessionPrefix(this.#localId, this.shareId));
        for (const key of rows.keys()) {
            await transaction.delete(key);
        }
    }

    /** Destroy in-memory epoch secrets. Durable state remains loadable. */
    destroy(): void {
        if (this.#destroyed) {
            return;
        }
        for (const pending of this.#pending.values()) {
            pending.prepared.abandonPersisted();
        }
        this.#pending.clear();
        this.channel.destroy();
        this.#destroyed = true;
    }
}

/** Owner authority for one Rig share and its single MLS group. */
export class SharedSessionOwner extends SharedSessionBase {
    readonly #delivery: SharedSessionInvitationDelivery;
    readonly #entrySource: SessionEntrySource;
    #operationPending = false;

    private constructor(
        options: SharedSessionOwnerOptions,
        record: DurableSharedSessionRecord,
        channel: MlsGroupChannel,
    ) {
        super(options, record, channel);
        this.#delivery = options.invitationDelivery;
        this.#entrySource = options.entrySource;
    }

    /** Create, persist, and subscribe one owner-only epoch-zero share. */
    static async create(
        shareId: string,
        options: SharedSessionOwnerOptions,
    ): Promise<SharedSessionOwner> {
        validateSharedSessionShareId(shareId);
        const localId = identityId(options.identity);
        const key = recordKey(localId, shareId);
        if (
            (await options.store.get(key)) !== undefined ||
            (await options.store.get(terminalKey(localId, shareId))) !== undefined ||
            (await options.store.get(bindingKey(localId, shareId))) !== undefined
        ) {
            throw new SharedSessionIdentityCollisionError();
        }
        const channel = new MlsGroupChannel(createMlsGroup(options.identity));
        const state: SharedSessionState = {
            shareId,
            groupId: encodeBase64Url(channel.groupId),
            ownerId: localId,
            stateSequence: 0,
            status: "active",
            members: [],
        };
        const epochState = channel.serializeEpoch();
        const record: DurableSharedSessionRecord = {
            role: "owner",
            state,
            owner: copyIdentity(options.identity),
            epochState,
            persistenceGeneration: channel.persistenceGeneration,
            appliedCommitFingerprints: [],
            appliedApplicationFingerprints: [],
            maximumSequence: 0,
            internalStatus: "active",
            stateDirty: false,
            pendingRemovePeerIds: [],
        };
        try {
            await options.store.transaction(async (transaction) => {
                if ((await transaction.get(key)) !== undefined) {
                    throw new SharedSessionIdentityCollisionError();
                }
                await transaction.set(key, encodeDurableSharedSessionRecord(record));
                await transaction.set(bindingKey(localId, shareId), bindingBytes(state));
                await options.callbacks.persistState(transaction, state);
            });
            const session = new SharedSessionOwner(options, record, channel);
            await session.subscribe();
            return session;
        } catch (error: unknown) {
            channel.destroy();
            throw error;
        } finally {
            zeroBytes(epochState);
        }
    }

    /** Restore one owner share from its secret-bearing durable checkpoint. */
    static async load(
        shareId: string,
        options: SharedSessionOwnerOptions,
    ): Promise<SharedSessionOwner> {
        validateSharedSessionShareId(shareId);
        const key = recordKey(identityId(options.identity), shareId);
        const bytes = await options.store.get(key);
        if (bytes === undefined) {
            throw new Error("Shared-session owner state was not found");
        }
        let record: DurableSharedSessionRecord;
        try {
            record = decodeDurableSharedSessionRecord(bytes);
        } finally {
            zeroBytes(bytes);
        }
        if (
            record.role !== "owner" ||
            record.state.shareId !== shareId ||
            !equalBytes(record.owner.signingKey, options.identity.signingKey)
        ) {
            throw new SharedSessionIdentityCollisionError();
        }
        const binding = await options.store.get(bindingKey(identityId(options.identity), shareId));
        if (binding === undefined) {
            throw new SharedSessionIdentityCollisionError();
        }
        validateBinding(binding, record.state);
        const epoch = MlsEpochState.deserialize(record.epochState, {
            localSigningSecretKey: options.identity.signingSecretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            minimumPersistenceGeneration: record.persistenceGeneration,
        });
        const channel = new MlsGroupChannel(
            epoch,
            record.appliedCommitFingerprints,
            record.appliedApplicationFingerprints,
        );
        if (encodeBase64Url(channel.groupId) !== record.state.groupId) {
            channel.destroy();
            throw new SharedSessionIdentityCollisionError();
        }
        const session = new SharedSessionOwner(options, record, channel);
        await session.subscribe();
        return session;
    }

    protected override async deliverInvitation(invitation: SharedSessionInvitation): Promise<void> {
        await this.#delivery.deliver(invitation);
    }

    /** Retry transport outboxes, then resume any interrupted control transition. */
    override async retry(): Promise<SharedSessionRetryReport> {
        const report = await super.retry();
        if (report.failures.length > 0) {
            return report;
        }
        const failures: Error[] = [];
        let published = report.published;
        try {
            if (this.record.stateDirty) {
                await this.publishStateIfDirty(this.record.internalStatus === "stopping");
                published += 1;
            }
            if (this.record.pendingRemovePeerIds.length > 0) {
                await this.removePendingMembers(this.record.internalStatus === "stopping");
                published += 1;
            }
            if (
                this.record.internalStatus === "stopping" &&
                !this.record.stateDirty &&
                this.record.pendingRemovePeerIds.length === 0
            ) {
                await this.finalizeStop(this.record.state);
            }
        } catch (error: unknown) {
            failures.push(error instanceof Error ? error : new Error(String(error)));
        }
        return {
            published,
            historyPages: report.historyPages,
            failures,
        };
    }

    /** Append one gapless opaque Rig projection and publish its signed owner frame. */
    async append(input: SharedSessionAppendInput): Promise<SharedSessionEntry> {
        this.beginOperation();
        try {
            const withId: SharedSessionEntryInput = {
                ...input,
                shareEventId: input.shareEventId ?? uuidV7(this.now()),
            };
            const entry = createSharedSessionEntry(this.shareId, withId);
            if (entry.shareSequence !== this.record.maximumSequence + 1) {
                throw new SharedSessionProtocolError(
                    "sequence-gap",
                    "Owner append sequence must be the next gapless value",
                );
            }
            const frame = encodeSharedSessionOwnerEntryFrame({
                identity: this.identity,
                groupId: this.channel.groupId,
                entry,
            });
            try {
                await this.prepareApplication(frame, async (transaction, record) => {
                    const replay = await persistEntryReplay(transaction, this.localId, entry);
                    if (replay === "new") {
                        await this.callbacks.persistEntry(transaction, entry);
                    }
                    return { ...record, maximumSequence: entry.shareSequence };
                });
                return entry;
            } finally {
                zeroBytes(frame);
            }
        } finally {
            this.endOperation();
        }
    }

    /** Batch-add friends with one MLS Commit, Welcome, and state sequence. */
    async inviteMany(
        invitees: readonly SharedSessionInvitee[],
    ): Promise<SharedSessionInviteResult> {
        this.beginOperation();
        try {
            return await this.inviteManyExclusive(invitees);
        } finally {
            this.endOperation();
        }
    }

    private async inviteManyExclusive(
        invitees: readonly SharedSessionInvitee[],
    ): Promise<SharedSessionInviteResult> {
        this.ensureActive();
        const existingPeers = new Set(this.record.state.members.map((member) => member.peerId));
        const newPeerCount = invitees.filter(
            (invitee) => !existingPeers.has(identityId(invitee.identity)),
        ).length;
        if (
            invitees.length === 0 ||
            this.record.state.members.length + newPeerCount > MAX_SHARED_SESSION_MEMBERS
        ) {
            throw new Error("Invalid shared-session invite batch size");
        }
        const peerIds = invitees.map((invitee) => identityId(invitee.identity));
        if (new Set(peerIds).size !== invitees.length) {
            throw new Error("Duplicate shared-session invitee");
        }
        for (const [index, invitee] of invitees.entries()) {
            if (
                !verifyMlsKeyPackage(invitee.keyPackage) ||
                !equalBytes(
                    invitee.keyPackage.leafNode.signatureKey,
                    invitee.identity.signingKey,
                ) ||
                this.record.state.members.some(
                    (member) => member.peerId === peerIds[index] && member.status === "active",
                )
            ) {
                throw new Error("Invalid or already-active shared-session invitee");
            }
        }
        const history = await this.buildHistoryOffer();
        const nextMembers = [...this.record.state.members];
        const grants = peerIds.map((peerId) => {
            const previousIndex = nextMembers.findIndex((member) => member.peerId === peerId);
            const previous = nextMembers[previousIndex];
            const grant: SharedSessionMemberGrant =
                previous === undefined
                    ? {
                          shareMemberId: randomOpaqueId(16),
                          peerId,
                          grantEpoch: 1,
                          status: "active",
                      }
                    : {
                          ...previous,
                          grantEpoch: previous.grantEpoch + 1,
                          status: "active",
                      };
            if (previousIndex < 0) {
                nextMembers.push(grant);
            } else {
                nextMembers[previousIndex] = grant;
            }
            return grant;
        });
        const state: SharedSessionState = {
            ...this.record.state,
            stateSequence: this.record.state.stateSequence + 1,
            members: nextMembers,
        };
        const invitations: SharedSessionInvitation[] = [];
        await this.prepareCommit(
            invitees.map((invitee) => ({ type: "add" as const, keyPackage: invitee.keyPackage })),
            async (transaction, prepared, record, event) => {
                if (
                    prepared.welcome === undefined ||
                    prepared.addedLeaves.length !== invitees.length
                ) {
                    throw new Error("Shared-session batch Add did not produce one Welcome");
                }
                const tree = encodeMlsRatchetTree(prepared.tree);
                try {
                    for (const [index, invitee] of invitees.entries()) {
                        const recipientId = peerIds[index]!;
                        const text = encodeSharedSessionInvitation(
                            {
                                version: 1,
                                shareId: this.shareId,
                                groupId: this.channel.groupId,
                                ownerId: this.record.state.ownerId,
                                recipientId,
                                state,
                                grant: grants[index]!,
                                welcome: prepared.welcome,
                                tree,
                                keyPackageReference: mlsKeyPackageReference(invitee.keyPackage),
                                commitFingerprint: prepared.fingerprint,
                                ...(history.offer === undefined
                                    ? {}
                                    : { historyOffer: history.offer }),
                            },
                            this.identity,
                        );
                        const invitation: SharedSessionInvitation = {
                            recipient: copyIdentity(invitee.identity),
                            deliveryId: randomOpaqueId(24),
                            sentAt: this.now(),
                            text,
                        };
                        invitations.push(invitation);
                        await transaction.set(
                            outboxKey(
                                this.localId,
                                this.shareId,
                                0,
                                `${index.toString().padStart(4, "0")}-${event.id}`,
                            ),
                            encodeDurableSharedSessionOutbox({
                                kind: "invitation",
                                shareId: this.shareId,
                                invitation,
                            }),
                        );
                    }
                } finally {
                    zeroBytes(tree);
                }
                await this.callbacks.persistState(transaction, state);
                return {
                    ...record,
                    state,
                    stateDirty: true,
                    maximumSequence: Math.max(record.maximumSequence, history.throughSequence),
                };
            },
            true,
        );
        const retry = await this.retry();
        if (retry.failures.length > 0) {
            throw new AggregateError(
                retry.failures,
                "Shared-session invitations or batch Commit remain pending",
            );
        }
        await this.publishStateIfDirty();
        return { state: copyState(state), invitations };
    }

    /** Add or re-add one friend through the batch-safe path. */
    async invite(invitee: SharedSessionInvitee): Promise<SharedSessionInviteResult> {
        return this.inviteMany([invitee]);
    }

    /** Revoke one active grant after an authenticated ended state frame. */
    async revoke(peer: Pick<IdentityPublicKeys, "signingKey">): Promise<SharedSessionState> {
        this.beginOperation();
        try {
            this.ensureActive();
            const peerId = identityId(peer);
            const memberIndex = this.record.state.members.findIndex(
                (member) => member.peerId === peerId && member.status === "active",
            );
            if (memberIndex < 0) {
                throw new Error("Shared-session member is not active");
            }
            const members = this.record.state.members.map((member, index) =>
                index === memberIndex ? { ...member, status: "ended" as const } : member,
            );
            const state: SharedSessionState = {
                ...this.record.state,
                stateSequence: this.record.state.stateSequence + 1,
                members,
            };
            this.record = {
                ...this.record,
                state,
                stateDirty: true,
                pendingRemovePeerIds: [...new Set([...this.record.pendingRemovePeerIds, peerId])],
            };
            await this.store.transaction(async (transaction) => {
                await this.saveRecord(transaction, this.record);
                await this.callbacks.persistState(transaction, state);
            });
            await this.publishStateIfDirty();
            await this.removePendingMembers(false);
            return copyState(this.record.state);
        } finally {
            this.endOperation();
        }
    }

    /**
     * End every active grant, remove all members together, and retire the share.
     *
     * Cooperative deletion cannot erase data or page keys already saved by a
     * former member.
     */
    async stop(): Promise<SharedSessionState> {
        this.beginOperation();
        try {
            return await this.stopExclusive();
        } finally {
            this.endOperation();
        }
    }

    private async stopExclusive(): Promise<SharedSessionState> {
        this.ensureActive();
        const membersStillInGroup = this.channel.memberSignatureKeys.flatMap((key) =>
            key !== undefined && !equalBytes(key, this.identity.signingKey)
                ? [identityId({ signingKey: key })]
                : [],
        );
        const state: SharedSessionState = {
            ...this.record.state,
            stateSequence: this.record.state.stateSequence + 1,
            status: "stopped",
            members: this.record.state.members.map((member) => ({
                ...member,
                status: "ended",
            })),
        };
        this.record = {
            ...this.record,
            state,
            internalStatus: "stopping",
            stateDirty: true,
            pendingRemovePeerIds: membersStillInGroup,
        };
        await this.store.transaction(async (transaction) => {
            await this.saveRecord(transaction, this.record);
            await this.callbacks.persistState(transaction, state);
        });
        await this.publishStateIfDirty(true);
        await this.removePendingMembers(true);
        return this.finalizeStop(state);
    }

    private async finalizeStop(stopped: SharedSessionState): Promise<SharedSessionState> {
        await this.store.transaction(async (transaction) => {
            await this.callbacks.persistState(transaction, stopped);
            const rows = await transaction.list(sessionPrefix(this.localId, this.shareId));
            for (const key of rows.keys()) {
                await transaction.delete(key);
            }
            await this.client.retireTopicCursors(transaction, this.channel.topic);
            await transaction.set(
                terminalKey(this.localId, this.shareId),
                canonicalJsonBytes({
                    groupId: this.groupId,
                    ownerId: stopped.ownerId,
                    shareId: stopped.shareId,
                    stateSequence: stopped.stateSequence,
                    status: "stopped",
                    version: 1,
                }),
            );
        });
        this.record = {
            ...this.record,
            state: stopped,
            internalStatus: "stopped",
            pendingRemovePeerIds: [],
        };
        this.retireInMemory();
        return copyState(stopped);
    }

    protected override async retryHistory(): Promise<number> {
        return 0;
    }

    private async publishStateIfDirty(allowStopping: boolean = false): Promise<void> {
        if (!this.record.stateDirty) {
            return;
        }
        if (!allowStopping && this.record.internalStatus !== "active") {
            throw new Error("Cannot publish non-terminal state while stopping");
        }
        const frame = encodeSharedSessionOwnerStateFrame({
            identity: this.identity,
            groupId: this.channel.groupId,
            state: this.record.state,
        });
        try {
            const previousStatus = this.record.internalStatus;
            if (previousStatus === "stopping") {
                this.record = { ...this.record, internalStatus: "active" };
            }
            await this.prepareApplication(frame, async (_transaction, record) => ({
                ...record,
                internalStatus: previousStatus,
                stateDirty: false,
            }));
        } finally {
            zeroBytes(frame);
        }
    }

    private async removePendingMembers(stopping: boolean): Promise<void> {
        if (this.record.pendingRemovePeerIds.length === 0) {
            return;
        }
        const removals = this.record.pendingRemovePeerIds.flatMap((peerId) => {
            const signingKey = decodeBase64Url(peerId);
            const leaf = this.channel.memberSignatureKeys.findIndex(
                (key) => key !== undefined && equalBytes(key, signingKey),
            );
            if (leaf < 0) {
                return [];
            }
            return [{ type: "remove" as const, removed: leaf }];
        });
        if (removals.length === 0) {
            this.record = { ...this.record, pendingRemovePeerIds: [] };
            await this.store.transaction(async (transaction) => {
                await this.saveRecord(transaction, this.record);
            });
            return;
        }
        if (stopping) {
            this.record = { ...this.record, internalStatus: "active" };
        }
        await this.prepareCommit(removals, async (_transaction, _prepared, record) => ({
            ...record,
            internalStatus: stopping ? "stopping" : "active",
            pendingRemovePeerIds: [],
        }));
    }

    private async buildHistoryOffer(): Promise<{
        readonly offer?: import("@slopus/murmur").EncryptedFileDescriptor;
        readonly throughSequence: number;
    }> {
        let afterSequence = 0;
        let previous: import("@slopus/murmur").EncryptedFileDescriptor | undefined;
        let pages: SharedSessionHistoryPageDescriptor[] = [];
        for (;;) {
            const sourcePage = await this.#entrySource.readPage({
                afterSequence,
                maximumEntries: MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES,
                maximumBytes: MAX_SHARED_SESSION_HISTORY_PAGE_BYTES,
            });
            if (
                sourcePage.entries.length > MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES ||
                (sourcePage.entries.length === 0 && !sourcePage.done)
            ) {
                throw new Error("SessionEntrySource returned an invalid bounded page");
            }
            if (sourcePage.entries.length > 0) {
                const entries = sourcePage.entries.map((entry) =>
                    createSharedSessionEntry(this.shareId, entry),
                );
                if (
                    entries[0]!.shareSequence !== afterSequence + 1 ||
                    entries.some(
                        (entry, index) => entry.shareSequence !== afterSequence + index + 1,
                    )
                ) {
                    throw new SharedSessionProtocolError(
                        "sequence-gap",
                        "SessionEntrySource history is not gapless",
                    );
                }
                const plaintext = encodeSharedSessionHistoryPage(entries);
                const encrypted = encryptFile(plaintext, {
                    name: `murmur-shared-session-page-${entries[0]!.shareSequence}.json`,
                    mediaType: "application/vnd.murmur.shared-session-page+json",
                });
                try {
                    await this.client.putBlob(encrypted.blob.bytes);
                    pages.push({
                        firstSequence: entries[0]!.shareSequence,
                        lastSequence: entries.at(-1)!.shareSequence,
                        entryCount: entries.length,
                        file: encrypted.descriptor,
                    });
                    afterSequence = entries.at(-1)!.shareSequence;
                } finally {
                    zeroBytes(plaintext);
                    zeroBytes(encrypted.blob.bytes);
                }
            }
            if (pages.length === MAX_SHARED_SESSION_OFFER_PAGES || sourcePage.done) {
                if (pages.length > 0) {
                    const offerBytes = encodeSharedSessionHistoryOffer({
                        version: 1,
                        shareId: this.shareId,
                        groupId: this.groupId,
                        throughSequence: afterSequence,
                        pages,
                        ...(previous === undefined ? {} : { previous }),
                    });
                    const encryptedOffer = encryptFile(offerBytes, {
                        name: `murmur-shared-session-offer-${afterSequence}.json`,
                        mediaType: "application/vnd.murmur.shared-session-offer+json",
                    });
                    try {
                        await this.client.putBlob(encryptedOffer.blob.bytes);
                        previous = encryptedOffer.descriptor;
                        pages = [];
                    } finally {
                        zeroBytes(offerBytes);
                        zeroBytes(encryptedOffer.blob.bytes);
                    }
                }
                if (sourcePage.done) {
                    return {
                        ...(previous === undefined ? {} : { offer: previous }),
                        throughSequence: afterSequence,
                    };
                }
            }
        }
    }

    private beginOperation(): void {
        if (this.#operationPending) {
            throw new Error("Shared-session owner operation is already in progress");
        }
        this.#operationPending = true;
    }

    private endOperation(): void {
        this.#operationPending = false;
    }
}

/** Friend-side replica and authenticated text-post capability. */
export class SharedSessionMember extends SharedSessionBase {
    private constructor(
        options: SharedSessionMemberOptions,
        record: DurableSharedSessionRecord,
        channel: MlsGroupChannel,
    ) {
        super(options, record, channel);
    }

    /** Verify, atomically adopt, persist, and subscribe one owner invitation. */
    static async join(options: SharedSessionJoinOptions): Promise<SharedSessionMember> {
        const invitation = decodeSharedSessionInvitation(options.invitation, options.expectedOwner);
        const localId = identityId(options.identity);
        if (
            invitation.recipientId !== localId ||
            invitation.grant.peerId !== localId ||
            !equalBytes(
                mlsKeyPackageReference(options.keyPackageBundle.keyPackage),
                invitation.keyPackageReference,
            )
        ) {
            throw new Error("Shared-session invitation is not for this KeyPackage identity");
        }
        const tree = decodeMlsRatchetTree(invitation.tree, {
            groupId: invitation.groupId,
            authenticateCredential: authenticateMurmurMlsCredential,
        });
        const epoch = joinMlsGroupFromWelcome({
            identity: options.identity,
            inviter: options.expectedOwner,
            groupId: invitation.groupId,
            welcome: invitation.welcome,
            tree,
            keyPackageBundle: options.keyPackageBundle,
        });
        const channel = new MlsGroupChannel(epoch, [invitation.commitFingerprint]);
        const key = recordKey(localId, invitation.shareId);
        if (
            (await options.store.get(key)) !== undefined ||
            (await options.store.get(terminalKey(localId, invitation.shareId))) !== undefined
        ) {
            channel.destroy();
            throw new SharedSessionIdentityCollisionError();
        }
        const epochState = channel.serializeEpoch();
        const record: DurableSharedSessionRecord = {
            role: "member",
            state: copyState(invitation.state),
            owner: copyIdentity(options.expectedOwner),
            epochState,
            persistenceGeneration: channel.persistenceGeneration,
            appliedCommitFingerprints: channel.appliedCommitFingerprints,
            appliedApplicationFingerprints: [],
            maximumSequence: 0,
            internalStatus: "active",
            stateDirty: false,
            pendingRemovePeerIds: [],
            ...(invitation.historyOffer === undefined
                ? {}
                : {
                      history: {
                          discovery: invitation.historyOffer,
                          offerCount: 0,
                          pageIndex: 0,
                          highestSequence: 0,
                          pendingEntries: [],
                      },
                  }),
        };
        try {
            await options.store.transaction(async (transaction) => {
                if ((await transaction.get(key)) !== undefined) {
                    throw new SharedSessionIdentityCollisionError();
                }
                const binding = await transaction.get(bindingKey(localId, invitation.shareId));
                if (binding === undefined) {
                    await transaction.set(
                        bindingKey(localId, invitation.shareId),
                        bindingBytes(invitation.state),
                    );
                } else {
                    validateBinding(binding, invitation.state);
                }
                await transaction.set(key, encodeDurableSharedSessionRecord(record));
                await options.callbacks.persistState(transaction, invitation.state);
            });
            const session = new SharedSessionMember(options, record, channel);
            await session.subscribe();
            return session;
        } catch (error: unknown) {
            channel.destroy();
            throw error;
        } finally {
            zeroBytes(epochState);
        }
    }

    /** Restore one active friend replica and its bounded backfill checkpoint. */
    static async load(
        shareId: string,
        options: SharedSessionMemberOptions,
    ): Promise<SharedSessionMember> {
        validateSharedSessionShareId(shareId);
        const bytes = await options.store.get(recordKey(identityId(options.identity), shareId));
        if (bytes === undefined) {
            throw new Error("Shared-session member state was not found");
        }
        let record: DurableSharedSessionRecord;
        try {
            record = decodeDurableSharedSessionRecord(bytes);
        } finally {
            zeroBytes(bytes);
        }
        if (record.role !== "member" || record.state.shareId !== shareId) {
            throw new SharedSessionIdentityCollisionError();
        }
        const epoch = MlsEpochState.deserialize(record.epochState, {
            localSigningSecretKey: options.identity.signingSecretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            minimumPersistenceGeneration: record.persistenceGeneration,
        });
        const channel = new MlsGroupChannel(
            epoch,
            record.appliedCommitFingerprints,
            record.appliedApplicationFingerprints,
        );
        if (encodeBase64Url(channel.groupId) !== record.state.groupId) {
            channel.destroy();
            throw new SharedSessionIdentityCollisionError();
        }
        const binding = await options.store.get(bindingKey(identityId(options.identity), shareId));
        if (binding === undefined) {
            channel.destroy();
            throw new SharedSessionIdentityCollisionError();
        }
        validateBinding(binding, record.state);
        const session = new SharedSessionMember(options, record, channel);
        await session.subscribe();
        return session;
    }

    /** Publish one caller-stable authenticated text post to the owner. */
    async post(
        postId: string,
        text: string,
        timestamp: number = this.now(),
    ): Promise<SharedSessionPost> {
        this.ensureActive();
        const grant = this.record.state.members.find(
            (member) => member.peerId === this.localId && member.status === "active",
        );
        if (grant === undefined) {
            throw new Error("Local identity has no active shared-session grant");
        }
        const post: SharedSessionPost = {
            shareId: this.shareId,
            authenticatedPeerId: this.localId,
            shareMemberId: grant.shareMemberId,
            grantEpoch: grant.grantEpoch,
            postId,
            timestamp,
            text,
        };
        const frame = encodeSharedSessionPostFrame(this.channel.groupId, post);
        try {
            await this.prepareApplication(frame, async (transaction, record) => {
                await this.callbacks.persistPost(transaction, post);
                return record;
            });
            return post;
        } finally {
            zeroBytes(frame);
        }
    }
}
