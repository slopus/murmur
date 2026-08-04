import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import type { MurmurGroup, MurmurGroupEvent, MurmurStore } from "@slopus/murmur";
import {
    ChatAlreadyOpenError,
    ChatAttachmentAuthenticationError,
    ChatAttachmentSourceChangedError,
    ChatClosedError,
    ChatCodecError,
    ChatFrameTooLargeError,
    ChatOutboxFailedError,
    ChatStoreCorruptionError,
    ChatValidationError,
} from "../errors.js";
import type {
    ChatAttachment,
    ChatAttachmentInput,
    ChatChange,
    ChatConversation,
    ChatDownloadOptions,
    ChatHistoryItem,
    ChatHistoryPage,
    ChatMessage,
    ChatOutboxEntry,
    ChatServiceOptions,
    ChatSyncOptions,
} from "../types.js";
import {
    clearAttachmentStage,
    hashAttachmentSource,
    openVerifiedAttachment,
    stageAttachment,
    uploadStagedAttachment,
    verifyManifestShape,
} from "./attachmentCrypto.js";
import { abortError, encodeBase64Url, ensureNotAborted, equalBytes, sequenceKey } from "./bytes.js";
import {
    ATTACHMENT_CHUNK_BYTES,
    CHAT_PREFIX,
    chatDescriptor,
    decodeCursor,
    decodeFrame,
    decodeOutbox,
    decodeProjection,
    encodeCursor,
    encodeFrame,
    encodeOutbox,
    encodeProjection,
    FILE_ID_BYTES,
    type EncodedAttachmentIntent,
    type EncodedManifest,
    GROUP_ID_BYTES,
    HASH_BYTES,
    IDENTITY_BYTES,
    isChatDescriptor,
    KEY_BYTES,
    MAXIMUM_ATTACHMENTS,
    MAXIMUM_ATTACHMENT_BYTES,
    MAXIMUM_FRAME_BYTES,
    MESSAGE_ID_BYTES,
    type OutboxRecord,
} from "./codec.js";

const OUTBOX_PREFIX = `${CHAT_PREFIX}outbox/`;
const PROJECTION_PREFIX = `${CHAT_PREFIX}projection/`;
const CURSOR_PREFIX = `${CHAT_PREFIX}cursor/`;
const DEDUPE_PREFIX = `${CHAT_PREFIX}dedupe/`;
const DELIVERED_PREFIX = `${CHAT_PREFIX}delivered/`;
const QUARANTINE_PREFIX = `${CHAT_PREFIX}quarantine/`;
const DIAGNOSTIC_PREFIX = `${CHAT_PREFIX}diagnostics/`;
const REBUILD_PREFIX = `${CHAT_PREFIX}rebuild/`;
const STAGING_PREFIX = `${CHAT_PREFIX}staging/`;
const ENQUEUE_COUNTER_KEY = `${CHAT_PREFIX}meta/enqueue-sequence`;
const STORE_PAGE = 64;
const GROUP_PAGE = 100;
const QUARANTINE_SLOTS = 64n;
const DEFAULT_DOWNLOAD_MAXIMUM = 16 * 1024 * 1024;
const DEFAULT_OPERATION_TIMEOUT = 30_000;
const CONSTRUCTOR_TOKEN = Symbol("ChatService");
const activeStores = new WeakSet<object>();

/**
 * Durable generic chat semantics over opaque Murmur MLS group streams.
 *
 * The service does not own or close the supplied Murmur. One live service per
 * store object is allowed in the current JavaScript realm.
 */
export class ChatService<TMessage, TAttachmentMetadata> {
    readonly #options: ChatServiceOptions<TMessage, TAttachmentMetadata>;
    readonly #abort = new AbortController();
    readonly #listeners = new Set<(change: ChatChange) => void>();
    readonly #idlePollMilliseconds: number;
    readonly #operationTimeoutMilliseconds: number;
    #workTail: Promise<void> = Promise.resolve();
    #workerPromise: Promise<void> | undefined;
    #timer: ReturnType<typeof setTimeout> | undefined;
    #wakeRequested = false;
    #closing = false;
    #closed = false;
    #closePromise: Promise<void> | undefined;
    #convergenceError: Error | undefined;
    #backoffMilliseconds = 100;

    private constructor(token: symbol, options: ChatServiceOptions<TMessage, TAttachmentMetadata>) {
        if (token !== CONSTRUCTOR_TOKEN) {
            throw new ChatValidationError("Use ChatService.open()");
        }
        this.#options = options;
        this.#idlePollMilliseconds = options.idlePollMilliseconds ?? 250;
        this.#operationTimeoutMilliseconds =
            options.operationTimeoutMilliseconds ?? DEFAULT_OPERATION_TIMEOUT;
    }

    /** Validate options, detect duplicate instances, and start convergence. */
    static async open<TMessage, TAttachmentMetadata>(
        options: ChatServiceOptions<TMessage, TAttachmentMetadata>,
    ): Promise<ChatService<TMessage, TAttachmentMetadata>> {
        validateOptions(options);
        const storeObject = options.store as object;
        if (activeStores.has(storeObject)) {
            throw new ChatAlreadyOpenError("A ChatService already owns this store namespace");
        }
        activeStores.add(storeObject);
        try {
            const counter = await options.store.get(ENQUEUE_COUNTER_KEY);
            if (counter !== undefined) decodeCursor(counter);
            const service = new ChatService(CONSTRUCTOR_TOKEN, options);
            service.#schedule(0);
            return service;
        } catch (error: unknown) {
            activeStores.delete(storeObject);
            if (error instanceof ChatStoreCorruptionError) throw error;
            throw error;
        }
    }

    /** Defensive copy of the local authenticated Murmur identity key. */
    get identityKey(): Uint8Array {
        this.#ensureOpen();
        return this.#options.murmur.identityKey;
    }

    /** Last infrastructure convergence error; per-intent errors live in outbox state. */
    get convergenceError(): Error | undefined {
        this.#ensureOpen();
        return this.#convergenceError;
    }

    /** Create a fresh opaque chat group. */
    async createConversation(members: readonly Uint8Array[] = []): Promise<Uint8Array> {
        this.#ensureOpen();
        validateMembers(members);
        const id = await this.#options.murmur.groups.create(chatDescriptor(), members);
        this.#emit({ kind: "conversation", conversationId: id });
        this.#wake();
        return id.slice();
    }

    /** List only strict version-one chat descriptors. */
    async listConversations(): Promise<readonly ChatConversation[]> {
        this.#ensureOpen();
        const groups = await this.#options.murmur.groups.list();
        return groups.filter((group) => isChatDescriptor(group.descriptor)).map(conversationView);
    }

    /** Read one chat conversation. */
    async getConversation(conversationId: Uint8Array): Promise<ChatConversation | undefined> {
        this.#ensureOpen();
        validateConversationId(conversationId);
        const page = await this.#options.murmur.groups.get(conversationId, { limit: 1 });
        return page === undefined || !isChatDescriptor(page.group.descriptor)
            ? undefined
            : conversationView(page.group);
    }

    /** Add a member only while the local conversation is active. */
    async addMember(conversationId: Uint8Array, identityKey: Uint8Array): Promise<void> {
        this.#ensureOpen();
        validateConversationId(conversationId);
        validateIdentity(identityKey);
        await this.#requireActiveConversation(conversationId);
        await this.#options.murmur.groups.add(conversationId, identityKey);
        this.#emit({ kind: "conversation", conversationId });
        this.#wake();
    }

    /** Remove a member only while the local conversation is active. */
    async removeMember(conversationId: Uint8Array, identityKey: Uint8Array): Promise<void> {
        this.#ensureOpen();
        validateConversationId(conversationId);
        validateIdentity(identityKey);
        await this.#requireActiveConversation(conversationId);
        await this.#options.murmur.groups.remove(conversationId, identityKey);
        this.#emit({ kind: "conversation", conversationId });
        this.#wake();
    }

    /**
     * Durably enqueue in a transactionally allocated monotonic order.
     *
     * `messageId` is retry/dedupe material, not globally unique event identity.
     */
    async send(
        conversationId: Uint8Array,
        input: {
            readonly message: TMessage;
            readonly attachments?: readonly ChatAttachmentInput<TAttachmentMetadata>[];
            readonly claimedAt?: number;
        },
    ): Promise<Uint8Array> {
        this.#ensureOpen();
        validateConversationId(conversationId);
        await this.#requireActiveConversation(conversationId);
        const attachments = input.attachments ?? [];
        if (!Array.isArray(attachments) || attachments.length > MAXIMUM_ATTACHMENTS) {
            throw new ChatValidationError(
                `A message may contain at most ${MAXIMUM_ATTACHMENTS} attachments`,
            );
        }
        const body = this.#encodeMessage(input.message);
        const messageId = randomBytes(MESSAGE_ID_BYTES);
        const claimedAt = input.claimedAt ?? Date.now();
        if (!Number.isSafeInteger(claimedAt) || claimedAt < 0) {
            body.fill(0);
            messageId.fill(0);
            throw new ChatValidationError("claimedAt must be a non-negative safe integer");
        }
        const intents: EncodedAttachmentIntent[] = [];
        const operation = this.#operation(this.#abort.signal);
        try {
            for (const attachment of attachments) {
                validateAttachmentInput(attachment);
                const metadata = this.#encodeMetadata(attachment.metadata);
                let source;
                try {
                    source = await this.#options.resolveAttachmentSource(
                        attachment.sourceId,
                        operation.signal,
                    );
                } catch (error: unknown) {
                    metadata.fill(0);
                    throw outboxFailure("source-unavailable", error);
                }
                if (
                    source.sourceId !== attachment.sourceId ||
                    !Number.isSafeInteger(source.byteLength) ||
                    source.byteLength < 0 ||
                    source.byteLength > MAXIMUM_ATTACHMENT_BYTES
                ) {
                    metadata.fill(0);
                    throw new ChatValidationError("Invalid attachment source");
                }
                const sourceHash = await hashAttachmentSource(source, operation.signal);
                intents.push({
                    stageState: "new",
                    sourceId: attachment.sourceId,
                    metadata,
                    fileId: randomBytes(FILE_ID_BYTES),
                    fileKey: randomBytes(KEY_BYTES),
                    sourceHash,
                    plaintextLength: source.byteLength,
                });
            }
            preflightFrame(messageId, claimedAt, body, intents);
            let enqueueSequence = 0n;
            await this.#options.store.transaction(async (transaction) => {
                const counter = await transaction.get(ENQUEUE_COUNTER_KEY);
                const current = counter === undefined ? 0n : decodeCursor(counter);
                enqueueSequence = current + 1n;
                const record: OutboxRecord = {
                    status: intents.length === 0 ? "ready" : "preparing",
                    enqueueSequence,
                    conversationId: conversationId.slice(),
                    messageId: messageId.slice(),
                    claimedAt,
                    body: body.slice(),
                    attachments: intents,
                };
                if (record.status === "ready") {
                    record.frameDigest = frameDigest(record);
                }
                const encoded = encodeOutbox(record);
                try {
                    await transaction.set(ENQUEUE_COUNTER_KEY, encodeCursor(enqueueSequence));
                    await transaction.set(outboxKey(enqueueSequence, messageId), encoded);
                } finally {
                    encoded.fill(0);
                    zeroOutbox(record);
                }
            });
            this.#emit({ kind: "outbox", conversationId });
            this.#wake();
            return messageId.slice();
        } finally {
            operation.dispose();
            body.fill(0);
            messageId.fill(0);
            for (const intent of intents) zeroIntent(intent);
        }
    }

    /** Canonical relay-sequence history, including explicit unknown variants. */
    async history(
        conversationId: Uint8Array,
        options: { readonly after?: bigint; readonly limit?: number } = {},
    ): Promise<ChatHistoryPage<TMessage, TAttachmentMetadata>> {
        this.#ensureOpen();
        validateConversationId(conversationId);
        await this.#requireConversation(conversationId);
        const after = options.after ?? 0n;
        const limit = options.limit ?? 64;
        if (after < 0n || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
            throw new ChatValidationError("Invalid history page");
        }
        const prefix = projectionPrefix(conversationId);
        const entries = await this.#options.store.scan(
            prefix,
            after === 0n
                ? { limit: limit + 1 }
                : { after: `${prefix}${sequenceKey(after)}`, limit: limit + 1 },
        );
        const messages: ChatHistoryItem<TMessage, TAttachmentMetadata>[] = [];
        for (const [key, encoded] of [...entries].slice(0, limit)) {
            const sequence = BigInt(`0x${key.slice(prefix.length)}`);
            try {
                messages.push(this.#decodeProjected(conversationId, sequence, encoded));
            } catch (error: unknown) {
                messages.push({
                    kind: "unknown",
                    eventId: eventId(conversationId, sequence),
                    conversationId: conversationId.slice(),
                    sequence,
                    rawFrame: encoded.slice(),
                    reason: boundedErrorMessage(error),
                });
                if (error instanceof ChatStoreCorruptionError) {
                    await this.#options.store.set(rebuildKey(conversationId), encodeCursor(1n));
                    this.#wake();
                }
            }
        }
        const last = messages.at(-1);
        return {
            messages,
            ...(entries.size > limit && last !== undefined ? { nextAfter: last.sequence } : {}),
        };
    }

    /** Page every durable intent in monotonic enqueue order. */
    async outbox(): Promise<readonly ChatOutboxEntry[]> {
        this.#ensureOpen();
        const result: ChatOutboxEntry[] = [];
        let after: string | undefined;
        for (;;) {
            const page = await this.#options.store.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: STORE_PAGE,
            });
            for (const [key, bytes] of page) {
                after = key;
                try {
                    const record = decodeOutbox(bytes);
                    result.push(outboxView(record));
                    zeroOutbox(record);
                } catch {
                    await this.#isolateCorruptOutbox(key, bytes);
                }
            }
            if (page.size < STORE_PAGE) break;
        }
        return result;
    }

    /** Retry one failed intent; unsafe partial staging rotates key and file ID. */
    async retry(messageId: Uint8Array): Promise<void> {
        await this.#workExclusive(() => this.#retry(messageId));
    }

    async #retry(messageId: Uint8Array): Promise<void> {
        this.#ensureOpen();
        validateMessageId(messageId);
        const found = await this.#findOutbox(messageId);
        if (found === undefined) throw new ChatValidationError("Outbox message not found");
        const { key, record } = found;
        try {
            if (record.status !== "failed") {
                throw new ChatValidationError("Only failed outbox entries can be retried");
            }
            await this.#requireActiveConversation(record.conversationId);
            const needsFreshSource = record.attachments.some(
                (attachment) =>
                    attachment.stageState === "staging" ||
                    record.lastError?.code === "source-changed" ||
                    record.lastError?.code === "source-unavailable" ||
                    record.lastError?.code === "operation-timeout",
            );
            if (needsFreshSource) {
                const operation = this.#operation(this.#abort.signal);
                try {
                    for (let index = 0; index < record.attachments.length; index += 1) {
                        const attachment = record.attachments[index]!;
                        if (attachment.stageState === "uploaded") continue;
                        const source = await this.#options.resolveAttachmentSource(
                            attachment.sourceId,
                            operation.signal,
                        );
                        if (
                            source.sourceId !== attachment.sourceId ||
                            source.byteLength > MAXIMUM_ATTACHMENT_BYTES
                        ) {
                            throw new ChatAttachmentSourceChangedError(
                                "Resolved attachment source identity or length is invalid",
                            );
                        }
                        const digest = await hashAttachmentSource(source, operation.signal);
                        await clearAttachmentStage(
                            this.#options.store,
                            attachmentStagePrefix(record, index),
                        );
                        attachment.fileId.fill(0);
                        attachment.fileKey.fill(0);
                        attachment.sourceHash.fill(0);
                        if (attachment.manifest !== undefined) {
                            zeroManifest(attachment.manifest);
                        }
                        attachment.fileId = randomBytes(FILE_ID_BYTES);
                        attachment.fileKey = randomBytes(KEY_BYTES);
                        attachment.sourceHash = digest;
                        attachment.plaintextLength = source.byteLength;
                        delete attachment.manifest;
                        attachment.stageState = "new";
                    }
                } finally {
                    operation.dispose();
                }
            }
            record.status = record.attachments.length === 0 ? "ready" : "preparing";
            delete record.lastError;
            if (record.status === "ready") record.frameDigest = frameDigest(record);
            await this.#persistOutbox(key, record);
            this.#emit({ kind: "outbox", conversationId: record.conversationId });
            this.#wake();
        } finally {
            zeroOutbox(record);
        }
    }

    /** Cancel and durably drop one unsent or failed intent. */
    async cancel(messageId: Uint8Array): Promise<void> {
        await this.#workExclusive(() => this.#cancel(messageId));
    }

    async #cancel(messageId: Uint8Array): Promise<void> {
        this.#ensureOpen();
        validateMessageId(messageId);
        const found = await this.#findOutbox(messageId);
        if (found === undefined) return;
        try {
            if (found.record.status === "handed-off") {
                throw new ChatValidationError(
                    "A handed-off Murmur event can no longer be cancelled",
                );
            }
            for (let index = 0; index < found.record.attachments.length; index += 1) {
                await clearAttachmentStage(
                    this.#options.store,
                    attachmentStagePrefix(found.record, index),
                );
            }
            await this.#options.store.delete(found.key);
            this.#emit({ kind: "outbox", conversationId: found.record.conversationId });
        } finally {
            zeroOutbox(found.record);
        }
    }

    /** Alias for `cancel`. */
    async drop(messageId: Uint8Array): Promise<void> {
        await this.cancel(messageId);
    }

    /**
     * Atomically mark derived state for reset, page-delete it, then refold.
     * Interrupted rebuild markers are resumed by the worker.
     */
    async rebuild(conversationId?: Uint8Array): Promise<void> {
        await this.#workExclusive(() => this.#rebuild(conversationId));
        await this.sync();
    }

    async #rebuild(conversationId?: Uint8Array): Promise<void> {
        this.#ensureOpen();
        const ids =
            conversationId === undefined
                ? (await this.listConversations()).map((conversation) => conversation.id)
                : [conversationId.slice()];
        for (const id of ids) {
            validateConversationId(id);
            await this.#requireConversation(id);
            await this.#options.store.set(rebuildKey(id), encodeCursor(1n));
            await this.#finishRebuild(id);
        }
    }

    /** Stream verified plaintext chunks under the operation deadline. */
    openAttachment(
        attachment: ChatAttachment<TAttachmentMetadata>,
        options: { readonly signal?: AbortSignal } = {},
    ): AsyncIterable<Uint8Array> {
        this.#ensureOpen();
        validateAttachmentObject(attachment);
        const metadata = this.#encodeMetadata(attachment.metadata);
        const createOperation = (): { signal: AbortSignal; dispose: () => void } =>
            this.#operation(options.signal ?? this.#abort.signal);
        const blobStore = this.#options.blobStore;
        return (async function* (): AsyncIterable<Uint8Array> {
            let manifest: EncodedManifest | undefined;
            let operation: { signal: AbortSignal; dispose: () => void } | undefined;
            let iterator: AsyncIterator<Uint8Array> | undefined;
            try {
                manifest = publicAttachmentManifest(attachment, metadata);
                operation = createOperation();
                iterator = openVerifiedAttachment(
                    manifest,
                    attachment.conversationId,
                    attachment.sender,
                    blobStore,
                    operation.signal,
                )[Symbol.asyncIterator]();
                for (;;) {
                    const next = await iterator.next();
                    if (next.done === true) break;
                    yield next.value;
                }
            } finally {
                await iterator?.return?.();
                operation?.dispose();
                if (manifest !== undefined) zeroManifest(manifest);
                else metadata.fill(0);
            }
        })();
    }

    /** Download a whole attachment under an explicit bounded allocation cap. */
    async downloadAttachment(
        attachment: ChatAttachment<TAttachmentMetadata>,
        options: ChatDownloadOptions = {},
    ): Promise<Uint8Array> {
        this.#ensureOpen();
        validateAttachmentObject(attachment);
        const maximumBytes = options.maximumBytes ?? DEFAULT_DOWNLOAD_MAXIMUM;
        if (
            !Number.isSafeInteger(maximumBytes) ||
            maximumBytes < 0 ||
            maximumBytes > MAXIMUM_ATTACHMENT_BYTES ||
            attachment.plaintextLength > maximumBytes
        ) {
            throw new ChatValidationError("Attachment exceeds bounded download maximum");
        }
        const result = new Uint8Array(attachment.plaintextLength);
        let offset = 0;
        try {
            for await (const chunk of this.openAttachment(
                attachment,
                options.signal === undefined ? {} : { signal: options.signal },
            )) {
                if (chunk.length > result.length - offset) {
                    chunk.fill(0);
                    throw new ChatAttachmentAuthenticationError(
                        "Authenticated stream exceeded plaintext length",
                    );
                }
                result.set(chunk, offset);
                offset += chunk.length;
                chunk.fill(0);
            }
            if (offset !== result.length) {
                throw new ChatAttachmentAuthenticationError("Authenticated stream was truncated");
            }
            return result;
        } catch (error: unknown) {
            result.fill(0);
            throw error;
        }
    }

    /** Subscribe to coalescible changes. */
    onChange(listener: (change: ChatChange) => void): () => void {
        this.#ensureOpen();
        if (typeof listener !== "function") throw new ChatValidationError("Invalid listener");
        this.#listeners.add(listener);
        return (): void => {
            this.#listeners.delete(listener);
        };
    }

    /** Run a serialized worker boundary without blocking read APIs. */
    async sync(options: ChatSyncOptions = {}): Promise<void> {
        this.#ensureOpen();
        await this.#workExclusive(async () => {
            const signal = options.signal ?? this.#abort.signal;
            ensureNotAborted(signal);
            await this.#options.murmur.sync({ signal });
            for (let pass = 0; pass < 4; pass += 1) {
                const changed = await this.#converge(signal);
                if (!changed) break;
                await this.#options.murmur.sync({ signal });
            }
            await this.#project(signal);
            this.#convergenceError = undefined;
            this.#backoffMilliseconds = 100;
        });
    }

    /** Abort chat/blob work; the supplied Murmur remains open. */
    async close(): Promise<void> {
        if (this.#closePromise !== undefined) return this.#closePromise;
        this.#closing = true;
        if (this.#timer !== undefined) clearTimeout(this.#timer);
        this.#abort.abort(new ChatClosedError("Chat service is closing"));
        this.#closePromise = (async (): Promise<void> => {
            await this.#workerPromise;
            await this.#workTail;
            this.#listeners.clear();
            activeStores.delete(this.#options.store as object);
            this.#closed = true;
        })();
        return this.#closePromise;
    }

    async #converge(signal: AbortSignal): Promise<boolean> {
        let changed = false;
        let after: string | undefined;
        for (;;) {
            ensureNotAborted(signal);
            const page = await this.#options.store.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: STORE_PAGE,
            });
            for (const [key, bytes] of page) {
                after = key;
                let record: OutboxRecord;
                try {
                    record = decodeOutbox(bytes);
                } catch {
                    await this.#isolateCorruptOutbox(key, bytes);
                    changed = true;
                    continue;
                }
                try {
                    if (record.status === "failed") continue;
                    const conversation = await this.#requireConversation(record.conversationId);
                    if (conversation.status !== "active") {
                        await this.#failOutbox(
                            key,
                            record,
                            "group-removed",
                            "Conversation is removed",
                        );
                        changed = true;
                        continue;
                    }
                    if (record.status === "preparing") {
                        await this.#prepareRecord(key, record, signal);
                        changed = true;
                    }
                    if (record.status === "ready") {
                        const frame = encodeRecordFrame(record);
                        try {
                            await this.#options.murmur.groups.send(record.conversationId, frame);
                        } finally {
                            frame.fill(0);
                        }
                        record.status = "handed-off";
                        await this.#persistOutbox(key, record);
                        changed = true;
                    }
                    if (record.status === "handed-off" && record.frameDigest !== undefined) {
                        const delivered = deliveredKey(
                            record.conversationId,
                            record.messageId,
                            record.frameDigest,
                        );
                        if ((await this.#options.store.get(delivered)) !== undefined) {
                            await this.#options.store.transaction(async (transaction) => {
                                await transaction.delete(key);
                                await transaction.delete(delivered);
                            });
                            changed = true;
                        }
                    }
                    this.#emit({ kind: "outbox", conversationId: record.conversationId });
                } catch (error: unknown) {
                    if (signal.aborted) throw abortError(signal);
                    const failure = classifyOutboxFailure(error);
                    await this.#failOutbox(key, record, failure.code, failure.message);
                    changed = true;
                } finally {
                    zeroOutbox(record);
                }
            }
            if (page.size < STORE_PAGE) break;
        }
        if (await this.#project(signal)) changed = true;
        return changed;
    }

    async #prepareRecord(
        key: string,
        record: OutboxRecord,
        parentSignal: AbortSignal,
    ): Promise<void> {
        for (let index = 0; index < record.attachments.length; index += 1) {
            const attachment = record.attachments[index]!;
            const prefix = attachmentStagePrefix(record, index);
            if (attachment.stageState === "staging") {
                await clearAttachmentStage(this.#options.store, prefix);
                attachment.fileId.fill(0);
                attachment.fileKey.fill(0);
                attachment.fileId = randomBytes(FILE_ID_BYTES);
                attachment.fileKey = randomBytes(KEY_BYTES);
                if (attachment.manifest !== undefined) {
                    zeroManifest(attachment.manifest);
                }
                delete attachment.manifest;
                attachment.stageState = "new";
                await this.#persistOutbox(key, record);
            }
            if (attachment.stageState === "new") {
                const operation = this.#operation(parentSignal);
                try {
                    let source;
                    try {
                        source = await this.#options.resolveAttachmentSource(
                            attachment.sourceId,
                            operation.signal,
                        );
                    } catch (error: unknown) {
                        throw outboxFailure("source-unavailable", error);
                    }
                    await clearAttachmentStage(this.#options.store, prefix);
                    attachment.stageState = "staging";
                    await this.#persistOutbox(key, record);
                    attachment.manifest = await stageAttachment(
                        source,
                        attachment,
                        record.conversationId,
                        this.#options.murmur.identityKey,
                        this.#options.store,
                        prefix,
                        operation.signal,
                    );
                    attachment.stageState = "staged";
                    await this.#persistOutbox(key, record);
                } finally {
                    operation.dispose();
                }
            }
            if (attachment.stageState === "staged") {
                const operation = this.#operation(parentSignal);
                try {
                    await uploadStagedAttachment(
                        attachment.manifest!,
                        this.#options.store,
                        prefix,
                        this.#options.blobStore,
                        operation.signal,
                    );
                    attachment.stageState = "uploaded";
                    await this.#persistOutbox(key, record);
                    await clearAttachmentStage(this.#options.store, prefix);
                } finally {
                    operation.dispose();
                }
            }
        }
        record.status = "ready";
        delete record.lastError;
        record.frameDigest = frameDigest(record);
        await this.#persistOutbox(key, record);
    }

    async #project(signal: AbortSignal): Promise<boolean> {
        let changed = false;
        const groups = await this.#options.murmur.groups.list();
        for (const group of groups) {
            ensureNotAborted(signal);
            if (!isChatDescriptor(group.descriptor)) continue;
            try {
                if ((await this.#options.store.get(rebuildKey(group.id))) !== undefined) {
                    await this.#finishRebuild(group.id);
                }
                const cursorKey = groupCursorKey(group.id);
                const cursorBytes = await this.#options.store.get(cursorKey);
                let after = cursorBytes === undefined ? 0n : decodeCursor(cursorBytes);
                if (after > 0n) {
                    const projection = await this.#options.store.scan(projectionPrefix(group.id), {
                        limit: 1,
                    });
                    const quarantine = await this.#options.store.scan(quarantinePrefix(group.id), {
                        limit: 1,
                    });
                    if (projection.size === 0 && quarantine.size === 0) {
                        await this.#resetDerivedGroup(group.id);
                        after = 0n;
                    }
                }
                for (;;) {
                    const page = await this.#options.murmur.groups.get(group.id, {
                        after,
                        limit: GROUP_PAGE,
                    });
                    if (page === undefined || page.events.length === 0) break;
                    for (const event of page.events) {
                        ensureNotAborted(signal);
                        const accepted = await this.#projectEvent(group.id, event);
                        after = event.sequence;
                        changed = true;
                        if (accepted) {
                            this.#emit({ kind: "message", conversationId: group.id });
                        }
                    }
                    if (page.nextAfter === undefined) break;
                }
            } catch (error: unknown) {
                if (signal.aborted) throw error;
                await this.#diagnose("projection", sha256(group.id));
                if (error instanceof ChatStoreCorruptionError) {
                    await this.#resetDerivedGroup(group.id);
                    changed = true;
                }
            }
        }
        return changed;
    }

    async #projectEvent(conversationId: Uint8Array, event: MurmurGroupEvent): Promise<boolean> {
        let frame: ReturnType<typeof decodeFrame>;
        try {
            frame = decodeFrame(event.bytes);
            for (const manifest of frame.attachments) verifyManifestShape(manifest);
        } catch {
            const digest = sha256(event.bytes);
            await this.#options.store.transaction(async (transaction) => {
                await transaction.set(
                    quarantineKey(conversationId, event.sequence % QUARANTINE_SLOTS),
                    digest,
                );
                await transaction.set(groupCursorKey(conversationId), encodeCursor(event.sequence));
            });
            return false;
        }
        const digest = sha256(event.bytes);
        const dedupe = dedupeKey(conversationId, event.sender, frame.messageId, digest);
        const projection = projectionKey(conversationId, event.sequence);
        const ownEvent = equalBytes(event.sender, this.#options.murmur.identityKey);
        let accepted = false;
        await this.#options.store.transaction(async (transaction) => {
            const priorBytes = await transaction.get(dedupe);
            const priorSequence = priorBytes === undefined ? undefined : decodeCursor(priorBytes);
            const projected = await transaction.get(projection);
            if (priorSequence === undefined || priorSequence === event.sequence) {
                if (projected === undefined) {
                    await transaction.set(projection, encodeProjection(event.sender, event.bytes));
                    accepted = true;
                } else {
                    decodeProjection(projected);
                }
                await transaction.set(dedupe, encodeCursor(event.sequence));
            }
            if (ownEvent) {
                await transaction.set(
                    deliveredKey(conversationId, frame.messageId, digest),
                    encodeCursor(event.sequence),
                );
            }
            await transaction.set(groupCursorKey(conversationId), encodeCursor(event.sequence));
        });
        return accepted;
    }

    #decodeProjected(
        conversationId: Uint8Array,
        sequence: bigint,
        encoded: Uint8Array,
    ): ChatMessage<TMessage, TAttachmentMetadata> {
        const projection = decodeProjection(encoded);
        const frame = decodeFrame(projection.frame);
        const application = this.#decodeApplication(frame);
        return {
            kind: "message",
            eventId: eventId(conversationId, sequence),
            conversationId: conversationId.slice(),
            sequence,
            sender: projection.sender.slice(),
            messageId: frame.messageId.slice(),
            claimedAt: frame.claimedAt,
            message: application.message,
            attachments: frame.attachments.map((manifest, index) => ({
                metadata: application.metadata[index]!,
                fileId: manifest.fileId.slice(),
                blobId: manifest.blobId.slice(),
                plaintextLength: manifest.plaintextLength,
                chunkSize: manifest.chunkSize,
                chunkCount: manifest.chunkCount,
                fileKey: manifest.fileKey.slice(),
                keyCommitment: manifest.commitment.slice(),
                conversationId: conversationId.slice(),
                sender: projection.sender.slice(),
            })),
        };
    }

    #decodeApplication(frame: ReturnType<typeof decodeFrame>): {
        message: TMessage;
        metadata: TAttachmentMetadata[];
    } {
        try {
            const message = this.#options.decodeMessage(frame.body.slice());
            const metadata = frame.attachments.map((manifest) =>
                this.#options.decodeAttachmentMetadata(manifest.metadata.slice()),
            );
            return { message, metadata };
        } catch (error: unknown) {
            throw new ChatCodecError(
                error instanceof Error
                    ? `Application codec rejected frame: ${error.message}`
                    : "Application codec rejected frame",
            );
        }
    }

    #encodeMessage(message: TMessage): Uint8Array {
        try {
            const bytes = this.#options.encodeMessage(message);
            if (!(bytes instanceof Uint8Array)) {
                throw new ChatValidationError("Message encoder did not return Uint8Array");
            }
            if (bytes.length > MAXIMUM_FRAME_BYTES) {
                throw new ChatFrameTooLargeError("Message body exceeds Murmur's frame bound");
            }
            return bytes.slice();
        } catch (error: unknown) {
            if (error instanceof ChatFrameTooLargeError || error instanceof ChatValidationError) {
                throw error;
            }
            throw new ChatCodecError(
                error instanceof Error ? error.message : "Message encoding failed",
            );
        }
    }

    #encodeMetadata(metadata: TAttachmentMetadata): Uint8Array {
        try {
            const bytes = this.#options.encodeAttachmentMetadata(metadata);
            if (!(bytes instanceof Uint8Array) || bytes.length > MAXIMUM_FRAME_BYTES) {
                throw new ChatValidationError("Invalid encoded attachment metadata");
            }
            return bytes.slice();
        } catch (error: unknown) {
            if (error instanceof ChatValidationError) throw error;
            throw new ChatCodecError(
                error instanceof Error ? error.message : "Metadata encoding failed",
            );
        }
    }

    async #findOutbox(
        messageId: Uint8Array,
    ): Promise<{ key: string; record: OutboxRecord } | undefined> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#options.store.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: STORE_PAGE,
            });
            for (const [key, encoded] of page) {
                after = key;
                let record: OutboxRecord;
                try {
                    record = decodeOutbox(encoded);
                } catch {
                    await this.#isolateCorruptOutbox(key, encoded);
                    continue;
                }
                if (equalBytes(record.messageId, messageId)) return { key, record };
                zeroOutbox(record);
            }
            if (page.size < STORE_PAGE) return undefined;
        }
    }

    async #failOutbox(
        key: string,
        record: OutboxRecord,
        code: string,
        message: string,
    ): Promise<void> {
        record.status = "failed";
        record.lastError = { code: code.slice(0, 128), message: message.slice(0, 1024) };
        await this.#persistOutbox(key, record);
        this.#emit({ kind: "outbox", conversationId: record.conversationId });
    }

    async #persistOutbox(key: string, record: OutboxRecord): Promise<void> {
        const encoded = encodeOutbox(record);
        try {
            await this.#options.store.set(key, encoded);
        } finally {
            encoded.fill(0);
        }
    }

    async #requireConversation(conversationId: Uint8Array): Promise<MurmurGroup> {
        const page = await this.#options.murmur.groups.get(conversationId, { limit: 1 });
        if (page === undefined || !isChatDescriptor(page.group.descriptor)) {
            throw new ChatValidationError("Chat conversation not found");
        }
        return page.group;
    }

    async #requireActiveConversation(conversationId: Uint8Array): Promise<MurmurGroup> {
        const group = await this.#requireConversation(conversationId);
        if (group.status !== "active") {
            throw new ChatValidationError("Chat conversation is not active");
        }
        return group;
    }

    async #finishRebuild(conversationId: Uint8Array): Promise<void> {
        for (const prefix of [
            projectionPrefix(conversationId),
            dedupePrefix(conversationId),
            deliveredPrefix(conversationId),
            quarantinePrefix(conversationId),
        ]) {
            await deletePrefix(this.#options.store, prefix);
        }
        await this.#options.store.transaction(async (transaction) => {
            await transaction.delete(groupCursorKey(conversationId));
            await transaction.delete(rebuildKey(conversationId));
        });
    }

    async #resetDerivedGroup(conversationId: Uint8Array): Promise<void> {
        await this.#options.store.set(rebuildKey(conversationId), encodeCursor(1n));
        await this.#finishRebuild(conversationId);
    }

    async #isolateCorruptOutbox(key: string, bytes: Uint8Array): Promise<void> {
        const digest = sha256(bytes);
        await this.#diagnose("outbox", digest);
        const suffix = key.slice(OUTBOX_PREFIX.length);
        if (/^[0-9a-f]{16}\/[A-Za-z0-9_-]{22}$/.test(suffix)) {
            await clearAttachmentStage(this.#options.store, `${STAGING_PREFIX}${suffix}/`);
        }
        await this.#options.store.delete(key);
    }

    async #diagnose(kind: string, digest: Uint8Array): Promise<void> {
        const slot = digest[0] ?? 0;
        await this.#options.store.set(
            `${DIAGNOSTIC_PREFIX}${kind}/${slot.toString(16).padStart(2, "0")}`,
            digest,
        );
    }

    #operation(parent: AbortSignal): { signal: AbortSignal; dispose: () => void } {
        const controller = new AbortController();
        const forward = (): void => controller.abort(parent.reason);
        if (parent.aborted) controller.abort(parent.reason);
        else parent.addEventListener("abort", forward, { once: true });
        const timer = setTimeout(
            () =>
                controller.abort(
                    new ChatOutboxFailedError(
                        "operation-timeout",
                        `Operation exceeded ${this.#operationTimeoutMilliseconds}ms`,
                    ),
                ),
            this.#operationTimeoutMilliseconds,
        );
        return {
            signal: controller.signal,
            dispose: (): void => {
                clearTimeout(timer);
                parent.removeEventListener("abort", forward);
            },
        };
    }

    #emit(change: ChatChange): void {
        const safe: ChatChange = {
            kind: change.kind,
            ...(change.conversationId === undefined
                ? {}
                : { conversationId: change.conversationId.slice() }),
        };
        for (const listener of this.#listeners) {
            try {
                listener(safe);
            } catch {
                // Listener failures cannot affect durable convergence.
            }
        }
    }

    #wake(): void {
        this.#wakeRequested = true;
        this.#schedule(0);
    }

    #schedule(delay: number): void {
        if (this.#closing || this.#closed || this.#workerPromise !== undefined) return;
        if (this.#timer !== undefined) clearTimeout(this.#timer);
        this.#timer = setTimeout(() => {
            this.#timer = undefined;
            this.#workerPromise = this.#workExclusive(async () => {
                this.#wakeRequested = false;
                try {
                    await this.#options.murmur.sync({ signal: this.#abort.signal });
                    await this.#converge(this.#abort.signal);
                    this.#convergenceError = undefined;
                    this.#backoffMilliseconds = 100;
                } catch (error: unknown) {
                    if (!this.#closing) {
                        this.#convergenceError =
                            error instanceof Error ? error : new Error("Chat convergence failed");
                        this.#emit({ kind: "error" });
                        this.#backoffMilliseconds = Math.min(this.#backoffMilliseconds * 2, 30_000);
                    }
                }
            })
                .catch((error: unknown) => {
                    if (!this.#closing) {
                        this.#convergenceError =
                            error instanceof Error ? error : new Error("Chat worker failed");
                    }
                })
                .finally(() => {
                    this.#workerPromise = undefined;
                    if (!this.#closing) {
                        this.#schedule(
                            this.#convergenceError === undefined
                                ? this.#wakeRequested
                                    ? 0
                                    : this.#idlePollMilliseconds
                                : this.#backoffMilliseconds,
                        );
                    }
                });
        }, delay);
    }

    async #workExclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#workTail;
        this.#workTail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await prior;
        try {
            this.#ensureOpen();
            return await operation();
        } finally {
            release?.();
        }
    }

    #ensureOpen(): void {
        if (this.#closing || this.#closed) throw new ChatClosedError("Chat service is closed");
    }
}

/** Explicitly zero a caller-owned attachment capability after use. */
export function destroyAttachment<TMetadata>(attachment: ChatAttachment<TMetadata>): void {
    validateAttachmentObject(attachment);
    attachment.fileKey.fill(0);
    attachment.fileId.fill(0);
    attachment.blobId.fill(0);
    attachment.keyCommitment.fill(0);
    attachment.conversationId.fill(0);
    attachment.sender.fill(0);
}

function preflightFrame(
    messageId: Uint8Array,
    claimedAt: number,
    body: Uint8Array,
    attachments: readonly EncodedAttachmentIntent[],
): void {
    const placeholders: EncodedManifest[] = attachments.map((attachment) => ({
        metadata: attachment.metadata,
        fileId: attachment.fileId,
        fileKey: attachment.fileKey,
        commitment: new Uint8Array(HASH_BYTES),
        blobId: new Uint8Array(HASH_BYTES),
        plaintextLength: attachment.plaintextLength,
        chunkSize: ATTACHMENT_CHUNK_BYTES,
        chunkCount: Math.max(1, Math.ceil(attachment.plaintextLength / ATTACHMENT_CHUNK_BYTES)),
    }));
    try {
        encodeFrame({ messageId, claimedAt, body, attachments: placeholders });
    } catch (error: unknown) {
        if (error instanceof ChatCodecError) {
            throw new ChatFrameTooLargeError(
                `Encoded chat frame exceeds ${MAXIMUM_FRAME_BYTES} bytes`,
            );
        }
        throw error;
    }
}

function frameDigest(record: OutboxRecord): Uint8Array {
    const frame = encodeRecordFrame(record);
    try {
        return sha256(frame);
    } finally {
        frame.fill(0);
    }
}

function encodeRecordFrame(record: OutboxRecord): Uint8Array {
    return encodeFrame({
        messageId: record.messageId,
        claimedAt: record.claimedAt,
        body: record.body,
        attachments: record.attachments.map((attachment) => attachment.manifest!),
    });
}

function outboxView(record: OutboxRecord): ChatOutboxEntry {
    return {
        enqueueSequence: record.enqueueSequence,
        conversationId: record.conversationId.slice(),
        messageId: record.messageId.slice(),
        status: record.status,
        attachmentCount: record.attachments.length,
        ...(record.lastError === undefined
            ? {}
            : {
                  lastError: {
                      code: record.lastError.code,
                      message: record.lastError.message,
                  },
              }),
    };
}

function conversationView(group: MurmurGroup): ChatConversation {
    return {
        id: group.id.slice(),
        members: group.members.map((member) => member.slice()),
        epoch: group.epoch,
        status: group.status,
    };
}

function validateOptions<TMessage, TMetadata>(
    options: ChatServiceOptions<TMessage, TMetadata>,
): void {
    if (
        options === null ||
        typeof options !== "object" ||
        options.murmur === null ||
        typeof options.murmur !== "object" ||
        options.store === null ||
        typeof options.store !== "object" ||
        options.blobStore === null ||
        typeof options.blobStore !== "object" ||
        typeof options.encodeMessage !== "function" ||
        typeof options.decodeMessage !== "function" ||
        typeof options.encodeAttachmentMetadata !== "function" ||
        typeof options.decodeAttachmentMetadata !== "function" ||
        typeof options.resolveAttachmentSource !== "function" ||
        typeof options.store.transaction !== "function" ||
        typeof options.store.scan !== "function" ||
        typeof options.blobStore.put !== "function" ||
        typeof options.blobStore.head !== "function" ||
        typeof options.blobStore.get !== "function"
    ) {
        throw new ChatValidationError("Invalid ChatService options");
    }
    const idle = options.idlePollMilliseconds ?? 250;
    const timeout = options.operationTimeoutMilliseconds ?? DEFAULT_OPERATION_TIMEOUT;
    if (
        !Number.isSafeInteger(idle) ||
        idle < 25 ||
        idle > 30_000 ||
        !Number.isSafeInteger(timeout) ||
        timeout < 25 ||
        timeout > 30_000
    ) {
        throw new ChatValidationError("Invalid chat worker timing options");
    }
}

function validateConversationId(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length !== GROUP_ID_BYTES) {
        throw new ChatValidationError("Conversation ID must contain 32 bytes");
    }
}

function validateIdentity(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) {
        throw new ChatValidationError("Identity key must contain 32 bytes");
    }
}

function validateMessageId(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length !== MESSAGE_ID_BYTES) {
        throw new ChatValidationError("Message ID must contain 16 bytes");
    }
}

function validateMembers(members: readonly Uint8Array[]): void {
    if (!Array.isArray(members)) throw new ChatValidationError("Members must be an array");
    for (const member of members) validateIdentity(member);
}

function validateAttachmentInput<TMetadata>(attachment: ChatAttachmentInput<TMetadata>): void {
    if (
        attachment === null ||
        typeof attachment !== "object" ||
        typeof attachment.sourceId !== "string" ||
        attachment.sourceId.length === 0 ||
        new TextEncoder().encode(attachment.sourceId).length > 4096
    ) {
        throw new ChatValidationError("Attachment sourceId must be non-empty and bounded");
    }
}

function outboxKey(sequence: bigint, messageId: Uint8Array): string {
    return `${OUTBOX_PREFIX}${sequenceKey(sequence)}/${encodeBase64Url(messageId)}`;
}

function projectionPrefix(conversationId: Uint8Array): string {
    return `${PROJECTION_PREFIX}${encodeBase64Url(conversationId)}/`;
}

function projectionKey(conversationId: Uint8Array, sequence: bigint): string {
    return `${projectionPrefix(conversationId)}${sequenceKey(sequence)}`;
}

function groupCursorKey(conversationId: Uint8Array): string {
    return `${CURSOR_PREFIX}${encodeBase64Url(conversationId)}`;
}

function dedupePrefix(conversationId: Uint8Array): string {
    return `${DEDUPE_PREFIX}${encodeBase64Url(conversationId)}/`;
}

function dedupeKey(
    conversationId: Uint8Array,
    sender: Uint8Array,
    messageId: Uint8Array,
    digest: Uint8Array,
): string {
    return `${dedupePrefix(conversationId)}${encodeBase64Url(sender)}/${encodeBase64Url(messageId)}/${encodeBase64Url(digest)}`;
}

function deliveredPrefix(conversationId: Uint8Array): string {
    return `${DELIVERED_PREFIX}${encodeBase64Url(conversationId)}/`;
}

function deliveredKey(
    conversationId: Uint8Array,
    messageId: Uint8Array,
    digest: Uint8Array,
): string {
    return `${deliveredPrefix(conversationId)}${encodeBase64Url(messageId)}/${encodeBase64Url(digest)}`;
}

function quarantinePrefix(conversationId: Uint8Array): string {
    return `${QUARANTINE_PREFIX}${encodeBase64Url(conversationId)}/`;
}

function quarantineKey(conversationId: Uint8Array, slot: bigint): string {
    return `${quarantinePrefix(conversationId)}${sequenceKey(slot)}`;
}

function rebuildKey(conversationId: Uint8Array): string {
    return `${REBUILD_PREFIX}${encodeBase64Url(conversationId)}`;
}

function attachmentStagePrefix(record: OutboxRecord, index: number): string {
    return `${STAGING_PREFIX}${sequenceKey(record.enqueueSequence)}/${encodeBase64Url(record.messageId)}/${index.toString(16).padStart(2, "0")}/`;
}

function eventId(conversationId: Uint8Array, sequence: bigint): string {
    return `${encodeBase64Url(conversationId)}:${sequenceKey(sequence)}`;
}

function publicAttachmentManifest<TMetadata>(
    attachment: ChatAttachment<TMetadata>,
    metadata: Uint8Array,
): EncodedManifest {
    validateAttachmentObject(attachment);
    const borrowed: EncodedManifest = {
        metadata,
        fileId: attachment.fileId,
        fileKey: attachment.fileKey,
        commitment: attachment.keyCommitment,
        blobId: attachment.blobId,
        plaintextLength: attachment.plaintextLength,
        chunkSize: attachment.chunkSize,
        chunkCount: attachment.chunkCount,
    };
    verifyManifestShape(borrowed);
    return {
        ...borrowed,
        metadata,
        fileId: borrowed.fileId.slice(),
        fileKey: borrowed.fileKey.slice(),
        commitment: borrowed.commitment.slice(),
        blobId: borrowed.blobId.slice(),
    };
}

function validateAttachmentObject<TMetadata>(attachment: ChatAttachment<TMetadata>): void {
    if (
        attachment === null ||
        typeof attachment !== "object" ||
        !(attachment.fileId instanceof Uint8Array) ||
        !(attachment.fileKey instanceof Uint8Array) ||
        !(attachment.blobId instanceof Uint8Array) ||
        !(attachment.keyCommitment instanceof Uint8Array) ||
        !(attachment.conversationId instanceof Uint8Array) ||
        !(attachment.sender instanceof Uint8Array) ||
        !Number.isSafeInteger(attachment.plaintextLength) ||
        !Number.isSafeInteger(attachment.chunkSize) ||
        !Number.isSafeInteger(attachment.chunkCount)
    ) {
        throw new ChatValidationError("Invalid attachment capability");
    }
}

async function deletePrefix(store: MurmurStore, prefix: string): Promise<void> {
    for (;;) {
        const page = await store.scan(prefix, { limit: STORE_PAGE });
        if (page.size === 0) return;
        await store.transaction(async (transaction) => {
            for (const key of page.keys()) await transaction.delete(key);
        });
    }
}

function classifyOutboxFailure(error: unknown): { code: string; message: string } {
    if (error instanceof ChatOutboxFailedError) {
        return { code: error.code, message: error.message };
    }
    if (error instanceof ChatAttachmentSourceChangedError) {
        return { code: "source-changed", message: error.message };
    }
    if (error instanceof ChatAttachmentAuthenticationError) {
        return { code: "blob-verification", message: error.message };
    }
    return {
        code: "operation-failed",
        message: error instanceof Error ? error.message : "Unknown outbox failure",
    };
}

function outboxFailure(code: string, error: unknown): ChatOutboxFailedError {
    return new ChatOutboxFailedError(
        code,
        error instanceof Error ? error.message : "Outbox operation failed",
    );
}

function boundedErrorMessage(error: unknown): string {
    return (error instanceof Error ? error.message : "Unknown projected frame").slice(0, 1024);
}

function zeroIntent(intent: EncodedAttachmentIntent): void {
    intent.metadata.fill(0);
    intent.fileId.fill(0);
    intent.fileKey.fill(0);
    intent.sourceHash.fill(0);
    if (intent.manifest !== undefined) zeroManifest(intent.manifest);
}

function zeroManifest(manifest: EncodedManifest): void {
    manifest.fileId.fill(0);
    manifest.fileKey.fill(0);
    manifest.commitment.fill(0);
    manifest.blobId.fill(0);
    manifest.metadata.fill(0);
}

function zeroOutbox(record: OutboxRecord): void {
    record.conversationId.fill(0);
    record.messageId.fill(0);
    record.body.fill(0);
    record.frameDigest?.fill(0);
    for (const intent of record.attachments) zeroIntent(intent);
}
