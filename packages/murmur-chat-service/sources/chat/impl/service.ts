import { randomBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";
import type { MurmurGroup, MurmurGroupEvent } from "@slopus/murmur";
import {
    ChatAttachmentSourceChangedError,
    ChatClosedError,
    ChatCodecError,
    ChatFrameTooLargeError,
    ChatStoreCorruptionError,
} from "../errors.js";
import type {
    ChatAttachment,
    ChatAttachmentInput,
    ChatChange,
    ChatConversation,
    ChatDownloadOptions,
    ChatHistoryPage,
    ChatMessage,
    ChatOutboxEntry,
    ChatServiceOptions,
    ChatSyncOptions,
} from "../types.js";
import {
    hashAttachmentSource,
    openVerifiedAttachment,
    prepareAndUploadAttachment,
    verifyManifestShape,
} from "./attachmentCrypto.js";
import { encodeBase64Url, ensureNotAborted, equalBytes, sequenceKey } from "./bytes.js";
import {
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
const STORE_PAGE = 256;
const GROUP_PAGE = 1_000;
const QUARANTINE_SLOTS = 64n;
const DEFAULT_DOWNLOAD_MAXIMUM = 16 * 1024 * 1024;

/**
 * Durable generic chat semantics over opaque Murmur MLS group streams.
 *
 * `ChatService` does not own the supplied Murmur instance. Closing chat aborts
 * only chat/blob work; callers close Murmur separately.
 */
export class ChatService<TMessage, TAttachmentMetadata> {
    readonly #options: ChatServiceOptions<TMessage, TAttachmentMetadata>;
    readonly #abort = new AbortController();
    readonly #listeners = new Set<(change: ChatChange) => void>();
    readonly #outboxErrors = new Map<string, Error>();
    readonly #idlePollMilliseconds: number;
    #tail: Promise<void> = Promise.resolve();
    #workerPromise: Promise<void> | undefined;
    #timer: ReturnType<typeof setTimeout> | undefined;
    #wakeRequested = false;
    #closing = false;
    #closed = false;
    #closePromise: Promise<void> | undefined;
    #convergenceError: Error | undefined;
    #backoffMilliseconds = 100;

    private constructor(options: ChatServiceOptions<TMessage, TAttachmentMetadata>) {
        this.#options = options;
        this.#idlePollMilliseconds = options.idlePollMilliseconds ?? 250;
    }

    /** Open durable chat state and start its single adaptive convergence worker. */
    static async open<TMessage, TAttachmentMetadata>(
        options: ChatServiceOptions<TMessage, TAttachmentMetadata>,
    ): Promise<ChatService<TMessage, TAttachmentMetadata>> {
        if (
            options === null ||
            typeof options !== "object" ||
            !Number.isSafeInteger(options.idlePollMilliseconds ?? 250) ||
            (options.idlePollMilliseconds ?? 250) < 25 ||
            (options.idlePollMilliseconds ?? 250) > 30_000
        ) {
            throw new Error("Invalid chat service options");
        }
        const service = new ChatService(options);
        await service.#validateStore();
        service.#schedule(0);
        return service;
    }

    /** Defensive copy of the local authenticated Murmur identity key. */
    get identityKey(): Uint8Array {
        this.#ensureOpen();
        return this.#options.murmur.identityKey;
    }

    /** Last background convergence error, retained until a successful `sync`. */
    get convergenceError(): Error | undefined {
        this.#ensureOpen();
        return this.#convergenceError;
    }

    /** Create a new opaque chat group every time, with no DM uniqueness rule. */
    async createConversation(members: readonly Uint8Array[] = []): Promise<Uint8Array> {
        return this.#exclusive(async () => {
            validateMembers(members);
            const id = await this.#options.murmur.groups.create(chatDescriptor(), members);
            this.#emit({ kind: "conversation", conversationId: id });
            this.#wake();
            return id.slice();
        });
    }

    /** List only groups whose strict descriptor identifies this chat protocol. */
    async listConversations(): Promise<readonly ChatConversation[]> {
        return this.#exclusive(async () => {
            const groups = await this.#options.murmur.groups.list();
            return groups
                .filter((group) => isChatDescriptor(group.descriptor))
                .map(conversationView);
        });
    }

    /** Read one chat conversation, or undefined for unknown/non-chat groups. */
    async getConversation(conversationId: Uint8Array): Promise<ChatConversation | undefined> {
        return this.#exclusive(async () => {
            validateConversationId(conversationId);
            const page = await this.#options.murmur.groups.get(conversationId, { limit: 1 });
            return page === undefined || !isChatDescriptor(page.group.descriptor)
                ? undefined
                : conversationView(page.group);
        });
    }

    /** Queue an MLS member addition through Murmur. */
    async addMember(conversationId: Uint8Array, identityKey: Uint8Array): Promise<void> {
        await this.#exclusive(async () => {
            validateConversationId(conversationId);
            validateIdentity(identityKey);
            await this.#requireConversation(conversationId);
            await this.#options.murmur.groups.add(conversationId, identityKey);
            this.#emit({ kind: "conversation", conversationId });
            this.#wake();
        });
    }

    /** Queue an MLS member removal through Murmur. */
    async removeMember(conversationId: Uint8Array, identityKey: Uint8Array): Promise<void> {
        await this.#exclusive(async () => {
            validateConversationId(conversationId);
            validateIdentity(identityKey);
            await this.#requireConversation(conversationId);
            await this.#options.murmur.groups.remove(conversationId, identityKey);
            this.#emit({ kind: "conversation", conversationId });
            this.#wake();
        });
    }

    /**
     * Persist a stable 16-byte message ID and exact upload/send intent before
     * any blob upload or Murmur group handoff.
     */
    async send(
        conversationId: Uint8Array,
        input: {
            readonly message: TMessage;
            readonly attachments?: readonly ChatAttachmentInput<TAttachmentMetadata>[];
            readonly claimedAt?: number;
        },
    ): Promise<Uint8Array> {
        return this.#exclusive(async () => {
            validateConversationId(conversationId);
            await this.#requireConversation(conversationId);
            const attachments = input.attachments ?? [];
            if (attachments.length > MAXIMUM_ATTACHMENTS) {
                throw new ChatCodecError(
                    `A message may contain at most ${MAXIMUM_ATTACHMENTS} attachments`,
                );
            }
            const body = this.#encodeMessage(input.message);
            const messageId = randomBytes(MESSAGE_ID_BYTES);
            const claimedAt = input.claimedAt ?? Date.now();
            if (!Number.isSafeInteger(claimedAt) || claimedAt < 0) {
                body.fill(0);
                messageId.fill(0);
                throw new ChatCodecError("claimedAt must be a non-negative safe integer");
            }
            const intents: EncodedAttachmentIntent[] = [];
            const preparationAbort = new AbortController();
            const forwardAbort = (): void => preparationAbort.abort(this.#abort.signal.reason);
            this.#abort.signal.addEventListener("abort", forwardAbort, { once: true });
            try {
                for (const attachment of attachments) {
                    if (
                        typeof attachment.sourceId !== "string" ||
                        attachment.sourceId.length === 0 ||
                        new TextEncoder().encode(attachment.sourceId).length > 4096
                    ) {
                        throw new ChatCodecError("Attachment sourceId must be non-empty");
                    }
                    const metadata = this.#encodeMetadata(attachment.metadata);
                    const source = await this.#options.resolveAttachmentSource(
                        attachment.sourceId,
                        preparationAbort.signal,
                    );
                    if (
                        source.sourceId !== attachment.sourceId ||
                        !Number.isSafeInteger(source.byteLength) ||
                        source.byteLength < 0 ||
                        source.byteLength > MAXIMUM_ATTACHMENT_BYTES
                    ) {
                        metadata.fill(0);
                        throw new ChatCodecError("Invalid attachment source");
                    }
                    const sourceHash = await hashAttachmentSource(source, preparationAbort.signal);
                    intents.push({
                        sourceId: attachment.sourceId,
                        metadata,
                        fileId: randomBytes(FILE_ID_BYTES),
                        fileKey: randomBytes(KEY_BYTES),
                        sourceHash,
                        plaintextLength: source.byteLength,
                    });
                }
                preflightFrame(messageId, claimedAt, body, intents);
                const record: OutboxRecord = {
                    status: intents.length === 0 ? "ready" : "preparing",
                    conversationId: conversationId.slice(),
                    messageId: messageId.slice(),
                    claimedAt,
                    body: body.slice(),
                    attachments: intents,
                };
                const encoded = encodeOutbox(record);
                try {
                    await this.#options.store.set(outboxKey(messageId), encoded);
                } finally {
                    encoded.fill(0);
                }
                this.#emit({ kind: "outbox", conversationId });
                this.#wake();
                const result = messageId.slice();
                zeroOutbox(record);
                messageId.fill(0);
                return result;
            } catch (error: unknown) {
                for (const intent of intents) zeroIntent(intent);
                messageId.fill(0);
                throw error instanceof ChatCodecError ||
                    error instanceof ChatFrameTooLargeError ||
                    error instanceof ChatAttachmentSourceChangedError
                    ? error
                    : new ChatCodecError(
                          error instanceof Error ? error.message : "Attachment preparation failed",
                      );
            } finally {
                this.#abort.signal.removeEventListener("abort", forwardAbort);
                body.fill(0);
            }
        });
    }

    /** Read exactly-once projected messages in canonical relay-sequence order. */
    async history(
        conversationId: Uint8Array,
        options: { readonly after?: bigint; readonly limit?: number } = {},
    ): Promise<ChatHistoryPage<TMessage, TAttachmentMetadata>> {
        return this.#exclusive(async () => {
            validateConversationId(conversationId);
            await this.#requireConversation(conversationId);
            const after = options.after ?? 0n;
            const limit = options.limit ?? 100;
            if (after < 0n || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
                throw new Error("Invalid history page");
            }
            const prefix = projectionPrefix(conversationId);
            const entries = await this.#options.store.scan(
                prefix,
                after === 0n
                    ? { limit: limit + 1 }
                    : { after: `${prefix}${sequenceKey(after)}`, limit: limit + 1 },
            );
            const selected = [...entries].slice(0, limit);
            const messages = selected.map(([key, encoded]) => {
                const sequence = BigInt(`0x${key.slice(prefix.length)}`);
                return this.#decodeProjected(conversationId, sequence, encoded);
            });
            const last = messages.at(-1);
            return {
                messages,
                ...(entries.size > limit && last !== undefined ? { nextAfter: last.sequence } : {}),
            };
        });
    }

    /** List durable upload/message intents that have not yet echoed into projection. */
    async outbox(): Promise<readonly ChatOutboxEntry[]> {
        return this.#exclusive(async () => {
            const result: ChatOutboxEntry[] = [];
            let after: string | undefined;
            for (;;) {
                const page = await this.#options.store.scan(OUTBOX_PREFIX, {
                    ...(after === undefined ? {} : { after }),
                    limit: STORE_PAGE,
                });
                for (const [key, bytes] of page) {
                    const record = decodeOutbox(bytes);
                    result.push({
                        conversationId: record.conversationId.slice(),
                        messageId: record.messageId.slice(),
                        status: record.status,
                        attachmentCount: record.attachments.length,
                        ...(this.#outboxErrors.get(key) === undefined
                            ? {}
                            : { lastError: this.#outboxErrors.get(key)! }),
                    });
                    after = key;
                }
                if (page.size < STORE_PAGE) break;
            }
            return result;
        });
    }

    /**
     * Stream independently authenticated plaintext chunks. No chunk is yielded
     * until its AEAD tag and all manifest bindings have verified.
     */
    openAttachment(
        attachment: ChatAttachment<TAttachmentMetadata>,
        options: { readonly signal?: AbortSignal } = {},
    ): AsyncIterable<Uint8Array> {
        this.#ensureOpen();
        const signal = options.signal ?? this.#abort.signal;
        const manifest = publicAttachmentManifest(
            attachment,
            this.#encodeMetadata(attachment.metadata),
        );
        const stream = openVerifiedAttachment(
            manifest,
            attachment.conversationId,
            attachment.sender,
            this.#options.blobStore,
            signal,
        );
        return (async function* (): AsyncIterable<Uint8Array> {
            try {
                yield* stream;
            } finally {
                zeroManifest(manifest);
            }
        })();
    }

    /** Download a whole attachment under an explicit conservative allocation cap. */
    async downloadAttachment(
        attachment: ChatAttachment<TAttachmentMetadata>,
        options: ChatDownloadOptions = {},
    ): Promise<Uint8Array> {
        this.#ensureOpen();
        const maximumBytes = options.maximumBytes ?? DEFAULT_DOWNLOAD_MAXIMUM;
        if (
            !Number.isSafeInteger(maximumBytes) ||
            maximumBytes < 0 ||
            maximumBytes > MAXIMUM_ATTACHMENT_BYTES ||
            attachment.plaintextLength > maximumBytes
        ) {
            throw new Error("Attachment exceeds bounded download maximum");
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
                    throw new Error("Authenticated stream exceeded plaintext length");
                }
                result.set(chunk, offset);
                offset += chunk.length;
                chunk.fill(0);
            }
            if (offset !== result.length) throw new Error("Authenticated stream was truncated");
            return result;
        } catch (error: unknown) {
            result.fill(0);
            throw error;
        }
    }

    /** Subscribe to coalescible chat changes; returns an idempotent unsubscribe. */
    onChange(listener: (change: ChatChange) => void): () => void {
        this.#ensureOpen();
        this.#listeners.add(listener);
        return (): void => {
            this.#listeners.delete(listener);
        };
    }

    /** Run an explicit Murmur and chat convergence boundary. */
    async sync(options: ChatSyncOptions = {}): Promise<void> {
        await this.#exclusive(async () => {
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

    /** Abort chat work and await the worker; the supplied Murmur remains open. */
    async close(): Promise<void> {
        if (this.#closePromise !== undefined) return this.#closePromise;
        this.#closing = true;
        if (this.#timer !== undefined) clearTimeout(this.#timer);
        this.#abort.abort(new ChatClosedError("Chat service is closing"));
        this.#closePromise = (async (): Promise<void> => {
            await this.#workerPromise;
            await this.#tail;
            this.#listeners.clear();
            this.#closed = true;
        })();
        return this.#closePromise;
    }

    async #validateStore(): Promise<void> {
        let after: string | undefined;
        for (;;) {
            const page = await this.#options.store.scan(CHAT_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: STORE_PAGE,
            });
            for (const [key, bytes] of page) {
                if (key.startsWith(OUTBOX_PREFIX)) decodeOutbox(bytes);
                else if (key.startsWith(PROJECTION_PREFIX)) decodeProjection(bytes);
                else if (
                    key.startsWith(CURSOR_PREFIX) ||
                    key.startsWith(DEDUPE_PREFIX) ||
                    key.startsWith(DELIVERED_PREFIX)
                ) {
                    decodeCursor(bytes);
                } else if (key.startsWith(QUARANTINE_PREFIX)) {
                    if (bytes.length !== HASH_BYTES) {
                        throw new ChatStoreCorruptionError("Corrupt chat quarantine record");
                    }
                } else {
                    throw new ChatStoreCorruptionError(`Unknown durable chat record: ${key}`);
                }
                after = key;
            }
            if (page.size < STORE_PAGE) break;
        }
    }

    async #converge(signal: AbortSignal): Promise<boolean> {
        let changed = false;
        const failures: Error[] = [];
        let after: string | undefined;
        for (;;) {
            ensureNotAborted(signal);
            const page = await this.#options.store.scan(OUTBOX_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: STORE_PAGE,
            });
            for (const [key, bytes] of page) {
                after = key;
                const record = decodeOutbox(bytes);
                try {
                    if (record.status === "preparing") {
                        for (const attachment of record.attachments) {
                            if (attachment.manifest !== undefined) continue;
                            attachment.manifest = await prepareAndUploadAttachment(
                                attachment,
                                record.conversationId,
                                this.#options.murmur.identityKey,
                                this.#options.resolveAttachmentSource,
                                this.#options.blobStore,
                                signal,
                            );
                            await this.#persistOutbox(key, record);
                            changed = true;
                        }
                        record.status = "ready";
                        await this.#persistOutbox(key, record);
                        this.#emit({ kind: "outbox", conversationId: record.conversationId });
                        changed = true;
                    }
                    if (record.status === "ready") {
                        const frame = encodeFrame({
                            messageId: record.messageId,
                            claimedAt: record.claimedAt,
                            body: record.body,
                            attachments: record.attachments.map(
                                (attachment) => attachment.manifest!,
                            ),
                        });
                        try {
                            await this.#options.murmur.groups.send(record.conversationId, frame);
                        } finally {
                            frame.fill(0);
                        }
                        record.status = "handed-off";
                        await this.#persistOutbox(key, record);
                        this.#emit({ kind: "outbox", conversationId: record.conversationId });
                        changed = true;
                    }
                    if (
                        record.status === "handed-off" &&
                        (await this.#options.store.get(deliveredKey(record.messageId))) !==
                            undefined
                    ) {
                        await this.#options.store.delete(key);
                        changed = true;
                    }
                    this.#outboxErrors.delete(key);
                } catch (error: unknown) {
                    const failure =
                        error instanceof Error
                            ? error
                            : new Error("Unknown outbox convergence error");
                    this.#outboxErrors.set(key, failure);
                    failures.push(failure);
                } finally {
                    zeroOutbox(record);
                }
            }
            if (page.size < STORE_PAGE) break;
        }
        if (await this.#project(signal)) changed = true;
        if (failures.length > 0) {
            throw new AggregateError(failures, "One or more chat outbox intents failed");
        }
        return changed;
    }

    async #project(signal: AbortSignal): Promise<boolean> {
        let changed = false;
        const groups = await this.#options.murmur.groups.list();
        for (const group of groups) {
            ensureNotAborted(signal);
            if (!isChatDescriptor(group.descriptor)) continue;
            const cursorKey = groupCursorKey(group.id);
            const cursorBytes = await this.#options.store.get(cursorKey);
            let after = cursorBytes === undefined ? 0n : decodeCursor(cursorBytes);
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
        }
        return changed;
    }

    async #projectEvent(conversationId: Uint8Array, event: MurmurGroupEvent): Promise<boolean> {
        let frame: ReturnType<typeof decodeFrame> | undefined;
        try {
            frame = decodeFrame(event.bytes);
            this.#decodeApplication(frame);
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
        const ownEvent = equalBytes(event.sender, this.#options.murmur.identityKey);
        let accepted = false;
        await this.#options.store.transaction(async (transaction) => {
            const prior = await transaction.get(dedupe);
            if (prior === undefined) {
                await transaction.set(
                    projectionKey(conversationId, event.sequence),
                    encodeProjection(event.sender, event.bytes),
                );
                await transaction.set(dedupe, encodeCursor(event.sequence));
                if (ownEvent) {
                    await transaction.set(
                        deliveredKey(frame.messageId),
                        encodeCursor(event.sequence),
                    );
                }
                accepted = true;
            } else {
                decodeCursor(prior);
            }
            await transaction.set(groupCursorKey(conversationId), encodeCursor(event.sequence));
        });
        if (accepted && ownEvent) {
            await this.#options.store.delete(outboxKey(frame.messageId));
        }
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
            if (!(bytes instanceof Uint8Array))
                throw new Error("encoder did not return Uint8Array");
            if (bytes.length > MAXIMUM_FRAME_BYTES)
                throw new ChatFrameTooLargeError("Message body exceeds Murmur's frame bound");
            return bytes.slice();
        } catch (error: unknown) {
            if (error instanceof ChatFrameTooLargeError) throw error;
            throw new ChatCodecError(
                error instanceof Error ? error.message : "Message encoding failed",
            );
        }
    }

    #encodeMetadata(metadata: TAttachmentMetadata): Uint8Array {
        try {
            const bytes = this.#options.encodeAttachmentMetadata(metadata);
            if (!(bytes instanceof Uint8Array))
                throw new Error("encoder did not return Uint8Array");
            if (bytes.length > MAXIMUM_FRAME_BYTES) throw new Error("metadata is oversized");
            return bytes.slice();
        } catch (error: unknown) {
            throw new ChatCodecError(
                error instanceof Error ? error.message : "Metadata encoding failed",
            );
        }
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
            throw new Error("Chat conversation not found");
        }
        return page.group;
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
                // Listener failures do not affect durable convergence.
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
            this.#workerPromise = this.#exclusive(async () => {
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
                        this.#emit({ kind: "error" });
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

    async #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#tail;
        this.#tail = new Promise<void>((resolve) => {
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
        chunkSize: 256 * 1024,
        chunkCount:
            attachment.plaintextLength === 0
                ? 0
                : Math.ceil(attachment.plaintextLength / (256 * 1024)),
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

function conversationView(group: MurmurGroup): ChatConversation {
    return {
        id: group.id.slice(),
        members: group.members.map((member) => member.slice()),
        epoch: group.epoch,
        status: group.status,
    };
}

function validateConversationId(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length !== GROUP_ID_BYTES) {
        throw new Error("Conversation ID must contain 32 bytes");
    }
}

function validateIdentity(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) {
        throw new Error("Identity key must contain 32 bytes");
    }
}

function validateMembers(members: readonly Uint8Array[]): void {
    for (const member of members) validateIdentity(member);
}

function outboxKey(messageId: Uint8Array): string {
    return `${OUTBOX_PREFIX}${encodeBase64Url(messageId)}`;
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

function dedupeKey(
    conversationId: Uint8Array,
    sender: Uint8Array,
    messageId: Uint8Array,
    digest: Uint8Array,
): string {
    return `${DEDUPE_PREFIX}${encodeBase64Url(conversationId)}/${encodeBase64Url(sender)}/${encodeBase64Url(messageId)}/${encodeBase64Url(digest)}`;
}

function deliveredKey(messageId: Uint8Array): string {
    return `${DELIVERED_PREFIX}${encodeBase64Url(messageId)}`;
}

function quarantineKey(conversationId: Uint8Array, slot: bigint): string {
    return `${QUARANTINE_PREFIX}${encodeBase64Url(conversationId)}/${sequenceKey(slot)}`;
}

function publicAttachmentManifest<TMetadata>(
    attachment: ChatAttachment<TMetadata>,
    metadata: Uint8Array,
): EncodedManifest {
    const manifest: EncodedManifest = {
        metadata,
        fileId: attachment.fileId.slice(),
        fileKey: attachment.fileKey.slice(),
        commitment: attachment.keyCommitment.slice(),
        blobId: attachment.blobId.slice(),
        plaintextLength: attachment.plaintextLength,
        chunkSize: attachment.chunkSize,
        chunkCount: attachment.chunkCount,
    };
    verifyManifestShape(manifest);
    return manifest;
}

function zeroIntent(intent: EncodedAttachmentIntent): void {
    intent.metadata.fill(0);
    intent.fileId.fill(0);
    intent.fileKey.fill(0);
    intent.sourceHash.fill(0);
    if (intent.manifest !== undefined) {
        zeroManifest(intent.manifest);
    }
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
    for (const intent of record.attachments) zeroIntent(intent);
}
