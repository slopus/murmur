import type { MurmurClient } from "../client/index.js";
import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes } from "../crypto/index.js";
import { FriendBook, identityId, pairwiseTopic, type FriendRecord } from "../identity/index.js";
import {
    DirectMessageIdCollisionError,
    MAX_FILE_BYTES,
    MAX_MESSAGE_ATTACHMENTS,
    acceptPrivateMessageFromContactInTransaction,
    createPrivateMessage,
    decodeEncryptedPrivateMessage,
    decryptFile,
    decryptPrivateMessageFromContact,
    encodeEncryptedPrivateMessage,
    encodePrivateMessage,
    encryptFile,
    encryptPrivateMessageForContact,
    privateMessageListElementId,
    privateMessageSelfListElementId,
    validateFileDescriptor,
    validatePrivateMessageId,
    type EncryptedFile,
    type EncryptedFileDescriptor,
    type EncryptedPrivateMessage,
    type OpenedPrivateMessage,
    type PrivateMessage,
} from "../messaging/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    createRelayEvent,
    verifyRelayBlob,
    type AppendListOperation,
    type ListElement,
    type RelayBlob,
} from "../transport/index.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    equalBytes,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import {
    decodeDirectChatOutboxRecord,
    decodeDirectChatSendRecord,
    encodeDirectChatOutboxRecord,
    encodeDirectChatSendRecord,
    type DirectChatOutboxRecord,
    type DirectChatRelayProgress,
    type DirectChatSendRecord,
} from "./impl/directChatCodec.js";
import {
    DirectChatAttachmentIntegrityError,
    DirectChatAttachmentPolicyError,
    DirectChatAttachmentUnavailableError,
    type DirectChatAttachmentInput,
    type DirectChatAttachmentPolicyState,
    type DirectChatCallbacks,
    type DirectChatEventResult,
    type DirectChatHistoryResult,
    type DirectChatMessage,
    type DirectChatMessageInput,
    type DirectChatSendOptions,
    type DirectChatSyncResult,
} from "./types.js";

export type {
    DirectChatAttachmentInput,
    DirectChatAttachmentPolicyState,
    DirectChatCallbacks,
    DirectChatEventResult,
    DirectChatHistoryResult,
    DirectChatMessage,
    DirectChatMessageInput,
    DirectChatOrdering,
    DirectChatSendOptions,
    DirectChatSyncResult,
} from "./types.js";
export {
    DirectChatAttachmentIntegrityError,
    DirectChatAttachmentPolicyError,
    DirectChatAttachmentUnavailableError,
} from "./types.js";

const SEND_PREFIX = "direct-chat/v1/send";
const OUTBOX_PREFIX = "direct-chat/v1/outbox";
const OUTBOX_BLOB_PREFIX = "direct-chat/v2/outbox-blob";
const QUARANTINE_PREFIX = "direct-chat/v1/quarantine";
const MAXIMUM_QUARANTINE_RECORDS = 128;
const MAXIMUM_DIRECT_CHAT_LIST_ELEMENT_BYTES = 256 * 1024;
const OUTBOUND_EVENT_REFRESH_MILLISECONDS = 4 * 60 * 1_000;
/** Absolute plaintext limit for a non-image direct-chat attachment. */
export const MAX_DIRECT_CHAT_DOCUMENT_BYTES = 10 * 1024 * 1024;
/** Aggregate plaintext attachment limit for one logical direct message. */
export const MAX_DIRECT_CHAT_ATTACHMENT_BYTES = 64 * 1024 * 1024;
/** Maximum attachment count for one logical direct message. */
export const MAX_DIRECT_CHAT_ATTACHMENTS = MAX_MESSAGE_ATTACHMENTS;

class InvalidDirectChatEnvelopeError extends Error {}

interface PreparedEnvelope {
    readonly encrypted: EncryptedPrivateMessage;
    readonly opened: OpenedPrivateMessage;
    readonly direction: "incoming" | "outgoing";
}

/** Report from retrying exact pending direct-chat events after a restart. */
export interface DirectChatRetryReport {
    readonly published: number;
    readonly failures: readonly Error[];
}

function sameIdentity(left: IdentityPublicKeys, right: IdentityPublicKeys): boolean {
    return (
        equalBytes(left.signingKey, right.signingKey) &&
        equalBytes(left.encryptionKey, right.encryptionKey)
    );
}

function clearMessageSecrets(message: PrivateMessage): void {
    for (const attachment of message.attachments) {
        zeroBytes(attachment.key);
        zeroBytes(attachment.nonce);
    }
}

function decodeOutboxAndZero(bytes: Uint8Array): DirectChatOutboxRecord {
    try {
        return decodeDirectChatOutboxRecord(bytes);
    } finally {
        zeroBytes(bytes);
    }
}

function surfacedMessage(
    owner: IdentityKeyPair,
    friend: IdentityPublicKeys,
    direction: "incoming" | "outgoing",
    message: PrivateMessage,
    source: "local-send" | "relay" = "relay",
): DirectChatMessage {
    const sender = direction === "incoming" ? friend : owner;
    return {
        direction,
        source,
        topic: pairwiseTopic(owner, friend),
        friend: {
            signingKey: friend.signingKey.slice(),
            encryptionKey: friend.encryptionKey.slice(),
        },
        sender: {
            signingKey: sender.signingKey.slice(),
            encryptionKey: sender.encryptionKey.slice(),
        },
        message,
        ordering: {
            sentAt: message.sentAt,
            senderId: identityId(sender),
            messageId: message.id,
        },
    };
}

function validateSendOptions(options: DirectChatSendOptions): void {
    if (
        typeof options !== "object" ||
        options === null ||
        Object.keys(options).some((key) => !["id", "sentAt"].includes(key))
    ) {
        throw new Error("Invalid direct-chat send options");
    }
    if (options.id !== undefined) {
        validatePrivateMessageId(options.id);
    }
    if (
        options.sentAt !== undefined &&
        (!Number.isSafeInteger(options.sentAt) || options.sentAt < 0)
    ) {
        throw new Error("Direct-chat sentAt must be a non-negative safe integer");
    }
}

function validateMessageInput(input: DirectChatMessageInput): void {
    if (
        typeof input !== "object" ||
        input === null ||
        Object.keys(input).length !== 2 ||
        Object.keys(input).some((key) => !["text", "attachments"].includes(key)) ||
        typeof input.text !== "string" ||
        !Array.isArray(input.attachments) ||
        input.attachments.length > MAX_DIRECT_CHAT_ATTACHMENTS
    ) {
        throw new Error("Invalid direct-chat message input");
    }
    let aggregateBytes = 0;
    for (const attachment of input.attachments) {
        if (
            typeof attachment !== "object" ||
            attachment === null ||
            Object.keys(attachment).some((key) => !["name", "mediaType", "bytes"].includes(key)) ||
            typeof attachment.name !== "string" ||
            (attachment.mediaType !== undefined && typeof attachment.mediaType !== "string") ||
            !(attachment.bytes instanceof Uint8Array)
        ) {
            throw new Error("Invalid direct-chat attachment input");
        }
        const mediaType = attachment.mediaType ?? "application/octet-stream";
        validateFileDescriptor({
            version: 1,
            blobId: "A".repeat(43),
            key: new Uint8Array(32),
            nonce: new Uint8Array(12),
            name: attachment.name,
            mediaType,
            plaintextBytes: attachment.bytes.length,
        });
        if (
            !mediaType.toLowerCase().startsWith("image/") &&
            attachment.bytes.length > MAX_DIRECT_CHAT_DOCUMENT_BYTES
        ) {
            throw new DirectChatAttachmentPolicyError(
                `Direct-chat document exceeds ${MAX_DIRECT_CHAT_DOCUMENT_BYTES} bytes`,
            );
        }
        aggregateBytes += attachment.bytes.length;
        if (
            !Number.isSafeInteger(aggregateBytes) ||
            aggregateBytes > MAX_DIRECT_CHAT_ATTACHMENT_BYTES
        ) {
            throw new DirectChatAttachmentPolicyError(
                `Direct-chat attachments exceed ${MAX_DIRECT_CHAT_ATTACHMENT_BYTES} aggregate bytes`,
            );
        }
    }
}

function attachmentDigests(attachments: readonly DirectChatAttachmentInput[]): string[] {
    return attachments.map((attachment) => {
        const digest = hashBytes(attachment.bytes);
        try {
            return encodeBase64Url(digest);
        } finally {
            zeroBytes(digest);
        }
    });
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}

function cloneDescriptor(descriptor: EncryptedFileDescriptor): EncryptedFileDescriptor {
    return {
        ...descriptor,
        key: descriptor.key.slice(),
        nonce: descriptor.nonce.slice(),
    };
}

function sendFingerprint(friend: IdentityPublicKeys, message: PrivateMessage): string {
    const messageBytes = encodePrivateMessage(message);
    let preimage: Uint8Array | undefined;
    let digest: Uint8Array | undefined;
    try {
        preimage = canonicalJsonBytes({
            context: "murmur/direct-chat-canonical-send/v1",
            friend: identityId(friend),
            message: encodeBase64Url(messageBytes),
        });
        digest = hashBytes(preimage);
        return encodeBase64Url(digest);
    } finally {
        zeroBytes(messageBytes);
        if (preimage !== undefined) {
            zeroBytes(preimage);
        }
        if (digest !== undefined) {
            zeroBytes(digest);
        }
    }
}

/**
 * Browser-safe text direct-message engine over existing client, friend, and
 * storage primitives.
 *
 * Applications retain their own chat/message/read-state tables through the
 * transaction callbacks. This class retains only protocol state.
 */
export class DirectChat {
    readonly #identity: IdentityKeyPair;
    readonly #client: MurmurClient;
    readonly #friends: FriendBook;
    readonly #store: MurmurStore;
    readonly #callbacks: DirectChatCallbacks;
    readonly #now: () => number;
    readonly #ownerId: string;
    readonly #friendByTopic = new Map<string, FriendRecord>();

    constructor(options: {
        readonly identity: IdentityKeyPair;
        readonly client: MurmurClient;
        readonly friends: FriendBook;
        readonly store: MurmurStore;
        readonly callbacks: DirectChatCallbacks;
        readonly now?: () => number;
    }) {
        if (
            options.identity.signingKey.length !== 32 ||
            options.identity.encryptionKey.length !== 32 ||
            options.identity.signingSecretKey.length !== 32 ||
            options.identity.encryptionSecretKey.length !== 32
        ) {
            throw new Error("DirectChat identity keys must be 32 bytes");
        }
        this.#identity = options.identity;
        this.#client = options.client;
        this.#friends = options.friends;
        this.#store = options.store;
        this.#callbacks = options.callbacks;
        this.#now = options.now ?? Date.now;
        this.#ownerId = identityId(options.identity);
    }

    /** Follow every active and removed friend topic to preserve gapless cursors. */
    async subscribe(): Promise<void> {
        this.#friendByTopic.clear();
        for (const friend of await this.#friends.list({ includeRemoved: true })) {
            const topic = pairwiseTopic(this.#identity, friend.identity);
            this.#friendByTopic.set(topic, friend);
            await this.#client.subscribe(topic);
        }
    }

    /** Refresh subscriptions after one friend profile/status transaction. */
    async subscribeFriend(friend: FriendRecord): Promise<void> {
        const topic = pairwiseTopic(this.#identity, friend.identity);
        this.#friendByTopic.set(topic, friend);
        await this.#client.subscribe(topic);
    }

    /** Send text through the canonical message path without changing its signature. */
    async sendText(
        friendIdentity: Pick<IdentityPublicKeys, "signingKey">,
        text: string,
        options: DirectChatSendOptions = {},
    ): Promise<DirectChatMessage> {
        return this.sendMessage(friendIdentity, { text, attachments: [] }, options);
    }

    /**
     * Send one logical message with encrypted photos or documents.
     *
     * The application message, both permanent encrypted copies, ciphertext
     * blobs, callback state, and resumable per-relay progress are committed
     * before the first upload. A publication error may therefore be retried
     * safely with the same caller-owned ID after a crash.
     */
    async sendMessage(
        friendIdentity: Pick<IdentityPublicKeys, "signingKey">,
        input: DirectChatMessageInput,
        options: DirectChatSendOptions = {},
    ): Promise<DirectChatMessage> {
        validateSendOptions(options);
        validateMessageInput(input);
        const friend = await this.#friends.get(friendIdentity, { includeRemoved: true });
        if (friend === undefined) {
            throw new Error("Direct-chat friend not found");
        }
        if (friend.status === "removed") {
            throw new Error("Cannot send a direct message to a removed friend");
        }
        if (options.id !== undefined) {
            const retained = await this.#readSendRecord(options.id);
            if (retained !== undefined) {
                this.#assertCanonicalRetry(retained, friend.identity, input, options.sentAt);
                try {
                    await this.#publishPending(options.id);
                    return surfacedMessage(
                        this.#identity,
                        retained.friend,
                        "outgoing",
                        retained.message,
                        "local-send",
                    );
                } catch (error: unknown) {
                    clearMessageSecrets(retained.message);
                    throw error;
                }
            }
        }

        const digests = attachmentDigests(input.attachments);
        const encryptedFiles: EncryptedFile[] = [];
        let message: PrivateMessage;
        try {
            for (const attachment of input.attachments) {
                encryptedFiles.push(
                    encryptFile(attachment.bytes, {
                        name: attachment.name,
                        ...(attachment.mediaType === undefined
                            ? {}
                            : { mediaType: attachment.mediaType }),
                    }),
                );
            }
            message = createPrivateMessage(
                input.text,
                encryptedFiles.map((file) => file.descriptor),
                options.sentAt ?? this.#now(),
                options.id,
            );
        } catch (error: unknown) {
            for (const file of encryptedFiles) {
                zeroBytes(file.blob.bytes);
                zeroBytes(file.descriptor.key);
                zeroBytes(file.descriptor.nonce);
            }
            throw error;
        }
        let recipientEnvelope: EncryptedPrivateMessage;
        let selfEnvelope: EncryptedPrivateMessage;
        let recipientBytes: Uint8Array | undefined;
        let selfBytes: Uint8Array | undefined;
        try {
            recipientEnvelope = encryptPrivateMessageForContact(
                this.#identity,
                friend.identity,
                message,
            );
            selfEnvelope = encryptPrivateMessageForContact(this.#identity, this.#identity, message);
            recipientBytes = encodeEncryptedPrivateMessage(recipientEnvelope);
            selfBytes = encodeEncryptedPrivateMessage(selfEnvelope);
            if (
                recipientBytes.length > MAXIMUM_DIRECT_CHAT_LIST_ELEMENT_BYTES ||
                selfBytes.length > MAXIMUM_DIRECT_CHAT_LIST_ELEMENT_BYTES
            ) {
                throw new Error(
                    `Direct-chat message exceeds the ${MAXIMUM_DIRECT_CHAT_LIST_ELEMENT_BYTES}-byte relay list-element limit`,
                );
            }
        } catch (error: unknown) {
            if (recipientBytes !== undefined) {
                zeroBytes(recipientBytes);
            }
            if (selfBytes !== undefined) {
                zeroBytes(selfBytes);
            }
            clearMessageSecrets(message);
            for (const file of encryptedFiles) {
                zeroBytes(file.blob.bytes);
            }
            throw error;
        }
        if (recipientBytes === undefined || selfBytes === undefined) {
            throw new Error("DirectChat did not prepare both encrypted message copies");
        }
        let sendRecord: DirectChatSendRecord;
        let outbox: DirectChatOutboxRecord;
        try {
            const topic = pairwiseTopic(this.#identity, friend.identity);
            const event = createRelayEvent(
                this.#identity,
                topic,
                recipientBytes,
                {
                    list: [
                        {
                            op: "append",
                            id: privateMessageListElementId(this.#identity, message),
                            bytes: recipientBytes,
                        },
                        {
                            op: "append",
                            id: privateMessageSelfListElementId(
                                this.#identity,
                                friend.identity,
                                message,
                            ),
                            bytes: selfBytes,
                        },
                    ],
                },
                this.#now(),
            );
            sendRecord = {
                friend: friend.identity,
                message,
                fingerprint: sendFingerprint(friend.identity, message),
                attachmentDigests: digests,
            };
            outbox = {
                schemaVersion: 2,
                event,
                friend: friend.identity,
                message,
                blobIds: encryptedFiles.map((file) => file.blob.id),
                relays: this.#client.relayIds.map((relayId) => ({
                    relayId,
                    uploadedBlobIds: [],
                    eventPublished: false,
                })),
                published: false,
            };
        } catch (error: unknown) {
            zeroBytes(recipientBytes);
            zeroBytes(selfBytes);
            clearMessageSecrets(message);
            for (const file of encryptedFiles) {
                zeroBytes(file.blob.bytes);
            }
            throw error;
        }
        let retained: DirectChatSendRecord | undefined;
        let completed = false;
        try {
            retained = await this.#store.transaction(async (transaction) => {
                const existingBytes = await transaction.get(this.#sendKey(message.id));
                if (existingBytes !== undefined) {
                    try {
                        const existing = decodeDirectChatSendRecord(existingBytes);
                        this.#assertCanonicalRetry(
                            existing,
                            friend.identity,
                            input,
                            options.sentAt,
                        );
                        return existing;
                    } finally {
                        zeroBytes(existingBytes);
                    }
                }
                const surface = surfacedMessage(
                    this.#identity,
                    friend.identity,
                    "outgoing",
                    message,
                    "local-send",
                );
                await acceptPrivateMessageFromContactInTransaction(
                    transaction,
                    this.#identity,
                    selfEnvelope,
                    async (consumerTransaction) =>
                        this.#callbacks.persistMessage(consumerTransaction, surface),
                );
                await transaction.set(
                    this.#sendKey(message.id),
                    encodeDirectChatSendRecord(sendRecord),
                );
                await transaction.set(
                    this.#outboxKey(message.id),
                    encodeDirectChatOutboxRecord(outbox),
                );
                for (const file of encryptedFiles) {
                    await transaction.set(
                        this.#outboxBlobKey(message.id, file.blob.id),
                        file.blob.bytes.slice(),
                    );
                }
                return sendRecord;
            });
            await this.#publishPending(message.id);
            const surface = surfacedMessage(
                this.#identity,
                retained.friend,
                "outgoing",
                retained.message,
                "local-send",
            );
            completed = true;
            return surface;
        } finally {
            zeroBytes(recipientBytes);
            zeroBytes(selfBytes);
            for (const file of encryptedFiles) {
                zeroBytes(file.blob.bytes);
            }
            if (!completed || retained !== sendRecord) {
                clearMessageSecrets(message);
            }
        }
    }

    /**
     * Download and authenticate one content-addressed attachment without
     * adding local cache or product state.
     */
    async fetchAttachment(descriptorValue: EncryptedFileDescriptor): Promise<Uint8Array> {
        const descriptor = cloneDescriptor(descriptorValue);
        let blob: RelayBlob | undefined;
        try {
            validateFileDescriptor(descriptor);
            const policy = this.attachmentPolicy(descriptor);
            if (policy.status === "blocked") {
                throw new DirectChatAttachmentPolicyError(
                    `Direct-chat document exceeds ${policy.maximumBytes} bytes`,
                );
            }
            const expectedCiphertextBytes = descriptor.plaintextBytes + 16;
            if (
                !Number.isSafeInteger(expectedCiphertextBytes) ||
                expectedCiphertextBytes > MAX_FILE_BYTES + 16
            ) {
                throw new DirectChatAttachmentPolicyError(
                    "Direct-chat attachment ciphertext exceeds the transport policy",
                );
            }
            try {
                blob = await this.#client.getBlob(descriptor.blobId, expectedCiphertextBytes);
            } catch (error: unknown) {
                throw new DirectChatAttachmentIntegrityError({
                    cause: error,
                });
            }
            if (blob === undefined) {
                throw new DirectChatAttachmentUnavailableError();
            }
            try {
                return decryptFile(descriptor, blob);
            } catch (error: unknown) {
                throw new DirectChatAttachmentIntegrityError({
                    cause: error,
                });
            }
        } finally {
            zeroBytes(descriptor.key);
            zeroBytes(descriptor.nonce);
            if (blob !== undefined) {
                zeroBytes(blob.bytes);
            }
        }
    }

    /** Classify authenticated attachment metadata without fetching ciphertext. */
    attachmentPolicy(descriptor: EncryptedFileDescriptor): DirectChatAttachmentPolicyState {
        validateFileDescriptor(descriptor);
        return !descriptor.mediaType.toLowerCase().startsWith("image/") &&
            descriptor.plaintextBytes > MAX_DIRECT_CHAT_DOCUMENT_BYTES
            ? {
                  status: "blocked",
                  reason: "document-too-large",
                  maximumBytes: MAX_DIRECT_CHAT_DOCUMENT_BYTES,
              }
            : { status: "allowed" };
    }

    /** Retry every exact pending event independently after a crash or outage. */
    async retryPending(): Promise<DirectChatRetryReport> {
        const entries = await this.#store.list(`${OUTBOX_PREFIX}/${this.#ownerId}/`);
        let published = 0;
        const failures: Error[] = [];
        for (const key of [...entries.keys()].sort()) {
            const id = key.slice(key.lastIndexOf("/") + 1);
            try {
                await this.#publishPending(id);
                published += 1;
            } catch (error: unknown) {
                failures.push(error instanceof Error ? error : new Error(String(error)));
            }
        }
        return { published, failures };
    }

    /** Process one event from a shared MurmurClient synchronization loop. */
    async handleEvent(
        delivery: import("../client/index.js").ReceivedEvent,
    ): Promise<DirectChatEventResult> {
        const friend = this.#friendByTopic.get(delivery.event.topic);
        if (friend === undefined) {
            return { status: "unhandled", event: delivery };
        }
        try {
            const payloadEnvelope = decodeEncryptedPrivateMessage(delivery.event.payload);
            if (payloadEnvelope.recipient !== this.#ownerId) {
                let prepared: PreparedEnvelope | undefined;
                for (const operation of delivery.event.list ?? []) {
                    if (operation.op !== "append" || !operation.id.startsWith("self-message:")) {
                        continue;
                    }
                    try {
                        prepared = this.#prepareEnvelope(
                            friend.identity,
                            operation.bytes,
                            operation.id,
                        );
                        break;
                    } catch (error: unknown) {
                        if (!(error instanceof InvalidDirectChatEnvelopeError)) {
                            throw error;
                        }
                    }
                }
                if (prepared === undefined) {
                    await this.#quarantineEvent(friend, delivery, "invalid-direct-envelope");
                    return { status: "quarantined" };
                }
                return await this.#acceptEvent(friend, delivery, prepared);
            }
            const prepared = this.#prepareEnvelope(friend.identity, delivery.event.payload);
            return await this.#acceptEvent(friend, delivery, prepared);
        } catch (error: unknown) {
            if (error instanceof DirectMessageIdCollisionError) {
                await this.#quarantineEvent(friend, delivery, "direct-message-id-collision");
                return { status: "quarantined" };
            }
            if (error instanceof InvalidDirectChatEnvelopeError || error instanceof SyntaxError) {
                await this.#quarantineEvent(friend, delivery, "invalid-direct-envelope");
                return { status: "quarantined" };
            }
            throw error;
        }
    }

    /** Retry pending sends, then process one bounded client synchronization pass. */
    async sync(waitMilliseconds: number = 0, signal?: AbortSignal): Promise<DirectChatSyncResult> {
        await this.subscribe();
        await this.retryPending();
        const result = await this.#client.sync(waitMilliseconds, signal);
        if (result.status === "reset") {
            return result;
        }
        const opened: DirectChatMessage[] = [];
        const unhandled: import("../client/index.js").ReceivedEvent[] = [];
        let duplicates = 0;
        let quarantined = 0;
        for (const delivery of result.events) {
            const handled = await this.handleEvent(delivery);
            if (handled.status === "opened" && handled.message !== undefined) {
                opened.push(handled.message);
            } else if (handled.status === "duplicate") {
                duplicates += 1;
            } else if (handled.status === "quarantined") {
                quarantined += 1;
            } else if (handled.status === "unhandled") {
                unhandled.push(delivery);
            }
        }
        return { status: "events", opened, duplicates, quarantined, unhandled };
    }

    /** Yield authenticated logical messages for a client dedicated to direct chat. */
    async *events(
        signal?: AbortSignal,
        waitMilliseconds: number = 25_000,
    ): AsyncIterable<DirectChatMessage> {
        while (signal?.aborted !== true) {
            const result = await this.sync(waitMilliseconds, signal);
            if (result.status === "reset") {
                throw new Error("Direct-chat topic reset requires permanent history recovery");
            }
            if (result.unhandled.length > 0) {
                throw new Error("DirectChat.events requires a client dedicated to direct chat");
            }
            for (const message of result.opened) {
                yield message;
            }
        }
    }

    /** Load permanent recipient/self copies for one friend from one relay. */
    async loadHistory(
        friendIdentity: Pick<IdentityPublicKeys, "signingKey">,
        relayId?: string,
    ): Promise<DirectChatHistoryResult> {
        const friend = await this.#friends.get(friendIdentity, { includeRemoved: true });
        if (friend === undefined) {
            throw new Error("Direct-chat friend not found");
        }
        const topic = pairwiseTopic(this.#identity, friend.identity);
        return this.#client.loadTopic(
            topic,
            async (transaction, state) => {
                const opened: DirectChatMessage[] = [];
                let duplicates = 0;
                let quarantined = 0;
                for (const element of state.elements) {
                    const outcome = await this.#acceptHistoryElement(transaction, friend, element);
                    if (outcome.status === "opened" && outcome.message !== undefined) {
                        opened.push(outcome.message);
                    } else if (outcome.status === "duplicate") {
                        duplicates += 1;
                    } else if (outcome.status === "quarantined") {
                        quarantined += 1;
                    }
                }
                return { opened, duplicates, quarantined };
            },
            relayId,
        );
    }

    /** Recover one explicit reset descriptor through permanent list state. */
    async recoverReset(
        reset: import("../client/index.js").TopicResetRequired,
    ): Promise<DirectChatHistoryResult> {
        await this.subscribe();
        const friend = this.#friendByTopic.get(reset.topic);
        if (friend === undefined) {
            throw new Error("Reset does not belong to a known direct-chat topic");
        }
        return this.loadHistory(friend.identity, reset.relayId);
    }

    async #acceptEvent(
        friend: FriendRecord,
        delivery: import("../client/index.js").ReceivedEvent,
        prepared: PreparedEnvelope,
    ): Promise<DirectChatEventResult> {
        let surface: DirectChatMessage | undefined;
        try {
            const accepted = await this.#store.transaction(async (transaction) =>
                acceptPrivateMessageFromContactInTransaction(
                    transaction,
                    this.#identity,
                    prepared.encrypted,
                    async (consumerTransaction, opened) => {
                        surface = surfacedMessage(
                            this.#identity,
                            friend.identity,
                            prepared.direction,
                            opened.message,
                        );
                        if (friend.status === "removed") {
                            await this.#writeQuarantine(
                                consumerTransaction,
                                friend,
                                "removed-friend-message",
                                delivery.event.id,
                                delivery.event.payload,
                            );
                        } else {
                            await this.#callbacks.persistMessage(consumerTransaction, surface);
                        }
                    },
                    delivery.advanceCursor,
                ),
            );
            if (friend.status === "removed" && accepted.status === "opened") {
                clearMessageSecrets(accepted.message);
                return { status: "quarantined" };
            }
            if (accepted.status === "duplicate") {
                clearMessageSecrets(accepted.message);
            }
            return {
                status: accepted.status,
                ...(accepted.status === "opened" && surface !== undefined
                    ? { message: surface }
                    : {}),
            };
        } finally {
            clearMessageSecrets(prepared.opened.message);
        }
    }

    async #acceptHistoryElement(
        transaction: StoreTransaction,
        friend: FriendRecord,
        element: ListElement,
    ): Promise<{
        readonly status: "opened" | "duplicate" | "quarantined";
        readonly message?: DirectChatMessage;
    }> {
        if (!element.id.startsWith("message:") && !element.id.startsWith("self-message:")) {
            return { status: "duplicate" };
        }
        let envelope: EncryptedPrivateMessage;
        try {
            envelope = decodeEncryptedPrivateMessage(element.bytes);
        } catch {
            await this.#writeQuarantine(
                transaction,
                friend,
                "invalid-history-envelope",
                element.id,
                element.bytes,
            );
            return { status: "quarantined" };
        }
        if (envelope.recipient !== this.#ownerId) {
            return { status: "duplicate" };
        }
        let prepared: PreparedEnvelope | undefined;
        try {
            const ready = this.#prepareEnvelope(friend.identity, element.bytes, element.id);
            prepared = ready;
            let surface: DirectChatMessage | undefined;
            const accepted = await acceptPrivateMessageFromContactInTransaction(
                transaction,
                this.#identity,
                ready.encrypted,
                async (consumerTransaction, opened) => {
                    surface = surfacedMessage(
                        this.#identity,
                        friend.identity,
                        ready.direction,
                        opened.message,
                    );
                    if (friend.status === "removed") {
                        await this.#writeQuarantine(
                            consumerTransaction,
                            friend,
                            "removed-friend-history",
                            element.id,
                            element.bytes,
                        );
                    } else {
                        await this.#callbacks.persistMessage(consumerTransaction, surface);
                    }
                },
            );
            if (friend.status === "removed" && accepted.status === "opened") {
                clearMessageSecrets(accepted.message);
                return { status: "quarantined" };
            }
            if (accepted.status === "duplicate") {
                clearMessageSecrets(accepted.message);
            }
            return {
                status: accepted.status,
                ...(accepted.status === "opened" && surface !== undefined
                    ? { message: surface }
                    : {}),
            };
        } catch (error: unknown) {
            if (
                error instanceof InvalidDirectChatEnvelopeError ||
                error instanceof DirectMessageIdCollisionError ||
                error instanceof SyntaxError
            ) {
                await this.#writeQuarantine(
                    transaction,
                    friend,
                    error instanceof DirectMessageIdCollisionError
                        ? "history-id-collision"
                        : "invalid-history-envelope",
                    element.id,
                    element.bytes,
                );
                return { status: "quarantined" };
            }
            throw error;
        } finally {
            if (prepared !== undefined) {
                clearMessageSecrets(prepared.opened.message);
            }
        }
    }

    #prepareEnvelope(
        friend: IdentityPublicKeys,
        bytes: Uint8Array,
        listId?: string,
    ): PreparedEnvelope {
        let encrypted: EncryptedPrivateMessage;
        try {
            encrypted = decodeEncryptedPrivateMessage(bytes);
        } catch {
            throw new InvalidDirectChatEnvelopeError();
        }
        if (encrypted.recipient !== this.#ownerId) {
            throw new InvalidDirectChatEnvelopeError();
        }
        let opened: OpenedPrivateMessage;
        try {
            opened = decryptPrivateMessageFromContact(this.#identity, encrypted);
        } catch {
            throw new InvalidDirectChatEnvelopeError();
        }
        let direction: "incoming" | "outgoing";
        if (sameIdentity(opened.identity, friend)) {
            direction = "incoming";
            if (
                listId !== undefined &&
                listId !== privateMessageListElementId(friend, opened.message)
            ) {
                clearMessageSecrets(opened.message);
                throw new InvalidDirectChatEnvelopeError();
            }
        } else if (sameIdentity(opened.identity, this.#identity)) {
            direction = "outgoing";
            if (
                listId === undefined ||
                listId !== privateMessageSelfListElementId(this.#identity, friend, opened.message)
            ) {
                clearMessageSecrets(opened.message);
                throw new InvalidDirectChatEnvelopeError();
            }
        } else {
            clearMessageSecrets(opened.message);
            throw new InvalidDirectChatEnvelopeError();
        }
        return { encrypted, opened, direction };
    }

    async #publishPending(id: string): Promise<void> {
        const key = this.#outboxKey(id);
        const bytes = await this.#store.get(key);
        if (bytes === undefined) {
            return;
        }
        let pending = decodeOutboxAndZero(bytes);
        try {
            if (pending.schemaVersion === 1) {
                const upgraded = await this.#upgradeLegacyOutbox(key, pending);
                if (upgraded.message !== pending.message) {
                    clearMessageSecrets(pending.message);
                }
                pending = upgraded;
            }
            this.#validatePendingOutbox(pending);
            await this.#validatePendingBlobs(id, pending);
            const failures: Error[] = [];
            for (const relayId of pending.relays.map((relay) => relay.relayId)) {
                let relay = pending.relays.find((item) => item.relayId === relayId);
                if (relay?.eventPublished === true) {
                    continue;
                }
                try {
                    for (const blobId of pending.blobIds) {
                        relay = pending.relays.find((item) => item.relayId === relayId);
                        if (relay?.uploadedBlobIds.includes(blobId) === true) {
                            continue;
                        }
                        const blob = await this.#readOutboxBlob(id, pending, blobId);
                        try {
                            await this.#client.putBlobToRelay(blob, relayId);
                        } finally {
                            zeroBytes(blob.bytes);
                        }
                        const next = await this.#recordBlobUploaded(
                            key,
                            pending.event.id,
                            relayId,
                            blobId,
                        );
                        if (next.message !== pending.message) {
                            clearMessageSecrets(pending.message);
                        }
                        pending = next;
                    }
                    const result = await this.#publishToRelay(key, pending, relayId);
                    if (!result.publishedRelayIds.includes(relayId)) {
                        throw new Error(`Relay ${relayId} rejected the direct-chat event`);
                    }
                    const next = await this.#recordEventPublished(key, pending.event.id, relayId);
                    if (next.message !== pending.message) {
                        clearMessageSecrets(pending.message);
                    }
                    pending = next;
                } catch (error: unknown) {
                    failures.push(error instanceof Error ? error : new Error(String(error)));
                }
            }
            if (!pending.relays.every((relay) => relay.eventPublished) && !pending.published) {
                const cause = failures[0];
                throw new Error(
                    `Every transport rejected the direct-chat event${
                        cause === undefined ? "" : `: ${cause.message}`
                    }`,
                    cause === undefined ? undefined : { cause },
                );
            }
        } finally {
            zeroBytes(bytes);
            clearMessageSecrets(pending.message);
        }
    }

    async #publishToRelay(
        key: string,
        pendingValue: DirectChatOutboxRecord,
        relayId: string,
    ): Promise<Awaited<ReturnType<MurmurClient["publishEvent"]>>> {
        let pending = pendingValue;
        try {
            const stale =
                this.#now() - pending.event.createdAt >= OUTBOUND_EVENT_REFRESH_MILLISECONDS;
            let result: Awaited<ReturnType<MurmurClient["publishEvent"]>>;
            let refreshed = false;
            try {
                // Exact retry first recovers a receipt whose response was lost,
                // even after the timestamp window.
                result = await this.#client.publishEventToRelay(pending.event, relayId);
            } catch (error: unknown) {
                if (!stale) {
                    throw error;
                }
                pending = await this.#refreshPendingEvent(key, pending);
                this.#validatePendingOutbox(pending);
                result = await this.#publishReplacement(pending, relayId);
                refreshed = true;
            }
            if (!refreshed && stale && result.failedRelayIds.includes(relayId)) {
                pending = await this.#refreshPendingEvent(key, pending);
                this.#validatePendingOutbox(pending);
                result = await this.#publishReplacement(pending, relayId);
            }
            return result;
        } finally {
            if (pending.message !== pendingValue.message) {
                clearMessageSecrets(pending.message);
            }
        }
    }

    async #upgradeLegacyOutbox(
        key: string,
        pending: DirectChatOutboxRecord,
    ): Promise<DirectChatOutboxRecord> {
        if (pending.message.attachments.length !== 0) {
            throw new Error("Legacy direct-chat outbox unexpectedly contains attachments");
        }
        const upgraded: DirectChatOutboxRecord = {
            ...pending,
            schemaVersion: 2,
            blobIds: [],
            relays: this.#client.relayIds.map((relayId) => ({
                relayId,
                uploadedBlobIds: [],
                eventPublished: false,
            })),
        };
        return this.#store.transaction(async (transaction) => {
            const currentBytes = await transaction.get(key);
            if (currentBytes === undefined) {
                return upgraded;
            }
            const current = decodeOutboxAndZero(currentBytes);
            if (current.event.id !== pending.event.id || current.schemaVersion !== 1) {
                return current;
            }
            try {
                await transaction.set(key, encodeDirectChatOutboxRecord(upgraded));
                return upgraded;
            } finally {
                clearMessageSecrets(current.message);
            }
        });
    }

    async #recordBlobUploaded(
        key: string,
        eventId: string,
        relayId: string,
        blobId: string,
    ): Promise<DirectChatOutboxRecord> {
        return this.#store.transaction(async (transaction) => {
            const currentBytes = await transaction.get(key);
            if (currentBytes === undefined) {
                throw new Error("Direct-chat outbox disappeared during blob upload");
            }
            const current = decodeOutboxAndZero(currentBytes);
            let transferred = false;
            try {
                if (current.event.id !== eventId && current.previousEvent?.id !== eventId) {
                    throw new Error("Direct-chat outbox changed during blob upload");
                }
                const relays = current.relays.map((relay) =>
                    relay.relayId !== relayId || relay.uploadedBlobIds.includes(blobId)
                        ? relay
                        : {
                              ...relay,
                              uploadedBlobIds: [...relay.uploadedBlobIds, blobId],
                          },
                );
                if (!relays.some((relay) => relay.relayId === relayId)) {
                    throw new Error("Direct-chat outbox references an unknown relay");
                }
                const updated = { ...current, relays };
                await transaction.set(key, encodeDirectChatOutboxRecord(updated));
                transferred = true;
                return updated;
            } finally {
                if (!transferred) {
                    clearMessageSecrets(current.message);
                }
            }
        });
    }

    async #recordEventPublished(
        key: string,
        eventId: string,
        relayId: string,
    ): Promise<DirectChatOutboxRecord> {
        return this.#store.transaction(async (transaction) => {
            const currentBytes = await transaction.get(key);
            if (currentBytes === undefined) {
                throw new Error("Direct-chat outbox disappeared during event publication");
            }
            const current = decodeOutboxAndZero(currentBytes);
            let transferred = false;
            try {
                if (current.event.id !== eventId && current.previousEvent?.id !== eventId) {
                    throw new Error("Direct-chat outbox changed during event publication");
                }
                const relays: DirectChatRelayProgress[] = current.relays.map((relay) =>
                    relay.relayId === relayId ? { ...relay, eventPublished: true } : relay,
                );
                if (!relays.some((relay) => relay.relayId === relayId)) {
                    throw new Error("Direct-chat outbox references an unknown relay");
                }
                const updated: DirectChatOutboxRecord = {
                    ...current,
                    relays,
                    published: true,
                };
                if (!current.published) {
                    await this.#callbacks.messagePublished?.(
                        transaction,
                        surfacedMessage(
                            this.#identity,
                            current.friend,
                            "outgoing",
                            current.message,
                            "local-send",
                        ),
                    );
                }
                if (relays.every((relay) => relay.eventPublished)) {
                    await transaction.delete(key);
                    for (const blobId of current.blobIds) {
                        await transaction.delete(this.#outboxBlobKey(current.message.id, blobId));
                    }
                } else {
                    await transaction.set(key, encodeDirectChatOutboxRecord(updated));
                }
                transferred = true;
                return updated;
            } finally {
                if (!transferred) {
                    clearMessageSecrets(current.message);
                }
            }
        });
    }

    async #validatePendingBlobs(id: string, pending: DirectChatOutboxRecord): Promise<void> {
        for (const blobId of pending.blobIds) {
            const blob = await this.#readOutboxBlob(id, pending, blobId);
            try {
                if (!verifyRelayBlob(blob)) {
                    throw new Error("Direct-chat outbox blob failed content-address validation");
                }
            } finally {
                zeroBytes(blob.bytes);
            }
        }
    }

    async #readOutboxBlob(
        id: string,
        pending: DirectChatOutboxRecord,
        blobId: string,
    ): Promise<RelayBlob> {
        const bytes = await this.#store.get(this.#outboxBlobKey(id, blobId));
        if (bytes === undefined) {
            throw new Error("Direct-chat encrypted attachment outbox is incomplete");
        }
        const descriptor = pending.message.attachments.find(
            (attachment) => attachment.blobId === blobId,
        );
        if (
            descriptor === undefined ||
            bytes.length !== descriptor.plaintextBytes + 16 ||
            !verifyRelayBlob({ id: blobId, bytes })
        ) {
            zeroBytes(bytes);
            throw new Error("Direct-chat encrypted attachment outbox failed validation");
        }
        return { id: blobId, bytes };
    }

    async #refreshPendingEvent(
        key: string,
        pending: DirectChatOutboxRecord,
    ): Promise<DirectChatOutboxRecord> {
        const now = this.#now();
        if (now - pending.event.createdAt < OUTBOUND_EVENT_REFRESH_MILLISECONDS) {
            return pending;
        }
        const replacement = createRelayEvent(
            this.#identity,
            pending.event.topic,
            pending.event.payload,
            {
                ...(pending.event.snapshot === undefined
                    ? {}
                    : { snapshot: pending.event.snapshot }),
                ...(pending.event.list === undefined ? {} : { list: pending.event.list }),
            },
            now,
        );
        const refreshed: DirectChatOutboxRecord = {
            schemaVersion: 2,
            event: replacement,
            previousEvent: pending.event,
            friend: pending.friend,
            message: pending.message,
            blobIds: pending.blobIds,
            relays: pending.relays,
            published: pending.published,
        };
        return this.#store.transaction(async (transaction) => {
            const currentBytes = await transaction.get(key);
            if (currentBytes === undefined) {
                return refreshed;
            }
            const current = decodeOutboxAndZero(currentBytes);
            if (current.event.id !== pending.event.id) {
                return current;
            }
            try {
                await transaction.set(key, encodeDirectChatOutboxRecord(refreshed));
                return refreshed;
            } finally {
                clearMessageSecrets(current.message);
            }
        });
    }

    async #publishReplacement(
        pending: DirectChatOutboxRecord,
        relayId: string,
    ): Promise<Awaited<ReturnType<MurmurClient["publishEvent"]>>> {
        if (pending.previousEvent === undefined) {
            throw new Error("DirectChat clock did not advance a stale pending event");
        }
        return this.#client.publishEventToRelay(pending.event, relayId);
    }

    #validatePendingOutbox(pending: DirectChatOutboxRecord): void {
        const expectedTopic = pairwiseTopic(this.#identity, pending.friend);
        const recipientId = privateMessageListElementId(this.#identity, pending.message);
        const selfId = privateMessageSelfListElementId(
            this.#identity,
            pending.friend,
            pending.message,
        );
        const appends = (pending.event.list ?? []).filter(
            (operation): operation is AppendListOperation => operation.op === "append",
        );
        const recipient = appends.find((operation) => operation.id === recipientId);
        const self = appends.find((operation) => operation.id === selfId);
        const expectedBlobIds = pending.message.attachments.map((attachment) => attachment.blobId);
        const relayIds = pending.relays.map((relay) => relay.relayId);
        let aggregateBytes = 0;
        for (const descriptor of pending.message.attachments) {
            aggregateBytes += descriptor.plaintextBytes;
            if (
                (!descriptor.mediaType.toLowerCase().startsWith("image/") &&
                    descriptor.plaintextBytes > MAX_DIRECT_CHAT_DOCUMENT_BYTES) ||
                aggregateBytes > MAX_DIRECT_CHAT_ATTACHMENT_BYTES
            ) {
                throw new Error("Direct-chat outbox attachment policy validation failed");
            }
        }
        if (
            pending.schemaVersion !== 2 ||
            pending.event.topic !== expectedTopic ||
            pending.event.list?.length !== 2 ||
            appends.length !== 2 ||
            recipient === undefined ||
            self === undefined ||
            !equalBytes(recipient.bytes, pending.event.payload) ||
            new Set(expectedBlobIds).size !== expectedBlobIds.length ||
            !sameStrings(pending.blobIds, expectedBlobIds) ||
            relayIds.length === 0 ||
            new Set(relayIds).size !== relayIds.length ||
            relayIds.some((relayId) => !this.#client.relayIds.includes(relayId)) ||
            pending.relays.some(
                (relay) =>
                    new Set(relay.uploadedBlobIds).size !== relay.uploadedBlobIds.length ||
                    relay.uploadedBlobIds.some((blobId) => !pending.blobIds.includes(blobId)) ||
                    (relay.eventPublished &&
                        !pending.blobIds.every((blobId) => relay.uploadedBlobIds.includes(blobId))),
            )
        ) {
            throw new Error("Direct-chat outbox does not match its canonical message");
        }
        const recipientEnvelope = decodeEncryptedPrivateMessage(recipient.bytes);
        if (
            recipientEnvelope.recipient !== identityId(pending.friend) ||
            recipientEnvelope.sender.signingKey !== encodeBase64Url(this.#identity.signingKey) ||
            recipientEnvelope.sender.encryptionKey !== encodeBase64Url(this.#identity.encryptionKey)
        ) {
            throw new Error("Direct-chat outbox recipient copy is not bound to its friend");
        }
        const prepared = this.#prepareEnvelope(pending.friend, self.bytes, self.id);
        const expected = encodePrivateMessage(pending.message);
        const actual = encodePrivateMessage(prepared.opened.message);
        try {
            if (!equalBytes(expected, actual)) {
                throw new Error("Direct-chat outbox self copy does not match its message");
            }
        } finally {
            zeroBytes(expected);
            zeroBytes(actual);
            clearMessageSecrets(prepared.opened.message);
        }
    }

    async #readSendRecord(id: string): Promise<DirectChatSendRecord | undefined> {
        const bytes = await this.#store.get(this.#sendKey(id));
        if (bytes === undefined) {
            return undefined;
        }
        try {
            return decodeDirectChatSendRecord(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    #assertCanonicalRetry(
        retained: DirectChatSendRecord,
        friend: IdentityPublicKeys,
        input: DirectChatMessageInput,
        sentAt: number | undefined,
    ): void {
        const digests = attachmentDigests(input.attachments);
        const matches =
            sameIdentity(retained.friend, friend) &&
            retained.message.text === input.text &&
            retained.message.attachments.length === input.attachments.length &&
            retained.message.attachments.every((descriptor, index) => {
                const attachment = input.attachments[index];
                return (
                    attachment !== undefined &&
                    descriptor.name === attachment.name &&
                    descriptor.mediaType === (attachment.mediaType ?? "application/octet-stream") &&
                    descriptor.plaintextBytes === attachment.bytes.length
                );
            }) &&
            sameStrings(retained.attachmentDigests, digests) &&
            (sentAt === undefined || retained.message.sentAt === sentAt) &&
            retained.fingerprint === sendFingerprint(retained.friend, retained.message);
        if (!matches) {
            clearMessageSecrets(retained.message);
            throw new DirectMessageIdCollisionError();
        }
    }

    async #quarantineEvent(
        friend: FriendRecord,
        delivery: import("../client/index.js").ReceivedEvent,
        reason: string,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await this.#writeQuarantine(
                transaction,
                friend,
                reason,
                delivery.event.id,
                delivery.event.payload,
            );
            await delivery.advanceCursor(transaction);
        });
    }

    async #writeQuarantine(
        transaction: StoreTransaction,
        friend: FriendRecord,
        reason: string,
        sourceId: string,
        bytes: Uint8Array,
    ): Promise<void> {
        const digest = hashBytes(bytes);
        const record = utf8Encode(
            JSON.stringify({
                version: 1,
                reason,
                friend: identityId(friend.identity),
                sourceId,
                bytes: bytes.length,
                fingerprint: encodeBase64Url(digest),
            }),
        );
        const prefix = `${QUARANTINE_PREFIX}/${this.#ownerId}/`;
        const observedAt = this.#now();
        if (!Number.isSafeInteger(observedAt) || observedAt < 0) {
            throw new Error("DirectChat clock returned an invalid quarantine time");
        }
        const key = `${prefix}${observedAt.toString().padStart(16, "0")}/${encodeBase64Url(
            digest,
        )}/${encodeBase64Url(utf8Encode(sourceId))}`;
        try {
            await transaction.set(key, record);
            const records = await transaction.list(prefix);
            const keys = [...records.keys()].sort();
            for (const expired of keys.slice(
                0,
                Math.max(0, keys.length - MAXIMUM_QUARANTINE_RECORDS),
            )) {
                await transaction.delete(expired);
            }
        } finally {
            zeroBytes(digest);
            zeroBytes(record);
        }
    }

    #sendKey(id: string): string {
        return `${SEND_PREFIX}/${this.#ownerId}/${id}`;
    }

    #outboxKey(id: string): string {
        return `${OUTBOX_PREFIX}/${this.#ownerId}/${id}`;
    }

    #outboxBlobKey(id: string, blobId: string): string {
        return `${OUTBOX_BLOB_PREFIX}/${this.#ownerId}/${id}/${blobId}`;
    }
}
