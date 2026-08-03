import type { MurmurClient } from "../client/index.js";
import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes } from "../crypto/index.js";
import { FriendBook, identityId, pairwiseTopic, type FriendRecord } from "../identity/index.js";
import {
    DirectMessageIdCollisionError,
    acceptPrivateMessageFromContactInTransaction,
    createPrivateMessage,
    decodeEncryptedPrivateMessage,
    decryptPrivateMessageFromContact,
    encodeEncryptedPrivateMessage,
    encodePrivateMessage,
    encryptPrivateMessageForContact,
    privateMessageListElementId,
    privateMessageSelfListElementId,
    validatePrivateMessageId,
    type EncryptedPrivateMessage,
    type OpenedPrivateMessage,
    type PrivateMessage,
} from "../messaging/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    createRelayEvent,
    type AppendListOperation,
    type ListElement,
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
    type DirectChatSendRecord,
} from "./impl/directChatCodec.js";
import type {
    DirectChatCallbacks,
    DirectChatEventResult,
    DirectChatHistoryResult,
    DirectChatMessage,
    DirectChatSendOptions,
    DirectChatSyncResult,
} from "./types.js";

export type {
    DirectChatCallbacks,
    DirectChatEventResult,
    DirectChatHistoryResult,
    DirectChatMessage,
    DirectChatOrdering,
    DirectChatSendOptions,
    DirectChatSyncResult,
} from "./types.js";

const SEND_PREFIX = "direct-chat/v1/send";
const OUTBOX_PREFIX = "direct-chat/v1/outbox";
const QUARANTINE_PREFIX = "direct-chat/v1/quarantine";
const MAXIMUM_QUARANTINE_RECORDS = 128;

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

    /**
     * Send text with an optional caller-owned canonical ID.
     *
     * The API deliberately has no attachment input. Unknown option fields,
     * including an attempted `attachments` field from untyped JavaScript, are
     * rejected.
     */
    async sendText(
        friendIdentity: Pick<IdentityPublicKeys, "signingKey">,
        text: string,
        options: DirectChatSendOptions = {},
    ): Promise<DirectChatMessage> {
        validateSendOptions(options);
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
                this.#assertCanonicalRetry(retained, friend.identity, text, options.sentAt);
                await this.#publishPending(options.id);
                return surfacedMessage(
                    this.#identity,
                    retained.friend,
                    "outgoing",
                    retained.message,
                    "local-send",
                );
            }
        }

        const message = createPrivateMessage(text, [], options.sentAt ?? this.#now(), options.id);
        const recipientEnvelope = encryptPrivateMessageForContact(
            this.#identity,
            friend.identity,
            message,
        );
        const selfEnvelope = encryptPrivateMessageForContact(
            this.#identity,
            this.#identity,
            message,
        );
        const recipientBytes = encodeEncryptedPrivateMessage(recipientEnvelope);
        const selfBytes = encodeEncryptedPrivateMessage(selfEnvelope);
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
        const sendRecord: DirectChatSendRecord = {
            friend: friend.identity,
            message,
            fingerprint: sendFingerprint(friend.identity, message),
        };
        const outbox: DirectChatOutboxRecord = {
            event,
            friend: friend.identity,
            message,
        };
        let retained: DirectChatSendRecord | undefined;
        try {
            retained = await this.#store.transaction(async (transaction) => {
                const existingBytes = await transaction.get(this.#sendKey(message.id));
                if (existingBytes !== undefined) {
                    const existing = decodeDirectChatSendRecord(existingBytes);
                    this.#assertCanonicalRetry(existing, friend.identity, text, options.sentAt);
                    return existing;
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
                return sendRecord;
            });
            await this.#publishPending(message.id);
            return surfacedMessage(
                this.#identity,
                retained.friend,
                "outgoing",
                retained.message,
                "local-send",
            );
        } finally {
            zeroBytes(recipientBytes);
            zeroBytes(selfBytes);
            if (retained !== sendRecord) {
                clearMessageSecrets(message);
            }
        }
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
        let candidateBytes = delivery.event.payload;
        let listId: string | undefined;
        try {
            const payloadEnvelope = decodeEncryptedPrivateMessage(candidateBytes);
            if (payloadEnvelope.recipient !== this.#ownerId) {
                const selfOperation = delivery.event.list?.find(
                    (operation): operation is AppendListOperation =>
                        operation.op === "append" && operation.id.startsWith("self-message:"),
                );
                if (selfOperation === undefined) {
                    await this.#quarantineEvent(friend, delivery, "invalid-direct-envelope");
                    return { status: "quarantined" };
                }
                candidateBytes = selfOperation.bytes;
                listId = selfOperation.id;
            }
            const prepared = this.#prepareEnvelope(friend.identity, candidateBytes, listId);
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
        try {
            const encrypted = decodeEncryptedPrivateMessage(bytes);
            if (encrypted.recipient !== this.#ownerId) {
                throw new InvalidDirectChatEnvelopeError();
            }
            const opened = decryptPrivateMessageFromContact(this.#identity, encrypted);
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
                    listId !==
                        privateMessageSelfListElementId(this.#identity, friend, opened.message)
                ) {
                    clearMessageSecrets(opened.message);
                    throw new InvalidDirectChatEnvelopeError();
                }
            } else {
                clearMessageSecrets(opened.message);
                throw new InvalidDirectChatEnvelopeError();
            }
            return { encrypted, opened, direction };
        } catch (error: unknown) {
            if (error instanceof InvalidDirectChatEnvelopeError) {
                throw error;
            }
            throw new InvalidDirectChatEnvelopeError();
        }
    }

    async #publishPending(id: string): Promise<void> {
        const key = this.#outboxKey(id);
        const bytes = await this.#store.get(key);
        if (bytes === undefined) {
            return;
        }
        const pending = decodeDirectChatOutboxRecord(bytes);
        try {
            this.#validatePendingOutbox(pending);
            await this.#client.publishEvent(pending.event);
            const surface = surfacedMessage(
                this.#identity,
                pending.friend,
                "outgoing",
                pending.message,
                "local-send",
            );
            await this.#store.transaction(async (transaction) => {
                if ((await transaction.get(key)) === undefined) {
                    return;
                }
                await this.#callbacks.messagePublished?.(transaction, surface);
                await transaction.delete(key);
            });
        } finally {
            zeroBytes(bytes);
            clearMessageSecrets(pending.message);
        }
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
        if (
            pending.message.attachments.length !== 0 ||
            pending.event.topic !== expectedTopic ||
            pending.event.list?.length !== 2 ||
            appends.length !== 2 ||
            recipient === undefined ||
            self === undefined ||
            !equalBytes(recipient.bytes, pending.event.payload)
        ) {
            throw new Error("Direct-chat outbox does not match its canonical text message");
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
        text: string,
        sentAt: number | undefined,
    ): void {
        const matches =
            sameIdentity(retained.friend, friend) &&
            retained.message.text === text &&
            retained.message.attachments.length === 0 &&
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
        const key = `${prefix}${encodeBase64Url(digest)}/${encodeBase64Url(utf8Encode(sourceId))}`;
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
}
