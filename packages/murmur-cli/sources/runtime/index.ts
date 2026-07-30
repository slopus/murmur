import {
    ContactBook,
    DirectMessageIdCollisionError,
    MAX_FILE_BYTES,
    MAX_MESSAGE_ATTACHMENTS,
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    MurmurClient,
    acceptPrivateMessageFromContact,
    createPrivateMessage,
    createRelayEvent,
    decodeBase64Url,
    decodeEncryptedPrivateMessage,
    decryptContactProfile,
    decryptFile,
    decryptPrivateMessageFromContact,
    deriveNestedTopic,
    destroyIdentity,
    encodeBase64Url,
    encodeEncryptedPrivateMessage,
    encodeRelayEventWire,
    encryptFile,
    encryptPrivateMessageForContact,
    encryptProfileForContact,
    generateIdentityKeyPair,
    identityId,
    identityInboxTopic,
    hashBytes,
    utf8Decode,
    utf8Encode,
    validateIdentityProfile,
    zeroBytes,
    type Contact,
    type IdentityProfile,
    type IdentityPublicKeys,
    type MurmurStore,
    type ReceivedEvent,
    type RelayBlob,
    type RelayTransport,
    type StoreTransaction,
} from "@murmur/core";
import {
    decodeCliAccount,
    decodeCliOutboundMessage,
    decodeCliProfileEnvelope,
    decodeCliStoredMessage,
    encodeCliAccount,
    encodeCliOutboundMessage,
    encodeCliProfileEnvelope,
    encodeCliStoredMessage,
    type CliOutboundMessage,
} from "./impl/runtimeCodec.js";
import type {
    CliAccount,
    CliAttachmentInput,
    CliPublicIdentity,
    CliStoredMessage,
    CliSyncResult,
} from "./types.js";

export type {
    CliAccount,
    CliAttachmentInput,
    CliContact,
    CliPublicIdentity,
    CliStoredMessage,
    CliSyncResult,
} from "./types.js";

const ACCOUNT_KEY = "cli/account/v1";
const MESSAGE_PREFIX = "cli/messages/v1";
const MESSAGE_SEQUENCE_PREFIX = "cli/message-sequence/v1";
const OUTBOUND_PREFIX = "cli/outbound/v1";
const OUTBOUND_BLOB_PREFIX = "cli/outbound-blobs/v1";
const QUARANTINE_PREFIX = "cli/quarantine/v1";
const MAXIMUM_QUARANTINE_RECORDS = 64;
const DIRECT_TOPIC_COMPONENT = utf8Encode("direct-private-message/v1");

/** Maximum total plaintext attachment bytes retained for one CLI message. */
export const MAX_CLI_ATTACHMENT_BYTES = MAX_FILE_BYTES;
/** Maximum attachment count retained for one CLI message. */
export const MAX_CLI_ATTACHMENTS = MAX_MESSAGE_ATTACHMENTS;

function validateTransports(transports: readonly RelayTransport[]): void {
    if (transports.length === 0) {
        throw new Error("At least one Murmur relay transport is required");
    }
    if (new Set(transports.map((transport) => transport.id)).size !== transports.length) {
        throw new Error("Murmur relay transport identifiers must be unique");
    }
}

function validateAttachments(attachments: readonly CliAttachmentInput[]): void {
    if (attachments.length > MAX_CLI_ATTACHMENTS) {
        throw new Error(`A CLI message may contain at most ${MAX_CLI_ATTACHMENTS} attachments`);
    }
    let total = 0;
    for (const attachment of attachments) {
        if (!(attachment.bytes instanceof Uint8Array)) {
            throw new Error("CLI attachment bytes must be a Uint8Array");
        }
        total += attachment.bytes.length;
        if (!Number.isSafeInteger(total) || total > MAX_CLI_ATTACHMENT_BYTES) {
            throw new Error(
                `CLI message attachments exceed ${MAX_CLI_ATTACHMENT_BYTES} aggregate bytes`,
            );
        }
    }
}

/** Stable opaque direct-message topic for one CLI identity. */
export function cliDirectMessageTopic(identity: IdentityPublicKeys): string {
    return deriveNestedTopic(identityInboxTopic(identity), DIRECT_TOPIC_COMPONENT);
}

function clearMessageSecrets(stored: Pick<CliStoredMessage, "message">): void {
    for (const attachment of stored.message.attachments) {
        zeroBytes(attachment.key);
        zeroBytes(attachment.nonce);
    }
}

function messageKey(ownerId: string, stored: CliStoredMessage): string {
    return `${MESSAGE_PREFIX}/${ownerId}/${stored.sequence
        .toString()
        .padStart(16, "0")}/${stored.conversationId}/${stored.message.id}/${stored.direction}`;
}

async function persistStoredMessage(
    transaction: Pick<StoreTransaction, "set">,
    key: string,
    stored: CliStoredMessage,
): Promise<void> {
    const encoded = encodeCliStoredMessage(stored);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

async function nextMessageSequence(
    transaction: StoreTransaction,
    ownerId: string,
): Promise<number> {
    const key = `${MESSAGE_SEQUENCE_PREFIX}/${ownerId}`;
    const currentBytes = await transaction.get(key);
    let current = 0;
    if (currentBytes !== undefined) {
        try {
            const value = utf8Decode(currentBytes);
            if (!/^(?:0|[1-9]\d*)$/.test(value)) {
                throw new Error("Invalid CLI message sequence");
            }
            current = Number(value);
            if (!Number.isSafeInteger(current) || current < 0) {
                throw new Error("Invalid CLI message sequence");
            }
        } finally {
            zeroBytes(currentBytes);
        }
    }
    const next = current + 1;
    if (!Number.isSafeInteger(next)) {
        throw new Error("CLI message sequence is exhausted");
    }
    const encoded = utf8Encode(String(next));
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
    return next;
}

function outboundKey(ownerId: string, eventId: string): string {
    return `${OUTBOUND_PREFIX}/${ownerId}/${eventId}`;
}

function outboundBlobKey(ownerId: string, eventId: string, blobId: string): string {
    return `${OUTBOUND_BLOB_PREFIX}/${ownerId}/${eventId}/${blobId}`;
}

async function persistOutboundMessage(
    transaction: StoreTransaction,
    key: string,
    outbound: CliOutboundMessage,
): Promise<void> {
    const encoded = encodeCliOutboundMessage(outbound);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

function validateCliShareableProfile(account: CliAccount): void {
    const payload = encodeCliProfileEnvelope(
        encryptProfileForContact(account.identity, account.identity, account.profile),
    );
    try {
        if (payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
            throw new Error("CLI encrypted profile exceeds the relay event payload limit");
        }
    } finally {
        zeroBytes(payload);
    }
}

/** Encode both public identity keys as one command-line-safe contact token. */
export function encodeCliIdentityToken(identity: IdentityPublicKeys): string {
    if (identity.signingKey.length !== 32 || identity.encryptionKey.length !== 32) {
        throw new Error("CLI identity public keys must be 32 bytes");
    }
    return `${encodeBase64Url(identity.signingKey)}.${encodeBase64Url(identity.encryptionKey)}`;
}

/** Decode one strict contact token emitted by `murmur me`. */
export function decodeCliIdentityToken(token: string): IdentityPublicKeys {
    const parts = token.split(".");
    if (
        parts.length !== 2 ||
        !/^[A-Za-z0-9_-]{43}$/.test(parts[0] ?? "") ||
        !/^[A-Za-z0-9_-]{43}$/.test(parts[1] ?? "")
    ) {
        throw new Error("Invalid Murmur identity token");
    }
    const signingKey = decodeBase64Url(parts[0] ?? "");
    const encryptionKey = decodeBase64Url(parts[1] ?? "");
    if (
        signingKey.length !== 32 ||
        encryptionKey.length !== 32 ||
        encodeBase64Url(signingKey) !== parts[0] ||
        encodeBase64Url(encryptionKey) !== parts[1]
    ) {
        throw new Error("Invalid Murmur identity token");
    }
    return { signingKey, encryptionKey };
}

/** Durable Node runtime used by the CLI and its end-to-end tests. */
export class MurmurCliRuntime {
    readonly #store: MurmurStore;
    readonly #transports: readonly RelayTransport[];
    #account: CliAccount | undefined;
    #client: MurmurClient | undefined;
    #contacts: ContactBook | undefined;

    private constructor(
        store: MurmurStore,
        transports: readonly RelayTransport[],
        account?: CliAccount,
    ) {
        validateTransports(transports);
        this.#store = store;
        this.#transports = [...transports];
        this.#account = account;
        if (account !== undefined) {
            const services = this.#createAccountServices(account);
            this.#client = services.client;
            this.#contacts = services.contacts;
        }
    }

    /** Open a runtime from durable storage without generating keys implicitly. */
    static async open(options: {
        readonly store: MurmurStore;
        readonly transports: readonly RelayTransport[];
    }): Promise<MurmurCliRuntime> {
        validateTransports(options.transports);
        const encoded = await options.store.get(ACCOUNT_KEY);
        if (encoded === undefined) {
            return new MurmurCliRuntime(options.store, options.transports);
        }
        let account: CliAccount | undefined;
        try {
            account = decodeCliAccount(encoded);
            validateCliShareableProfile(account);
            return new MurmurCliRuntime(options.store, options.transports, account);
        } catch (error: unknown) {
            if (account !== undefined) {
                destroyIdentity(account.identity);
                if (account.profile.avatar !== undefined) {
                    zeroBytes(account.profile.avatar);
                }
            }
            throw error;
        } finally {
            zeroBytes(encoded);
        }
    }

    /** Whether this data directory already owns an identity. */
    get signedIn(): boolean {
        return this.#account !== undefined;
    }

    /** Generate and durably persist a new account. */
    async signIn(profile: IdentityProfile): Promise<CliPublicIdentity> {
        if (this.#account !== undefined) {
            throw new Error("A Murmur identity already exists in this data directory");
        }
        validateIdentityProfile(profile);
        const account: CliAccount = {
            identity: generateIdentityKeyPair(),
            profile: {
                name: profile.name,
                ...(profile.avatar === undefined ? {} : { avatar: profile.avatar.slice() }),
                ...(profile.metadata === undefined ? {} : { metadata: { ...profile.metadata } }),
            },
        };
        let encoded: Uint8Array | undefined;
        try {
            validateCliShareableProfile(account);
            const services = this.#createAccountServices(account);
            encoded = encodeCliAccount(account);
            await this.#store.set(ACCOUNT_KEY, encoded.slice());
            this.#account = account;
            this.#client = services.client;
            this.#contacts = services.contacts;
            return this.publicIdentity();
        } catch (error: unknown) {
            destroyIdentity(account.identity);
            if (account.profile.avatar !== undefined) {
                zeroBytes(account.profile.avatar);
            }
            throw error;
        } finally {
            if (encoded !== undefined) {
                zeroBytes(encoded);
            }
        }
    }

    /** Public identity and profile safe to print or give to a contact. */
    publicIdentity(): CliPublicIdentity {
        const account = this.#requireAccount();
        return {
            id: identityId(account.identity),
            token: encodeCliIdentityToken(account.identity),
            identity: {
                signingKey: account.identity.signingKey.slice(),
                encryptionKey: account.identity.encryptionKey.slice(),
            },
            profile: {
                name: account.profile.name,
                ...(account.profile.avatar === undefined
                    ? {}
                    : { avatar: account.profile.avatar.slice() }),
                ...(account.profile.metadata === undefined
                    ? {}
                    : { metadata: { ...account.profile.metadata } }),
            },
        };
    }

    /** Send this account's encrypted profile to one public identity. */
    async shareProfile(token: string): Promise<void> {
        const account = this.#requireAccount();
        const recipient = decodeCliIdentityToken(token);
        const payload = encodeCliProfileEnvelope(
            encryptProfileForContact(account.identity, recipient, account.profile),
        );
        try {
            await this.#requireClient().publish(identityInboxTopic(recipient), payload, [
                recipient,
            ]);
        } finally {
            zeroBytes(payload);
        }
    }

    /** List authenticated profiles received from contacts. */
    async contacts(): Promise<readonly Contact[]> {
        return this.#requireContacts().list();
    }

    /** Remove one local contact by signing identity or full token. */
    async removeContact(value: string): Promise<void> {
        const contact = await this.#resolveContact(value);
        await this.#requireContacts().remove(contact.identity);
    }

    /** Encrypt files and one signed private message to an authenticated contact. */
    async send(
        recipientValue: string,
        text: string,
        attachments: readonly CliAttachmentInput[] = [],
        now: number = Date.now(),
    ): Promise<string> {
        const account = this.#requireAccount();
        validateAttachments(attachments);
        const contact = await this.#resolveContact(recipientValue);
        const encryptedFiles: ReturnType<typeof encryptFile>[] = [];
        let stored: CliStoredMessage | undefined;
        let payload: Uint8Array | undefined;
        try {
            for (const attachment of attachments) {
                encryptedFiles.push(
                    encryptFile(attachment.bytes, {
                        name: attachment.name,
                        ...(attachment.mediaType === undefined
                            ? {}
                            : { mediaType: attachment.mediaType }),
                    }),
                );
            }
            const message = createPrivateMessage(
                text,
                encryptedFiles.map((file) => file.descriptor),
                now,
            );
            payload = encodeEncryptedPrivateMessage(
                encryptPrivateMessageForContact(account.identity, contact.identity, message),
            );
            const event = createRelayEvent(
                account.identity,
                cliDirectMessageTopic(contact.identity),
                payload,
                [contact.identity],
            );
            const ownerId = identityId(account.identity);
            let outbound: CliOutboundMessage | undefined;
            await this.#store.transaction(async (transaction) => {
                stored = {
                    sequence: await nextMessageSequence(transaction, ownerId),
                    direction: "outgoing",
                    conversationId: identityId(contact.identity),
                    status: "pending",
                    message,
                };
                const key = messageKey(ownerId, stored);
                outbound = {
                    event,
                    messageKey: key,
                    blobIds: encryptedFiles.map((file) => file.blob.id),
                };
                await persistStoredMessage(transaction, key, stored);
                await persistOutboundMessage(transaction, outboundKey(ownerId, event.id), outbound);
                for (const file of encryptedFiles) {
                    await transaction.set(
                        outboundBlobKey(ownerId, event.id, file.blob.id),
                        file.blob.bytes.slice(),
                    );
                }
            });
            if (outbound === undefined) {
                throw new Error("CLI outbound message was not persisted");
            }
            await this.#flushOutboundMessage(ownerId, outbound);
            return message.id;
        } finally {
            if (payload !== undefined) {
                zeroBytes(payload);
            }
            if (stored !== undefined) {
                clearMessageSecrets(stored);
            } else {
                for (const file of encryptedFiles) {
                    zeroBytes(file.descriptor.key);
                    zeroBytes(file.descriptor.nonce);
                }
            }
        }
    }

    /** Retry retained outbox entries and process one bounded relay batch. */
    async sync(waitMilliseconds: number = 0, signal?: AbortSignal): Promise<CliSyncResult> {
        const account = this.#requireAccount();
        const client = this.#requireClient();
        const ownerId = identityId(account.identity);
        const retryReport = await client.retryOutboundSettled();
        for (const result of retryReport.results) {
            await this.#completeOutboundMessage(ownerId, result.event.id);
        }
        const applicationRetryFailures = await this.#flushOutboundMessages(ownerId);
        const retriedOutbound = retryReport.results.length;
        const retryFailures = retryReport.failures.length + applicationRetryFailures;
        let profiles = 0;
        let messages = 0;
        let duplicates = 0;
        let deferred = 0;
        let quarantined = 0;

        for (let batch = 0; batch < 625; batch += 1) {
            const deliveries = await client.sync(batch === 0 ? waitMilliseconds : 0, signal);
            if (deliveries.length === 0) {
                break;
            }
            for (const delivery of deliveries) {
                if (delivery.event.topic === identityInboxTopic(account.identity)) {
                    let opened: ReturnType<typeof decryptContactProfile>;
                    try {
                        opened = decryptContactProfile(
                            account.identity,
                            decodeCliProfileEnvelope(delivery.event.payload),
                        );
                    } catch {
                        await this.#quarantine(ownerId, delivery, "invalid-profile");
                        quarantined += 1;
                        continue;
                    }
                    try {
                        await this.#requireContacts().save(opened);
                        await delivery.acknowledge();
                        profiles += 1;
                    } catch {
                        deferred += 1;
                    } finally {
                        if (opened.profile.avatar !== undefined) {
                            zeroBytes(opened.profile.avatar);
                        }
                    }
                    continue;
                }
                if (delivery.event.topic === cliDirectMessageTopic(account.identity)) {
                    try {
                        const encrypted = decodeEncryptedPrivateMessage(delivery.event.payload);
                        const validated = decryptPrivateMessageFromContact(
                            account.identity,
                            encrypted,
                        );
                        clearMessageSecrets(validated);
                    } catch {
                        await this.#quarantine(ownerId, delivery, "invalid-private-message");
                        quarantined += 1;
                        continue;
                    }
                    let accepted:
                        | Awaited<ReturnType<typeof acceptPrivateMessageFromContact>>
                        | undefined;
                    try {
                        accepted = await acceptPrivateMessageFromContact(
                            this.#store,
                            account.identity,
                            decodeEncryptedPrivateMessage(delivery.event.payload),
                            async (transaction, opened): Promise<void> => {
                                const stored: CliStoredMessage = {
                                    sequence: await nextMessageSequence(transaction, ownerId),
                                    direction: "incoming",
                                    conversationId: identityId(opened.identity),
                                    status: "received",
                                    message: opened.message,
                                };
                                await persistStoredMessage(
                                    transaction,
                                    messageKey(identityId(account.identity), stored),
                                    stored,
                                );
                            },
                        );
                        await delivery.acknowledge();
                        if (accepted.status === "opened") {
                            messages += 1;
                        } else {
                            duplicates += 1;
                        }
                    } catch (error: unknown) {
                        if (error instanceof DirectMessageIdCollisionError) {
                            await this.#quarantine(ownerId, delivery, "private-message-collision");
                            quarantined += 1;
                        } else {
                            deferred += 1;
                        }
                    } finally {
                        if (accepted !== undefined) {
                            clearMessageSecrets(accepted);
                        }
                    }
                    continue;
                }
                await this.#quarantine(ownerId, delivery, "unsupported-topic");
                quarantined += 1;
            }
            if (batch === 624) {
                throw new Error("Murmur sync exceeded its 10000-delivery drain budget");
            }
        }
        return {
            profiles,
            messages,
            duplicates,
            deferred,
            retriedOutbound,
            retryFailures,
            quarantined,
        };
    }

    /** Read stable local history, optionally for one contact. */
    async messages(
        contactValue?: string,
        limit: number = 100,
    ): Promise<readonly CliStoredMessage[]> {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
            throw new Error("Message limit must be between 1 and 10000");
        }
        const account = this.#requireAccount();
        const conversationId =
            contactValue === undefined
                ? undefined
                : identityId((await this.#resolveContact(contactValue)).identity);
        const prefix = `${MESSAGE_PREFIX}/${identityId(account.identity)}/`;
        const values = [...(await this.#store.list(prefix)).values()];
        const records: CliStoredMessage[] = [];
        try {
            for (const value of values) {
                records.push(decodeCliStoredMessage(value));
            }
        } catch (error: unknown) {
            for (const stored of records) {
                clearMessageSecrets(stored);
            }
            throw error;
        } finally {
            for (const value of values) {
                zeroBytes(value);
            }
        }
        const filtered =
            conversationId === undefined
                ? records
                : records.filter((stored) => stored.conversationId === conversationId);
        for (const stored of records) {
            if (!filtered.includes(stored)) {
                clearMessageSecrets(stored);
            }
        }
        const start = Math.max(0, filtered.length - limit);
        for (const stored of filtered.slice(0, start)) {
            clearMessageSecrets(stored);
        }
        return filtered.slice(start);
    }

    /** Download, authenticate, and decrypt one attachment from local history. */
    async attachment(messageId: string, name: string): Promise<Uint8Array> {
        const history = await this.messages(undefined, 10_000);
        try {
            const matches = history.filter((stored) => stored.message.id === messageId);
            if (matches.length !== 1) {
                throw new Error(
                    matches.length === 0 ? "Message not found" : "Message identifier is ambiguous",
                );
            }
            const descriptor = matches[0]?.message.attachments.find(
                (attachment) => attachment.name === name,
            );
            if (descriptor === undefined) {
                throw new Error("Attachment not found");
            }
            const blob = await this.#requireClient().getBlob(descriptor.blobId);
            if (blob === undefined) {
                throw new Error("Encrypted attachment blob is unavailable");
            }
            return decryptFile(descriptor, blob);
        } finally {
            for (const stored of history) {
                clearMessageSecrets(stored);
            }
        }
    }

    async #flushOutboundMessages(ownerId: string): Promise<number> {
        const values = await this.#store.list(`${OUTBOUND_PREFIX}/${ownerId}/`);
        let failures = 0;
        for (const value of values.values()) {
            let outbound: CliOutboundMessage;
            try {
                outbound = decodeCliOutboundMessage(value);
            } finally {
                zeroBytes(value);
            }
            try {
                await this.#flushOutboundMessage(ownerId, outbound);
            } catch {
                failures += 1;
            }
        }
        return failures;
    }

    async #flushOutboundMessage(ownerId: string, outbound: CliOutboundMessage): Promise<void> {
        for (const blobId of outbound.blobIds) {
            const bytes = await this.#store.get(
                outboundBlobKey(ownerId, outbound.event.id, blobId),
            );
            if (bytes === undefined) {
                throw new Error("CLI encrypted attachment outbox is incomplete");
            }
            try {
                const blob: RelayBlob = { id: blobId, bytes };
                for (const transport of this.#transports) {
                    await transport.putBlob({
                        id: blob.id,
                        bytes: blob.bytes.slice(),
                    });
                }
            } finally {
                zeroBytes(bytes);
            }
        }
        await this.#requireClient().publishEvent(outbound.event);
        await this.#completeOutboundMessage(ownerId, outbound.event.id);
    }

    async #completeOutboundMessage(ownerId: string, eventId: string): Promise<void> {
        const key = outboundKey(ownerId, eventId);
        const encodedOutbound = await this.#store.get(key);
        if (encodedOutbound === undefined) {
            return;
        }
        let outbound: CliOutboundMessage;
        try {
            outbound = decodeCliOutboundMessage(encodedOutbound);
        } finally {
            zeroBytes(encodedOutbound);
        }
        await this.#store.transaction(async (transaction) => {
            const encodedMessage = await transaction.get(outbound.messageKey);
            if (encodedMessage === undefined) {
                throw new Error("CLI outbound history record is missing");
            }
            let stored: CliStoredMessage;
            try {
                stored = decodeCliStoredMessage(encodedMessage);
            } finally {
                zeroBytes(encodedMessage);
            }
            try {
                await persistStoredMessage(transaction, outbound.messageKey, {
                    ...stored,
                    status: "sent",
                });
                await transaction.delete(key);
                for (const blobId of outbound.blobIds) {
                    await transaction.delete(outboundBlobKey(ownerId, eventId, blobId));
                }
            } finally {
                clearMessageSecrets(stored);
            }
        });
    }

    async #quarantine(ownerId: string, delivery: ReceivedEvent, reason: string): Promise<void> {
        const eventBytes = encodeRelayEventWire(delivery.event);
        const fingerprint = encodeBase64Url(hashBytes(eventBytes));
        const record = utf8Encode(
            JSON.stringify({
                version: 1,
                reason,
                eventId: delivery.event.id,
                topic: delivery.event.topic,
                sender: identityId(delivery.event.sender),
                payloadBytes: delivery.event.payload.length,
                fingerprint,
            }),
        );
        const prefix = `${QUARANTINE_PREFIX}/${ownerId}/`;
        const key = `${prefix}${delivery.event.createdAt.toString().padStart(16, "0")}/${
            delivery.event.id
        }/${fingerprint}`;
        try {
            await this.#store.transaction(async (transaction) => {
                await transaction.set(key, record.slice());
                const records = await transaction.list(prefix);
                const keys = [...records.keys()].sort();
                for (const value of records.values()) {
                    zeroBytes(value);
                }
                for (const expired of keys.slice(
                    0,
                    Math.max(0, keys.length - MAXIMUM_QUARANTINE_RECORDS),
                )) {
                    await transaction.delete(expired);
                }
            });
        } finally {
            zeroBytes(record);
            zeroBytes(eventBytes);
        }
        await delivery.acknowledge();
    }

    /** Zero the in-memory account secrets. Durable data remains available. */
    destroy(): void {
        if (this.#account !== undefined) {
            destroyIdentity(this.#account.identity);
            if (this.#account.profile.avatar !== undefined) {
                zeroBytes(this.#account.profile.avatar);
            }
        }
        this.#account = undefined;
        this.#client = undefined;
        this.#contacts = undefined;
    }

    async #resolveContact(value: string): Promise<Contact> {
        const contacts = await this.#requireContacts().list();
        let signingId = value;
        if (value.includes(".")) {
            signingId = identityId(decodeCliIdentityToken(value));
        }
        const contact = contacts.find((candidate) => identityId(candidate.identity) === signingId);
        if (contact === undefined) {
            throw new Error("Contact not found; exchange profiles before messaging");
        }
        return contact;
    }

    #createAccountServices(account: CliAccount): {
        readonly client: MurmurClient;
        readonly contacts: ContactBook;
    } {
        return {
            client: new MurmurClient({
                identity: account.identity,
                store: this.#store,
                transports: this.#transports,
            }),
            contacts: new ContactBook(account.identity, this.#store),
        };
    }

    #requireAccount(): CliAccount {
        if (this.#account === undefined) {
            throw new Error("No Murmur identity; run `murmur sign-in` first");
        }
        return this.#account;
    }

    #requireClient(): MurmurClient {
        if (this.#client === undefined) {
            throw new Error("No Murmur identity; run `murmur sign-in` first");
        }
        return this.#client;
    }

    #requireContacts(): ContactBook {
        if (this.#contacts === undefined) {
            throw new Error("No Murmur identity; run `murmur sign-in` first");
        }
        return this.#contacts;
    }
}
