import {
    DirectChat,
    FriendBook,
    MAX_FILE_BYTES,
    MAX_MESSAGE_ATTACHMENTS,
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    MurmurClient,
    createPrivateMessage,
    createRelayEvent,
    createDocumentDelete,
    createDocumentInsert,
    createDocumentOperationId,
    decodeBase64Url,
    decryptContactProfile,
    decryptFile,
    destroyIdentity,
    encodeBase64Url,
    encodeEncryptedPrivateMessage,
    encodeSignedRelayEventWire,
    encryptFile,
    encryptPrivateMessageForContact,
    encryptProfileForContact,
    equalBytes,
    generateIdentityKeyPair,
    identityId,
    identityInboxTopic,
    hashBytes,
    pairwiseTopic,
    privateMessageListElementId,
    randomBytes,
    utf8Decode,
    utf8Encode,
    validateIdentityProfile,
    zeroBytes,
    type Contact,
    type DirectChatMessage,
    type FriendRecord,
    type DocumentOperation,
    type DocumentOperationId,
    type IdentityProfile,
    type IdentityKeyPair,
    type IdentityPublicKeys,
    type MurmurStore,
    type ReceivedEvent,
    type RelayBlob,
    type RelayTransport,
    type StoreTransaction,
} from "@slopus/murmur";
import {
    MlsEpochState,
    MlsGroupChannel,
    authenticateMurmurMlsCredential,
    createMlsGroup,
    createMlsKeyPackage,
    createMlsTreeEpochFromWelcome,
    decodeMlsKeyPackage,
    decodeMlsRatchetTree,
    deserializeMlsKeyPackageBundle,
    destroyMlsKeyPackageBundle,
    destroyMlsEpochSecrets,
    encodeMlsKeyPackage,
    encodeMlsRatchetTree,
    mlsKeyPackageReference,
    openMlsWelcome,
    serializeMlsKeyPackageBundle,
    verifyMlsKeyPackage,
    type MlsKeyPackage,
    type PreparedMlsGroupApplication,
    type PreparedMlsGroupCommit,
} from "@murmur/mls";
import {
    applyCliDocumentOperation,
    decodeCliDocumentApplication,
    decodeCliDocumentRecord,
    encodeCliDocumentApplication,
    encodeCliDocumentRecord,
    nextCliDocumentOperationSequence,
    openCliDocument,
    type CliDocumentApplication,
    type CliDocumentRecord,
} from "./impl/documentCodec.js";
import {
    decodeCliGroupInvitation,
    decodeCliGroupMessage,
    decodeCliGroupOutbound,
    decodeCliGroupRecord,
    decodeCliStoredGroupMessage,
    encodeCliGroupInvitation,
    encodeCliGroupMessage,
    encodeCliGroupOutbound,
    encodeCliGroupRecord,
    encodeCliStoredGroupMessage,
    type CliGroupOutbound,
    type CliGroupInvitation,
    type CliGroupRecord,
} from "./impl/groupCodec.js";
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
    CliDocumentSummary,
    CliGroupMessage,
    CliGroupSummary,
    CliPublicIdentity,
    CliStoredMessage,
    CliStoredGroupMessage,
    CliSyncResult,
} from "./types.js";

export type {
    CliAccount,
    CliAttachmentInput,
    CliContact,
    CliDocumentSummary,
    CliGroupMessage,
    CliGroupSummary,
    CliPublicIdentity,
    CliStoredGroupMessage,
    CliStoredMessage,
    CliSyncResult,
} from "./types.js";

const ACCOUNT_KEY = "cli/account/v1";
const MESSAGE_PREFIX = "cli/messages/v1";
const MESSAGE_SEQUENCE_PREFIX = "cli/message-sequence/v1";
const DIRECT_MESSAGE_INDEX_PREFIX = "cli/direct-message-index/v1";
const OUTBOUND_PREFIX = "cli/outbound/v1";
const OUTBOUND_BLOB_PREFIX = "cli/outbound-blobs/v1";
const QUARANTINE_PREFIX = "cli/quarantine/v1";
const LOCAL_KEY_PACKAGE_PREFIX = "cli/key-packages/local/v1";
const CONTACT_KEY_PACKAGE_PREFIX = "cli/key-packages/contact/v1";
const GROUP_PREFIX = "cli/groups/v1";
const REMOVED_GROUP_PREFIX = "cli/removed-groups/v1";
const GROUP_OUTBOUND_PREFIX = "cli/group-outbound/v1";
const GROUP_MESSAGE_PREFIX = "cli/group-messages/v1";
const GROUP_SEQUENCE_PREFIX = "cli/group-sequence/v1";
const DOCUMENT_PREFIX = "cli/documents/v1";
const MAXIMUM_QUARANTINE_RECORDS = 64;
const MAXIMUM_LOCAL_KEY_PACKAGES = 64;
const MAXIMUM_DEFERRED_GROUP_DELIVERIES = 10_000;

interface LoadedCliGroup {
    readonly name: string;
    readonly channel: MlsGroupChannel;
}

type CliGroupDeliveryResult = "message" | "document" | "commit" | "duplicate" | "deferred";

type PendingCliGroupPublication =
    | {
          readonly kind: "commit";
          readonly groupId: string;
          readonly outboxKey: string;
          readonly prepared: PreparedMlsGroupCommit;
      }
    | {
          readonly kind: "document";
          readonly groupId: string;
          readonly outboxKey: string;
          readonly prepared: PreparedMlsGroupApplication;
      }
    | {
          readonly kind: "application";
          readonly groupId: string;
          readonly outboxKey: string;
          readonly messageKey: string;
          readonly prepared: PreparedMlsGroupApplication;
      };

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

/** Shared-secret direct-message capability topic for one contact pair. */
export function cliDirectMessageTopic(self: IdentityKeyPair, peer: IdentityPublicKeys): string {
    return pairwiseTopic(self, peer);
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

function directMessageIndexKey(ownerId: string, conversationId: string, id: string): string {
    return `${DIRECT_MESSAGE_INDEX_PREFIX}/${ownerId}/${conversationId}/${id}`;
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

function localKeyPackageKey(ownerId: string, reference: Uint8Array): string {
    return `${LOCAL_KEY_PACKAGE_PREFIX}/${ownerId}/${encodeBase64Url(reference)}`;
}

function contactKeyPackageKey(ownerId: string, contactId: string): string {
    return `${CONTACT_KEY_PACKAGE_PREFIX}/${ownerId}/${contactId}`;
}

function cliGroupId(groupId: Uint8Array): string {
    return encodeBase64Url(hashBytes(groupId));
}

function cliGroupKey(ownerId: string, groupId: string): string {
    return `${GROUP_PREFIX}/${ownerId}/${groupId}`;
}

function cliGroupOutboundKey(
    ownerId: string,
    groupId: string,
    event: Pick<CliGroupOutbound["event"], "id" | "createdAt">,
    order: number,
): string {
    return `${GROUP_OUTBOUND_PREFIX}/${ownerId}/${groupId}/${event.createdAt
        .toString()
        .padStart(16, "0")}/${order}/${event.id}`;
}

function cliGroupMessageKey(
    ownerId: string,
    stored: Pick<CliStoredGroupMessage, "sequence" | "groupId" | "message" | "direction">,
): string {
    return `${GROUP_MESSAGE_PREFIX}/${ownerId}/${stored.sequence
        .toString()
        .padStart(16, "0")}/${stored.groupId}/${stored.message.id}/${stored.direction}`;
}

function cliDocumentKey(ownerId: string, groupId: string, documentId: string): string {
    return `${DOCUMENT_PREFIX}/${ownerId}/${groupId}/${documentId}`;
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

async function persistCliGroupRecord(
    transaction: Pick<StoreTransaction, "set">,
    key: string,
    record: CliGroupRecord,
): Promise<void> {
    const encoded = encodeCliGroupRecord(record);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

async function persistCliGroupOutbound(
    transaction: Pick<StoreTransaction, "set">,
    key: string,
    outbound: CliGroupOutbound,
): Promise<void> {
    const encoded = encodeCliGroupOutbound(outbound);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

async function persistCliStoredGroupMessage(
    transaction: Pick<StoreTransaction, "set">,
    key: string,
    stored: CliStoredGroupMessage,
): Promise<void> {
    const encoded = encodeCliStoredGroupMessage(stored);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

async function persistCliDocumentRecord(
    transaction: Pick<StoreTransaction, "set">,
    key: string,
    document: CliDocumentRecord,
): Promise<void> {
    const encoded = encodeCliDocumentRecord(document);
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
}

async function nextGroupSequence(transaction: StoreTransaction, ownerId: string): Promise<number> {
    const key = `${GROUP_SEQUENCE_PREFIX}/${ownerId}`;
    const currentBytes = await transaction.get(key);
    let current = 0;
    if (currentBytes !== undefined) {
        try {
            const value = utf8Decode(currentBytes);
            if (!/^(?:0|[1-9]\d*)$/.test(value)) {
                throw new Error("Invalid CLI group message sequence");
            }
            current = Number(value);
            if (!Number.isSafeInteger(current) || current < 0) {
                throw new Error("Invalid CLI group message sequence");
            }
        } finally {
            zeroBytes(currentBytes);
        }
    }
    const next = current + 1;
    if (!Number.isSafeInteger(next)) {
        throw new Error("CLI group message sequence is exhausted");
    }
    const encoded = utf8Encode(String(next));
    try {
        await transaction.set(key, encoded.slice());
    } finally {
        zeroBytes(encoded);
    }
    return next;
}

function includeFingerprint(
    fingerprints: readonly Uint8Array[],
    fingerprint: Uint8Array,
): readonly Uint8Array[] {
    return fingerprints.some((current) => equalBytes(current, fingerprint))
        ? fingerprints.map((current) => current.slice())
        : [...fingerprints.map((current) => current.slice()), fingerprint.slice()];
}

function validateCliShareableProfile(account: CliAccount): void {
    const bundle = createMlsKeyPackage(account.identity);
    let payload: Uint8Array | undefined;
    let keyPackage: Uint8Array | undefined;
    try {
        keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
        payload = encodeCliProfileEnvelope(
            encryptProfileForContact(
                account.identity,
                account.identity,
                account.profile,
                keyPackage,
            ),
        );
        if (payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
            throw new Error("CLI encrypted profile exceeds the relay event payload limit");
        }
    } finally {
        if (payload !== undefined) {
            zeroBytes(payload);
        }
        if (keyPackage !== undefined) {
            zeroBytes(keyPackage);
        }
        destroyMlsKeyPackageBundle(bundle);
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
    #contacts: FriendBook | undefined;
    #directChat: DirectChat | undefined;
    #stagedDirectGroups: { readonly id: string; readonly group: LoadedCliGroup }[] = [];
    readonly #groups = new Map<string, LoadedCliGroup>();
    readonly #removedGroups = new Set<string>();
    readonly #pendingGroupPublications = new Map<string, PendingCliGroupPublication>();
    readonly #deferredGroupDeliveries = new Map<string, ReceivedEvent>();

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
            this.#directChat = services.directChat;
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
        let runtime: MurmurCliRuntime | undefined;
        try {
            account = decodeCliAccount(encoded);
            validateCliShareableProfile(account);
            runtime = new MurmurCliRuntime(options.store, options.transports, account);
            await runtime.#loadGroups();
            await runtime.#loadRemovedGroups();
            return runtime;
        } catch (error: unknown) {
            if (runtime !== undefined) {
                runtime.#destroyGroups();
            }
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
            this.#directChat = services.directChat;
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
        const bundle = createMlsKeyPackage(account.identity);
        const reference = mlsKeyPackageReference(bundle.keyPackage);
        let durableBundle: Uint8Array | undefined;
        let encodedKeyPackage: Uint8Array | undefined;
        let payload: Uint8Array | undefined;
        try {
            durableBundle = serializeMlsKeyPackageBundle(bundle);
            await this.#store.set(
                localKeyPackageKey(identityId(account.identity), reference),
                durableBundle.slice(),
            );
            await this.#pruneLocalKeyPackages(identityId(account.identity));
            encodedKeyPackage = encodeMlsKeyPackage(bundle.keyPackage);
            payload = encodeCliProfileEnvelope(
                encryptProfileForContact(
                    account.identity,
                    recipient,
                    account.profile,
                    encodedKeyPackage,
                ),
            );
            if (payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
                throw new Error("CLI encrypted profile exceeds the relay event payload limit");
            }
            await this.#requireClient().publishUnlinkable(identityInboxTopic(recipient), payload, {
                list: [
                    {
                        op: "append",
                        id: `profile:${encodeBase64Url(hashBytes(payload))}`,
                        bytes: payload,
                    },
                ],
            });
        } finally {
            if (durableBundle !== undefined) {
                zeroBytes(durableBundle);
            }
            if (encodedKeyPackage !== undefined) {
                zeroBytes(encodedKeyPackage);
            }
            if (payload !== undefined) {
                zeroBytes(payload);
            }
            destroyMlsKeyPackageBundle(bundle);
        }
    }

    /** List authenticated profiles received from contacts. */
    async contacts(): Promise<readonly Contact[]> {
        return this.#requireContacts().list();
    }

    /** Remove one local contact by signing identity or full token. */
    async removeContact(value: string): Promise<void> {
        const account = this.#requireAccount();
        const contact = await this.#resolveContact(value);
        await this.#requireContacts().remove(contact.identity);
        await this.#store.delete(
            contactKeyPackageKey(identityId(account.identity), identityId(contact.identity)),
        );
    }

    /** Create, persist, and subscribe a one-member RFC 9420 group. */
    async createGroup(name: string): Promise<string> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const epoch = createMlsGroup(account.identity);
        const channel = new MlsGroupChannel(epoch);
        const groupId = cliGroupId(channel.groupId);
        let state: Uint8Array | undefined;
        try {
            if (this.#groups.has(groupId) || this.#removedGroups.has(groupId)) {
                throw new Error("Generated MLS group identifier collided");
            }
            state = channel.serializeEpoch();
            await persistCliGroupRecord(this.#store, cliGroupKey(ownerId, groupId), {
                name,
                epochState: state,
                persistenceGeneration: channel.persistenceGeneration,
                appliedCommitFingerprints: [],
                appliedApplicationFingerprints: [],
            });
            this.#groups.set(groupId, { name, channel });
            await channel.subscribe(this.#requireClient());
            return groupId;
        } catch (error: unknown) {
            if (!this.#groups.has(groupId)) {
                channel.destroy();
            }
            throw error;
        } finally {
            if (state !== undefined) {
                zeroBytes(state);
            }
        }
    }

    /** List locally owned MLS groups and authenticated member identities. */
    groups(): readonly CliGroupSummary[] {
        return [...this.#groups.entries()]
            .map(([id, group]) => ({
                id,
                name: group.name,
                epoch: group.channel.epoch,
                members: group.channel.memberSignatureKeys.map((key) =>
                    key === undefined ? undefined : identityId({ signingKey: key }),
                ),
            }))
            .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
    }

    /** Add one contact with a fresh one-use KeyPackage and send its Welcome. */
    async inviteToGroup(groupValue: string, contactValue: string): Promise<void> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const [groupId, group] = this.#resolveGroup(groupValue);
        await this.#ensureNoDurableGroupOutbox(ownerId, groupId);
        const contact = await this.#resolveContact(contactValue);
        const contactId = identityId(contact.identity);
        const encodedKeyPackage = await this.#store.get(contactKeyPackageKey(ownerId, contactId));
        if (encodedKeyPackage === undefined) {
            throw new Error("Contact has no unused MLS KeyPackage; exchange profiles again");
        }
        let keyPackage: MlsKeyPackage;
        try {
            keyPackage = decodeMlsKeyPackage(encodedKeyPackage);
        } finally {
            zeroBytes(encodedKeyPackage);
        }
        if (
            !verifyMlsKeyPackage(keyPackage) ||
            !equalBytes(keyPackage.leafNode.signatureKey, contact.identity.signingKey)
        ) {
            throw new Error("Contact MLS KeyPackage does not match the authenticated profile");
        }
        const prepared = group.channel.prepareCommit([{ type: "add", keyPackage }]);
        let persisted = false;
        let checkpoint: Uint8Array | undefined;
        let treeBytes: Uint8Array | undefined;
        let invitationPayload: Uint8Array | undefined;
        try {
            if (prepared.welcome === undefined || prepared.addedLeaves.length !== 1) {
                throw new Error("MLS Add did not produce exactly one Welcome leaf");
            }
            checkpoint = prepared.serializeNextEpoch();
            treeBytes = encodeMlsRatchetTree(prepared.tree);
            const invitationText = encodeCliGroupInvitation({
                name: group.name,
                groupId: group.channel.groupId,
                welcome: prepared.welcome,
                tree: treeBytes,
                keyPackageReference: mlsKeyPackageReference(keyPackage),
                commitFingerprint: prepared.fingerprint,
            });
            const invitationMessage = createPrivateMessage(invitationText);
            invitationPayload = encodeEncryptedPrivateMessage(
                encryptPrivateMessageForContact(
                    account.identity,
                    contact.identity,
                    invitationMessage,
                ),
            );
            if (invitationPayload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
                throw new Error("MLS group invitation exceeds the relay payload limit");
            }
            const publicationTime = Date.now();
            const invitationEvent = createRelayEvent(
                account.identity,
                cliDirectMessageTopic(account.identity, contact.identity),
                invitationPayload,
                {
                    list: [
                        {
                            op: "append",
                            id: privateMessageListElementId(account.identity, invitationMessage),
                            bytes: invitationPayload,
                        },
                    ],
                },
                publicationTime,
            );
            const commitEvent = createRelayEvent(
                account.identity,
                group.channel.topic,
                prepared.payload,
                {},
                publicationTime,
            );
            const invitationOutboxKey = cliGroupOutboundKey(ownerId, groupId, invitationEvent, 0);
            const commitOutboxKey = cliGroupOutboundKey(ownerId, groupId, commitEvent, 1);
            await this.#store.transaction(async (transaction) => {
                await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                    name: group.name,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedCommitFingerprints: includeFingerprint(
                        group.channel.appliedCommitFingerprints,
                        prepared.fingerprint,
                    ),
                    appliedApplicationFingerprints: group.channel.appliedApplicationFingerprints,
                });
                await persistCliGroupOutbound(transaction, invitationOutboxKey, {
                    kind: "invitation",
                    groupId,
                    event: invitationEvent,
                });
                await persistCliGroupOutbound(transaction, commitOutboxKey, {
                    kind: "commit",
                    groupId,
                    event: commitEvent,
                });
                await transaction.delete(contactKeyPackageKey(ownerId, contactId));
            });
            persisted = true;
            prepared.markPersisted();
            const pending: PendingCliGroupPublication = {
                kind: "commit",
                groupId,
                outboxKey: commitOutboxKey,
                prepared,
            };
            this.#pendingGroupPublications.set(commitEvent.id, pending);
            await this.#requireClient().publishEvent(invitationEvent);
            await this.#store.delete(invitationOutboxKey);
            await this.#publishPendingGroupCommit(commitEvent, pending);
        } catch (error: unknown) {
            if (!persisted) {
                prepared.cancel();
            }
            throw error;
        } finally {
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
            if (treeBytes !== undefined) {
                zeroBytes(treeBytes);
            }
            if (invitationPayload !== undefined) {
                zeroBytes(invitationPayload);
            }
        }
    }

    /** Cryptographically remove one authenticated contact from an MLS group. */
    async removeFromGroup(groupValue: string, contactValue: string): Promise<void> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const [groupId, group] = this.#resolveGroup(groupValue);
        await this.#ensureNoDurableGroupOutbox(ownerId, groupId);
        const contact = await this.#resolveContact(contactValue);
        const removed = group.channel.memberSignatureKeys.findIndex(
            (key) => key !== undefined && equalBytes(key, contact.identity.signingKey),
        );
        if (removed < 0) {
            throw new Error("Contact is not an active MLS group member");
        }
        const prepared = group.channel.prepareCommit([{ type: "remove", removed }]);
        let persisted = false;
        let checkpoint: Uint8Array | undefined;
        try {
            checkpoint = prepared.serializeNextEpoch();
            const event = createRelayEvent(
                account.identity,
                group.channel.topic,
                prepared.payload,
                {
                    list: [
                        {
                            op: "append",
                            id: `message:${encodeBase64Url(prepared.fingerprint)}`,
                            bytes: prepared.payload,
                        },
                    ],
                },
            );
            const outboxKey = cliGroupOutboundKey(ownerId, groupId, event, 1);
            await this.#store.transaction(async (transaction) => {
                await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                    name: group.name,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedCommitFingerprints: includeFingerprint(
                        group.channel.appliedCommitFingerprints,
                        prepared.fingerprint,
                    ),
                    appliedApplicationFingerprints: group.channel.appliedApplicationFingerprints,
                });
                await persistCliGroupOutbound(transaction, outboxKey, {
                    kind: "commit",
                    groupId,
                    event,
                });
            });
            persisted = true;
            prepared.markPersisted();
            const pending: PendingCliGroupPublication = {
                kind: "commit",
                groupId,
                outboxKey,
                prepared,
            };
            this.#pendingGroupPublications.set(event.id, pending);
            await this.#publishPendingGroupCommit(event, pending);
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

    /** Encrypt, checkpoint, persist, and publish one MLS group message. */
    async sendToGroup(groupValue: string, text: string, now: number = Date.now()): Promise<string> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const [groupId, group] = this.#resolveGroup(groupValue);
        await this.#ensureNoDurableGroupOutbox(ownerId, groupId);
        const sender = group.channel.memberSignatureKeys.findIndex(
            (key) => key !== undefined && equalBytes(key, account.identity.signingKey),
        );
        if (sender < 0) {
            throw new Error("Local identity is not an active MLS group member");
        }
        const message: CliGroupMessage = {
            id: encodeBase64Url(randomBytes(16)),
            sentAt: now,
            text,
        };
        const applicationData = encodeCliGroupMessage(message);
        const prepared = group.channel.prepareSend(applicationData);
        let persisted = false;
        let checkpoint: Uint8Array | undefined;
        try {
            if (prepared.payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
                throw new Error("MLS group message exceeds the relay payload limit");
            }
            checkpoint = prepared.serializeEpoch();
            const event = createRelayEvent(account.identity, group.channel.topic, prepared.payload);
            const outboxKey = cliGroupOutboundKey(ownerId, groupId, event, 2);
            let messageKey = "";
            await this.#store.transaction(async (transaction) => {
                const stored: CliStoredGroupMessage = {
                    sequence: await nextGroupSequence(transaction, ownerId),
                    groupId,
                    direction: "outgoing",
                    status: "pending",
                    sender,
                    message,
                };
                messageKey = cliGroupMessageKey(ownerId, stored);
                await persistCliStoredGroupMessage(transaction, messageKey, stored);
                await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                    name: group.name,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedCommitFingerprints: group.channel.appliedCommitFingerprints,
                    appliedApplicationFingerprints: includeFingerprint(
                        group.channel.appliedApplicationFingerprints,
                        prepared.fingerprint,
                    ),
                });
                await persistCliGroupOutbound(transaction, outboxKey, {
                    kind: "application",
                    groupId,
                    event,
                    messageKey,
                });
            });
            persisted = true;
            prepared.markPersisted();
            const pending: PendingCliGroupPublication = {
                kind: "application",
                groupId,
                outboxKey,
                messageKey,
                prepared,
            };
            this.#pendingGroupPublications.set(event.id, pending);
            await this.#publishPendingGroupApplication(event, pending);
            return message.id;
        } catch (error: unknown) {
            if (!persisted) {
                prepared.cancel();
            }
            throw error;
        } finally {
            zeroBytes(applicationData);
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
        }
    }

    /** Read durable group history, optionally filtered to one group. */
    async groupMessages(
        groupValue?: string,
        limit: number = 100,
    ): Promise<readonly CliStoredGroupMessage[]> {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
            throw new Error("Group message limit must be between 1 and 10000");
        }
        const ownerId = identityId(this.#requireAccount().identity);
        const groupId = groupValue === undefined ? undefined : this.#resolveGroup(groupValue)[0];
        const values = [
            ...(await this.#store.list(`${GROUP_MESSAGE_PREFIX}/${ownerId}/`)).values(),
        ];
        const messages: CliStoredGroupMessage[] = [];
        try {
            for (const value of values) {
                messages.push(decodeCliStoredGroupMessage(value));
            }
        } finally {
            for (const value of values) {
                zeroBytes(value);
            }
        }
        const filtered =
            groupId === undefined
                ? messages
                : messages.filter((message) => message.groupId === groupId);
        return filtered.slice(Math.max(0, filtered.length - limit));
    }

    /** Create and announce an empty shared document inside one MLS group. */
    async createDocument(groupValue: string, name: string): Promise<string> {
        const [groupId, group] = this.#resolveGroup(groupValue);
        const id = encodeBase64Url(randomBytes(16));
        const record: CliDocumentRecord = {
            id,
            groupId,
            name,
            operations: [],
            actorHighWaterMarks: [],
        };
        await this.#publishDocumentApplication(
            groupId,
            group,
            {
                documentId: id,
                name,
            },
            record,
        );
        return id;
    }

    /** Insert one immutable span into a shared document. */
    async insertDocument(
        documentValue: string,
        text: string,
        after: DocumentOperationId | null = null,
    ): Promise<DocumentOperationId> {
        const resolved = await this.#resolveDocument(documentValue);
        const actor = identityId(this.#requireAccount().identity);
        const sequence = nextCliDocumentOperationSequence(resolved.record, actor);
        const operation = createDocumentInsert(
            createDocumentOperationId(actor, sequence),
            after,
            text,
        );
        await this.#publishDocumentOperation(resolved.record, operation);
        return operation.id;
    }

    /** Add one permanent tombstone to a shared document. */
    async deleteDocument(
        documentValue: string,
        target: DocumentOperationId,
    ): Promise<DocumentOperationId> {
        const resolved = await this.#resolveDocument(documentValue);
        const actor = identityId(this.#requireAccount().identity);
        const sequence = nextCliDocumentOperationSequence(resolved.record, actor);
        const operation = createDocumentDelete(createDocumentOperationId(actor, sequence), target);
        await this.#publishDocumentOperation(resolved.record, operation);
        return operation.id;
    }

    /** List deterministic rendered views of locally known shared documents. */
    async documents(groupValue?: string): Promise<readonly CliDocumentSummary[]> {
        const ownerId = identityId(this.#requireAccount().identity);
        const groupId = groupValue === undefined ? undefined : this.#resolveGroup(groupValue)[0];
        const entries = await this.#store.list(`${DOCUMENT_PREFIX}/${ownerId}/`);
        const documents: CliDocumentSummary[] = [];
        try {
            for (const [key, value] of entries) {
                const record = decodeCliDocumentRecord(value);
                if (key !== cliDocumentKey(ownerId, record.groupId, record.id)) {
                    throw new Error("Durable CLI document key does not match its record");
                }
                if (groupId !== undefined && record.groupId !== groupId) {
                    continue;
                }
                const document = openCliDocument(record);
                documents.push({
                    id: record.id,
                    groupId: record.groupId,
                    name: record.name,
                    text: document.render(),
                    operationCount: record.operations.length,
                    operations: document.operations(),
                });
            }
        } finally {
            for (const value of entries.values()) {
                zeroBytes(value);
            }
        }
        return documents.sort((left, right) =>
            left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
        );
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
        if (attachments.length === 0) {
            return (
                await this.#requireDirectChat().sendText(contact.identity, text, { sentAt: now })
            ).message.id;
        }
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
                cliDirectMessageTopic(account.identity, contact.identity),
                payload,
                {
                    list: [
                        {
                            op: "append",
                            id: privateMessageListElementId(account.identity, message),
                            bytes: payload,
                        },
                    ],
                },
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
        await client.subscribe(identityInboxTopic(account.identity));
        const knownContacts = [...(await this.#requireContacts().list({ includeRemoved: true }))];
        await this.#requireDirectChat().subscribe();
        await Promise.all(
            [...this.#groups.values()].map(async (group) => group.channel.subscribe(client)),
        );
        const directRetry = await this.#requireDirectChat().retryPending();
        const retryReport = await client.retryOutboundSettled();
        for (const result of retryReport.results) {
            await this.#completeOutboundMessage(ownerId, result.event.id);
            await this.#completeRetriedGroupPublication(result);
        }
        const applicationRetryFailures = await this.#flushOutboundMessages(ownerId);
        const groupRetryFailures = await this.#flushGroupOutbound(ownerId);
        const retriedOutbound = retryReport.results.length;
        const retryFailures =
            retryReport.failures.length +
            directRetry.failures.length +
            applicationRetryFailures +
            groupRetryFailures;
        let profiles = 0;
        let messages = 0;
        let duplicates = 0;
        let deferred = 0;
        let quarantined = 0;
        let groupMessages = 0;
        let groupCommits = 0;
        let invitations = 0;
        let documentUpdates = 0;

        for (let batch = 0; batch < 625; batch += 1) {
            const syncResult = await client.sync(batch === 0 ? waitMilliseconds : 0, signal);
            if (syncResult.status === "reset") {
                for (const reset of syncResult.resets) {
                    const friend = knownContacts.find(
                        (candidate) =>
                            cliDirectMessageTopic(account.identity, candidate.identity) ===
                            reset.topic,
                    );
                    if (friend === undefined) {
                        throw new Error(
                            `Relay topic ${reset.topic} on ${reset.relayId} requires a state reload`,
                        );
                    }
                    this.#stagedDirectGroups = [];
                    try {
                        const recovered = await this.#requireDirectChat().recoverReset(reset);
                        messages += recovered.opened.length;
                        duplicates += recovered.duplicates;
                        quarantined += recovered.quarantined;
                        for (const acceptedGroup of this.#takeStagedDirectGroups()) {
                            this.#groups.set(acceptedGroup.id, acceptedGroup.group);
                            await acceptedGroup.group.channel.subscribe(client);
                            invitations += 1;
                        }
                    } catch (error: unknown) {
                        for (const staged of this.#takeStagedDirectGroups()) {
                            staged.group.channel.destroy();
                        }
                        throw error;
                    }
                }
                continue;
            }
            const deliveries = syncResult.events;
            if (deliveries.length === 0) {
                break;
            }
            for (const delivery of deliveries) {
                if (delivery.event.topic === identityInboxTopic(account.identity)) {
                    let opened: ReturnType<typeof decryptContactProfile>;
                    let keyPackage: MlsKeyPackage | undefined;
                    try {
                        const envelope = decodeCliProfileEnvelope(delivery.event.payload);
                        opened = decryptContactProfile(account.identity, envelope.encrypted);
                        keyPackage =
                            opened.privateData === undefined
                                ? undefined
                                : decodeMlsKeyPackage(opened.privateData);
                        if (
                            keyPackage !== undefined &&
                            (!verifyMlsKeyPackage(keyPackage) ||
                                !equalBytes(
                                    keyPackage.leafNode.signatureKey,
                                    opened.identity.signingKey,
                                ))
                        ) {
                            throw new Error(
                                "Profile KeyPackage does not match its authenticated sender",
                            );
                        }
                    } catch {
                        await this.#quarantine(ownerId, delivery, "invalid-profile");
                        quarantined += 1;
                        continue;
                    }
                    try {
                        let saved: FriendRecord | undefined;
                        let encodedKeyPackage: Uint8Array | undefined;
                        if (keyPackage !== undefined) {
                            encodedKeyPackage = encodeMlsKeyPackage(keyPackage);
                        }
                        try {
                            saved = await this.#store.transaction(async (transaction) => {
                                const contact = await this.#requireContacts().saveInTransaction(
                                    transaction,
                                    opened,
                                );
                                if (encodedKeyPackage !== undefined) {
                                    await transaction.set(
                                        contactKeyPackageKey(ownerId, identityId(opened.identity)),
                                        encodedKeyPackage,
                                    );
                                }
                                await delivery.advanceCursor(transaction);
                                return contact;
                            });
                        } finally {
                            if (encodedKeyPackage !== undefined) {
                                zeroBytes(encodedKeyPackage);
                            }
                        }
                        if (saved === undefined) {
                            throw new Error("Authenticated friend was not persisted");
                        }
                        const persistedFriend = saved;
                        if (
                            !knownContacts.some((contact) =>
                                equalBytes(
                                    contact.identity.signingKey,
                                    persistedFriend.identity.signingKey,
                                ),
                            )
                        ) {
                            knownContacts.push(persistedFriend);
                        }
                        await this.#requireDirectChat().subscribeFriend(persistedFriend);
                        profiles += 1;
                    } catch {
                        deferred += 1;
                    } finally {
                        if (opened.profile.avatar !== undefined) {
                            zeroBytes(opened.profile.avatar);
                        }
                        if (opened.privateData !== undefined) {
                            zeroBytes(opened.privateData);
                        }
                    }
                    continue;
                }
                const directContact = knownContacts.find(
                    (contact) =>
                        delivery.event.topic ===
                        cliDirectMessageTopic(account.identity, contact.identity),
                );
                if (directContact !== undefined) {
                    this.#stagedDirectGroups = [];
                    try {
                        const accepted = await this.#requireDirectChat().handleEvent(delivery);
                        if (accepted.status === "unhandled") {
                            throw new Error("DirectChat did not recognize a known pairwise topic");
                        }
                        for (const acceptedGroup of this.#takeStagedDirectGroups()) {
                            this.#groups.set(acceptedGroup.id, acceptedGroup.group);
                            await acceptedGroup.group.channel.subscribe(client);
                            invitations += 1;
                        }
                        if (accepted.status === "opened") {
                            messages += 1;
                        } else if (accepted.status === "duplicate") {
                            duplicates += 1;
                        } else {
                            quarantined += 1;
                        }
                    } catch {
                        for (const staged of this.#takeStagedDirectGroups()) {
                            staged.group.channel.destroy();
                        }
                        deferred += 1;
                    }
                    continue;
                }
                const groupEntry = [...this.#groups.entries()].find(
                    ([, group]) => group.channel.topic === delivery.event.topic,
                );
                if (groupEntry !== undefined) {
                    const result = await this.#handleGroupDelivery(
                        ownerId,
                        groupEntry[0],
                        groupEntry[1],
                        delivery,
                    );
                    if (result === "message") {
                        groupMessages += 1;
                    } else if (result === "document") {
                        documentUpdates += 1;
                    } else if (result === "commit") {
                        groupCommits += 1;
                    } else if (result === "duplicate") {
                        duplicates += 1;
                    } else {
                        this.#deferGroupDelivery(delivery);
                        deferred += 1;
                    }
                    continue;
                }
                if (
                    delivery.event.topic.startsWith("mls:") &&
                    this.#removedGroups.has(delivery.event.topic.slice(4))
                ) {
                    try {
                        await this.#store.transaction(async (transaction) =>
                            delivery.advanceCursor(transaction),
                        );
                        duplicates += 1;
                    } catch {
                        deferred += 1;
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
        const deferredRetry = await this.#retryDeferredGroupDeliveries(ownerId);
        groupMessages += deferredRetry.messages;
        documentUpdates += deferredRetry.documents;
        groupCommits += deferredRetry.commits;
        duplicates += deferredRetry.duplicates;
        deferred = Math.max(0, deferred - deferredRetry.resolved);
        return {
            profiles,
            messages,
            duplicates,
            deferred,
            retriedOutbound,
            retryFailures,
            quarantined,
            groupMessages,
            groupCommits,
            invitations,
            documentUpdates,
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

    async #loadGroups(): Promise<void> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const entries = await this.#store.list(`${GROUP_PREFIX}/${ownerId}/`);
        try {
            for (const [key, value] of entries) {
                const expectedPrefix = `${GROUP_PREFIX}/${ownerId}/`;
                const groupId = key.slice(expectedPrefix.length);
                const loaded = this.#decodeLoadedGroup(groupId, value);
                if (this.#groups.has(groupId)) {
                    loaded.channel.destroy();
                    throw new Error("Duplicate durable CLI group");
                }
                this.#groups.set(groupId, loaded);
            }
        } catch (error: unknown) {
            this.#destroyGroups();
            throw error;
        } finally {
            for (const value of entries.values()) {
                zeroBytes(value);
            }
        }
    }

    async #loadRemovedGroups(): Promise<void> {
        const ownerId = identityId(this.#requireAccount().identity);
        const prefix = `${REMOVED_GROUP_PREFIX}/${ownerId}/`;
        const entries = await this.#store.list(prefix);
        for (const [key, value] of entries) {
            try {
                const groupId = key.slice(prefix.length);
                if (
                    !/^[A-Za-z0-9_-]{43}$/.test(groupId) ||
                    value.length !== 1 ||
                    value[0] !== 1 ||
                    this.#groups.has(groupId)
                ) {
                    throw new Error("Invalid removed CLI group tombstone");
                }
                this.#removedGroups.add(groupId);
            } finally {
                zeroBytes(value);
            }
        }
    }

    #decodeLoadedGroup(groupId: string, bytes: Uint8Array): LoadedCliGroup {
        const account = this.#requireAccount();
        const record = decodeCliGroupRecord(bytes);
        let epoch: MlsEpochState | undefined;
        try {
            epoch = MlsEpochState.deserialize(record.epochState, {
                localSigningSecretKey: account.identity.signingSecretKey,
                authenticateCredential: authenticateMurmurMlsCredential,
                minimumPersistenceGeneration: record.persistenceGeneration,
            });
            if (cliGroupId(epoch.groupId) !== groupId) {
                throw new Error("Durable CLI group key does not match its MLS group");
            }
            const channel = new MlsGroupChannel(
                epoch,
                record.appliedCommitFingerprints,
                record.appliedApplicationFingerprints,
            );
            epoch = undefined;
            return { name: record.name, channel };
        } finally {
            zeroBytes(record.epochState);
            epoch?.destroy();
        }
    }

    #destroyGroups(): void {
        for (const pending of this.#pendingGroupPublications.values()) {
            pending.prepared.abandonPersisted();
        }
        this.#pendingGroupPublications.clear();
        this.#deferredGroupDeliveries.clear();
        for (const group of this.#groups.values()) {
            group.channel.destroy();
        }
        this.#groups.clear();
        this.#removedGroups.clear();
    }

    async #pruneLocalKeyPackages(ownerId: string): Promise<void> {
        const entries = await this.#store.list(`${LOCAL_KEY_PACKAGE_PREFIX}/${ownerId}/`);
        const retained: Array<{
            readonly key: string;
            readonly notBefore: bigint;
        }> = [];
        const invalid: string[] = [];
        for (const [key, value] of entries) {
            try {
                const bundle = deserializeMlsKeyPackageBundle(value);
                try {
                    retained.push({
                        key,
                        notBefore: bundle.keyPackage.leafNode.notBefore,
                    });
                } finally {
                    destroyMlsKeyPackageBundle(bundle);
                }
            } catch {
                invalid.push(key);
            } finally {
                zeroBytes(value);
            }
        }
        retained.sort((left, right) =>
            left.notBefore < right.notBefore
                ? -1
                : left.notBefore > right.notBefore
                  ? 1
                  : left.key < right.key
                    ? -1
                    : left.key > right.key
                      ? 1
                      : 0,
        );
        const excess = Math.max(0, retained.length - MAXIMUM_LOCAL_KEY_PACKAGES);
        await this.#store.transaction(async (transaction) => {
            for (const key of [...invalid, ...retained.slice(0, excess).map((item) => item.key)]) {
                await transaction.delete(key);
            }
        });
    }

    #resolveGroup(value: string): readonly [string, LoadedCliGroup] {
        const direct = this.#groups.get(value);
        if (direct !== undefined) {
            return [value, direct];
        }
        const matches = [...this.#groups.entries()].filter(([, group]) => group.name === value);
        if (matches.length !== 1) {
            throw new Error(matches.length === 0 ? "Group not found" : "Group name is ambiguous");
        }
        return matches[0]!;
    }

    async #ensureNoDurableGroupOutbox(ownerId: string, groupId: string): Promise<void> {
        const entries = await this.#store.list(`${GROUP_OUTBOUND_PREFIX}/${ownerId}/${groupId}/`);
        try {
            if (entries.size > 0) {
                throw new Error("MLS group has an unresolved durable publication");
            }
        } finally {
            for (const value of entries.values()) {
                zeroBytes(value);
            }
        }
    }

    async #resolveDocument(
        value: string,
    ): Promise<{ readonly key: string; readonly record: CliDocumentRecord }> {
        const ownerId = identityId(this.#requireAccount().identity);
        const entries = await this.#store.list(`${DOCUMENT_PREFIX}/${ownerId}/`);
        const matches: Array<{ readonly key: string; readonly record: CliDocumentRecord }> = [];
        try {
            for (const [key, bytes] of entries) {
                const record = decodeCliDocumentRecord(bytes);
                if (key !== cliDocumentKey(ownerId, record.groupId, record.id)) {
                    throw new Error("Durable CLI document key does not match its record");
                }
                if (record.id === value || record.name === value) {
                    matches.push({ key, record });
                }
            }
        } finally {
            for (const bytes of entries.values()) {
                zeroBytes(bytes);
            }
        }
        const exact = matches.find((match) => match.record.id === value);
        if (exact !== undefined) {
            return exact;
        }
        if (matches.length !== 1) {
            throw new Error(
                matches.length === 0 ? "Document not found" : "Document name is ambiguous",
            );
        }
        return matches[0]!;
    }

    async #publishDocumentOperation(
        record: CliDocumentRecord,
        operation: DocumentOperation,
    ): Promise<void> {
        const group = this.#groups.get(record.groupId);
        if (group === undefined) {
            throw new Error("Document MLS group is no longer active");
        }
        const updated = applyCliDocumentOperation(
            record,
            operation,
            identityId(this.#requireAccount().identity),
        );
        await this.#publishDocumentApplication(
            record.groupId,
            group,
            {
                documentId: record.id,
                name: record.name,
                operation,
            },
            updated,
        );
    }

    async #publishDocumentApplication(
        groupId: string,
        group: LoadedCliGroup,
        application: CliDocumentApplication,
        document: CliDocumentRecord,
    ): Promise<void> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        await this.#ensureNoDurableGroupOutbox(ownerId, groupId);
        const applicationData = encodeCliDocumentApplication(application);
        const prepared = group.channel.prepareSend(applicationData);
        let persisted = false;
        let checkpoint: Uint8Array | undefined;
        try {
            if (prepared.payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
                throw new Error("MLS document update exceeds the relay payload limit");
            }
            checkpoint = prepared.serializeEpoch();
            const event = createRelayEvent(account.identity, group.channel.topic, prepared.payload);
            const outboxKey = cliGroupOutboundKey(ownerId, groupId, event, 2);
            await this.#store.transaction(async (transaction) => {
                await persistCliDocumentRecord(
                    transaction,
                    cliDocumentKey(ownerId, groupId, document.id),
                    document,
                );
                await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                    name: group.name,
                    epochState: checkpoint!,
                    persistenceGeneration: prepared.persistenceGeneration,
                    appliedCommitFingerprints: group.channel.appliedCommitFingerprints,
                    appliedApplicationFingerprints: includeFingerprint(
                        group.channel.appliedApplicationFingerprints,
                        prepared.fingerprint,
                    ),
                });
                await persistCliGroupOutbound(transaction, outboxKey, {
                    kind: "document",
                    groupId,
                    event,
                });
            });
            persisted = true;
            prepared.markPersisted();
            const pending: PendingCliGroupPublication = {
                kind: "document",
                groupId,
                outboxKey,
                prepared,
            };
            this.#pendingGroupPublications.set(event.id, pending);
            await this.#publishPendingGroupDocument(event, pending);
        } catch (error: unknown) {
            if (!persisted) {
                prepared.cancel();
            }
            throw error;
        } finally {
            zeroBytes(applicationData);
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
        }
    }

    async #acceptGroupInvitation(
        transaction: StoreTransaction,
        inviter: IdentityPublicKeys,
        invitation: CliGroupInvitation,
    ): Promise<{ readonly id: string; readonly group: LoadedCliGroup }> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const groupId = cliGroupId(invitation.groupId);
        if (
            this.#groups.has(groupId) ||
            (await transaction.get(cliGroupKey(ownerId, groupId))) !== undefined
        ) {
            throw new Error("MLS group invitation collides with existing local state");
        }
        const bundleKey = localKeyPackageKey(ownerId, invitation.keyPackageReference);
        const encodedBundle = await transaction.get(bundleKey);
        if (encodedBundle === undefined) {
            throw new Error("MLS group invitation references an unavailable KeyPackage");
        }
        let bundle: ReturnType<typeof deserializeMlsKeyPackageBundle> | undefined;
        let opened: ReturnType<typeof openMlsWelcome> | undefined;
        let channel: MlsGroupChannel | undefined;
        let checkpoint: Uint8Array | undefined;
        try {
            bundle = deserializeMlsKeyPackageBundle(encodedBundle);
            if (
                !equalBytes(
                    mlsKeyPackageReference(bundle.keyPackage),
                    invitation.keyPackageReference,
                )
            ) {
                throw new Error("MLS invitation KeyPackage reference mismatch");
            }
            const tree = decodeMlsRatchetTree(invitation.tree, {
                groupId: invitation.groupId,
                authenticateCredential: authenticateMurmurMlsCredential,
            });
            const nodes = tree.nodes;
            const localLeaves: number[] = [];
            for (let leaf = 0; leaf < tree.leafCount; leaf += 1) {
                const node = nodes[leaf * 2];
                if (
                    node?.type === "leaf" &&
                    equalBytes(node.signatureKey, bundle.keyPackage.leafNode.signatureKey) &&
                    equalBytes(node.encryptionKey, bundle.keyPackage.leafNode.encryptionKey)
                ) {
                    localLeaves.push(leaf);
                }
            }
            if (localLeaves.length !== 1) {
                throw new Error("MLS invitation tree does not contain exactly one joining leaf");
            }
            opened = openMlsWelcome({
                welcome: invitation.welcome,
                keyPackageBundle: bundle,
                expectedGroupId: invitation.groupId,
                validateExternalTree: (groupInfo) => {
                    const signer = nodes[groupInfo.signer * 2];
                    return equalBytes(groupInfo.context.treeHash, tree.treeHash()) &&
                        equalBytes(groupInfo.context.groupId, invitation.groupId) &&
                        signer?.type === "leaf" &&
                        equalBytes(signer.signatureKey, inviter.signingKey)
                        ? signer.signatureKey
                        : undefined;
                },
            });
            const epoch = createMlsTreeEpochFromWelcome({
                opened,
                tree,
                localLeaf: localLeaves[0]!,
                leafKeyPair: bundle.leafKeyPair,
                localSigningSecretKey: account.identity.signingSecretKey,
                authenticateCredential: authenticateMurmurMlsCredential,
            });
            opened = undefined;
            channel = new MlsGroupChannel(epoch, [invitation.commitFingerprint]);
            checkpoint = channel.serializeEpoch();
            await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                name: invitation.name,
                epochState: checkpoint,
                persistenceGeneration: channel.persistenceGeneration,
                appliedCommitFingerprints: channel.appliedCommitFingerprints,
                appliedApplicationFingerprints: [],
            });
            await transaction.delete(bundleKey);
            const group = { name: invitation.name, channel };
            channel = undefined;
            return { id: groupId, group };
        } catch (error: unknown) {
            channel?.destroy();
            if (opened !== undefined) {
                destroyMlsEpochSecrets(opened.epochSecrets);
                if (opened.pathSecret !== undefined) {
                    zeroBytes(opened.pathSecret);
                }
            }
            throw error;
        } finally {
            zeroBytes(encodedBundle);
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
            if (bundle !== undefined) {
                destroyMlsKeyPackageBundle(bundle);
            }
        }
    }

    async #applyDocumentApplication(
        transaction: StoreTransaction,
        ownerId: string,
        groupId: string,
        group: LoadedCliGroup,
        sender: number,
        application: CliDocumentApplication,
    ): Promise<void> {
        const signingKey = group.channel.memberSignatureKeys[sender];
        if (signingKey === undefined) {
            throw new Error("MLS document sender is not an active group member");
        }
        const actor = identityId({ signingKey });
        const key = cliDocumentKey(ownerId, groupId, application.documentId);
        const encoded = await transaction.get(key);
        let existing: CliDocumentRecord | undefined;
        if (encoded !== undefined) {
            try {
                existing = decodeCliDocumentRecord(encoded);
            } finally {
                zeroBytes(encoded);
            }
            if (existing.id !== application.documentId || existing.groupId !== groupId) {
                throw new Error("Durable CLI document key does not match its record");
            }
        }
        const name =
            existing === undefined || application.name < existing.name
                ? application.name
                : existing.name;
        const base: CliDocumentRecord = existing ?? {
            id: application.documentId,
            groupId,
            name,
            operations: [],
            actorHighWaterMarks: [],
        };
        const updated =
            application.operation === undefined
                ? { ...base, name }
                : {
                      ...applyCliDocumentOperation(base, application.operation, actor),
                      name,
                  };
        await persistCliDocumentRecord(transaction, key, updated);
    }

    #deferGroupDelivery(delivery: ReceivedEvent): void {
        const key = `${delivery.event.id}/${encodeBase64Url(delivery.event.signature)}`;
        if (
            !this.#deferredGroupDeliveries.has(key) &&
            this.#deferredGroupDeliveries.size >= MAXIMUM_DEFERRED_GROUP_DELIVERIES
        ) {
            throw new Error("Too many deferred MLS group deliveries");
        }
        this.#deferredGroupDeliveries.set(key, delivery);
    }

    async #retryDeferredGroupDeliveries(ownerId: string): Promise<{
        readonly messages: number;
        readonly documents: number;
        readonly commits: number;
        readonly duplicates: number;
        readonly resolved: number;
    }> {
        let messages = 0;
        let documents = 0;
        let commits = 0;
        let duplicates = 0;
        let resolved = 0;
        for (let pass = 0; pass < Math.max(1, this.#deferredGroupDeliveries.size); pass += 1) {
            let progressed = false;
            for (const [key, delivery] of this.#deferredGroupDeliveries) {
                const groupEntry = [...this.#groups.entries()].find(
                    ([, group]) => group.channel.topic === delivery.event.topic,
                );
                let result: CliGroupDeliveryResult;
                if (groupEntry !== undefined) {
                    result = await this.#handleGroupDelivery(
                        ownerId,
                        groupEntry[0],
                        groupEntry[1],
                        delivery,
                    );
                } else if (
                    delivery.event.topic.startsWith("mls:") &&
                    this.#removedGroups.has(delivery.event.topic.slice(4))
                ) {
                    try {
                        await this.#store.transaction(async (transaction) =>
                            delivery.advanceCursor(transaction),
                        );
                        result = "duplicate";
                    } catch {
                        result = "deferred";
                    }
                } else {
                    result = "deferred";
                }
                if (result === "deferred") {
                    continue;
                }
                this.#deferredGroupDeliveries.delete(key);
                progressed = true;
                resolved += 1;
                if (result === "message") {
                    messages += 1;
                } else if (result === "document") {
                    documents += 1;
                } else if (result === "commit") {
                    commits += 1;
                } else {
                    duplicates += 1;
                }
            }
            if (!progressed) {
                break;
            }
        }
        return { messages, documents, commits, duplicates, resolved };
    }

    async #handleGroupDelivery(
        ownerId: string,
        groupId: string,
        group: LoadedCliGroup,
        delivery: ReceivedEvent,
    ): Promise<CliGroupDeliveryResult> {
        const handled = group.channel.handle(delivery);
        if (handled === undefined || handled.status === "deferred") {
            return "deferred";
        }
        if (handled.status === "applied" || handled.status === "application-applied") {
            try {
                await this.#store.transaction(async (transaction) =>
                    handled.advanceCursor(transaction),
                );
                return "duplicate";
            } catch {
                return "deferred";
            }
        }
        if (handled.status === "removed") {
            let persisted = false;
            try {
                await this.#store.transaction(async (transaction) => {
                    await transaction.delete(cliGroupKey(ownerId, groupId));
                    await transaction.set(
                        `${REMOVED_GROUP_PREFIX}/${ownerId}/${groupId}`,
                        new Uint8Array([1]),
                    );
                    await handled.advanceCursor(transaction);
                });
                persisted = true;
                handled.markPersisted();
                this.#groups.delete(groupId);
                this.#removedGroups.add(groupId);
                return "commit";
            } catch {
                if (!persisted) {
                    handled.cancel();
                }
                return "deferred";
            }
        }
        if (handled.status === "commit") {
            let persisted = false;
            let checkpoint: Uint8Array | undefined;
            try {
                checkpoint = handled.serializeNextEpoch();
                await this.#store.transaction(async (transaction) => {
                    await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                        name: group.name,
                        epochState: checkpoint!,
                        persistenceGeneration: handled.persistenceGeneration,
                        appliedCommitFingerprints: includeFingerprint(
                            group.channel.appliedCommitFingerprints,
                            handled.fingerprint,
                        ),
                        appliedApplicationFingerprints:
                            group.channel.appliedApplicationFingerprints,
                    });
                    await handled.advanceCursor(transaction);
                });
                persisted = true;
                handled.markPersisted();
                handled.adopt();
                return "commit";
            } catch {
                if (!persisted) {
                    handled.cancel();
                }
                return "deferred";
            } finally {
                if (checkpoint !== undefined) {
                    zeroBytes(checkpoint);
                }
            }
        }
        let persisted = false;
        let checkpoint: Uint8Array | undefined;
        try {
            const documentApplication = decodeCliDocumentApplication(
                handled.message.applicationData,
            );
            const message =
                documentApplication === undefined
                    ? decodeCliGroupMessage(handled.message.applicationData)
                    : undefined;
            checkpoint = handled.serializeEpoch();
            await this.#store.transaction(async (transaction) => {
                if (documentApplication === undefined) {
                    const stored: CliStoredGroupMessage = {
                        sequence: await nextGroupSequence(transaction, ownerId),
                        groupId,
                        direction: "incoming",
                        status: "received",
                        sender: handled.message.sender,
                        message: message!,
                    };
                    await persistCliStoredGroupMessage(
                        transaction,
                        cliGroupMessageKey(ownerId, stored),
                        stored,
                    );
                } else {
                    await this.#applyDocumentApplication(
                        transaction,
                        ownerId,
                        groupId,
                        group,
                        handled.message.sender,
                        documentApplication,
                    );
                }
                await persistCliGroupRecord(transaction, cliGroupKey(ownerId, groupId), {
                    name: group.name,
                    epochState: checkpoint!,
                    persistenceGeneration: handled.persistenceGeneration,
                    appliedCommitFingerprints: group.channel.appliedCommitFingerprints,
                    appliedApplicationFingerprints: includeFingerprint(
                        group.channel.appliedApplicationFingerprints,
                        handled.fingerprint,
                    ),
                });
                await handled.advanceCursor(transaction);
            });
            persisted = true;
            handled.markPersisted();
            return documentApplication === undefined ? "message" : "document";
        } catch {
            if (!persisted) {
                await this.#reloadGroup(groupId);
            }
            return "deferred";
        } finally {
            zeroBytes(handled.message.applicationData);
            zeroBytes(handled.message.authenticatedData);
            if (checkpoint !== undefined) {
                zeroBytes(checkpoint);
            }
        }
    }

    async #reloadGroup(groupId: string): Promise<void> {
        const ownerId = identityId(this.#requireAccount().identity);
        const encoded = await this.#store.get(cliGroupKey(ownerId, groupId));
        if (encoded === undefined) {
            throw new Error("Durable CLI group disappeared");
        }
        try {
            const loaded = this.#decodeLoadedGroup(groupId, encoded);
            const prior = this.#groups.get(groupId);
            this.#groups.set(groupId, loaded);
            prior?.channel.destroy();
        } finally {
            zeroBytes(encoded);
        }
    }

    #exactGroupPublisher(event: CliGroupOutbound["event"]): {
        publish(topic: string, payload: Uint8Array): ReturnType<MurmurClient["publishEvent"]>;
        subscribe(topic: string): Promise<void>;
    } {
        const client = this.#requireClient();
        return {
            publish: async (topic, payload) => {
                if (topic !== event.topic || !equalBytes(payload, event.payload)) {
                    throw new Error("Prepared MLS publication changed its exact relay event");
                }
                return client.publishEvent(event);
            },
            subscribe: async (topic) => client.subscribe(topic),
        };
    }

    async #publishPendingGroupCommit(
        event: CliGroupOutbound["event"],
        pending: Extract<PendingCliGroupPublication, { readonly kind: "commit" }>,
    ): Promise<void> {
        await pending.prepared.publish(this.#exactGroupPublisher(event));
        pending.prepared.adopt();
        await this.#store.delete(pending.outboxKey);
        this.#pendingGroupPublications.delete(event.id);
    }

    async #publishPendingGroupApplication(
        event: CliGroupOutbound["event"],
        pending: Extract<PendingCliGroupPublication, { readonly kind: "application" }>,
    ): Promise<void> {
        await pending.prepared.publish(this.#exactGroupPublisher(event));
        await this.#completeGroupApplicationOutbox(pending.outboxKey, pending.messageKey);
        this.#pendingGroupPublications.delete(event.id);
    }

    async #publishPendingGroupDocument(
        event: CliGroupOutbound["event"],
        pending: Extract<PendingCliGroupPublication, { readonly kind: "document" }>,
    ): Promise<void> {
        await pending.prepared.publish(this.#exactGroupPublisher(event));
        await this.#store.delete(pending.outboxKey);
        this.#pendingGroupPublications.delete(event.id);
    }

    async #completeRetriedGroupPublication(
        result: Awaited<ReturnType<MurmurClient["publishEvent"]>>,
    ): Promise<void> {
        const pending = this.#pendingGroupPublications.get(result.event.id);
        if (pending === undefined) {
            return;
        }
        pending.prepared.confirmPublished(result);
        if (pending.kind === "commit") {
            pending.prepared.adopt();
            await this.#store.delete(pending.outboxKey);
        } else if (pending.kind === "application") {
            await this.#completeGroupApplicationOutbox(pending.outboxKey, pending.messageKey);
        } else {
            await this.#store.delete(pending.outboxKey);
        }
        this.#pendingGroupPublications.delete(result.event.id);
    }

    async #flushGroupOutbound(ownerId: string): Promise<number> {
        const entries = await this.#store.list(`${GROUP_OUTBOUND_PREFIX}/${ownerId}/`);
        let failures = 0;
        const blockedGroups = new Set<string>();
        for (const [key, value] of entries) {
            let outbound: CliGroupOutbound;
            try {
                outbound = decodeCliGroupOutbound(value);
            } finally {
                zeroBytes(value);
            }
            if (blockedGroups.has(outbound.groupId)) {
                continue;
            }
            try {
                const pending = this.#pendingGroupPublications.get(outbound.event.id);
                if (pending?.kind === "commit") {
                    await this.#publishPendingGroupCommit(outbound.event, pending);
                } else if (pending?.kind === "application") {
                    await this.#publishPendingGroupApplication(outbound.event, pending);
                } else if (pending?.kind === "document") {
                    await this.#publishPendingGroupDocument(outbound.event, pending);
                } else {
                    await this.#requireClient().publishEvent(outbound.event);
                    if (outbound.kind === "application") {
                        await this.#completeGroupApplicationOutbox(key, outbound.messageKey!);
                    } else {
                        await this.#store.delete(key);
                    }
                }
            } catch {
                failures += 1;
                blockedGroups.add(outbound.groupId);
            }
        }
        return failures;
    }

    async #completeGroupApplicationOutbox(outboxKey: string, messageKey: string): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            const encoded = await transaction.get(messageKey);
            if (encoded === undefined) {
                throw new Error("CLI group outbox history record is missing");
            }
            let stored: CliStoredGroupMessage;
            try {
                stored = decodeCliStoredGroupMessage(encoded);
            } finally {
                zeroBytes(encoded);
            }
            await persistCliStoredGroupMessage(transaction, messageKey, {
                ...stored,
                status: "sent",
            });
            await transaction.delete(outboxKey);
        });
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

    async #persistDirectChatMessage(
        transaction: StoreTransaction,
        surfaced: DirectChatMessage,
    ): Promise<void> {
        const account = this.#requireAccount();
        const ownerId = identityId(account.identity);
        const conversationId = identityId(surfaced.friend);
        if (surfaced.direction === "incoming") {
            const invitation = decodeCliGroupInvitation(surfaced.message.text);
            if (invitation !== undefined) {
                this.#stagedDirectGroups.push(
                    await this.#acceptGroupInvitation(transaction, surfaced.sender, invitation),
                );
            }
        }
        const stored: CliStoredMessage = {
            sequence: await nextMessageSequence(transaction, ownerId),
            direction: surfaced.direction,
            conversationId,
            status:
                surfaced.direction === "incoming"
                    ? "received"
                    : surfaced.source === "local-send"
                      ? "pending"
                      : "sent",
            message: surfaced.message,
        };
        const key = messageKey(ownerId, stored);
        await persistStoredMessage(transaction, key, stored);
        await transaction.set(
            directMessageIndexKey(ownerId, conversationId, surfaced.message.id),
            utf8Encode(key),
        );
    }

    async #markDirectChatMessagePublished(
        transaction: StoreTransaction,
        surfaced: DirectChatMessage,
    ): Promise<void> {
        const ownerId = identityId(this.#requireAccount().identity);
        const conversationId = identityId(surfaced.friend);
        const index = await transaction.get(
            directMessageIndexKey(ownerId, conversationId, surfaced.message.id),
        );
        if (index === undefined) {
            throw new Error("CLI direct-chat history index is missing");
        }
        const key = utf8Decode(index);
        if (!key.startsWith(`${MESSAGE_PREFIX}/${ownerId}/`)) {
            throw new Error("Invalid CLI direct-chat history index");
        }
        const encoded = await transaction.get(key);
        if (encoded === undefined) {
            throw new Error("CLI direct-chat history record is missing");
        }
        const stored = decodeCliStoredMessage(encoded);
        try {
            if (
                stored.direction !== "outgoing" ||
                stored.conversationId !== conversationId ||
                stored.message.id !== surfaced.message.id
            ) {
                throw new Error("CLI direct-chat history index does not match its message");
            }
            await persistStoredMessage(transaction, key, { ...stored, status: "sent" });
        } finally {
            clearMessageSecrets(stored);
            zeroBytes(index);
            zeroBytes(encoded);
        }
    }

    async #quarantine(ownerId: string, delivery: ReceivedEvent, reason: string): Promise<void> {
        const eventBytes = encodeSignedRelayEventWire(delivery.event);
        const fingerprint = encodeBase64Url(hashBytes(eventBytes));
        const record = utf8Encode(
            JSON.stringify({
                version: 1,
                reason,
                eventId: delivery.event.id,
                topic: delivery.event.topic,
                sender: identityId(delivery.event.author),
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
                await delivery.advanceCursor(transaction);
            });
        } finally {
            zeroBytes(record);
            zeroBytes(eventBytes);
        }
    }

    /** Zero the in-memory account secrets. Durable data remains available. */
    destroy(): void {
        this.#destroyGroups();
        if (this.#account !== undefined) {
            destroyIdentity(this.#account.identity);
            if (this.#account.profile.avatar !== undefined) {
                zeroBytes(this.#account.profile.avatar);
            }
        }
        this.#account = undefined;
        this.#client = undefined;
        this.#contacts = undefined;
        this.#directChat = undefined;
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
        readonly contacts: FriendBook;
        readonly directChat: DirectChat;
    } {
        const client = new MurmurClient({
            identity: account.identity,
            store: this.#store,
            transports: this.#transports,
        });
        const contacts = new FriendBook(account.identity, this.#store);
        return {
            client,
            contacts,
            directChat: new DirectChat({
                identity: account.identity,
                client,
                friends: contacts,
                store: this.#store,
                callbacks: {
                    persistMessage: async (transaction, surfaced) =>
                        this.#persistDirectChatMessage(transaction, surfaced),
                    messagePublished: async (transaction, surfaced) =>
                        this.#markDirectChatMessagePublished(transaction, surfaced),
                },
            }),
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

    #requireContacts(): FriendBook {
        if (this.#contacts === undefined) {
            throw new Error("No Murmur identity; run `murmur sign-in` first");
        }
        return this.#contacts;
    }

    #requireDirectChat(): DirectChat {
        if (this.#directChat === undefined) {
            throw new Error("No Murmur identity; run `murmur sign-in` first");
        }
        return this.#directChat;
    }

    #takeStagedDirectGroups(): readonly {
        readonly id: string;
        readonly group: LoadedCliGroup;
    }[] {
        const staged = this.#stagedDirectGroups;
        this.#stagedDirectGroups = [];
        return staged;
    }
}
