import type { IdentityKeyPair, IdentityPublicKey } from "../crypto/index.js";
import {
    decodeIdentityRoot,
    destroyIdentity,
    encodeIdentityRoot,
    generateIdentityKeyPair,
    hashBytes,
    randomBytes,
    validateIdentityPublicKey,
} from "../crypto/index.js";
import {
    FriendBook,
    FriendChannel,
    identityId,
    openFriendRequest,
    openFriendResponse,
    validateIdentityProfile,
    type FriendControlEnvelope,
    type FriendRecord,
    type FriendRequestEnvelope,
    type FriendResponseEnvelope,
    type IdentityProfile,
} from "../identity/index.js";
import { decodeFriendRecord, encodeFriendRecord } from "../identity/impl/friendCodec.js";
import { decodeProfilePayload, encodeProfilePayload } from "../identity/impl/profileCodec.js";
import {
    authenticateMurmurMlsCredential,
    createMlsGroup,
    createMlsKeyPackage,
    decodeMlsKeyPackage,
    decodeMlsRatchetTree,
    decodeMlsTreeCommit,
    deserializeMlsKeyPackageBundle,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    encodeMlsRatchetTree,
    joinMlsGroupFromWelcome,
    mlsKeyPackageReference,
    MlsEpochState,
    MlsLocalMemberRemovedError,
    serializeMlsKeyPackageBundle,
    verifyMlsKeyPackage,
    type MlsKeyPackage,
} from "../mls/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    HttpRelayTransport,
    encodeSignedRelayEventWire,
    relayTopicId,
    verifyRelayEvent,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicAccess,
} from "../transport/index.js";
import {
    concatBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import {
    decodeFriendControlFrame,
    encodeFriendControlFrame,
    type FriendControlFrame,
} from "./impl/controlCodec.js";
import {
    decodeGroup,
    decodeGroupEvent,
    decodeGroupOperation,
    decodeRelayOutbox,
    decodeStagedCommit,
    encodeGroup,
    encodeGroupEvent,
    encodeGroupOperation,
    encodeRelayOutbox,
    encodeStagedCommit,
    type GroupOperation,
    type RelayOutboxRecord,
    type StagedGroupCommit,
    type StoredGroup,
} from "./impl/stateCodec.js";
import {
    createCapabilityEvent,
    createResponseAddress,
    createUnlinkableEvent,
    friendControlAccess,
    groupAccess,
    inboxAccess,
    inboxAddress,
    parseInboxAddress,
    parseResponseAddress,
} from "./impl/topics.js";
import type {
    MurmurFriend,
    MurmurFriends,
    MurmurGroup,
    MurmurGroupPage,
    MurmurGroups,
    MurmurOpenOptions,
    MurmurSyncOptions,
} from "./types.js";

export type {
    MurmurFriend,
    MurmurFriends,
    MurmurFriendStatus,
    MurmurGroup,
    MurmurGroupEvent,
    MurmurGroupPage,
    MurmurGroups,
    MurmurGroupStatus,
    MurmurOpenOptions,
    MurmurSyncOptions,
} from "./types.js";

const ROOT_KEY = "murmur/v1/root";
const PROFILE_KEY = "murmur/v1/profile";
const OUTBOX_PREFIX = "murmur/v1/relay-outbox/";
const CURSOR_PREFIX = "murmur/v1/cursors/";
const GROUPS_PREFIX = "murmur/v1/groups/";
const LOCAL_KEY_PACKAGE_PREFIX = "murmur/v1/key-packages/local/";
const LOCAL_KEY_PACKAGE_CONSUMED_PREFIX = "murmur/v1/key-packages/local-consumed/";
const REMOTE_KEY_PACKAGE_PREFIX = "murmur/v1/key-packages/remote/";
const REMOTE_KEY_PACKAGE_CONSUMED_PREFIX = "murmur/v1/key-packages/remote-consumed/";
const KEY_PACKAGE_REQUEST_PREFIX = "murmur/v1/key-packages/requests/";
const KEY_PACKAGE_NEEDED_PREFIX = "murmur/v1/key-packages/needed/";
const CONTROL_REPLAY_PREFIX = "murmur/v1/control-replay/";
const CONTROL_SELF_PREFIX = "murmur/v1/control-self/";
const QUARANTINE_PREFIX = "murmur/v1/quarantine/";
const MAXIMUM_SYNC_PASSES = 64;
const EVENT_PAGE_LIMIT = 100;
const LOCAL_KEY_PACKAGE_TARGET = 2;
const MAXIMUM_DESCRIPTOR_BYTES = 256 * 1024;
const MAXIMUM_APPLICATION_BYTES = 256 * 1024;
const MAXIMUM_GROUP_PAGE = 1_000;
const MLS_PROTOCOL_VERSION = 1;
const MLS_PUBLIC_MESSAGE = 1;

interface RuntimeGroup {
    record: StoredGroup;
    epoch?: MlsEpochState;
}

type TopicContext =
    | { readonly kind: "inbox"; readonly access: TopicAccess }
    | {
          readonly kind: "response";
          readonly access: TopicAccess;
          readonly peer: IdentityPublicKey;
      }
    | {
          readonly kind: "control";
          readonly access: TopicAccess;
          readonly peer: IdentityPublicKey;
      }
    | {
          readonly kind: "group";
          readonly access: TopicAccess;
          readonly groupId: string;
      };

class TransactionStore implements MurmurStore {
    readonly #transaction: StoreTransaction;

    constructor(transaction: StoreTransaction) {
        this.#transaction = transaction;
    }

    get(key: string): Promise<Uint8Array | undefined> {
        return this.#transaction.get(key);
    }

    set(key: string, value: Uint8Array): Promise<void> {
        return this.#transaction.set(key, value);
    }

    delete(key: string): Promise<void> {
        return this.#transaction.delete(key);
    }

    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#transaction.list(prefix);
    }

    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return operation(this.#transaction);
    }
}

function copyProfile(profile: IdentityProfile): IdentityProfile {
    return {
        name: profile.name,
        ...(profile.avatar === undefined ? {} : { avatar: profile.avatar.slice() }),
        ...(profile.metadata === undefined ? {} : { metadata: { ...profile.metadata } }),
    };
}

function publicIdentity(identityKey: Uint8Array): IdentityPublicKey {
    if (!(identityKey instanceof Uint8Array)) {
        throw new Error("Identity key must be bytes");
    }
    const identity = { publicKey: identityKey.slice() };
    validateIdentityPublicKey(identity);
    return identity;
}

function cursorBytes(cursor: bigint): Uint8Array {
    return utf8Encode(cursor.toString());
}

function parseCursor(value: Uint8Array | undefined): bigint {
    if (value === undefined) {
        return 0n;
    }
    const text = utf8Decode(value);
    if (!/^(0|[1-9]\d*)$/.test(text)) {
        throw new Error("Invalid Murmur cursor");
    }
    const cursor = BigInt(text);
    if (cursor > 0x7fff_ffff_ffff_ffffn) {
        throw new Error("Murmur cursor exceeds relay sequence range");
    }
    return cursor;
}

function sequenceKey(sequence: bigint): string {
    return sequence.toString().padStart(20, "0");
}

function groupBase(groupId: string): string {
    return `${GROUPS_PREFIX}${groupId}/`;
}

function groupMetaKey(groupId: string): string {
    return `${groupBase(groupId)}meta`;
}

function groupEpochKey(groupId: string): string {
    return `${groupBase(groupId)}epoch`;
}

function groupStagedKey(groupId: string): string {
    return `${groupBase(groupId)}staged`;
}

function groupOperationPrefix(groupId: string): string {
    return `${groupBase(groupId)}operations/`;
}

function groupOperationKey(groupId: string, operationId: string): string {
    return `${groupOperationPrefix(groupId)}${operationId}`;
}

function groupEventPrefix(groupId: string): string {
    return `${groupBase(groupId)}events/`;
}

function groupEventKey(groupId: string, sequence: bigint): string {
    return `${groupEventPrefix(groupId)}${sequenceKey(sequence)}`;
}

function groupReplayKey(groupId: string, fingerprint: Uint8Array): string {
    return `${groupBase(groupId)}replay/${encodeBase64Url(fingerprint)}`;
}

function friendBookPrefix(owner: IdentityKeyPair): string {
    return `murmur/v1/friend-book/${identityId(owner)}/`;
}

function friendRecordKey(owner: IdentityKeyPair, peer: IdentityPublicKey): string {
    return `${friendBookPrefix(owner)}records/${identityId(peer)}`;
}

function friendOutboxKey(owner: IdentityKeyPair, id: string): string {
    return `${friendBookPrefix(owner)}outbox/${id}`;
}

function localKeyPackageKey(peer: IdentityPublicKey, reference: Uint8Array): string {
    return `${LOCAL_KEY_PACKAGE_PREFIX}${identityId(peer)}/${encodeBase64Url(reference)}`;
}

function remoteKeyPackageKey(peer: IdentityPublicKey, reference: Uint8Array): string {
    return `${REMOTE_KEY_PACKAGE_PREFIX}${identityId(peer)}/${encodeBase64Url(reference)}`;
}

function descriptorBinding(
    groupId: Uint8Array,
    nonce: Uint8Array,
    descriptor: Uint8Array,
): Uint8Array {
    return hashBytes(
        concatBytes(utf8Encode("murmur/group-descriptor/v1"), groupId, nonce, descriptor),
    );
}

function isCommit(payload: Uint8Array): boolean {
    return (
        payload.length >= 4 &&
        (((payload[0] ?? 0) << 8) | (payload[1] ?? 0)) === MLS_PROTOCOL_VERSION &&
        (((payload[2] ?? 0) << 8) | (payload[3] ?? 0)) === MLS_PUBLIC_MESSAGE
    );
}

function decodeEnvelope(
    bytes: Uint8Array,
    expected: "friend-request" | "friend-response" | "friend-control",
): FriendRequestEnvelope | FriendResponseEnvelope | FriendControlEnvelope {
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new Error("Invalid encrypted friend envelope");
    }
    const envelope = decoded as Record<string, unknown>;
    if (envelope.type !== expected) {
        throw new Error("Unexpected encrypted friend envelope");
    }
    return envelope as unknown as
        | FriendRequestEnvelope
        | FriendResponseEnvelope
        | FriendControlEnvelope;
}

function encodeEnvelope(
    envelope: FriendRequestEnvelope | FriendResponseEnvelope | FriendControlEnvelope,
): Uint8Array {
    return utf8Encode(JSON.stringify(envelope));
}

function friendView(record: FriendRecord): MurmurFriend {
    return {
        identityKey: record.identity.publicKey.slice(),
        ...(record.profile === undefined ? {} : { profile: copyProfile(record.profile) }),
        status: record.status,
    };
}

function groupView(group: RuntimeGroup): MurmurGroup {
    return {
        id: decodeBase64Url(group.record.id),
        descriptor: group.record.descriptor.slice(),
        members: group.record.members.map((member) => member.slice()),
        epoch: group.record.epoch,
        status: group.record.status,
    };
}

function destroyAccess(access: TopicAccess): void {
    access.readSecretKey?.fill(0);
    access.writeSecretKey?.fill(0);
}

function destroyStagedCommit(staged: StagedGroupCommit | undefined): void {
    if (staged === undefined) {
        return;
    }
    zeroBytes(staged.nextEpoch);
    zeroBytes(staged.fingerprint);
    zeroBytes(staged.peer);
    staged.keyPackageReference?.fill(0);
}

function friendStateError(error: unknown): boolean {
    if (!(error instanceof Error)) {
        return false;
    }
    return (
        error.name.startsWith("Friend") ||
        error.message.startsWith("Friend") ||
        error.message.startsWith("Cannot receive friendship") ||
        error.message.startsWith("Authenticated friend") ||
        error.message.includes("causal predecessor") ||
        error.message.includes("does not match durable outgoing")
    );
}

/**
 * The single browser-safe, stateful Murmur library facade.
 *
 * Construct instances with `Murmur.open()`. Nested friend and group objects
 * cannot be constructed independently and expose no synchronization
 * choreography.
 */
export class Murmur {
    readonly #identity: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #transport: RelayTransport;
    readonly #friendBook: FriendBook;
    readonly #groups = new Map<string, RuntimeGroup>();
    #profile: IdentityProfile;
    #tail: Promise<void> = Promise.resolve();
    #closed = false;

    /** Friend bootstrap and relationship operations bound to this instance. */
    readonly friends: MurmurFriends;

    /** Opaque MLS group-stream operations bound to this instance. */
    readonly groups: MurmurGroups;

    private constructor(
        identity: IdentityKeyPair,
        profile: IdentityProfile,
        store: MurmurStore,
        transport: RelayTransport,
        groups: ReadonlyMap<string, RuntimeGroup>,
    ) {
        this.#identity = identity;
        this.#profile = copyProfile(profile);
        this.#store = store;
        this.#transport = transport;
        this.#friendBook = new FriendBook(identity, store);
        for (const [groupId, group] of groups) {
            this.#groups.set(groupId, group);
        }
        this.friends = Object.freeze({
            request: async (identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#requestFriend(identityKey)),
            accept: async (identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#respondToFriend(identityKey, "accepted")),
            reject: async (identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#respondToFriend(identityKey, "rejected")),
            end: async (identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#endFriend(identityKey)),
            list: async (): Promise<readonly MurmurFriend[]> =>
                this.#exclusive(() => this.#listFriends()),
            get: async (identityKey: Uint8Array): Promise<MurmurFriend | undefined> =>
                this.#exclusive(() => this.#getFriend(identityKey)),
        });
        this.groups = Object.freeze({
            create: async (
                descriptor: Uint8Array,
                members: readonly Uint8Array[] = [],
            ): Promise<Uint8Array> => this.#exclusive(() => this.#createGroup(descriptor, members)),
            send: async (groupId: Uint8Array, bytes: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#queueGroupSend(groupId, bytes)),
            add: async (groupId: Uint8Array, identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#queueMembership(groupId, identityKey, "add")),
            remove: async (groupId: Uint8Array, identityKey: Uint8Array): Promise<void> =>
                this.#exclusive(() => this.#queueMembership(groupId, identityKey, "remove")),
            list: async (): Promise<readonly MurmurGroup[]> =>
                this.#exclusive(() => this.#listGroups()),
            get: async (
                groupId: Uint8Array,
                options: { readonly after?: bigint; readonly limit?: number } = {},
            ): Promise<MurmurGroupPage | undefined> =>
                this.#exclusive(() => this.#getGroup(groupId, options)),
        });
    }

    /**
     * Open or create the one identity rooted in the clean Murmur namespace.
     *
     * `initialProfile` is required for a new namespace and ignored when an
     * existing root is present. No legacy layouts are read or migrated.
     */
    static async open(options: MurmurOpenOptions): Promise<Murmur> {
        const relay = new URL(options.relay.toString());
        if (relay.protocol !== "http:" && relay.protocol !== "https:") {
            throw new Error("Murmur relay must use HTTP or HTTPS");
        }
        let identity: IdentityKeyPair;
        let profile: IdentityProfile;
        const storedRoot = await options.store.get(ROOT_KEY);
        if (storedRoot === undefined) {
            if (options.initialProfile === undefined) {
                throw new Error("An empty Murmur store requires initialProfile");
            }
            validateIdentityProfile(options.initialProfile);
            const namespace = await options.store.list("murmur/v1/");
            if (namespace.size !== 0) {
                throw new Error("Murmur namespace contains state without one root identity");
            }
            const generated = generateIdentityKeyPair();
            const rootBytes = encodeIdentityRoot(generated);
            const profileBytes = encodeProfilePayload(options.initialProfile);
            try {
                await options.store.transaction(async (transaction) => {
                    if ((await transaction.get(ROOT_KEY)) !== undefined) {
                        throw new Error("Murmur root identity was concurrently created");
                    }
                    await transaction.set(ROOT_KEY, rootBytes);
                    await transaction.set(PROFILE_KEY, profileBytes);
                });
                identity = generated;
                profile = copyProfile(options.initialProfile);
            } catch (error: unknown) {
                destroyIdentity(generated);
                throw error;
            } finally {
                zeroBytes(rootBytes);
                zeroBytes(profileBytes);
            }
        } else {
            try {
                identity = decodeIdentityRoot(storedRoot);
            } finally {
                zeroBytes(storedRoot);
            }
            const storedProfile = await options.store.get(PROFILE_KEY);
            if (storedProfile === undefined) {
                destroyIdentity(identity);
                throw new Error("Stored Murmur identity is missing its profile");
            }
            profile = decodeProfilePayload(storedProfile);
        }

        const groups = new Map<string, RuntimeGroup>();
        try {
            const records = await options.store.list(GROUPS_PREFIX);
            for (const [key, bytes] of records) {
                if (!key.endsWith("/meta")) {
                    continue;
                }
                const record = decodeGroup(bytes);
                if (key !== groupMetaKey(record.id)) {
                    throw new Error("Stored group key does not match its identifier");
                }
                let epoch: MlsEpochState | undefined;
                if (record.status === "active") {
                    const epochBytes = await options.store.get(groupEpochKey(record.id));
                    if (epochBytes === undefined) {
                        throw new Error("Active group is missing its MLS epoch");
                    }
                    try {
                        epoch = MlsEpochState.deserialize(epochBytes, {
                            localSigningSecretKey: identity.secretKey,
                            authenticateCredential: authenticateMurmurMlsCredential,
                            minimumPersistenceGeneration: record.persistenceGeneration,
                        });
                    } finally {
                        zeroBytes(epochBytes);
                    }
                    if (
                        encodeBase64Url(epoch.groupId) !== record.id ||
                        epoch.context.epoch !== record.epoch ||
                        epoch.persistenceGeneration !== record.persistenceGeneration
                    ) {
                        epoch.destroy();
                        throw new Error("Stored group metadata does not match its MLS epoch");
                    }
                }
                groups.set(record.id, { record, ...(epoch === undefined ? {} : { epoch }) });
            }
            return new Murmur(
                identity,
                profile,
                options.store,
                new HttpRelayTransport(relay.toString(), options.fetch ?? globalThis.fetch),
                groups,
            );
        } catch (error: unknown) {
            for (const group of groups.values()) {
                group.epoch?.destroy();
            }
            destroyIdentity(identity);
            throw error;
        }
    }

    /** Defensive copy of the one public Murmur identity key. */
    get identityKey(): Uint8Array {
        this.#ensureOpen();
        return this.#identity.publicKey.slice();
    }

    /** Defensive copy of the current local profile. */
    get profile(): IdentityProfile {
        this.#ensureOpen();
        return copyProfile(this.#profile);
    }

    /** Persist and durably announce a new profile to every active friend. */
    async setProfile(profile: IdentityProfile): Promise<void> {
        await this.#exclusive(async () => {
            validateIdentityProfile(profile);
            const encoded = encodeProfilePayload(profile);
            const active = (await this.#friendBook.list()).filter(
                (friend) => friend.status === "active",
            );
            try {
                await this.#store.transaction(async (transaction) => {
                    await transaction.set(PROFILE_KEY, encoded);
                    for (const friend of active) {
                        await this.#queueControl(
                            transaction,
                            friend.identity,
                            { type: "profile-update", profile },
                            { type: "friend-control" },
                        );
                    }
                });
                this.#profile = copyProfile(profile);
            } finally {
                zeroBytes(encoded);
            }
        });
    }

    /**
     * Converge all discovered friend and group topics.
     *
     * Immediate passes are bounded at 64. Every pass restores exact outboxes,
     * catches groups up before preparing new writes, and incorporates newly
     * discovered topics into the next pass.
     */
    async sync(options: MurmurSyncOptions = {}): Promise<void> {
        await this.#exclusive(() => this.#sync(options));
    }

    /** Zero all in-memory identity and MLS secrets. Durable state is retained. */
    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        for (const group of this.#groups.values()) {
            group.epoch?.destroy();
            zeroBytes(group.record.topicSecret);
        }
        this.#groups.clear();
        destroyIdentity(this.#identity);
        this.#profile.avatar?.fill(0);
    }

    /** Alias for `close()`. */
    destroy(): void {
        this.close();
    }

    async #requestFriend(identityKey: Uint8Array): Promise<void> {
        const peer = publicIdentity(identityKey);
        const responseAddress = createResponseAddress();
        await this.#friendBook.createRequest(peer, {
            profile: this.#profile,
            destination: inboxAddress(peer),
            responseAddress,
        });
    }

    async #respondToFriend(
        identityKey: Uint8Array,
        decision: "accepted" | "rejected",
    ): Promise<void> {
        const peer = publicIdentity(identityKey);
        if (decision === "accepted") {
            await this.#friendBook.respond(peer, {
                decision,
                profile: this.#profile,
                responseAddress: createResponseAddress(),
            });
            return;
        }
        await this.#friendBook.respond(peer, { decision });
    }

    async #endFriend(identityKey: Uint8Array): Promise<void> {
        await this.#friendBook.end(publicIdentity(identityKey));
    }

    async #listFriends(): Promise<readonly MurmurFriend[]> {
        return (await this.#friendBook.list()).map(friendView);
    }

    async #getFriend(identityKey: Uint8Array): Promise<MurmurFriend | undefined> {
        const friend = await this.#friendBook.get(publicIdentity(identityKey));
        return friend === undefined ? undefined : friendView(friend);
    }

    async #createGroup(
        descriptor: Uint8Array,
        members: readonly Uint8Array[],
    ): Promise<Uint8Array> {
        if (!(descriptor instanceof Uint8Array) || descriptor.length > MAXIMUM_DESCRIPTOR_BYTES) {
            throw new Error(`Group descriptor exceeds ${MAXIMUM_DESCRIPTOR_BYTES} bytes`);
        }
        const peers = members.map(publicIdentity);
        const unique = new Set(peers.map(identityId));
        if (unique.size !== peers.length) {
            throw new Error("Group creation contains duplicate members");
        }
        for (const peer of peers) {
            const friend = await this.#friendBook.get(peer);
            if (friend?.status !== "active") {
                throw new Error("Group members must be active friends");
            }
        }
        const epoch = createMlsGroup(this.#identity);
        const groupId = epoch.groupId;
        const id = encodeBase64Url(groupId);
        const descriptorNonce = randomBytes(32);
        const binding = descriptorBinding(groupId, descriptorNonce, descriptor);
        const topicSecret = randomBytes(32);
        const record: StoredGroup = {
            id,
            descriptor: descriptor.slice(),
            descriptorNonce,
            descriptorBinding: binding,
            topicSecret,
            members: [this.#identity.publicKey.slice()],
            createdAt: Date.now(),
            epoch: epoch.context.epoch,
            persistenceGeneration: epoch.persistenceGeneration,
            status: "active",
        };
        const epochBytes = epoch.serialize();
        try {
            await this.#store.transaction(async (transaction) => {
                if ((await transaction.get(groupMetaKey(id))) !== undefined) {
                    throw new Error("Random group identifier collision");
                }
                await transaction.set(groupMetaKey(id), encodeGroup(record));
                await transaction.set(groupEpochKey(id), epochBytes);
                for (const peer of peers) {
                    const operation = this.#newMembershipOperation("add", peer.publicKey);
                    await transaction.set(
                        groupOperationKey(id, operation.id),
                        encodeGroupOperation(operation),
                    );
                }
            });
            this.#groups.set(id, { record, epoch });
            return groupId.slice();
        } catch (error: unknown) {
            epoch.destroy();
            throw error;
        } finally {
            zeroBytes(epochBytes);
        }
    }

    async #queueGroupSend(groupId: Uint8Array, bytes: Uint8Array): Promise<void> {
        if (!(bytes instanceof Uint8Array) || bytes.length > MAXIMUM_APPLICATION_BYTES) {
            throw new Error(`Group event exceeds ${MAXIMUM_APPLICATION_BYTES} bytes`);
        }
        const group = this.#activeGroup(groupId);
        const operation: GroupOperation = {
            id: encodeBase64Url(randomBytes(24)),
            type: "send",
            payload: bytes.slice(),
            createdAt: Date.now(),
        };
        await this.#store.set(
            groupOperationKey(group.record.id, operation.id),
            encodeGroupOperation(operation),
        );
    }

    async #queueMembership(
        groupId: Uint8Array,
        identityKey: Uint8Array,
        type: "add" | "remove",
    ): Promise<void> {
        const group = this.#activeGroup(groupId);
        const peer = publicIdentity(identityKey);
        const present = group.record.members.some((member) => equalBytes(member, peer.publicKey));
        if (type === "add") {
            const friend = await this.#friendBook.get(peer);
            if (friend?.status !== "active") {
                throw new Error("Only active friends can be added to groups");
            }
            if (present) {
                throw new Error("Friend is already a group member");
            }
        } else {
            if (equalBytes(peer.publicKey, this.#identity.publicKey)) {
                throw new Error("The local member cannot remove itself");
            }
            if (!present) {
                throw new Error("Identity is not a current group member");
            }
        }
        const operation = this.#newMembershipOperation(type, peer.publicKey);
        await this.#store.set(
            groupOperationKey(group.record.id, operation.id),
            encodeGroupOperation(operation),
        );
    }

    #newMembershipOperation(
        type: "add" | "remove",
        peer: Uint8Array,
    ): Extract<GroupOperation, { type: "add" | "remove" }> {
        return {
            id: encodeBase64Url(randomBytes(24)),
            type,
            peer: peer.slice(),
            createdAt: Date.now(),
        };
    }

    async #listGroups(): Promise<readonly MurmurGroup[]> {
        return [...this.#groups.values()]
            .sort((left, right) =>
                left.record.id < right.record.id ? -1 : left.record.id > right.record.id ? 1 : 0,
            )
            .map(groupView);
    }

    async #getGroup(
        groupId: Uint8Array,
        options: { readonly after?: bigint; readonly limit?: number },
    ): Promise<MurmurGroupPage | undefined> {
        const id = this.#groupId(groupId);
        const group = this.#groups.get(id);
        if (group === undefined) {
            return undefined;
        }
        const after = options.after ?? 0n;
        const limit = options.limit ?? 100;
        if (
            after < 0n ||
            after > 0x7fff_ffff_ffff_ffffn ||
            !Number.isSafeInteger(limit) ||
            limit < 1 ||
            limit > MAXIMUM_GROUP_PAGE
        ) {
            throw new Error("Invalid group event page");
        }
        const stored = await this.#store.list(groupEventPrefix(id));
        const events = [...stored.values()]
            .map(decodeGroupEvent)
            .filter((event) => event.sequence > after)
            .sort((left, right) =>
                left.sequence < right.sequence ? -1 : left.sequence > right.sequence ? 1 : 0,
            );
        const page = events.slice(0, limit);
        const nextAfter =
            events.length > page.length && page.length > 0
                ? page[page.length - 1]!.sequence
                : undefined;
        return {
            group: groupView(group),
            events: page.map((event) => ({
                sequence: event.sequence,
                sender: event.sender.slice(),
                bytes: event.bytes.slice(),
            })),
            ...(nextAfter === undefined ? {} : { nextAfter }),
        };
    }

    #activeGroup(groupId: Uint8Array): RuntimeGroup & { epoch: MlsEpochState } {
        const group = this.#groups.get(this.#groupId(groupId));
        if (group?.record.status !== "active" || group.epoch === undefined) {
            throw new Error("Active group not found");
        }
        return group as RuntimeGroup & { epoch: MlsEpochState };
    }

    #groupId(groupId: Uint8Array): string {
        if (!(groupId instanceof Uint8Array) || groupId.length !== 32) {
            throw new Error("Group ID must contain 32 bytes");
        }
        return encodeBase64Url(groupId);
    }

    async #sync(options: MurmurSyncOptions): Promise<void> {
        const waitMilliseconds = options.waitMilliseconds ?? 0;
        if (
            !Number.isSafeInteger(waitMilliseconds) ||
            waitMilliseconds < 0 ||
            waitMilliseconds > 30_000
        ) {
            throw new Error("waitMilliseconds must be between 0 and 30000");
        }
        const attempted = new Set<string>();
        const publishErrors: Error[] = [];
        let waited = false;
        for (let pass = 0; pass < MAXIMUM_SYNC_PASSES; pass += 1) {
            if (options.signal?.aborted === true) {
                throw options.signal.reason ?? new Error("Murmur sync aborted");
            }
            let changed = false;
            changed = (await this.#materializeFriendOutbox()) || changed;
            const flushed = await this.#flushOutboxes(attempted);
            changed = flushed.changed || changed;
            publishErrors.push(...flushed.errors);
            changed = (await this.#readAllTopics(options.signal)) || changed;
            changed = (await this.#ensureKeyPackages()) || changed;
            changed = (await this.#prepareGroupOperations()) || changed;
            if (changed) {
                continue;
            }
            if (!waited && waitMilliseconds > 0) {
                waited = true;
                await this.#waitForActivity(waitMilliseconds, options.signal);
                continue;
            }
            if (publishErrors.length > 0) {
                throw publishErrors[0]!;
            }
            return;
        }
        throw new Error(`Murmur sync exceeded ${MAXIMUM_SYNC_PASSES} convergence passes`);
    }

    async #materializeFriendOutbox(): Promise<boolean> {
        const semantic = await this.#friendBook.listOutbox();
        if (semantic.length === 0) {
            return false;
        }
        const exact = [...(await this.#store.list(OUTBOX_PREFIX)).values()].map(decodeRelayOutbox);
        const materialized = new Set(
            exact.flatMap((record) =>
                record.purpose.type === "friend-exchange" ? [record.purpose.sourceId] : [],
            ),
        );
        let changed = false;
        for (const item of semantic) {
            if (materialized.has(item.id)) {
                continue;
            }
            let event: SignedRelayEvent;
            if (item.kind === "request") {
                const payload = encodeEnvelope(item.envelope);
                try {
                    event = createUnlinkableEvent(parseInboxAddress(item.destination), payload);
                } finally {
                    zeroBytes(payload);
                }
            } else if (item.kind === "response") {
                const access = parseResponseAddress(item.destination);
                const payload = encodeEnvelope(item.envelope);
                try {
                    if (access.topic.type !== "read") {
                        throw new Error("Friend response requires a Read Topic");
                    }
                    event = createUnlinkableEvent(access.topic, payload);
                } finally {
                    destroyAccess(access);
                    zeroBytes(payload);
                }
            } else {
                event = this.#createControlEvent(item.peer, {
                    type: "friendship-ended",
                    requestId: item.intent.requestId,
                });
            }
            const record: RelayOutboxRecord = {
                event,
                purpose: { type: "friend-exchange", sourceId: item.id },
                attempted: false,
            };
            await this.#store.transaction(async (transaction) => {
                if (
                    (await transaction.get(friendOutboxKey(this.#identity, item.id))) === undefined
                ) {
                    return;
                }
                await transaction.set(`${OUTBOX_PREFIX}${event.id}`, encodeRelayOutbox(record));
            });
            materialized.add(item.id);
            changed = true;
        }
        return changed;
    }

    async #flushOutboxes(
        attempted: Set<string>,
    ): Promise<{ readonly changed: boolean; readonly errors: readonly Error[] }> {
        const values = await this.#store.list(OUTBOX_PREFIX);
        const records = [...values]
            .map(([key, value]) => ({ key, record: decodeRelayOutbox(value) }))
            .sort((left, right) =>
                left.record.event.createdAt !== right.record.event.createdAt
                    ? left.record.event.createdAt - right.record.event.createdAt
                    : left.record.event.id < right.record.event.id
                      ? -1
                      : 1,
            );
        let changed = false;
        const errors: Error[] = [];
        for (const { key, record } of records) {
            if (attempted.has(record.event.id)) {
                continue;
            }
            attempted.add(record.event.id);
            const attemptedRecord = { ...record, attempted: true };
            await this.#store.transaction(async (transaction) => {
                if ((await transaction.get(key)) !== undefined) {
                    await transaction.set(key, encodeRelayOutbox(attemptedRecord));
                }
            });
            try {
                const outcome = await this.#transport.publish(record.event);
                if (outcome.seq < 1n) {
                    throw new Error("Relay returned an invalid publication sequence");
                }
                await this.#store.transaction(async (transaction) => {
                    if (record.purpose.type === "friend-exchange") {
                        const sourceId = record.purpose.sourceId;
                        const scoped = new FriendBook(
                            this.#identity,
                            new TransactionStore(transaction),
                        );
                        const pending = (await scoped.listOutbox()).find(
                            (item) => item.id === sourceId,
                        );
                        if (pending !== undefined) {
                            await scoped.confirmOutbox(
                                pending,
                                outcome.duplicate ? "duplicate" : "accepted",
                            );
                        }
                    }
                    if (
                        record.event.topic.type === "read-write" &&
                        record.event.topic.name === "control"
                    ) {
                        await transaction.set(
                            `${CONTROL_SELF_PREFIX}${record.event.id}`,
                            hashBytes(record.event.payload),
                        );
                    }
                    await transaction.delete(key);
                });
                changed = true;
            } catch (error: unknown) {
                errors.push(error instanceof Error ? error : new Error("Relay publication failed"));
            }
        }
        return { changed, errors };
    }

    async #discoverTopics(): Promise<readonly TopicContext[]> {
        const contexts: TopicContext[] = [{ kind: "inbox", access: inboxAccess(this.#identity) }];
        const seen = new Set([relayTopicId(contexts[0]!.access.topic)]);
        const friends = await this.#friendBook.list();
        for (const friend of friends) {
            if (friend.localResponseAddress !== undefined) {
                const access = parseResponseAddress(friend.localResponseAddress);
                const topicId = relayTopicId(access.topic);
                if (!seen.has(topicId)) {
                    seen.add(topicId);
                    contexts.push({
                        kind: "response",
                        access,
                        peer: friend.identity,
                    });
                } else {
                    destroyAccess(access);
                }
            }
            if (friend.status === "active" || friend.status === "ended") {
                const channel = new FriendChannel(this.#identity, friend.identity);
                const access = friendControlAccess(channel);
                channel.destroy();
                const topicId = relayTopicId(access.topic);
                if (!seen.has(topicId)) {
                    seen.add(topicId);
                    contexts.push({
                        kind: "control",
                        access,
                        peer: friend.identity,
                    });
                } else {
                    destroyAccess(access);
                }
            }
        }
        for (const group of this.#groups.values()) {
            const access = groupAccess(group.record.topicSecret);
            const topicId = relayTopicId(access.topic);
            if (!seen.has(topicId)) {
                seen.add(topicId);
                contexts.push({
                    kind: "group",
                    access,
                    groupId: group.record.id,
                });
            } else {
                destroyAccess(access);
            }
        }
        return contexts.sort((left, right) => {
            const leftId = relayTopicId(left.access.topic);
            const rightId = relayTopicId(right.access.topic);
            return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
        });
    }

    async #readAllTopics(signal?: AbortSignal): Promise<boolean> {
        const contexts = await this.#discoverTopics();
        let changed = false;
        try {
            for (const context of contexts) {
                changed = (await this.#readTopic(context, signal)) || changed;
            }
            return changed;
        } finally {
            for (const context of contexts) {
                destroyAccess(context.access);
            }
        }
    }

    async #readTopic(context: TopicContext, signal?: AbortSignal): Promise<boolean> {
        const topicId = relayTopicId(context.access.topic);
        const cursorKey = `${CURSOR_PREFIX}${topicId}`;
        let cursor = parseCursor(await this.#store.get(cursorKey));
        let changed = false;
        for (;;) {
            const page = await this.#transport.readEvents(
                context.access,
                cursor,
                EVENT_PAGE_LIMIT,
                0,
                signal,
            );
            if (page.head < cursor) {
                throw new Error("Relay returned a head behind the Murmur cursor");
            }
            let previous = cursor;
            for (const retained of page.events) {
                if (retained.seq <= previous || retained.seq > page.head) {
                    throw new Error("Relay returned an invalid event order");
                }
                await this.#processTopicEvent(
                    context,
                    retained.event,
                    retained.seq,
                    previous,
                    cursorKey,
                );
                previous = retained.seq;
                changed = true;
            }
            cursor = previous;
            if (page.exhausted) {
                if (page.head > cursor) {
                    await this.#store.transaction(async (transaction) => {
                        await this.#advanceCursor(transaction, cursorKey, cursor, page.head);
                    });
                    cursor = page.head;
                    changed = true;
                }
                return changed;
            }
            if (page.events.length === 0) {
                throw new Error("Relay returned an empty non-exhausted page");
            }
        }
    }

    async #processTopicEvent(
        context: TopicContext,
        event: SignedRelayEvent,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const expectedTopicId = relayTopicId(context.access.topic);
        const validOuter =
            relayTopicId(event.topic) === expectedTopicId &&
            verifyRelayEvent(event) &&
            (event.topic.type === "read" ||
                equalBytes(event.author.signingKey, event.topic.writeKey));
        if (!validOuter) {
            await this.#quarantine(expectedTopicId, sequence, event, expectedCursor, cursorKey);
            return;
        }
        if (context.kind === "inbox") {
            await this.#processInbox(event, sequence, expectedCursor, cursorKey);
            return;
        }
        if (context.kind === "response") {
            await this.#processResponse(context.peer, event, sequence, expectedCursor, cursorKey);
            return;
        }
        if (context.kind === "control") {
            await this.#processControl(context.peer, event, sequence, expectedCursor, cursorKey);
            return;
        }
        await this.#processGroupEvent(context.groupId, event, sequence, expectedCursor, cursorKey);
    }

    async #processInbox(
        event: SignedRelayEvent,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        let envelope: FriendRequestEnvelope;
        try {
            envelope = decodeEnvelope(event.payload, "friend-request") as FriendRequestEnvelope;
            const opened = openFriendRequest(this.#identity, envelope);
            opened.privateData?.fill(0);
        } catch {
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        try {
            await this.#store.transaction(async (transaction) => {
                const scoped = new FriendBook(this.#identity, new TransactionStore(transaction));
                await scoped.receiveRequest(envelope);
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            if (!friendStateError(error)) {
                throw error;
            }
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
        }
    }

    async #processResponse(
        peer: IdentityPublicKey,
        event: SignedRelayEvent,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        let envelope: FriendResponseEnvelope;
        try {
            envelope = decodeEnvelope(event.payload, "friend-response") as FriendResponseEnvelope;
            const opened = openFriendResponse(this.#identity, peer, envelope);
            if ("privateData" in opened) {
                opened.privateData?.fill(0);
            }
        } catch {
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        try {
            await this.#store.transaction(async (transaction) => {
                const scoped = new FriendBook(this.#identity, new TransactionStore(transaction));
                await scoped.receiveResponse(peer, envelope);
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            if (!friendStateError(error)) {
                throw error;
            }
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
        }
    }

    async #processControl(
        peer: IdentityPublicKey,
        event: SignedRelayEvent,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const selfFingerprint = hashBytes(event.payload);
        const exactOutbox = await this.#store.get(`${OUTBOX_PREFIX}${event.id}`);
        const selfMarker = await this.#store.get(`${CONTROL_SELF_PREFIX}${event.id}`);
        if (
            (selfMarker !== undefined && equalBytes(selfMarker, selfFingerprint)) ||
            (exactOutbox !== undefined &&
                equalBytes(decodeRelayOutbox(exactOutbox).event.payload, event.payload))
        ) {
            try {
                await this.#store.transaction(async (transaction) => {
                    if (exactOutbox !== undefined) {
                        const record = decodeRelayOutbox(exactOutbox);
                        if (record.purpose.type === "friend-exchange") {
                            const sourceId = record.purpose.sourceId;
                            const scoped = new FriendBook(
                                this.#identity,
                                new TransactionStore(transaction),
                            );
                            const pending = (await scoped.listOutbox()).find(
                                (item) => item.id === sourceId,
                            );
                            if (pending !== undefined) {
                                await scoped.confirmOutbox(pending, "accepted");
                            }
                        }
                    }
                    await transaction.delete(`${OUTBOX_PREFIX}${event.id}`);
                    await transaction.delete(`${CONTROL_SELF_PREFIX}${event.id}`);
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
                return;
            } finally {
                zeroBytes(selfFingerprint);
            }
        }
        zeroBytes(selfFingerprint);
        const channel = new FriendChannel(this.#identity, peer);
        let frame: FriendControlFrame;
        let messageId: string;
        let fingerprint: Uint8Array;
        try {
            const envelope = decodeEnvelope(
                event.payload,
                "friend-control",
            ) as FriendControlEnvelope;
            const opened = channel.open(envelope);
            const exactRetention =
                (opened.message.retention.kind === "durable" && event.expiresAt === undefined) ||
                (opened.message.retention.kind === "temporary" &&
                    event.expiresAt === opened.message.retention.expiresAt);
            if (!exactRetention) {
                throw new Error("Friend-control relay retention mismatch");
            }
            frame = decodeFriendControlFrame(opened.message.payload);
            messageId = opened.message.id;
            fingerprint = hashBytes(event.payload);
            zeroBytes(opened.message.payload);
        } catch {
            channel.destroy();
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        channel.destroy();
        const replayKey = `${CONTROL_REPLAY_PREFIX}${identityId(peer)}/${messageId}`;
        const existing = await this.#store.get(replayKey);
        if (existing !== undefined) {
            if (!equalBytes(existing, fingerprint)) {
                zeroBytes(fingerprint);
                await this.#quarantine(
                    relayTopicId(event.topic),
                    sequence,
                    event,
                    expectedCursor,
                    cursorKey,
                );
                return;
            }
            zeroBytes(fingerprint);
            await this.#store.transaction(async (transaction) => {
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
            return;
        }
        try {
            if (frame.type === "group-invitation") {
                await this.#adoptInvitation(
                    peer,
                    frame,
                    replayKey,
                    fingerprint,
                    sequence,
                    expectedCursor,
                    cursorKey,
                );
                return;
            }
            await this.#applyControlFrame(
                peer,
                frame,
                replayKey,
                fingerprint,
                sequence,
                expectedCursor,
                cursorKey,
            );
        } catch (error: unknown) {
            if (error instanceof Error && error.message.startsWith("Murmur persistence")) {
                throw error;
            }
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
        } finally {
            zeroBytes(fingerprint);
        }
    }

    async #applyControlFrame(
        peer: IdentityPublicKey,
        frame: Exclude<FriendControlFrame, { type: "group-invitation" }>,
        replayKey: string,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        let keyPackage: MlsKeyPackage | undefined;
        if (frame.type === "key-package-announce") {
            keyPackage = decodeMlsKeyPackage(frame.keyPackage);
            if (
                !verifyMlsKeyPackage(keyPackage) ||
                !equalBytes(keyPackage.leafNode.signatureKey, peer.publicKey) ||
                !equalBytes(mlsKeyPackageReference(keyPackage), frame.reference)
            ) {
                throw new Error("Invalid announced KeyPackage");
            }
        }
        try {
            await this.#store.transaction(async (transaction) => {
                const recordBytes = await transaction.get(friendRecordKey(this.#identity, peer));
                if (recordBytes === undefined) {
                    throw new Error("Friend-control sender is unknown");
                }
                const record = decodeFriendRecord(recordBytes);
                if (frame.type === "profile-update") {
                    if (record.status !== "active") {
                        throw new Error("Profile update requires an active friend");
                    }
                    await transaction.set(
                        friendRecordKey(this.#identity, peer),
                        encodeFriendRecord({
                            ...record,
                            profile: copyProfile(frame.profile),
                            updatedAt: Math.max(record.updatedAt, Date.now()),
                        }),
                    );
                } else if (frame.type === "friendship-ended") {
                    if (record.requestId !== frame.requestId) {
                        throw new Error("Friendship end does not match its exchange");
                    }
                    if (record.status !== "ended") {
                        await transaction.set(
                            friendRecordKey(this.#identity, peer),
                            encodeFriendRecord({
                                ...record,
                                status: "ended",
                                updatedAt: Math.max(record.updatedAt, Date.now()),
                            }),
                        );
                    }
                } else if (frame.type === "key-package-request") {
                    if (record.status !== "active") {
                        throw new Error("KeyPackage request requires an active friend");
                    }
                    await transaction.set(
                        `${KEY_PACKAGE_REQUEST_PREFIX}${identityId(peer)}`,
                        new Uint8Array([1]),
                    );
                } else {
                    if (record.status !== "active" || keyPackage === undefined) {
                        throw new Error("KeyPackage announce requires an active friend");
                    }
                    const consumedKey = `${REMOTE_KEY_PACKAGE_CONSUMED_PREFIX}${identityId(
                        peer,
                    )}/${encodeBase64Url(frame.reference)}`;
                    if ((await transaction.get(consumedKey)) === undefined) {
                        const remoteKey = remoteKeyPackageKey(peer, frame.reference);
                        const existing = await transaction.get(remoteKey);
                        if (existing !== undefined && !equalBytes(existing, frame.keyPackage)) {
                            throw new Error("KeyPackage reference collision");
                        }
                        await transaction.set(remoteKey, frame.keyPackage);
                        await transaction.delete(`${KEY_PACKAGE_NEEDED_PREFIX}${identityId(peer)}`);
                    }
                }
                await transaction.set(replayKey, fingerprint);
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            if (
                error instanceof Error &&
                (error.message.includes("active friend") ||
                    error.message.includes("does not match") ||
                    error.message.includes("unknown") ||
                    error.message.includes("collision"))
            ) {
                throw error;
            }
            throw new Error("Murmur persistence transaction failed", { cause: error });
        }
    }

    async #adoptInvitation(
        peer: IdentityPublicKey,
        frame: Extract<FriendControlFrame, { type: "group-invitation" }>,
        replayKey: string,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const id = encodeBase64Url(frame.groupId);
        const calculatedBinding = descriptorBinding(
            frame.groupId,
            frame.descriptorNonce,
            frame.descriptor,
        );
        try {
            if (!equalBytes(calculatedBinding, frame.descriptorBinding)) {
                throw new Error("Invitation descriptor binding mismatch");
            }
        } finally {
            zeroBytes(calculatedBinding);
        }
        const existingGroup = this.#groups.get(id);
        if (existingGroup !== undefined) {
            if (
                !equalBytes(existingGroup.record.descriptorBinding, frame.descriptorBinding) ||
                !equalBytes(existingGroup.record.topicSecret, frame.topicSecret)
            ) {
                throw new Error("Invitation collides with an existing group");
            }
            try {
                await this.#store.transaction(async (transaction) => {
                    await transaction.set(replayKey, fingerprint);
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
            } catch (error: unknown) {
                throw new Error("Murmur persistence transaction failed", {
                    cause: error,
                });
            }
            return;
        }
        const bundleKey = localKeyPackageKey(peer, frame.keyPackageReference);
        const bundleBytes = await this.#store.get(bundleKey);
        if (bundleBytes === undefined) {
            throw new Error("Invitation has no matching local KeyPackage");
        }
        const bundle = deserializeMlsKeyPackageBundle(bundleBytes);
        let epoch: MlsEpochState | undefined;
        let epochBytes: Uint8Array | undefined;
        let groupTopicAccess: TopicAccess | undefined;
        try {
            if (!equalBytes(mlsKeyPackageReference(bundle.keyPackage), frame.keyPackageReference)) {
                throw new Error("Invitation KeyPackage reference mismatch");
            }
            const tree = decodeMlsRatchetTree(frame.tree, {
                groupId: frame.groupId,
                authenticateCredential: authenticateMurmurMlsCredential,
            });
            epoch = joinMlsGroupFromWelcome({
                identity: this.#identity,
                inviter: peer,
                groupId: frame.groupId,
                welcome: frame.welcome,
                tree,
                keyPackageBundle: bundle,
            });
            epochBytes = epoch.serialize();
            const record: StoredGroup = {
                id,
                descriptor: frame.descriptor.slice(),
                descriptorNonce: frame.descriptorNonce.slice(),
                descriptorBinding: frame.descriptorBinding.slice(),
                topicSecret: frame.topicSecret.slice(),
                members: epoch.memberSignatureKeys.flatMap((member) =>
                    member === undefined ? [] : [member],
                ),
                createdAt: Date.now(),
                epoch: epoch.context.epoch,
                persistenceGeneration: epoch.persistenceGeneration,
                status: "active",
            };
            groupTopicAccess = groupAccess(frame.topicSecret);
            const groupCursorKey = `${CURSOR_PREFIX}${relayTopicId(groupTopicAccess.topic)}`;
            try {
                await this.#store.transaction(async (transaction) => {
                    const currentBundle = await transaction.get(bundleKey);
                    if (currentBundle === undefined || !equalBytes(currentBundle, bundleBytes)) {
                        throw new Error("Invitation KeyPackage was already consumed");
                    }
                    if ((await transaction.get(groupMetaKey(id))) !== undefined) {
                        throw new Error("Invitation group was concurrently installed");
                    }
                    await transaction.set(groupMetaKey(id), encodeGroup(record));
                    await transaction.set(groupEpochKey(id), epochBytes!);
                    await transaction.set(groupCursorKey, cursorBytes(frame.commitSequence));
                    await transaction.delete(bundleKey);
                    await transaction.set(
                        `${LOCAL_KEY_PACKAGE_CONSUMED_PREFIX}${identityId(
                            peer,
                        )}/${encodeBase64Url(frame.keyPackageReference)}`,
                        frame.keyPackageReference,
                    );
                    await transaction.set(replayKey, fingerprint);
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
            } catch (error: unknown) {
                throw new Error("Murmur persistence transaction failed", {
                    cause: error,
                });
            }
            this.#groups.set(id, { record, epoch });
            epoch = undefined;
        } finally {
            if (groupTopicAccess !== undefined) {
                destroyAccess(groupTopicAccess);
            }
            epoch?.destroy();
            epochBytes?.fill(0);
            destroyMlsKeyPackageBundle(bundle);
            zeroBytes(bundleBytes);
        }
    }

    async #processGroupEvent(
        groupId: string,
        event: SignedRelayEvent,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const group = this.#groups.get(groupId);
        if (group === undefined) {
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        const fingerprint = hashBytes(event.payload);
        try {
            const replay = await this.#store.get(groupReplayKey(groupId, fingerprint));
            if (replay !== undefined) {
                await this.#store.transaction(async (transaction) => {
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
                return;
            }
            if (group.record.status !== "active" || group.epoch === undefined) {
                await this.#quarantine(
                    relayTopicId(event.topic),
                    sequence,
                    event,
                    expectedCursor,
                    cursorKey,
                );
                return;
            }
            const activeGroup = group as RuntimeGroup & { epoch: MlsEpochState };
            if (isCommit(event.payload)) {
                await this.#processGroupCommit(
                    activeGroup,
                    event,
                    fingerprint,
                    sequence,
                    expectedCursor,
                    cursorKey,
                );
                return;
            }
            await this.#processGroupApplication(
                activeGroup,
                event,
                fingerprint,
                sequence,
                expectedCursor,
                cursorKey,
            );
        } finally {
            zeroBytes(fingerprint);
        }
    }

    async #processGroupCommit(
        group: RuntimeGroup & { epoch: MlsEpochState },
        event: SignedRelayEvent,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const stagedBytes = await this.#store.get(groupStagedKey(group.record.id));
        const staged = stagedBytes === undefined ? undefined : decodeStagedCommit(stagedBytes);
        if (
            staged !== undefined &&
            staged.eventId === event.id &&
            equalBytes(staged.fingerprint, fingerprint) &&
            staged.currentEpoch === group.record.epoch
        ) {
            try {
                await this.#adoptOwnCommit(
                    group,
                    staged,
                    event,
                    fingerprint,
                    sequence,
                    expectedCursor,
                    cursorKey,
                );
            } finally {
                destroyStagedCommit(staged);
            }
            return;
        }
        destroyStagedCommit(staged);
        const clone = this.#cloneEpoch(group);
        let transition: ReturnType<MlsEpochState["applyCommit"]> | undefined;
        try {
            transition = clone.applyCommit(event.payload);
        } catch (error: unknown) {
            if (error instanceof MlsLocalMemberRemovedError) {
                clone.destroy();
                await this.#adoptLocalRemoval(
                    group,
                    event,
                    fingerprint,
                    sequence,
                    expectedCursor,
                    cursorKey,
                );
                return;
            }
            clone.destroy();
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        const nextEpochBytes = transition.serialize();
        const nextMembers = this.#membersAfterCommit(group.epoch, event.payload);
        const nextRecord: StoredGroup = {
            ...group.record,
            members: nextMembers,
            epoch: group.record.epoch + 1n,
            persistenceGeneration: transition.persistenceGeneration,
        };
        try {
            await this.#store.transaction(async (transaction) => {
                await transaction.set(groupMetaKey(group.record.id), encodeGroup(nextRecord));
                await transaction.set(groupEpochKey(group.record.id), nextEpochBytes);
                await transaction.set(groupReplayKey(group.record.id, fingerprint), fingerprint);
                await transaction.delete(groupStagedKey(group.record.id));
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            transition.cancel();
            clone.destroy();
            throw error;
        } finally {
            zeroBytes(nextEpochBytes);
        }
        const next = transition.commit();
        group.epoch.destroy();
        group.epoch = next;
        group.record = nextRecord;
    }

    async #adoptOwnCommit(
        group: RuntimeGroup & { epoch: MlsEpochState },
        staged: StagedGroupCommit,
        event: SignedRelayEvent,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const next = MlsEpochState.deserialize(staged.nextEpoch, {
            localSigningSecretKey: this.#identity.secretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            minimumPersistenceGeneration: group.record.persistenceGeneration + 1n,
        });
        if (
            next.context.epoch !== group.record.epoch + 1n ||
            next.persistenceGeneration !== group.record.persistenceGeneration + 1n
        ) {
            next.destroy();
            throw new Error("Staged MLS candidate does not advance the active epoch");
        }
        const nextRecord: StoredGroup = {
            ...group.record,
            members: next.memberSignatureKeys.flatMap((member) =>
                member === undefined ? [] : [member],
            ),
            epoch: next.context.epoch,
            persistenceGeneration: next.persistenceGeneration,
        };
        try {
            await this.#store.transaction(async (transaction) => {
                const current = await transaction.get(groupStagedKey(group.record.id));
                if (
                    current === undefined ||
                    decodeStagedCommit(current).eventId !== staged.eventId
                ) {
                    throw new Error("Staged MLS candidate changed before adoption");
                }
                await transaction.set(groupMetaKey(group.record.id), encodeGroup(nextRecord));
                await transaction.set(groupEpochKey(group.record.id), staged.nextEpoch);
                await transaction.set(groupReplayKey(group.record.id, fingerprint), fingerprint);
                await transaction.delete(groupStagedKey(group.record.id));
                await transaction.delete(groupOperationKey(group.record.id, staged.operationId));
                await transaction.delete(`${OUTBOX_PREFIX}${event.id}`);
                if (
                    staged.type === "add" &&
                    staged.keyPackageReference !== undefined &&
                    staged.welcome !== undefined &&
                    staged.tree !== undefined
                ) {
                    await this.#queueControl(
                        transaction,
                        { publicKey: staged.peer },
                        {
                            type: "group-invitation",
                            groupId: decodeBase64Url(group.record.id),
                            descriptor: group.record.descriptor,
                            descriptorNonce: group.record.descriptorNonce,
                            descriptorBinding: group.record.descriptorBinding,
                            topicSecret: group.record.topicSecret,
                            keyPackageReference: staged.keyPackageReference,
                            welcome: staged.welcome,
                            tree: staged.tree,
                            commitSequence: sequence,
                        },
                        { type: "friend-control" },
                    );
                }
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            next.destroy();
            throw error;
        }
        group.epoch.destroy();
        group.epoch = next;
        group.record = nextRecord;
    }

    async #adoptLocalRemoval(
        group: RuntimeGroup,
        event: SignedRelayEvent,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const epoch = group.epoch;
        if (epoch === undefined) {
            throw new Error("Removed group has no active MLS epoch");
        }
        const nextRecord: StoredGroup = {
            ...group.record,
            members: this.#membersAfterCommit(epoch, event.payload),
            epoch: group.record.epoch + 1n,
            persistenceGeneration: group.record.persistenceGeneration + 1n,
            status: "removed",
        };
        await this.#store.transaction(async (transaction) => {
            await transaction.set(groupMetaKey(group.record.id), encodeGroup(nextRecord));
            await transaction.delete(groupEpochKey(group.record.id));
            await transaction.delete(groupStagedKey(group.record.id));
            await transaction.set(groupReplayKey(group.record.id, fingerprint), fingerprint);
            await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
        });
        epoch.destroy();
        delete group.epoch;
        group.record = nextRecord;
    }

    #membersAfterCommit(epoch: MlsEpochState, payload: Uint8Array): readonly Uint8Array[] {
        const members = [...epoch.memberSignatureKeys];
        const commit = decodeMlsTreeCommit(payload);
        const removals = commit.proposals.flatMap((proposal) =>
            proposal.type === "remove" ? [proposal.removed] : [],
        );
        for (const removed of removals) {
            members[removed] = undefined;
        }
        for (const proposal of commit.proposals) {
            if (proposal.type !== "add") {
                continue;
            }
            const blank = members.findIndex((member) => member === undefined);
            if (blank >= 0) {
                members[blank] = proposal.keyPackage.leafNode.signatureKey.slice();
            } else {
                members.push(proposal.keyPackage.leafNode.signatureKey.slice());
            }
        }
        return members.flatMap((member) => (member === undefined ? [] : [member.slice()]));
    }

    async #processGroupApplication(
        group: RuntimeGroup & { epoch: MlsEpochState },
        event: SignedRelayEvent,
        fingerprint: Uint8Array,
        sequence: bigint,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        const operations = [
            ...(await this.#store.list(groupOperationPrefix(group.record.id))).values(),
        ]
            .map(decodeGroupOperation)
            .filter(
                (operation): operation is Extract<GroupOperation, { type: "send" }> =>
                    operation.type === "send" &&
                    operation.attempt !== undefined &&
                    equalBytes(operation.attempt.fingerprint, fingerprint),
            );
        const own = operations[0];
        if (own?.attempt !== undefined) {
            if (own.attempt.epoch === group.record.epoch) {
                await this.#store.transaction(async (transaction) => {
                    await transaction.set(
                        groupEventKey(group.record.id, sequence),
                        encodeGroupEvent({
                            sequence,
                            sender: this.#identity.publicKey,
                            bytes: own.payload,
                        }),
                    );
                    await transaction.set(
                        groupReplayKey(group.record.id, fingerprint),
                        fingerprint,
                    );
                    await transaction.delete(groupOperationKey(group.record.id, own.id));
                    await transaction.delete(`${OUTBOX_PREFIX}${event.id}`);
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
            } else {
                const retried: GroupOperation = {
                    id: own.id,
                    type: "send",
                    payload: own.payload,
                    createdAt: own.createdAt,
                };
                await this.#store.transaction(async (transaction) => {
                    await transaction.set(
                        groupOperationKey(group.record.id, own.id),
                        encodeGroupOperation(retried),
                    );
                    await transaction.delete(`${OUTBOX_PREFIX}${event.id}`);
                    await this.#writeQuarantine(
                        transaction,
                        relayTopicId(event.topic),
                        sequence,
                        event,
                    );
                    await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
                });
            }
            return;
        }

        const clone = this.#cloneEpoch(group);
        let opened: ReturnType<MlsEpochState["openWithCheckpoint"]>;
        try {
            opened = clone.openWithCheckpoint(event.payload);
        } catch {
            clone.destroy();
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        const sender = clone.memberSignatureKeys[opened.message.sender];
        if (sender === undefined) {
            clone.destroy();
            zeroBytes(opened.state);
            zeroBytes(opened.message.applicationData);
            zeroBytes(opened.message.authenticatedData);
            await this.#quarantine(
                relayTopicId(event.topic),
                sequence,
                event,
                expectedCursor,
                cursorKey,
            );
            return;
        }
        const nextRecord: StoredGroup = {
            ...group.record,
            persistenceGeneration: opened.persistenceGeneration,
        };
        try {
            await this.#store.transaction(async (transaction) => {
                await transaction.set(groupMetaKey(group.record.id), encodeGroup(nextRecord));
                await transaction.set(groupEpochKey(group.record.id), opened.state);
                await transaction.set(
                    groupEventKey(group.record.id, sequence),
                    encodeGroupEvent({
                        sequence,
                        sender,
                        bytes: opened.message.applicationData,
                    }),
                );
                await transaction.set(groupReplayKey(group.record.id, fingerprint), fingerprint);
                await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
            });
        } catch (error: unknown) {
            clone.destroy();
            throw error;
        } finally {
            zeroBytes(opened.state);
            zeroBytes(opened.message.applicationData);
            zeroBytes(opened.message.authenticatedData);
        }
        group.epoch.destroy();
        group.epoch = clone;
        group.record = nextRecord;
    }

    async #prepareGroupOperations(): Promise<boolean> {
        let changed = false;
        const groups = [...this.#groups.values()].sort((left, right) =>
            left.record.id < right.record.id ? -1 : left.record.id > right.record.id ? 1 : 0,
        );
        for (const group of groups) {
            if (group.record.status !== "active" || group.epoch === undefined) {
                continue;
            }
            const activeGroup = group as RuntimeGroup & { epoch: MlsEpochState };
            if ((await this.#store.get(groupStagedKey(group.record.id))) !== undefined) {
                continue;
            }
            const operations = [
                ...(await this.#store.list(groupOperationPrefix(group.record.id))).values(),
            ]
                .map(decodeGroupOperation)
                .sort((left, right) =>
                    left.createdAt !== right.createdAt
                        ? left.createdAt - right.createdAt
                        : left.id < right.id
                          ? -1
                          : 1,
                );
            const operation = operations[0];
            if (operation === undefined) {
                continue;
            }
            if (operation.type === "send") {
                if (operation.attempt === undefined) {
                    await this.#prepareGroupSend(activeGroup, operation);
                    changed = true;
                }
                continue;
            }
            const present = group.record.members.some((member) =>
                equalBytes(member, operation.peer),
            );
            if (
                (operation.type === "add" && present) ||
                (operation.type === "remove" && !present)
            ) {
                await this.#store.delete(groupOperationKey(group.record.id, operation.id));
                changed = true;
                continue;
            }
            if (operation.type === "add") {
                const peer = { publicKey: operation.peer };
                const remote = await this.#store.list(
                    `${REMOTE_KEY_PACKAGE_PREFIX}${identityId(peer)}/`,
                );
                const candidate = [...remote]
                    .sort(([left], [right]) => (left < right ? -1 : 1))
                    .find(([, bytes]) => {
                        try {
                            const keyPackage = decodeMlsKeyPackage(bytes);
                            return (
                                verifyMlsKeyPackage(keyPackage) &&
                                equalBytes(keyPackage.leafNode.signatureKey, operation.peer)
                            );
                        } catch {
                            return false;
                        }
                    });
                if (candidate === undefined) {
                    changed = (await this.#requestKeyPackage(peer)) || changed;
                    continue;
                }
                await this.#prepareMembershipCommit(
                    activeGroup,
                    operation,
                    candidate[0],
                    candidate[1],
                );
                changed = true;
                continue;
            }
            await this.#prepareMembershipCommit(activeGroup, operation);
            changed = true;
        }
        return changed;
    }

    async #prepareGroupSend(
        group: RuntimeGroup & { epoch: MlsEpochState },
        operation: Extract<GroupOperation, { type: "send" }>,
    ): Promise<void> {
        const clone = this.#cloneEpoch(group);
        let checkpoint: Uint8Array | undefined;
        let access: TopicAccess | undefined;
        try {
            const payload = clone.seal(operation.payload);
            checkpoint = clone.serialize();
            access = groupAccess(group.record.topicSecret);
            const event = createCapabilityEvent(access, payload);
            const fingerprint = hashBytes(payload);
            const attempted: GroupOperation = {
                ...operation,
                attempt: {
                    eventId: event.id,
                    fingerprint,
                    epoch: group.record.epoch,
                },
            };
            const nextRecord: StoredGroup = {
                ...group.record,
                persistenceGeneration: clone.persistenceGeneration,
            };
            try {
                await this.#store.transaction(async (transaction) => {
                    const currentRecord = await transaction.get(groupMetaKey(group.record.id));
                    const currentOperation = await transaction.get(
                        groupOperationKey(group.record.id, operation.id),
                    );
                    if (
                        currentRecord === undefined ||
                        decodeGroup(currentRecord).persistenceGeneration !==
                            group.record.persistenceGeneration ||
                        currentOperation === undefined ||
                        decodeGroupOperation(currentOperation).type !== "send"
                    ) {
                        throw new Error("Group send base state changed");
                    }
                    await transaction.set(groupMetaKey(group.record.id), encodeGroup(nextRecord));
                    await transaction.set(groupEpochKey(group.record.id), checkpoint!);
                    await transaction.set(
                        groupOperationKey(group.record.id, operation.id),
                        encodeGroupOperation(attempted),
                    );
                    await transaction.set(
                        `${OUTBOX_PREFIX}${event.id}`,
                        encodeRelayOutbox({
                            event,
                            purpose: {
                                type: "group-application",
                                groupId: group.record.id,
                                operationId: operation.id,
                            },
                            attempted: false,
                        }),
                    );
                });
            } catch (error: unknown) {
                clone.destroy();
                throw error;
            }
            group.epoch.destroy();
            group.epoch = clone;
            group.record = nextRecord;
        } finally {
            checkpoint?.fill(0);
            if (access !== undefined) {
                destroyAccess(access);
            }
        }
    }

    async #prepareMembershipCommit(
        group: RuntimeGroup & { epoch: MlsEpochState },
        operation: Extract<GroupOperation, { type: "add" | "remove" }>,
        remoteKey?: string,
        remoteBytes?: Uint8Array,
    ): Promise<void> {
        const clone = this.#cloneEpoch(group);
        let access: TopicAccess | undefined;
        let nextEpoch: Uint8Array | undefined;
        let keyPackageReference: Uint8Array | undefined;
        let prepared: ReturnType<MlsEpochState["prepareCommit"]> | undefined;
        try {
            if (operation.type === "add") {
                if (remoteKey === undefined || remoteBytes === undefined) {
                    throw new Error("MLS Add requires a remote KeyPackage");
                }
                const keyPackage = decodeMlsKeyPackage(remoteBytes);
                if (
                    !verifyMlsKeyPackage(keyPackage) ||
                    !equalBytes(keyPackage.leafNode.signatureKey, operation.peer)
                ) {
                    throw new Error("Remote KeyPackage is no longer usable");
                }
                keyPackageReference = mlsKeyPackageReference(keyPackage);
                prepared = clone.prepareCommit([{ type: "add", keyPackage }]);
            } else {
                const removed = clone.memberSignatureKeys.findIndex(
                    (member) => member !== undefined && equalBytes(member, operation.peer),
                );
                if (removed < 0) {
                    throw new Error("MLS Remove member disappeared");
                }
                prepared = clone.prepareCommit([{ type: "remove", removed }]);
            }
            nextEpoch = prepared.transition.serialize();
            access = groupAccess(group.record.topicSecret);
            const event = createCapabilityEvent(access, prepared.commit);
            const fingerprint = hashBytes(prepared.commit);
            const staged: StagedGroupCommit = {
                operationId: operation.id,
                eventId: event.id,
                fingerprint,
                currentEpoch: group.record.epoch,
                nextEpoch,
                type: operation.type,
                peer: operation.peer,
                ...(keyPackageReference === undefined ? {} : { keyPackageReference }),
                ...(prepared.welcome === undefined ? {} : { welcome: prepared.welcome }),
                ...(prepared.welcome === undefined
                    ? {}
                    : { tree: encodeMlsRatchetTree(prepared.tree) }),
            };
            await this.#store.transaction(async (transaction) => {
                if ((await transaction.get(groupStagedKey(group.record.id))) !== undefined) {
                    throw new Error("Group already has a staged membership transition");
                }
                if (
                    (await transaction.get(groupOperationKey(group.record.id, operation.id))) ===
                    undefined
                ) {
                    throw new Error("Group membership operation disappeared");
                }
                if (operation.type === "add") {
                    const currentRemote = await transaction.get(remoteKey!);
                    if (currentRemote === undefined || !equalBytes(currentRemote, remoteBytes!)) {
                        throw new Error("Remote KeyPackage was already reserved");
                    }
                    await transaction.delete(remoteKey!);
                    await transaction.set(
                        `${REMOTE_KEY_PACKAGE_CONSUMED_PREFIX}${identityId({
                            publicKey: operation.peer,
                        })}/${encodeBase64Url(keyPackageReference!)}`,
                        keyPackageReference!,
                    );
                    await transaction.delete(
                        `${KEY_PACKAGE_NEEDED_PREFIX}${identityId({
                            publicKey: operation.peer,
                        })}`,
                    );
                }
                await transaction.set(groupStagedKey(group.record.id), encodeStagedCommit(staged));
                await transaction.set(
                    `${OUTBOX_PREFIX}${event.id}`,
                    encodeRelayOutbox({
                        event,
                        purpose: {
                            type: "group-commit",
                            groupId: group.record.id,
                            operationId: operation.id,
                        },
                        attempted: false,
                    }),
                );
            });
        } finally {
            if (prepared !== undefined) {
                try {
                    prepared.transition.cancel();
                } catch {
                    // A failed preparation may already have settled its transition.
                }
            }
            clone.destroy();
            if (access !== undefined) {
                destroyAccess(access);
            }
            nextEpoch?.fill(0);
            keyPackageReference?.fill(0);
        }
    }

    async #requestKeyPackage(peer: IdentityPublicKey): Promise<boolean> {
        const key = `${KEY_PACKAGE_NEEDED_PREFIX}${identityId(peer)}`;
        if ((await this.#store.get(key)) !== undefined) {
            return false;
        }
        let created = false;
        await this.#store.transaction(async (transaction) => {
            if ((await transaction.get(key)) !== undefined) {
                return;
            }
            await this.#queueControl(
                transaction,
                peer,
                { type: "key-package-request" },
                { type: "friend-control" },
            );
            await transaction.set(key, new Uint8Array([1]));
            created = true;
        });
        return created;
    }

    async #ensureKeyPackages(): Promise<boolean> {
        const active = (await this.#friendBook.list()).filter(
            (friend) => friend.status === "active",
        );
        let changed = false;
        for (const friend of active) {
            const peer = friend.identity;
            const prefix = `${LOCAL_KEY_PACKAGE_PREFIX}${identityId(peer)}/`;
            const stored = await this.#store.list(prefix);
            const available: {
                readonly reference: Uint8Array;
                readonly keyPackageBytes: Uint8Array;
            }[] = [];
            const now = BigInt(Math.floor(Date.now() / 1_000));
            for (const bytes of stored.values()) {
                let bundle;
                try {
                    bundle = deserializeMlsKeyPackageBundle(bytes);
                    if (
                        bundle.keyPackage.leafNode.notAfter < now ||
                        bundle.keyPackage.leafNode.notBefore > now
                    ) {
                        // An announced private bundle remains necessary to adopt a
                        // delayed invitation even after its public package expires.
                        // It is no longer eligible for a new Add, but deleting it
                        // here would make an already-winning Commit unrecoverable.
                        continue;
                    }
                    available.push({
                        reference: mlsKeyPackageReference(bundle.keyPackage),
                        keyPackageBytes: encodeMlsKeyPackage(bundle.keyPackage),
                    });
                } finally {
                    if (bundle !== undefined) {
                        destroyMlsKeyPackageBundle(bundle);
                    }
                    zeroBytes(bytes);
                }
            }
            while (available.length < LOCAL_KEY_PACKAGE_TARGET) {
                const bundle = createMlsKeyPackage(this.#identity);
                try {
                    const reference = mlsKeyPackageReference(bundle.keyPackage);
                    const bundleBytes = serializeMlsKeyPackageBundle(bundle);
                    const keyPackageBytes = encodeMlsKeyPackage(bundle.keyPackage);
                    const key = localKeyPackageKey(peer, reference);
                    await this.#store.transaction(async (transaction) => {
                        await transaction.set(key, bundleBytes);
                        await this.#queueControl(
                            transaction,
                            peer,
                            {
                                type: "key-package-announce",
                                reference,
                                keyPackage: keyPackageBytes,
                            },
                            { type: "friend-control" },
                        );
                    });
                    available.push({
                        reference,
                        keyPackageBytes,
                    });
                    changed = true;
                    zeroBytes(bundleBytes);
                } finally {
                    destroyMlsKeyPackageBundle(bundle);
                }
            }
            const requestKey = `${KEY_PACKAGE_REQUEST_PREFIX}${identityId(peer)}`;
            if ((await this.#store.get(requestKey)) !== undefined) {
                // A requester may have burned every previously announced package
                // while losing concurrent Commit races. Always mint one fresh
                // package in response instead of merely replaying the old pool.
                const freshBundle = createMlsKeyPackage(this.#identity);
                const freshReference = mlsKeyPackageReference(freshBundle.keyPackage);
                const freshBundleBytes = serializeMlsKeyPackageBundle(freshBundle);
                const freshKeyPackageBytes = encodeMlsKeyPackage(freshBundle.keyPackage);
                try {
                    await this.#store.transaction(async (transaction) => {
                        await transaction.set(
                            localKeyPackageKey(peer, freshReference),
                            freshBundleBytes,
                        );
                        for (const item of available) {
                            await this.#queueControl(
                                transaction,
                                peer,
                                {
                                    type: "key-package-announce",
                                    reference: item.reference,
                                    keyPackage: item.keyPackageBytes,
                                },
                                { type: "friend-control" },
                            );
                        }
                        await this.#queueControl(
                            transaction,
                            peer,
                            {
                                type: "key-package-announce",
                                reference: freshReference,
                                keyPackage: freshKeyPackageBytes,
                            },
                            { type: "friend-control" },
                        );
                        await transaction.delete(requestKey);
                    });
                    changed = true;
                } finally {
                    zeroBytes(freshBundleBytes);
                    zeroBytes(freshKeyPackageBytes);
                    zeroBytes(freshReference);
                    destroyMlsKeyPackageBundle(freshBundle);
                }
            }
        }
        return changed;
    }

    #createControlEvent(
        peer: IdentityPublicKey,
        frame: FriendControlFrame,
        expiresAt?: number,
    ): SignedRelayEvent {
        const channel = new FriendChannel(this.#identity, peer);
        const access = friendControlAccess(channel);
        const frameBytes = encodeFriendControlFrame(frame);
        let payload: Uint8Array | undefined;
        try {
            const message = channel.createMessage(
                frameBytes,
                expiresAt === undefined ? { kind: "durable" } : { kind: "temporary", expiresAt },
            );
            const envelope = channel.seal(message);
            payload = encodeEnvelope(envelope);
            return createCapabilityEvent(
                access,
                payload,
                expiresAt === undefined ? {} : { expiresAt },
            );
        } finally {
            channel.destroy();
            destroyAccess(access);
            zeroBytes(frameBytes);
            payload?.fill(0);
        }
    }

    async #queueControl(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
        frame: FriendControlFrame,
        purpose: RelayOutboxRecord["purpose"],
        expiresAt?: number,
    ): Promise<void> {
        const event = this.#createControlEvent(peer, frame, expiresAt);
        await transaction.set(
            `${OUTBOX_PREFIX}${event.id}`,
            encodeRelayOutbox({ event, purpose, attempted: false }),
        );
    }

    #cloneEpoch(group: RuntimeGroup & { epoch: MlsEpochState }): MlsEpochState {
        const serialized = group.epoch.serialize();
        try {
            return MlsEpochState.deserialize(serialized, {
                localSigningSecretKey: this.#identity.secretKey,
                authenticateCredential: authenticateMurmurMlsCredential,
                minimumPersistenceGeneration: group.record.persistenceGeneration,
            });
        } finally {
            zeroBytes(serialized);
        }
    }

    async #waitForActivity(waitMilliseconds: number, signal?: AbortSignal): Promise<void> {
        const contexts = await this.#discoverTopics();
        const controller = new AbortController();
        const abort = (): void => controller.abort(signal?.reason);
        signal?.addEventListener("abort", abort, { once: true });
        try {
            const waits = await Promise.all(
                contexts.map(async (context) => ({
                    context,
                    cursor: parseCursor(
                        await this.#store.get(
                            `${CURSOR_PREFIX}${relayTopicId(context.access.topic)}`,
                        ),
                    ),
                })),
            );
            const requests = waits.map(({ context, cursor }) =>
                this.#transport.readEvents(
                    context.access,
                    cursor,
                    EVENT_PAGE_LIMIT,
                    waitMilliseconds,
                    controller.signal,
                ),
            );
            try {
                await Promise.race(requests);
            } finally {
                controller.abort();
                await Promise.allSettled(requests);
            }
        } finally {
            signal?.removeEventListener("abort", abort);
            controller.abort();
            for (const context of contexts) {
                destroyAccess(context.access);
            }
        }
    }

    async #advanceCursor(
        transaction: StoreTransaction,
        cursorKey: string,
        expected: bigint,
        next: bigint,
    ): Promise<void> {
        const current = parseCursor(await transaction.get(cursorKey));
        if (current !== expected || next < current) {
            throw new Error("Murmur cursor cannot skip an unprocessed event");
        }
        await transaction.set(cursorKey, cursorBytes(next));
    }

    async #quarantine(
        topicId: string,
        sequence: bigint,
        event: SignedRelayEvent,
        expectedCursor: bigint,
        cursorKey: string,
    ): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            await this.#writeQuarantine(transaction, topicId, sequence, event);
            await this.#advanceCursor(transaction, cursorKey, expectedCursor, sequence);
        });
    }

    async #writeQuarantine(
        transaction: StoreTransaction,
        topicId: string,
        sequence: bigint,
        event: SignedRelayEvent,
    ): Promise<void> {
        const key = `${QUARANTINE_PREFIX}${topicId}/${sequenceKey(sequence)}`;
        const encoded = encodeSignedRelayEventWire(event);
        const existing = await transaction.get(key);
        if (existing !== undefined && !equalBytes(existing, encoded)) {
            throw new Error("Quarantine sequence collision");
        }
        await transaction.set(key, encoded);
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
        if (this.#closed) {
            throw new Error("Murmur is closed");
        }
    }
}
