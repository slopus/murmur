import type { IdentityKeyPair, IdentityPublicKey } from "../crypto/index.js";
import { randomBytes, validateIdentityKeyPair } from "../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import { copyFriendRecord, decodeFriendRecord, encodeFriendRecord } from "./impl/friendCodec.js";
import {
    createFriendRequest,
    createFriendResponse,
    friendRequestFingerprint,
    friendResponseFingerprint,
    openFriendRequest,
    openFriendResponse,
} from "./impl/friendProtocol.js";
import { identityId } from "./impl/identityCodec.js";
import {
    copyFriendOutboxItem,
    decodeFriendOutboxItem,
    encodeFriendOutboxItem,
    matchesFriendOutboxItem,
    validateFriendDestination,
} from "./impl/outboxCodec.js";
import {
    decodeOutgoingRequestTracker,
    encodeOutgoingRequestTracker,
    type OutgoingRequestTracker,
} from "./impl/outgoingTrackerCodec.js";
import type {
    CreateFriendRequestOptions,
    CreateFriendResponseOptions,
    FriendAcceptance,
    FriendBookOptions,
    FriendControlIntentOutboxItem,
    FriendOutboxItem,
    FriendOutboxOutcome,
    FriendRecord,
    FriendRequestEnvelope,
    FriendRequestOutboxItem,
    FriendResponseEnvelope,
    FriendResponseOutboxItem,
    PreparedFriendResponse,
} from "./types.js";

function validateTime(now: number): void {
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Friend time must be a non-negative safe integer");
    }
}

function newExchangeId(): string {
    return encodeBase64Url(randomBytes(24));
}

function validateExchangeId(id: string): void {
    if (id.length !== 32) {
        throw new Error("Friend exchange ID must encode exactly 24 bytes");
    }
    const decoded = decodeBase64Url(id);
    if (decoded.length !== 24 || encodeBase64Url(decoded) !== id) {
        throw new Error("Friend exchange ID must encode exactly 24 bytes");
    }
}

function compareContenders(
    leftRequester: IdentityPublicKey,
    leftRequestId: string,
    rightRequester: IdentityPublicKey,
    rightRequestId: string,
): number {
    const left = [identityId(leftRequester), leftRequestId] as const;
    const right = [identityId(rightRequester), rightRequestId] as const;
    if (left[0] !== right[0]) {
        return left[0] < right[0] ? -1 : 1;
    }
    return left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : 0;
}

/** Authenticated reuse of one exchange ID for different content. */
export class FriendExchangeIdCollisionError extends Error {
    constructor() {
        super("Authenticated friend exchange ID collision");
        this.name = "FriendExchangeIdCollisionError";
    }
}

/** Attempt to replace an unrelated durable outbox item with the same ID. */
export class FriendOutboxIdCollisionError extends Error {
    constructor() {
        super("Friend outbox ID collision");
        this.name = "FriendOutboxIdCollisionError";
    }
}

/** Durable, transactional request/response friendship lifecycle and outbox. */
export class FriendBook {
    readonly #owner: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #recordsPrefix: string;
    readonly #replayPrefix: string;
    readonly #outboxPrefix: string;
    readonly #outboxIdsPrefix: string;
    readonly #outgoingPrefix: string;
    readonly #generateId: () => string;

    constructor(owner: IdentityKeyPair, store: MurmurStore, options: FriendBookOptions = {}) {
        validateIdentityKeyPair(owner);
        const ownerId = identityId(owner);
        this.#owner = owner;
        this.#store = store;
        const prefix = `murmur/v1/friend-book/${ownerId}/`;
        this.#recordsPrefix = `${prefix}records/`;
        this.#replayPrefix = `${prefix}exchange-replay/`;
        this.#outboxPrefix = `${prefix}outbox/`;
        this.#outboxIdsPrefix = `${prefix}outbox-ids/`;
        this.#outgoingPrefix = `${prefix}outgoing/`;
        this.#generateId = options.generateId ?? newExchangeId;
    }

    /** Atomically prepare a pending request and its exact durable publication. */
    async createRequest(
        recipient: IdentityPublicKey,
        options: CreateFriendRequestOptions,
    ): Promise<FriendRequestOutboxItem> {
        const now = options.now ?? Date.now();
        validateTime(now);
        validateFriendDestination(options.destination);
        if (equalBytes(this.#owner.publicKey, recipient.publicKey)) {
            throw new Error("An identity cannot request friendship with itself");
        }
        const requestId = this.#newId();
        return this.#store.transaction(async (transaction) => {
            const key = this.#recordKey(recipient);
            const existing = await this.#read(transaction, key);
            if (existing !== undefined && existing.status !== "ended") {
                throw new Error(`Cannot request friendship from ${existing.status} state`);
            }
            if (existing !== undefined && now < existing.updatedAt) {
                throw new Error("Friend state must not move backwards in time");
            }
            const previousRequestId =
                existing?.status === "ended" ? existing.nextRequestPredecessorId : null;
            const envelope = createFriendRequest(this.#owner, recipient, {
                id: requestId,
                previousRequestId,
                responseAddress: options.responseAddress,
                profile: options.profile,
                ...(options.privateData === undefined ? {} : { privateData: options.privateData }),
            });
            const outbox: FriendRequestOutboxItem = {
                id: requestId,
                kind: "request",
                peer: { publicKey: recipient.publicKey.slice() },
                destination: options.destination,
                envelope,
                createdAt: now,
            };
            const record: FriendRecord = {
                identity: { publicKey: recipient.publicKey.slice() },
                requester: { publicKey: this.#owner.publicKey.slice() },
                status: "pending-outgoing",
                requestId,
                previousRequestId,
                nextRequestPredecessorId: previousRequestId,
                localResponseAddress: options.responseAddress,
                createdAt: existing?.createdAt ?? now,
                updatedAt: now,
            };
            await transaction.set(key, encodeFriendRecord(record));
            await this.#insertOutgoingTracker(transaction, recipient, requestId, previousRequestId);
            await this.#insertOutbox(transaction, outbox);
            return copyFriendOutboxItem(outbox);
        });
    }

    /**
     * Open an inbound request and converge simultaneous crossed requests.
     *
     * The lexicographically smaller `(requester identity ID, request ID)` wins
     * at both peers. A losing local request and its outbox item are retired in
     * the same transaction that adopts the winning inbound request.
     */
    async receiveRequest(
        envelope: FriendRequestEnvelope,
        now: number = Date.now(),
    ): Promise<FriendAcceptance> {
        validateTime(now);
        const opened = openFriendRequest(this.#owner, envelope);
        const fingerprint = friendRequestFingerprint(opened);
        try {
            return await this.#store.transaction(async (transaction) => {
                const replay = await this.#checkReplay(
                    transaction,
                    "request",
                    opened.sender,
                    opened.id,
                    fingerprint,
                );
                const key = this.#recordKey(opened.sender);
                const existing = await this.#read(transaction, key);
                if (existing !== undefined && now < existing.updatedAt) {
                    throw new Error("Friend state must not move backwards in time");
                }
                if (replay === "duplicate") {
                    if (existing === undefined) {
                        throw new Error("Friend request replay exists without durable state");
                    }
                    return { status: "duplicate", record: copyFriendRecord(existing) };
                }
                const replacesActive =
                    existing?.status === "active" &&
                    opened.previousRequestId === existing.requestId;
                if (existing?.status === "active" && !replacesActive) {
                    return { status: "superseded", record: copyFriendRecord(existing) };
                }
                if (
                    (existing === undefined && opened.previousRequestId !== null) ||
                    (existing?.status === "ended" &&
                        opened.previousRequestId !== existing.nextRequestPredecessorId) ||
                    (existing?.status === "pending-outgoing" &&
                        opened.previousRequestId !== existing.previousRequestId) ||
                    (existing?.status === "active" && !replacesActive)
                ) {
                    throw new Error("Friend request causal predecessor does not match");
                }
                if (existing?.status === "pending-outgoing") {
                    const incomingWins =
                        compareContenders(
                            opened.sender,
                            opened.id,
                            existing.requester,
                            existing.requestId,
                        ) < 0;
                    if (!incomingWins) {
                        return { status: "superseded", record: copyFriendRecord(existing) };
                    }
                    await this.#deleteRequestOutbox(
                        transaction,
                        existing.identity,
                        existing.requestId,
                    );
                    await this.#setOutgoingTracker(
                        transaction,
                        existing.identity,
                        existing.requestId,
                        "retired",
                    );
                } else if (
                    existing !== undefined &&
                    existing.status !== "ended" &&
                    existing.status !== "active"
                ) {
                    throw new Error(
                        `Cannot receive friendship request from ${existing.status} state`,
                    );
                }
                const record: FriendRecord = {
                    identity: { publicKey: opened.sender.publicKey.slice() },
                    requester: { publicKey: opened.sender.publicKey.slice() },
                    status: "pending-incoming",
                    requestId: opened.id,
                    previousRequestId: opened.previousRequestId,
                    nextRequestPredecessorId: opened.id,
                    profile: opened.profile,
                    peerResponseAddress: opened.responseAddress,
                    ...(existing?.localResponseAddress === undefined
                        ? {}
                        : { localResponseAddress: existing.localResponseAddress }),
                    ...(opened.privateData === undefined
                        ? {}
                        : { privateData: opened.privateData.slice() }),
                    createdAt: existing?.createdAt ?? now,
                    updatedAt: now,
                };
                await transaction.set(key, encodeFriendRecord(record));
                return { status: "opened", record: copyFriendRecord(record) };
            });
        } finally {
            zeroBytes(fingerprint);
            opened.privateData?.fill(0);
        }
    }

    /** Atomically transition an inbound request and queue its exact response. */
    async respond(
        peer: IdentityPublicKey,
        options: CreateFriendResponseOptions,
    ): Promise<PreparedFriendResponse> {
        const now = options.now ?? Date.now();
        validateTime(now);
        return this.#store.transaction(async (transaction) => {
            const key = this.#recordKey(peer);
            const existing = await this.#read(transaction, key);
            if (existing?.status !== "pending-incoming") {
                throw new Error("Friend response requires pending incoming state");
            }
            if (now < existing.updatedAt) {
                throw new Error("Friend state must not move backwards in time");
            }
            if (existing.peerResponseAddress === undefined) {
                throw new Error("Pending incoming friend is missing its response destination");
            }
            const responseId = this.#newId();
            const envelope =
                options.decision === "accepted"
                    ? createFriendResponse(this.#owner, existing.identity, {
                          id: responseId,
                          requestId: existing.requestId,
                          decision: "accepted",
                          profile: options.profile,
                          responseAddress: options.responseAddress,
                          ...(options.privateData === undefined
                              ? {}
                              : { privateData: options.privateData }),
                      })
                    : createFriendResponse(this.#owner, existing.identity, {
                          id: responseId,
                          requestId: existing.requestId,
                          decision: "rejected",
                      });
            const outbox: FriendResponseOutboxItem = {
                id: responseId,
                kind: "response",
                peer: { publicKey: existing.identity.publicKey.slice() },
                destination: existing.peerResponseAddress,
                envelope,
                createdAt: now,
            };
            const record: FriendRecord =
                options.decision === "accepted"
                    ? {
                          ...existing,
                          status: "active",
                          localResponseAddress: options.responseAddress,
                          updatedAt: now,
                      }
                    : { ...existing, status: "ended", updatedAt: now };
            await transaction.set(key, encodeFriendRecord(record));
            await this.#insertOutbox(transaction, outbox);
            return {
                outbox: copyFriendOutboxItem(outbox),
                record: copyFriendRecord(record),
            };
        });
    }

    /** Open a peer-bound response and establish or reject friendship atomically. */
    async receiveResponse(
        peer: IdentityPublicKey,
        envelope: FriendResponseEnvelope,
        now: number = Date.now(),
    ): Promise<FriendAcceptance> {
        validateTime(now);
        const opened = openFriendResponse(this.#owner, peer, envelope);
        const fingerprint = friendResponseFingerprint(opened);
        try {
            return await this.#store.transaction(async (transaction) => {
                const replay = await this.#checkReplay(
                    transaction,
                    "response",
                    opened.responder,
                    opened.id,
                    fingerprint,
                );
                const key = this.#recordKey(opened.responder);
                const existing = await this.#read(transaction, key);
                if (existing !== undefined && now < existing.updatedAt) {
                    throw new Error("Friend state must not move backwards in time");
                }
                if (replay === "duplicate") {
                    if (existing === undefined) {
                        throw new Error("Friend response replay exists without durable state");
                    }
                    return { status: "duplicate", record: copyFriendRecord(existing) };
                }
                const outgoingState = await this.#getOutgoingTracker(
                    transaction,
                    opened.responder,
                    opened.requestId,
                );
                const matchesPending =
                    outgoingState?.state === "pending" &&
                    existing?.status === "pending-outgoing" &&
                    existing.requestId === opened.requestId;
                if (!matchesPending) {
                    if (
                        existing !== undefined &&
                        (outgoingState?.state === "retired" || outgoingState?.state === "answered")
                    ) {
                        const terminal =
                            outgoingState.state === "retired" &&
                            outgoingState.previousRequestId === existing.nextRequestPredecessorId &&
                            existing.nextRequestPredecessorId !== opened.requestId
                                ? {
                                      ...existing,
                                      nextRequestPredecessorId: opened.requestId,
                                      updatedAt: now,
                                  }
                                : existing;
                        if (terminal !== existing) {
                            await transaction.set(key, encodeFriendRecord(terminal));
                        }
                        return {
                            status: "superseded",
                            record: copyFriendRecord(terminal),
                        };
                    }
                    throw new Error(
                        "Friend response does not match durable outgoing request state",
                    );
                }
                if (
                    existing?.status !== "pending-outgoing" ||
                    existing.requestId !== opened.requestId
                ) {
                    throw new Error("Friend response does not match pending outgoing state");
                }
                const record: FriendRecord =
                    opened.decision === "accepted"
                        ? {
                              ...existing,
                              status: "active",
                              nextRequestPredecessorId: existing.requestId,
                              profile: opened.profile,
                              peerResponseAddress: opened.responseAddress,
                              ...(opened.privateData === undefined
                                  ? {}
                                  : { privateData: opened.privateData.slice() }),
                              updatedAt: now,
                          }
                        : {
                              ...existing,
                              status: "ended",
                              nextRequestPredecessorId: existing.requestId,
                              updatedAt: now,
                          };
                await this.#deleteRequestOutbox(transaction, existing.identity, existing.requestId);
                await this.#setOutgoingTracker(
                    transaction,
                    existing.identity,
                    existing.requestId,
                    "answered",
                );
                await transaction.set(key, encodeFriendRecord(record));
                return { status: "opened", record: copyFriendRecord(record) };
            });
        } finally {
            zeroBytes(fingerprint);
            if ("privateData" in opened) {
                opened.privateData?.fill(0);
            }
        }
    }

    /** List exact pending publications in stable creation/ID order. */
    async listOutbox(): Promise<readonly FriendOutboxItem[]> {
        const values = await this.#store.list(this.#outboxPrefix);
        try {
            return [...values]
                .map(([, value]) => decodeFriendOutboxItem(value))
                .sort((left, right) =>
                    left.createdAt !== right.createdAt
                        ? left.createdAt - right.createdAt
                        : left.id < right.id
                          ? -1
                          : left.id > right.id
                            ? 1
                            : 0,
                )
                .map(copyFriendOutboxItem);
        } finally {
            for (const value of values.values()) {
                zeroBytes(value);
            }
        }
    }

    /**
     * Delete an exact outbox item only after accepted/idempotent publication.
     *
     * A stale or modified caller copy cannot confirm a different publication.
     */
    async confirmOutbox(item: FriendOutboxItem, outcome: FriendOutboxOutcome): Promise<boolean> {
        if (outcome !== "accepted" && outcome !== "duplicate") {
            throw new Error("Friend outbox requires an accepted or duplicate outcome");
        }
        return this.#store.transaction(async (transaction) => {
            const key = this.#outboxKey(item.id);
            const persisted = await transaction.get(key);
            if (persisted === undefined) {
                return false;
            }
            if (!matchesFriendOutboxItem(item, persisted)) {
                throw new Error("Friend outbox item does not exactly match persisted publication");
            }
            await transaction.delete(key);
            return true;
        });
    }

    /**
     * End friendship and atomically retire or enqueue the state-specific
     * terminal publication. Repeated calls in ended state are idempotent.
     */
    async end(peer: IdentityPublicKey, now: number = Date.now()): Promise<FriendRecord> {
        validateTime(now);
        return this.#store.transaction(async (transaction) => {
            const key = this.#recordKey(peer);
            const existing = await this.#read(transaction, key);
            if (existing === undefined) {
                throw new Error("Friend not found");
            }
            if (now < existing.updatedAt) {
                throw new Error("Friend state must not move backwards in time");
            }
            if (existing.status === "ended") {
                return copyFriendRecord(existing);
            }
            if (existing.status === "pending-outgoing") {
                await this.#setOutgoingTracker(
                    transaction,
                    existing.identity,
                    existing.requestId,
                    "retired",
                );
                await this.#insertEndIntent(transaction, existing, now);
            } else if (existing.status === "pending-incoming") {
                if (existing.peerResponseAddress === undefined) {
                    throw new Error("Pending incoming friend is missing its response destination");
                }
                const responseId = this.#newId();
                const envelope = createFriendResponse(this.#owner, existing.identity, {
                    id: responseId,
                    requestId: existing.requestId,
                    decision: "rejected",
                });
                await this.#insertOutbox(transaction, {
                    id: responseId,
                    kind: "response",
                    peer: { publicKey: existing.identity.publicKey.slice() },
                    destination: existing.peerResponseAddress,
                    envelope,
                    createdAt: now,
                });
            } else {
                await this.#insertEndIntent(transaction, existing, now);
                await this.#deletePeerExchangeOutbox(transaction, existing.identity);
            }
            const ended: FriendRecord = { ...existing, status: "ended", updatedAt: now };
            await transaction.set(key, encodeFriendRecord(ended));
            return copyFriendRecord(ended);
        });
    }

    /** Find durable state by its one public identity key. */
    async get(peer: IdentityPublicKey): Promise<FriendRecord | undefined> {
        const bytes = await this.#store.get(this.#recordKey(peer));
        if (bytes === undefined) {
            return undefined;
        }
        try {
            return copyFriendRecord(decodeFriendRecord(bytes));
        } finally {
            zeroBytes(bytes);
        }
    }

    /** List every lifecycle state in stable public-key order. */
    async list(): Promise<readonly FriendRecord[]> {
        const records = await this.#store.list(this.#recordsPrefix);
        try {
            return [...records]
                .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
                .map(([, value]) => copyFriendRecord(decodeFriendRecord(value)));
        } finally {
            for (const value of records.values()) {
                zeroBytes(value);
            }
        }
    }

    #recordKey(peer: IdentityPublicKey): string {
        return `${this.#recordsPrefix}${identityId(peer)}`;
    }

    #outboxKey(id: string): string {
        return `${this.#outboxPrefix}${id}`;
    }

    #outgoingKey(peer: IdentityPublicKey, id: string): string {
        return `${this.#outgoingPrefix}${identityId(peer)}/${id}`;
    }

    #newId(): string {
        const id = this.#generateId();
        validateExchangeId(id);
        return id;
    }

    async #read(transaction: StoreTransaction, key: string): Promise<FriendRecord | undefined> {
        const bytes = await transaction.get(key);
        if (bytes === undefined) {
            return undefined;
        }
        try {
            return decodeFriendRecord(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #insertOutbox(transaction: StoreTransaction, item: FriendOutboxItem): Promise<void> {
        const key = this.#outboxKey(item.id);
        const reservationKey = `${this.#outboxIdsPrefix}${item.id}`;
        if (
            (await transaction.get(key)) !== undefined ||
            (await transaction.get(reservationKey)) !== undefined
        ) {
            throw new FriendOutboxIdCollisionError();
        }
        await transaction.set(reservationKey, utf8Encode(item.kind));
        await transaction.set(key, encodeFriendOutboxItem(item));
    }

    async #insertEndIntent(
        transaction: StoreTransaction,
        existing: FriendRecord,
        now: number,
    ): Promise<void> {
        const intent: FriendControlIntentOutboxItem = {
            id: this.#newId(),
            kind: "control-intent",
            peer: { publicKey: existing.identity.publicKey.slice() },
            destination: "friend-channel",
            intent: {
                type: "friendship-ended",
                requestId: existing.requestId,
            },
            createdAt: now,
        };
        await this.#insertOutbox(transaction, intent);
    }

    async #deleteRequestOutbox(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
        requestId: string,
    ): Promise<void> {
        const key = this.#outboxKey(requestId);
        const bytes = await transaction.get(key);
        if (bytes === undefined) {
            return;
        }
        const item = decodeFriendOutboxItem(bytes);
        try {
            if (item.kind !== "request" || !equalBytes(item.peer.publicKey, peer.publicKey)) {
                throw new FriendOutboxIdCollisionError();
            }
            await transaction.delete(key);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #deletePeerExchangeOutbox(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
    ): Promise<void> {
        const items = await transaction.list(this.#outboxPrefix);
        try {
            for (const [key, bytes] of items) {
                const item = decodeFriendOutboxItem(bytes);
                if (
                    item.kind !== "control-intent" &&
                    equalBytes(item.peer.publicKey, peer.publicKey)
                ) {
                    await transaction.delete(key);
                }
            }
        } finally {
            for (const value of items.values()) {
                zeroBytes(value);
            }
        }
    }

    async #insertOutgoingTracker(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
        requestId: string,
        previousRequestId: string | null,
    ): Promise<void> {
        const key = this.#outgoingKey(peer, requestId);
        if ((await transaction.get(key)) !== undefined) {
            throw new FriendExchangeIdCollisionError();
        }
        await transaction.set(
            key,
            encodeOutgoingRequestTracker({
                state: "pending",
                previousRequestId,
            }),
        );
    }

    async #setOutgoingTracker(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
        requestId: string,
        state: "pending" | "retired" | "answered",
    ): Promise<void> {
        const key = this.#outgoingKey(peer, requestId);
        const existing = await this.#getOutgoingTracker(transaction, peer, requestId);
        if (existing?.state !== "pending") {
            throw new Error("Outgoing friend request tracker is not pending");
        }
        await transaction.set(
            key,
            encodeOutgoingRequestTracker({
                ...existing,
                state,
            }),
        );
    }

    async #getOutgoingTracker(
        transaction: StoreTransaction,
        peer: IdentityPublicKey,
        requestId: string,
    ): Promise<OutgoingRequestTracker | undefined> {
        const bytes = await transaction.get(this.#outgoingKey(peer, requestId));
        if (bytes === undefined) {
            return undefined;
        }
        try {
            return decodeOutgoingRequestTracker(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #checkReplay(
        transaction: StoreTransaction,
        kind: "request" | "response",
        peer: IdentityPublicKey,
        id: string,
        fingerprint: Uint8Array,
    ): Promise<"opened" | "duplicate"> {
        const key = `${this.#replayPrefix}${kind}/${identityId(peer)}/${id}`;
        const existing = await transaction.get(key);
        if (existing !== undefined) {
            if (!equalBytes(existing, fingerprint)) {
                throw new FriendExchangeIdCollisionError();
            }
            return "duplicate";
        }
        await transaction.set(key, fingerprint);
        return "opened";
    }
}
