import type { IdentityKeyPair, IdentityPublicKey } from "../crypto/index.js";
import { randomBytes, validateIdentityKeyPair } from "../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import { encodeBase64Url, equalBytes, zeroBytes } from "../utils/index.js";
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
import type {
    CreateFriendRequestOptions,
    CreateFriendResponseOptions,
    FriendAcceptance,
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

/** Durable, transactional request/response friendship lifecycle and outbox. */
export class FriendBook {
    readonly #owner: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #recordsPrefix: string;
    readonly #replayPrefix: string;
    readonly #outboxPrefix: string;

    constructor(owner: IdentityKeyPair, store: MurmurStore) {
        validateIdentityKeyPair(owner);
        const ownerId = identityId(owner);
        this.#owner = owner;
        this.#store = store;
        this.#recordsPrefix = `identity/v1/${ownerId}/friends/`;
        this.#replayPrefix = `identity/v1/${ownerId}/friend-exchange-replay/`;
        this.#outboxPrefix = `identity/v1/${ownerId}/friend-outbox/`;
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
        const requestId = newExchangeId();
        const envelope = createFriendRequest(this.#owner, recipient, {
            id: requestId,
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
        await this.#store.transaction(async (transaction) => {
            const key = this.#recordKey(recipient);
            const existing = await this.#read(transaction, key);
            if (existing !== undefined && existing.status !== "ended") {
                throw new Error(`Cannot request friendship from ${existing.status} state`);
            }
            if (existing !== undefined && now < existing.updatedAt) {
                throw new Error("Friend state must not move backwards in time");
            }
            const record: FriendRecord = {
                identity: { publicKey: recipient.publicKey.slice() },
                requester: { publicKey: this.#owner.publicKey.slice() },
                status: "pending-outgoing",
                requestId,
                localResponseAddress: options.responseAddress,
                createdAt: existing?.createdAt ?? now,
                updatedAt: now,
            };
            await transaction.set(key, encodeFriendRecord(record));
            await transaction.set(this.#outboxKey(outbox.id), encodeFriendOutboxItem(outbox));
        });
        return copyFriendOutboxItem(outbox);
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
                if (replay === "duplicate") {
                    if (existing === undefined) {
                        throw new Error("Friend request replay exists without durable state");
                    }
                    return { status: "duplicate", record: copyFriendRecord(existing) };
                }
                if (existing?.status === "active") {
                    return { status: "superseded", record: copyFriendRecord(existing) };
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
                    await transaction.delete(this.#outboxKey(existing.requestId));
                } else if (existing !== undefined && existing.status !== "ended") {
                    throw new Error(
                        `Cannot receive friendship request from ${existing.status} state`,
                    );
                }
                const record: FriendRecord = {
                    identity: { publicKey: opened.sender.publicKey.slice() },
                    requester: { publicKey: opened.sender.publicKey.slice() },
                    status: "pending-incoming",
                    requestId: opened.id,
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
            const responseId = newExchangeId();
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
            await transaction.set(this.#outboxKey(outbox.id), encodeFriendOutboxItem(outbox));
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
                if (replay === "duplicate") {
                    if (existing === undefined) {
                        throw new Error("Friend response replay exists without durable state");
                    }
                    return { status: "duplicate", record: copyFriendRecord(existing) };
                }
                if (
                    existing?.status !== "pending-outgoing" ||
                    existing.requestId !== opened.requestId
                ) {
                    throw new Error("Friend response does not match pending outgoing state");
                }
                if (now < existing.updatedAt) {
                    throw new Error("Friend state must not move backwards in time");
                }
                const record: FriendRecord =
                    opened.decision === "accepted"
                        ? {
                              ...existing,
                              status: "active",
                              profile: opened.profile,
                              peerResponseAddress: opened.responseAddress,
                              ...(opened.privateData === undefined
                                  ? {}
                                  : { privateData: opened.privateData.slice() }),
                              updatedAt: now,
                          }
                        : { ...existing, status: "ended", updatedAt: now };
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

    /** End pending or active friendship while retaining its durable record. */
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
            const ended: FriendRecord = { ...existing, status: "ended", updatedAt: now };
            await transaction.set(key, encodeFriendRecord(ended));
            return copyFriendRecord(ended);
        });
    }

    /** Find durable state by its one public identity key. */
    async get(peer: IdentityPublicKey): Promise<FriendRecord | undefined> {
        const bytes = await this.#store.get(this.#recordKey(peer));
        return bytes === undefined ? undefined : copyFriendRecord(decodeFriendRecord(bytes));
    }

    /** List every lifecycle state in stable public-key order. */
    async list(): Promise<readonly FriendRecord[]> {
        const records = await this.#store.list(this.#recordsPrefix);
        return [...records]
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([, value]) => copyFriendRecord(decodeFriendRecord(value)));
    }

    #recordKey(peer: IdentityPublicKey): string {
        return `${this.#recordsPrefix}${identityId(peer)}`;
    }

    #outboxKey(id: string): string {
        return `${this.#outboxPrefix}${id}`;
    }

    async #read(transaction: StoreTransaction, key: string): Promise<FriendRecord | undefined> {
        const bytes = await transaction.get(key);
        return bytes === undefined ? undefined : decodeFriendRecord(bytes);
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
