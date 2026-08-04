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
import type {
    FriendAcceptance,
    FriendRecord,
    FriendRequestEnvelope,
    FriendResponseDecision,
    FriendResponseEnvelope,
    IdentityProfile,
    PersistFriendRequest,
    PersistFriendResponse,
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

/** Authenticated reuse of one exchange ID for different content. */
export class FriendExchangeIdCollisionError extends Error {
    constructor() {
        super("Authenticated friend exchange ID collision");
        this.name = "FriendExchangeIdCollisionError";
    }
}

/** Durable, transactional request/response friendship lifecycle. */
export class FriendBook {
    readonly #owner: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #recordsPrefix: string;
    readonly #replayPrefix: string;

    constructor(owner: IdentityKeyPair, store: MurmurStore) {
        validateIdentityKeyPair(owner);
        const ownerId = identityId(owner);
        this.#owner = owner;
        this.#store = store;
        this.#recordsPrefix = `identity/v1/${ownerId}/friends/`;
        this.#replayPrefix = `identity/v1/${ownerId}/friend-exchange-replay/`;
    }

    /**
     * Create and persist a pending outgoing request.
     *
     * `persist` may atomically place the envelope in an application outbox.
     */
    async createRequest(
        recipient: IdentityPublicKey,
        profile: IdentityProfile,
        responseAddress: string,
        privateData?: Uint8Array,
        now: number = Date.now(),
        persist?: PersistFriendRequest,
    ): Promise<FriendRequestEnvelope> {
        validateTime(now);
        if (equalBytes(this.#owner.publicKey, recipient.publicKey)) {
            throw new Error("An identity cannot request friendship with itself");
        }
        const requestId = newExchangeId();
        const envelope = createFriendRequest(this.#owner, recipient, {
            id: requestId,
            responseAddress,
            profile,
            ...(privateData === undefined ? {} : { privateData }),
        });
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
                status: "pending-outgoing",
                requestId,
                createdAt: existing?.createdAt ?? now,
                updatedAt: now,
            };
            await transaction.set(key, encodeFriendRecord(record));
            await persist?.(transaction, envelope);
        });
        return envelope;
    }

    /** Open an inbound request and atomically persist pending incoming state. */
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
                if (existing !== undefined && existing.status !== "ended") {
                    throw new Error(
                        `Cannot receive friendship request from ${existing.status} state`,
                    );
                }
                const record: FriendRecord = {
                    identity: { publicKey: opened.sender.publicKey.slice() },
                    status: "pending-incoming",
                    requestId: opened.id,
                    profile: opened.profile,
                    peerResponseAddress: opened.responseAddress,
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
            if ("privateData" in opened) {
                opened.privateData?.fill(0);
            }
        }
    }

    /**
     * Accept or reject a pending inbound request and prepare its response.
     *
     * `persist` may atomically place the response in an application outbox.
     */
    async respond(
        peer: IdentityPublicKey,
        decision: FriendResponseDecision,
        profile?: IdentityProfile,
        responseAddress?: string,
        privateData?: Uint8Array,
        now: number = Date.now(),
        persist?: PersistFriendResponse,
    ): Promise<PreparedFriendResponse> {
        validateTime(now);
        if (
            decision === "rejected" &&
            (profile !== undefined || responseAddress !== undefined || privateData !== undefined)
        ) {
            throw new Error("Rejected response must not carry profile or private data");
        }
        return this.#store.transaction(async (transaction) => {
            const key = this.#recordKey(peer);
            const existing = await this.#read(transaction, key);
            if (existing?.status !== "pending-incoming") {
                throw new Error("Friend response requires pending incoming state");
            }
            if (now < existing.updatedAt) {
                throw new Error("Friend state must not move backwards in time");
            }
            const responseId = newExchangeId();
            const envelope =
                decision === "accepted"
                    ? createFriendResponse(this.#owner, existing.identity, {
                          id: responseId,
                          requestId: existing.requestId,
                          decision,
                          profile:
                              profile ??
                              (() => {
                                  throw new Error("Accepted response requires a profile");
                              })(),
                          responseAddress:
                              responseAddress ??
                              (() => {
                                  throw new Error("Accepted response requires a response address");
                              })(),
                          ...(privateData === undefined ? {} : { privateData }),
                      })
                    : createFriendResponse(this.#owner, existing.identity, {
                          id: responseId,
                          requestId: existing.requestId,
                          decision,
                      });
            const record: FriendRecord =
                decision === "accepted"
                    ? {
                          ...existing,
                          status: "active",
                          updatedAt: now,
                      }
                    : {
                          ...existing,
                          status: "ended",
                          updatedAt: now,
                      };
            await transaction.set(key, encodeFriendRecord(record));
            await persist?.(transaction, envelope);
            return { envelope, record: copyFriendRecord(record) };
        });
    }

    /** Open a response and atomically establish or reject friendship. */
    async receiveResponse(
        envelope: FriendResponseEnvelope,
        now: number = Date.now(),
    ): Promise<FriendAcceptance> {
        validateTime(now);
        const opened = openFriendResponse(this.#owner, envelope);
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
                        : {
                              ...existing,
                              status: "ended",
                              updatedAt: now,
                          };
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
