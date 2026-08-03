import type { IdentityPublicKeys } from "../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import { encodeBase64Url, equalBytes } from "../utils/index.js";
import { decodeFriendRecord, encodeFriendRecord } from "./impl/friendCodec.js";
import type { FriendQuery, FriendRecord, OpenedProfile } from "./types.js";

function friendIdentityId(identity: Pick<IdentityPublicKeys, "signingKey">): string {
    if (identity.signingKey.length !== 32) {
        throw new Error("Friend signing key must be 32 bytes");
    }
    return encodeBase64Url(identity.signingKey);
}

function validateTime(now: number): void {
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Friend time must be a non-negative safe integer");
    }
}

function copyFriend(record: FriendRecord): FriendRecord {
    return {
        identity: {
            signingKey: record.identity.signingKey.slice(),
            encryptionKey: record.identity.encryptionKey.slice(),
        },
        profile: {
            name: record.profile.name,
            ...(record.profile.avatar === undefined
                ? {}
                : { avatar: record.profile.avatar.slice() }),
            ...(record.profile.metadata === undefined
                ? {}
                : { metadata: { ...record.profile.metadata } }),
        },
        addedAt: record.addedAt,
        updatedAt: record.updatedAt,
        status: record.status,
        statusUpdatedAt: record.statusUpdatedAt,
    };
}

/** Durable friend collection whose authenticated identity records are never deleted. */
export class FriendBook {
    readonly #store: MurmurStore;
    readonly #prefix: string;

    constructor(owner: IdentityPublicKeys, store: MurmurStore) {
        if (owner.signingKey.length !== 32 || owner.encryptionKey.length !== 32) {
            throw new Error("FriendBook owner keys must be 32 bytes");
        }
        this.#store = store;
        // Reuse the ContactBook namespace so existing durable contacts upgrade in place.
        this.#prefix = `identity/${friendIdentityId(owner)}/contacts/`;
    }

    /** Insert/update an authenticated profile, reactivating a removed friend. */
    async save(openedProfile: OpenedProfile, now: number = Date.now()): Promise<FriendRecord> {
        return this.#store.transaction(async (transaction) =>
            this.saveInTransaction(transaction, openedProfile, now),
        );
    }

    /** Save a friend inside a caller-owned transaction. */
    async saveInTransaction(
        transaction: StoreTransaction,
        openedProfile: OpenedProfile,
        now: number = Date.now(),
    ): Promise<FriendRecord> {
        if (
            openedProfile.identity.signingKey.length !== 32 ||
            openedProfile.identity.encryptionKey.length !== 32
        ) {
            throw new Error("Friend identity keys must be 32 bytes");
        }
        validateTime(now);
        const key = `${this.#prefix}${friendIdentityId(openedProfile.identity)}`;
        const existingBytes = await transaction.get(key);
        const existing =
            existingBytes === undefined ? undefined : decodeFriendRecord(existingBytes);
        if (
            existing !== undefined &&
            (!equalBytes(existing.identity.signingKey, openedProfile.identity.signingKey) ||
                !equalBytes(existing.identity.encryptionKey, openedProfile.identity.encryptionKey))
        ) {
            throw new Error("Friend identity key collision");
        }
        if (
            existing !== undefined &&
            (now < existing.updatedAt || now < existing.statusUpdatedAt)
        ) {
            throw new Error("Friend updates must not move backwards in time");
        }
        const record: FriendRecord = {
            identity: {
                signingKey: openedProfile.identity.signingKey.slice(),
                encryptionKey: openedProfile.identity.encryptionKey.slice(),
            },
            profile: {
                name: openedProfile.profile.name,
                ...(openedProfile.profile.avatar === undefined
                    ? {}
                    : { avatar: openedProfile.profile.avatar.slice() }),
                ...(openedProfile.profile.metadata === undefined
                    ? {}
                    : { metadata: { ...openedProfile.profile.metadata } }),
            },
            addedAt: existing?.addedAt ?? now,
            updatedAt: now,
            status: "active",
            statusUpdatedAt:
                existing === undefined || existing.status === "removed"
                    ? now
                    : existing.statusUpdatedAt,
        };
        await transaction.set(key, encodeFriendRecord(record));
        return copyFriend(record);
    }

    /** Mark a friend removed while retaining its authenticated identity and profile forever. */
    async remove(
        identity: Pick<IdentityPublicKeys, "signingKey">,
        now: number = Date.now(),
    ): Promise<FriendRecord> {
        return this.#store.transaction(async (transaction) => {
            validateTime(now);
            const key = `${this.#prefix}${friendIdentityId(identity)}`;
            const bytes = await transaction.get(key);
            if (bytes === undefined) {
                throw new Error("Friend not found");
            }
            const existing = decodeFriendRecord(bytes);
            if (now < existing.updatedAt || now < existing.statusUpdatedAt) {
                throw new Error("Friend updates must not move backwards in time");
            }
            if (existing.status === "removed") {
                return copyFriend(existing);
            }
            const removed: FriendRecord = {
                ...existing,
                status: "removed",
                statusUpdatedAt: now,
            };
            await transaction.set(key, encodeFriendRecord(removed));
            return copyFriend(removed);
        });
    }

    /** Find a friend by signing identity. Removed records are hidden by default. */
    async get(
        identity: Pick<IdentityPublicKeys, "signingKey">,
        query: FriendQuery = {},
    ): Promise<FriendRecord | undefined> {
        const value = await this.#store.get(`${this.#prefix}${friendIdentityId(identity)}`);
        if (value === undefined) {
            return undefined;
        }
        const friend = decodeFriendRecord(value);
        return friend.status === "removed" && query.includeRemoved !== true
            ? undefined
            : copyFriend(friend);
    }

    /** List friends in stable identity order. Removed records are hidden by default. */
    async list(query: FriendQuery = {}): Promise<readonly FriendRecord[]> {
        const values = await this.#store.list(this.#prefix);
        return [...values]
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([, value]) => decodeFriendRecord(value))
            .filter((friend) => query.includeRemoved === true || friend.status === "active")
            .map(copyFriend);
    }
}
