import type { IdentityPublicKeys } from "../crypto/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import { FriendBook } from "./friendBook.js";
import type { Contact, OpenedProfile } from "./types.js";

/** Compatibility view over FriendBook. New code should use FriendBook directly. */
export class ContactBook {
    readonly #friends: FriendBook;

    constructor(owner: IdentityPublicKeys, store: MurmurStore) {
        this.#friends = new FriendBook(owner, store);
    }

    /** Insert or update an authenticated opened profile. */
    async save(openedProfile: OpenedProfile, now: number = Date.now()): Promise<Contact> {
        return this.#friends.save(openedProfile, now);
    }

    /**
     * Insert or update a profile inside a caller-owned atomic transaction.
     *
     * This is used when contact state and a relay topic cursor must commit
     * together.
     */
    async saveInTransaction(
        transaction: StoreTransaction,
        openedProfile: OpenedProfile,
        now: number = Date.now(),
    ): Promise<Contact> {
        return this.#friends.saveInTransaction(transaction, openedProfile, now);
    }

    /** Find a contact by public signing identity. */
    async get(identity: Pick<IdentityPublicKeys, "signingKey">): Promise<Contact | undefined> {
        return this.#friends.get(identity);
    }

    /** List contacts in stable identity order. */
    async list(): Promise<readonly Contact[]> {
        return this.#friends.list();
    }

    /** Remove one local contact. */
    async remove(identity: Pick<IdentityPublicKeys, "signingKey">): Promise<void> {
        if ((await this.#friends.get(identity, { includeRemoved: true })) === undefined) {
            return;
        }
        await this.#friends.remove(identity);
    }
}
