import type { IdentityPublicKeys } from "../crypto/index.js";
import type { MurmurStore } from "../storage/index.js";
import { encodeBase64Url } from "../utils/index.js";
import { decodeContact, encodeContact } from "./impl/contactCodec.js";
import type { Contact, OpenedProfile } from "./types.js";

function contactIdentityId(identity: Pick<IdentityPublicKeys, "signingKey">): string {
    if (identity.signingKey.length !== 32) {
        throw new Error("Contact signing key must be 32 bytes");
    }
    return encodeBase64Url(identity.signingKey);
}

/** Durable local contact collection scoped to one owner identity. */
export class ContactBook {
    readonly #store: MurmurStore;
    readonly #prefix: string;

    constructor(owner: IdentityPublicKeys, store: MurmurStore) {
        if (owner.signingKey.length !== 32 || owner.encryptionKey.length !== 32) {
            throw new Error("ContactBook owner keys must be 32 bytes");
        }
        this.#store = store;
        this.#prefix = `identity/${contactIdentityId(owner)}/contacts/`;
    }

    /** Insert or update an authenticated opened profile. */
    async save(openedProfile: OpenedProfile, now: number = Date.now()): Promise<Contact> {
        if (openedProfile.identity.encryptionKey.length !== 32) {
            throw new Error("Contact encryption key must be 32 bytes");
        }
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Contact time must be a non-negative safe integer");
        }
        const key = `${this.#prefix}${contactIdentityId(openedProfile.identity)}`;
        return this.#store.transaction(async (transaction) => {
            const existing = await transaction.get(key);
            const existingContact = existing === undefined ? undefined : decodeContact(existing);
            if (existingContact !== undefined && now < existingContact.updatedAt) {
                throw new Error("Contact updates must not move backwards in time");
            }
            const contact: Contact = {
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
                addedAt: existingContact?.addedAt ?? now,
                updatedAt: now,
            };
            await transaction.set(key, encodeContact(contact));
            return contact;
        });
    }

    /** Find a contact by public signing identity. */
    async get(identity: Pick<IdentityPublicKeys, "signingKey">): Promise<Contact | undefined> {
        const value = await this.#store.get(`${this.#prefix}${contactIdentityId(identity)}`);
        return value === undefined ? undefined : decodeContact(value);
    }

    /** List contacts in stable identity order. */
    async list(): Promise<readonly Contact[]> {
        const values = await this.#store.list(this.#prefix);
        return [...values]
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([, value]) => decodeContact(value));
    }

    /** Remove one local contact. */
    async remove(identity: Pick<IdentityPublicKeys, "signingKey">): Promise<void> {
        await this.#store.delete(`${this.#prefix}${contactIdentityId(identity)}`);
    }
}
