import type { MurmurStore, StoreTransaction } from "../../storage/index.js";
import type { MurmurUpdate } from "../../sessions/types.js";
import { equalBytes, zeroBytes } from "../../utils/index.js";
import type {
    MurmurContact,
    MurmurContactAdded,
    MurmurContactProfile,
    MurmurContactRemoved,
    MurmurContactRequested,
} from "../types.js";
import {
    decodeContactPacket,
    encodeContactPacket,
    validateContactProfile,
} from "./contactCodec.js";
import {
    CONTACT_EVENT_PREFIX,
    CONTACT_HANDSHAKE_PREFIX,
    CONTACT_IDENTITY_PREFIX,
    contactEventKey,
    contactHandshakeKey,
    contactIdentityKey,
    contactSessionKey,
    decodeContactEventRecord,
    decodeContactHandshakeRecord,
    decodeContactRecord,
    encodeContactEventRecord,
    encodeContactHandshakeRecord,
    encodeContactRecord,
    type ContactHandshakeRecord,
    type ContactRecord,
} from "./contactRecords.js";

const CONTACT_SCAN_LIMIT = 256;

/** Internal immutable snapshot of pending contact lifecycle callbacks. */
export interface PreparedContactEvents {
    readonly keys: readonly string[];
    readonly requested: readonly MurmurContactRequested[];
    readonly added: readonly MurmurContactAdded[];
    readonly removed: readonly MurmurContactRemoved[];
}

async function setAndZero(
    transaction: StoreTransaction,
    key: string,
    value: Uint8Array,
): Promise<void> {
    try {
        await transaction.set(key, value);
    } finally {
        zeroBytes(value);
    }
}

function publicContact(record: ContactRecord): MurmurContact {
    return Object.freeze({
        identity: record.identity.slice(),
        sessionId: record.sessionId.slice(),
        localProfile: record.localProfile,
        profile: record.profile,
        status: record.status,
    });
}

function validatePeer(identity: Uint8Array, self: Uint8Array): void {
    if (identity.length !== 32 || equalBytes(identity, self)) {
        throw new Error("Invalid contact identity");
    }
}

/** Internal durable contact state coordinator. */
export class ContactEngine {
    readonly #store: MurmurStore;
    readonly #identity: Uint8Array;
    readonly #now: () => number;

    constructor(store: MurmurStore, identity: Uint8Array, now: () => number) {
        this.#store = store;
        this.#identity = identity.slice();
        this.#now = now;
    }

    async recordOutgoing(
        sessionId: Uint8Array,
        identity: Uint8Array,
        profile: MurmurContactProfile,
    ): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.recordOutgoingInTransaction(transaction, sessionId, identity, profile),
        );
    }

    /** Persist an outgoing handshake inside a caller-owned Murmur transaction. */
    async recordOutgoingInTransaction(
        transaction: StoreTransaction,
        sessionId: Uint8Array,
        identity: Uint8Array,
        profile: MurmurContactProfile,
    ): Promise<void> {
        validatePeer(identity, this.#identity);
        const localProfile = validateContactProfile(profile);
        const existingContact = await transaction.get(contactIdentityKey(identity));
        if (existingContact !== undefined) {
            zeroBytes(existingContact);
            throw new Error("Identity is already a contact");
        }
        const existing = await transaction.get(contactHandshakeKey(sessionId));
        if (existing !== undefined) {
            zeroBytes(existing);
            throw new Error("Contact handshake already exists");
        }
        await setAndZero(
            transaction,
            contactHandshakeKey(sessionId),
            encodeContactHandshakeRecord({
                version: 1,
                direction: "outgoing",
                identity,
                sessionId,
                localProfile,
                localHelloProcessed: false,
                remoteHelloProcessed: false,
                createdAt: this.#now(),
            }),
        );
    }

    async outgoingWithoutHello(): Promise<readonly ContactHandshakeRecord[]> {
        const page = await this.#store.scan(CONTACT_HANDSHAKE_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const result: ContactHandshakeRecord[] = [];
        for (const bytes of page.values()) {
            try {
                const record = decodeContactHandshakeRecord(bytes);
                if (
                    record.localProfile !== undefined &&
                    record.localHelloDeliveryId === undefined
                ) {
                    result.push(record);
                } else {
                    zeroBytes(record.identity);
                    zeroBytes(record.sessionId);
                }
            } finally {
                zeroBytes(bytes);
            }
        }
        return result;
    }

    async recordLocalHello(sessionId: Uint8Array, deliveryId: string): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.recordLocalHelloInTransaction(transaction, sessionId, deliveryId),
        );
    }

    /** Persist one local hello ID inside a caller-owned Murmur transaction. */
    async recordLocalHelloInTransaction(
        transaction: StoreTransaction,
        sessionId: Uint8Array,
        deliveryId: string,
    ): Promise<void> {
        const bytes = await transaction.get(contactHandshakeKey(sessionId));
        if (bytes === undefined) throw new Error("Unknown contact handshake");
        const record = decodeContactHandshakeRecord(bytes);
        try {
            if (record.localProfile === undefined) {
                throw new Error("Contact handshake has no local profile");
            }
            await setAndZero(
                transaction,
                contactHandshakeKey(sessionId),
                encodeContactHandshakeRecord({
                    ...record,
                    localHelloDeliveryId: deliveryId,
                }),
            );
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async process(update: MurmurUpdate): Promise<"remove" | undefined> {
        const packet = decodeContactPacket(update.bytes);
        let remove = false;
        await this.#store.transaction(async (transaction) => {
            const processedEvent = await transaction.get(contactEventKey(update.id));
            if (processedEvent !== undefined) {
                try {
                    remove = decodeContactEventRecord(processedEvent).type === "removed";
                    return;
                } finally {
                    zeroBytes(processedEvent);
                }
            }
            const handshakeBytes = await transaction.get(contactHandshakeKey(update.sessionId));
            const contactBytes = await transaction.get(contactSessionKey(update.sessionId));
            try {
                const handshake =
                    handshakeBytes === undefined
                        ? undefined
                        : decodeContactHandshakeRecord(handshakeBytes);
                const contact =
                    contactBytes === undefined ? undefined : decodeContactRecord(contactBytes);
                try {
                    if (packet.type === "remove") {
                        if (
                            contact === undefined ||
                            (!equalBytes(update.sender, contact.identity) &&
                                !equalBytes(update.sender, this.#identity))
                        ) {
                            throw new Error("Invalid contact removal");
                        }
                        await this.#deleteContact(transaction, contact);
                        await setAndZero(
                            transaction,
                            contactEventKey(update.id),
                            encodeContactEventRecord({
                                version: 1,
                                type: "removed",
                                id: update.id,
                                identity: contact.identity,
                                sessionId: contact.sessionId,
                            }),
                        );
                        remove = true;
                        return;
                    }
                    if (handshake === undefined) {
                        if (
                            contact !== undefined &&
                            (equalBytes(update.sender, contact.identity) ||
                                equalBytes(update.sender, this.#identity))
                        ) {
                            return;
                        }
                        if (equalBytes(update.sender, this.#identity)) {
                            throw new Error("Unexpected local contact hello");
                        }
                        validatePeer(update.sender, this.#identity);
                        const existingIdentity = await transaction.get(
                            contactIdentityKey(update.sender),
                        );
                        if (existingIdentity !== undefined) {
                            zeroBytes(existingIdentity);
                            throw new Error("Identity is already a contact");
                        }
                        const incoming: ContactHandshakeRecord = {
                            version: 1,
                            direction: "incoming",
                            identity: update.sender,
                            sessionId: update.sessionId,
                            remoteProfile: packet.profile,
                            localHelloProcessed: false,
                            remoteHelloProcessed: true,
                            requestEventId: update.id,
                            createdAt: this.#now(),
                        };
                        await setAndZero(
                            transaction,
                            contactHandshakeKey(update.sessionId),
                            encodeContactHandshakeRecord(incoming),
                        );
                        await setAndZero(
                            transaction,
                            contactEventKey(update.id),
                            encodeContactEventRecord({
                                version: 1,
                                type: "requested",
                                id: update.id,
                                identity: update.sender,
                                sessionId: update.sessionId,
                                profile: packet.profile,
                            }),
                        );
                        return;
                    }
                    const fromSelf = equalBytes(update.sender, this.#identity);
                    if (!fromSelf && !equalBytes(update.sender, handshake.identity)) {
                        throw new Error("Contact hello sender does not match the handshake");
                    }
                    if (!fromSelf && handshake.remoteProfile !== undefined) {
                        const expected = encodeContactPacket({
                            version: 1,
                            type: "hello",
                            profile: handshake.remoteProfile,
                        });
                        try {
                            if (!equalBytes(expected, update.bytes)) {
                                throw new Error("Contact profile changed during the handshake");
                            }
                        } finally {
                            zeroBytes(expected);
                        }
                    }
                    const next: ContactHandshakeRecord = {
                        ...handshake,
                        ...(fromSelf ? {} : { remoteProfile: packet.profile }),
                        localHelloProcessed: handshake.localHelloProcessed || fromSelf,
                        remoteHelloProcessed: handshake.remoteHelloProcessed || !fromSelf,
                    };
                    if (
                        next.localHelloProcessed &&
                        next.remoteHelloProcessed &&
                        next.localProfile !== undefined &&
                        next.remoteProfile !== undefined
                    ) {
                        const confirmed: ContactRecord = {
                            version: 1,
                            identity: next.identity,
                            sessionId: next.sessionId,
                            localProfile: next.localProfile,
                            profile: next.remoteProfile,
                            status: "active",
                            confirmedAt: this.#now(),
                        };
                        await setAndZero(
                            transaction,
                            contactIdentityKey(confirmed.identity),
                            encodeContactRecord(confirmed),
                        );
                        await setAndZero(
                            transaction,
                            contactSessionKey(confirmed.sessionId),
                            encodeContactRecord(confirmed),
                        );
                        await transaction.delete(contactHandshakeKey(next.sessionId));
                        await setAndZero(
                            transaction,
                            contactEventKey(update.id),
                            encodeContactEventRecord({
                                version: 1,
                                type: "added",
                                id: update.id,
                                identity: confirmed.identity,
                                sessionId: confirmed.sessionId,
                                localProfile: confirmed.localProfile,
                                profile: confirmed.profile,
                            }),
                        );
                    } else {
                        await setAndZero(
                            transaction,
                            contactHandshakeKey(next.sessionId),
                            encodeContactHandshakeRecord(next),
                        );
                    }
                } finally {
                    if (handshake !== undefined) {
                        zeroBytes(handshake.identity);
                        zeroBytes(handshake.sessionId);
                    }
                    if (contact !== undefined) {
                        zeroBytes(contact.identity);
                        zeroBytes(contact.sessionId);
                    }
                }
            } finally {
                if (handshakeBytes !== undefined) zeroBytes(handshakeBytes);
                if (contactBytes !== undefined) zeroBytes(contactBytes);
            }
        });
        return remove ? "remove" : undefined;
    }

    async accept(sessionId: Uint8Array, profile: MurmurContactProfile): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.acceptInTransaction(transaction, sessionId, profile),
        );
    }

    /** Persist an accepted profile and optional hello ID in a Murmur transaction. */
    async acceptInTransaction(
        transaction: StoreTransaction,
        sessionId: Uint8Array,
        profile: MurmurContactProfile,
        deliveryId?: string,
    ): Promise<void> {
        const localProfile = validateContactProfile(profile);
        const bytes = await transaction.get(contactHandshakeKey(sessionId));
        if (bytes === undefined) throw new Error("Unknown contact request");
        const record = decodeContactHandshakeRecord(bytes);
        try {
            if (record.direction !== "incoming" || record.remoteProfile === undefined) {
                throw new Error("Contact request cannot be accepted");
            }
            await setAndZero(
                transaction,
                contactHandshakeKey(sessionId),
                encodeContactHandshakeRecord({
                    ...record,
                    localProfile,
                    ...(deliveryId === undefined ? {} : { localHelloDeliveryId: deliveryId }),
                }),
            );
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async reject(sessionId: Uint8Array): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.rejectInTransaction(transaction, sessionId),
        );
    }

    /** Delete one pending handshake inside a caller-owned Murmur transaction. */
    async rejectInTransaction(transaction: StoreTransaction, sessionId: Uint8Array): Promise<void> {
        await transaction.delete(contactHandshakeKey(sessionId));
    }

    async markRemoving(identity: Uint8Array, deliveryId: string): Promise<ContactRecord> {
        return this.#store.transaction((transaction) =>
            this.markRemovingInTransaction(transaction, identity, deliveryId),
        );
    }

    /** Persist contact removal intent inside a caller-owned Murmur transaction. */
    async markRemovingInTransaction(
        transaction: StoreTransaction,
        identity: Uint8Array,
        deliveryId: string,
    ): Promise<ContactRecord> {
        const bytes = await transaction.get(contactIdentityKey(identity));
        if (bytes === undefined) throw new Error("Unknown contact");
        const record = decodeContactRecord(bytes);
        try {
            const next: ContactRecord = {
                ...record,
                status: "removing",
                removeDeliveryId: deliveryId,
            };
            await setAndZero(transaction, contactIdentityKey(identity), encodeContactRecord(next));
            await setAndZero(
                transaction,
                contactSessionKey(record.sessionId),
                encodeContactRecord(next),
            );
            return next;
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async contact(identity: Uint8Array): Promise<MurmurContact | undefined> {
        const bytes = await this.#store.get(contactIdentityKey(identity));
        if (bytes === undefined) return undefined;
        const record = decodeContactRecord(bytes);
        try {
            return publicContact(record);
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async contacts(): Promise<readonly MurmurContact[]> {
        const page = await this.#store.scan(CONTACT_IDENTITY_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const contacts: MurmurContact[] = [];
        for (const bytes of page.values()) {
            const record = decodeContactRecord(bytes);
            try {
                contacts.push(publicContact(record));
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        return Object.freeze(contacts);
    }

    async requests(): Promise<readonly MurmurContactRequested[]> {
        const page = await this.#store.scan(CONTACT_HANDSHAKE_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const requests: MurmurContactRequested[] = [];
        for (const bytes of page.values()) {
            const record = decodeContactHandshakeRecord(bytes);
            try {
                if (
                    record.direction === "incoming" &&
                    record.remoteProfile !== undefined &&
                    record.requestEventId !== undefined
                ) {
                    requests.push(
                        Object.freeze({
                            id: record.requestEventId,
                            identity: record.identity.slice(),
                            sessionId: record.sessionId.slice(),
                            profile: record.remoteProfile,
                        }),
                    );
                }
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        return Object.freeze(requests);
    }

    async prepareEvents(): Promise<PreparedContactEvents> {
        const page = await this.#store.scan(CONTACT_EVENT_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const keys: string[] = [];
        const requested: MurmurContactRequested[] = [];
        const added: MurmurContactAdded[] = [];
        const removed: MurmurContactRemoved[] = [];
        for (const [key, bytes] of page) {
            const event = decodeContactEventRecord(bytes);
            try {
                keys.push(key);
                if (event.type === "requested") {
                    requested.push(
                        Object.freeze({
                            id: event.id,
                            identity: event.identity.slice(),
                            sessionId: event.sessionId.slice(),
                            profile: event.profile,
                        }),
                    );
                } else if (event.type === "added") {
                    added.push(
                        Object.freeze({
                            id: event.id,
                            contact: Object.freeze({
                                identity: event.identity.slice(),
                                sessionId: event.sessionId.slice(),
                                localProfile: event.localProfile,
                                profile: event.profile,
                                status: "active",
                            }),
                        }),
                    );
                } else {
                    removed.push(
                        Object.freeze({
                            id: event.id,
                            identity: event.identity.slice(),
                            sessionId: event.sessionId.slice(),
                        }),
                    );
                }
            } finally {
                zeroBytes(event.identity);
                zeroBytes(event.sessionId);
                zeroBytes(bytes);
            }
        }
        return {
            keys,
            requested: Object.freeze(requested),
            added: Object.freeze(added),
            removed: Object.freeze(removed),
        };
    }

    async deletePreparedEvents(
        transaction: StoreTransaction,
        prepared: PreparedContactEvents,
    ): Promise<void> {
        for (const key of prepared.keys) {
            await transaction.delete(key);
        }
    }

    async #deleteContact(transaction: StoreTransaction, record: ContactRecord): Promise<void> {
        await transaction.delete(contactIdentityKey(record.identity));
        await transaction.delete(contactSessionKey(record.sessionId));
        await transaction.delete(contactHandshakeKey(record.sessionId));
    }
}
