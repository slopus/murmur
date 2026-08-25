import type { MurmurStore, StoreTransaction } from "../../storage/index.js";
import type { MurmurUpdate } from "../../sessions/types.js";
import {
    decodeMlsKeyPackage,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
} from "../../mls/index.js";
import { canonicalJsonBytes, equalBytes, zeroBytes, type JsonValue } from "../../utils/index.js";
import type {
    MurmurContactAdmission,
    MurmurContact,
    MurmurContactAdded,
    MurmurContactProfile,
    MurmurContactRemoved,
    MurmurContactRequested,
    MurmurContactUpdated,
    MurmurOutgoingContactRequest,
} from "../types.js";
import {
    CONTACT_ADMISSION_LOW_WATERMARK,
    decodeContactPacket,
    encodeContactPacket,
    validateContactProfile,
} from "./contactCodec.js";
import {
    CONTACT_EVENT_PREFIX,
    CONTACT_HANDSHAKE_PREFIX,
    CONTACT_IDENTITY_PREFIX,
    CONTACT_LOCAL_PROFILE_KEY,
    CONTACT_SOCIAL_PREFIX,
    contactEventKey,
    contactHandshakeKey,
    contactIdentityKey,
    contactSessionKey,
    contactSocialKey,
    decodeContactEventRecord,
    decodeContactHandshakeRecord,
    decodeContactLocalProfileRecord,
    decodeContactRecord,
    decodeContactSocialRecord,
    encodeContactEventRecord,
    encodeContactHandshakeRecord,
    encodeContactLocalProfileRecord,
    encodeContactRecord,
    type ContactHandshakeRecord,
    type ContactRecord,
} from "./contactRecords.js";

const CONTACT_SCAN_LIMIT = 256;

/** One active contact included in an atomic local profile publication. */
export interface ContactProfileUpdateTarget {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
}

/** Bounded immutable local profile mutation prepared before its MLS transaction. */
export interface PreparedContactProfileUpdate {
    readonly revision: number;
    readonly profile: MurmurContactProfile;
    readonly targets: readonly ContactProfileUpdateTarget[];
}

/** One cached contact KeyPackage selected for a new MLS membership. */
export interface ContactAdmissionSelection {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly generation: number;
    readonly keyPackage: Uint8Array;
    readonly reference: Uint8Array;
    readonly reusable: boolean;
}

/** One local refill packet waiting to be queued through a technical contact session. */
export interface ContactRefillRequest {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly generation: number;
}

/** One remote refill request waiting for a newly generated admission response. */
export interface ContactSupplyRequest {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly generation: number;
}

/** Internal immutable snapshot of pending contact lifecycle callbacks. */
export interface PreparedContactEvents {
    readonly keys: readonly string[];
    readonly requested: readonly MurmurContactRequested[];
    readonly added: readonly MurmurContactAdded[];
    readonly updated: readonly MurmurContactUpdated[];
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

function publicOutgoingRequest(record: ContactHandshakeRecord): MurmurOutgoingContactRequest {
    return Object.freeze({
        identity: record.identity.slice(),
        sessionId: record.sessionId.slice(),
        createdAt: record.createdAt,
    });
}

function validatePeer(identity: Uint8Array, self: Uint8Array): void {
    if (identity.length !== 32 || equalBytes(identity, self)) {
        throw new Error("Invalid contact identity");
    }
}

function validateAdmissionIdentity(
    admission: MurmurContactAdmission,
    identity: Uint8Array,
    now: number,
): void {
    for (const bytes of [...admission.oneTimeKeyPackages, admission.lastResortKeyPackage]) {
        const keyPackage = decodeMlsKeyPackage(bytes);
        if (
            !verifyMlsKeyPackage(keyPackage, Math.floor(now / 1_000)) ||
            !equalBytes(encodeMlsKeyPackage(keyPackage), bytes) ||
            !equalBytes(keyPackage.leafNode.signatureKey, identity) ||
            !equalBytes(keyPackage.leafNode.credential.identity, identity)
        ) {
            throw new Error("Contact admission identity does not match");
        }
    }
}

function equalProfiles(left: MurmurContactProfile, right: MurmurContactProfile): boolean {
    const leftBytes = canonicalJsonBytes(left as unknown as JsonValue);
    const rightBytes = canonicalJsonBytes(right as unknown as JsonValue);
    try {
        return equalBytes(leftBytes, rightBytes);
    } finally {
        zeroBytes(leftBytes);
        zeroBytes(rightBytes);
    }
}

async function writeContact(transaction: StoreTransaction, record: ContactRecord): Promise<void> {
    await setAndZero(transaction, contactIdentityKey(record.identity), encodeContactRecord(record));
    await setAndZero(transaction, contactSessionKey(record.sessionId), encodeContactRecord(record));
    await transaction.delete(contactSocialKey(record.identity));
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
        localAdmission: MurmurContactAdmission,
    ): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.recordOutgoingInTransaction(
                transaction,
                sessionId,
                identity,
                profile,
                localAdmission,
            ),
        );
    }

    /** Persist an outgoing handshake inside a caller-owned Murmur transaction. */
    async recordOutgoingInTransaction(
        transaction: StoreTransaction,
        sessionId: Uint8Array,
        identity: Uint8Array,
        profile: MurmurContactProfile,
        localAdmission: MurmurContactAdmission,
    ): Promise<void> {
        validatePeer(identity, this.#identity);
        validateAdmissionIdentity(localAdmission, this.#identity, this.#now());
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
                version: 2,
                direction: "outgoing",
                identity,
                sessionId,
                localProfile,
                localHelloProcessed: false,
                remoteHelloProcessed: false,
                createdAt: this.#now(),
                localAdmission,
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
                                version: 2,
                                type: "removed",
                                id: update.id,
                                identity: contact.identity,
                                sessionId: contact.sessionId,
                            }),
                        );
                        remove = true;
                        return;
                    }
                    if (packet.type === "profile_update") {
                        if (contact === undefined) {
                            throw new Error("Contact profile update has no confirmed contact");
                        }
                        const fromSelf = equalBytes(update.sender, this.#identity);
                        if (!fromSelf && !equalBytes(update.sender, contact.identity)) {
                            throw new Error("Contact profile update sender does not match");
                        }
                        if (contact.status !== "active") return;
                        const currentRevision = fromSelf
                            ? contact.localProfileRevision
                            : contact.remoteProfileRevision;
                        const currentProfile = fromSelf ? contact.localProfile : contact.profile;
                        if (packet.revision < currentRevision) return;
                        if (packet.revision === currentRevision) {
                            if (!equalProfiles(packet.profile, currentProfile)) {
                                throw new Error("Conflicting contact profile revision");
                            }
                            return;
                        }
                        const next: ContactRecord = {
                            ...contact,
                            ...(fromSelf
                                ? {
                                      localProfile: packet.profile,
                                      localProfileRevision: packet.revision,
                                  }
                                : {
                                      profile: packet.profile,
                                      remoteProfileRevision: packet.revision,
                                  }),
                        };
                        await writeContact(transaction, next);
                        if (!fromSelf) {
                            await setAndZero(
                                transaction,
                                contactEventKey(update.id),
                                encodeContactEventRecord({
                                    version: 2,
                                    type: "updated",
                                    id: update.id,
                                    identity: next.identity,
                                    sessionId: next.sessionId,
                                    localProfile: next.localProfile,
                                    profile: next.profile,
                                }),
                            );
                        }
                        return;
                    }
                    if (
                        packet.type === "admission_request" ||
                        packet.type === "admission_response"
                    ) {
                        if (contact === undefined) {
                            throw new Error("Contact admission packet has no confirmed contact");
                        }
                        const fromSelf = equalBytes(update.sender, this.#identity);
                        if (!fromSelf && !equalBytes(update.sender, contact.identity)) {
                            throw new Error("Contact admission sender does not match");
                        }
                        if (fromSelf) return;
                        if (packet.type === "admission_request") {
                            if (packet.generation > contact.localAdmissionGeneration) {
                                throw new Error(
                                    "Contact requested an unknown admission generation",
                                );
                            }
                            await writeContact(transaction, {
                                ...contact,
                                supplyRequestEventId: update.id,
                            });
                            return;
                        }
                        validateAdmissionIdentity(packet.admission, contact.identity, this.#now());
                        if (packet.admission.generation <= contact.remoteAdmission.generation) {
                            return;
                        }
                        const {
                            refillRequestDeliveryId: _refillRequestDeliveryId,
                            ...withoutRefillRequest
                        } = contact;
                        await writeContact(transaction, {
                            ...withoutRefillRequest,
                            remoteAdmission: packet.admission,
                            refillNeeded: false,
                        });
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
                        validateAdmissionIdentity(packet.admission, update.sender, this.#now());
                        const existingIdentity = await transaction.get(
                            contactIdentityKey(update.sender),
                        );
                        if (existingIdentity !== undefined) {
                            zeroBytes(existingIdentity);
                            throw new Error("Identity is already a contact");
                        }
                        const incoming: ContactHandshakeRecord = {
                            version: 2,
                            direction: "incoming",
                            identity: update.sender,
                            sessionId: update.sessionId,
                            remoteProfile: packet.profile,
                            remoteAdmission: packet.admission,
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
                                version: 2,
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
                            version: 2,
                            type: "hello",
                            profile: handshake.remoteProfile,
                            admission: handshake.remoteAdmission!,
                        });
                        try {
                            if (!equalBytes(expected, update.bytes)) {
                                throw new Error("Contact profile changed during the handshake");
                            }
                        } finally {
                            zeroBytes(expected);
                        }
                    }
                    validateAdmissionIdentity(
                        packet.admission,
                        fromSelf ? this.#identity : handshake.identity,
                        this.#now(),
                    );
                    const next: ContactHandshakeRecord = {
                        ...handshake,
                        ...(fromSelf
                            ? {}
                            : {
                                  remoteProfile: packet.profile,
                                  remoteAdmission: packet.admission,
                              }),
                        localHelloProcessed: handshake.localHelloProcessed || fromSelf,
                        remoteHelloProcessed: handshake.remoteHelloProcessed || !fromSelf,
                    };
                    if (
                        next.localHelloProcessed &&
                        next.remoteHelloProcessed &&
                        next.localProfile !== undefined &&
                        next.remoteProfile !== undefined &&
                        next.localAdmission !== undefined &&
                        next.remoteAdmission !== undefined
                    ) {
                        const confirmed: ContactRecord = {
                            version: 2,
                            identity: next.identity,
                            sessionId: next.sessionId,
                            localProfile: next.localProfile,
                            profile: next.remoteProfile,
                            localProfileRevision: 0,
                            remoteProfileRevision: 0,
                            status: "active",
                            confirmedAt: this.#now(),
                            localAdmissionGeneration: next.localAdmission.generation,
                            remoteAdmission: next.remoteAdmission,
                            refillNeeded:
                                next.remoteAdmission.oneTimeKeyPackages.length <=
                                CONTACT_ADMISSION_LOW_WATERMARK,
                        };
                        await writeContact(transaction, confirmed);
                        await transaction.delete(contactHandshakeKey(next.sessionId));
                        await setAndZero(
                            transaction,
                            contactEventKey(update.id),
                            encodeContactEventRecord({
                                version: 2,
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

    async accept(
        sessionId: Uint8Array,
        profile: MurmurContactProfile,
        localAdmission: MurmurContactAdmission,
    ): Promise<void> {
        await this.#store.transaction((transaction) =>
            this.acceptInTransaction(transaction, sessionId, profile, localAdmission),
        );
    }

    /** Persist an accepted profile and optional hello ID in a Murmur transaction. */
    async acceptInTransaction(
        transaction: StoreTransaction,
        sessionId: Uint8Array,
        profile: MurmurContactProfile,
        localAdmission: MurmurContactAdmission,
        deliveryId?: string,
    ): Promise<void> {
        const localProfile = validateContactProfile(profile);
        validateAdmissionIdentity(localAdmission, this.#identity, this.#now());
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
                    localAdmission,
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

    /** Select one cached remote KeyPackage, preferring deletion-safe one-use material. */
    async selectAdmission(identity: Uint8Array): Promise<ContactAdmissionSelection> {
        const bytes = await this.#store.get(contactIdentityKey(identity));
        if (bytes === undefined) throw new Error("Unknown contact");
        const record = decodeContactRecord(bytes);
        try {
            if (record.status !== "active") throw new Error("Contact is not active");
            let keyPackageBytes: Uint8Array | undefined;
            let reusable = false;
            for (const candidate of record.remoteAdmission.oneTimeKeyPackages) {
                const keyPackage = decodeMlsKeyPackage(candidate);
                if (verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000))) {
                    keyPackageBytes = candidate;
                    break;
                }
            }
            if (keyPackageBytes === undefined) {
                const fallback = decodeMlsKeyPackage(record.remoteAdmission.lastResortKeyPackage);
                if (!verifyMlsKeyPackage(fallback, Math.floor(this.#now() / 1_000))) {
                    throw new Error("Contact admission material is expired");
                }
                keyPackageBytes = record.remoteAdmission.lastResortKeyPackage;
                reusable = true;
            }
            const keyPackage = decodeMlsKeyPackage(keyPackageBytes);
            return Object.freeze({
                identity: record.identity.slice(),
                sessionId: record.sessionId.slice(),
                generation: record.remoteAdmission.generation,
                keyPackage: keyPackageBytes.slice(),
                reference: mlsKeyPackageReference(keyPackage),
                reusable,
            });
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    /** Consume one selected package in the caller's session-creation transaction. */
    async consumeAdmissionInTransaction(
        transaction: StoreTransaction,
        selection: ContactAdmissionSelection,
    ): Promise<void> {
        const bytes = await transaction.get(contactIdentityKey(selection.identity));
        if (bytes === undefined) throw new Error("Unknown contact");
        const record = decodeContactRecord(bytes);
        try {
            if (
                record.status !== "active" ||
                record.remoteAdmission.generation !== selection.generation ||
                !equalBytes(record.sessionId, selection.sessionId)
            ) {
                throw new Error("Contact admission changed before use");
            }
            let oneTimeKeyPackages = [...record.remoteAdmission.oneTimeKeyPackages];
            if (selection.reusable) {
                const fallback = decodeMlsKeyPackage(record.remoteAdmission.lastResortKeyPackage);
                if (!equalBytes(mlsKeyPackageReference(fallback), selection.reference)) {
                    throw new Error("Contact last-resort admission changed before use");
                }
            } else {
                const index = oneTimeKeyPackages.findIndex((candidate) =>
                    equalBytes(
                        mlsKeyPackageReference(decodeMlsKeyPackage(candidate)),
                        selection.reference,
                    ),
                );
                if (index < 0) throw new Error("Contact one-use admission was already consumed");
                oneTimeKeyPackages.splice(index, 1);
            }
            const next: ContactRecord = {
                ...record,
                remoteAdmission: {
                    ...record.remoteAdmission,
                    oneTimeKeyPackages: Object.freeze(oneTimeKeyPackages),
                },
                refillNeeded:
                    selection.reusable ||
                    oneTimeKeyPackages.length <= CONTACT_ADMISSION_LOW_WATERMARK,
            };
            await writeContact(transaction, next);
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async refillRequests(): Promise<readonly ContactRefillRequest[]> {
        const page = await this.#store.scan(CONTACT_IDENTITY_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const result: ContactRefillRequest[] = [];
        for (const bytes of page.values()) {
            const record = decodeContactRecord(bytes);
            try {
                if (
                    record.status === "active" &&
                    record.refillNeeded &&
                    record.refillRequestDeliveryId === undefined
                ) {
                    result.push(
                        Object.freeze({
                            identity: record.identity.slice(),
                            sessionId: record.sessionId.slice(),
                            generation: record.remoteAdmission.generation,
                        }),
                    );
                }
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        return Object.freeze(result);
    }

    async markRefillRequestedInTransaction(
        transaction: StoreTransaction,
        identity: Uint8Array,
        deliveryId: string,
    ): Promise<void> {
        const bytes = await transaction.get(contactIdentityKey(identity));
        if (bytes === undefined) throw new Error("Unknown contact");
        const record = decodeContactRecord(bytes);
        try {
            await writeContact(transaction, {
                ...record,
                refillRequestDeliveryId: deliveryId,
            });
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async supplyRequests(): Promise<readonly ContactSupplyRequest[]> {
        const page = await this.#store.scan(CONTACT_IDENTITY_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const result: ContactSupplyRequest[] = [];
        for (const bytes of page.values()) {
            const record = decodeContactRecord(bytes);
            try {
                if (record.status === "active" && record.supplyRequestEventId !== undefined) {
                    result.push(
                        Object.freeze({
                            identity: record.identity.slice(),
                            sessionId: record.sessionId.slice(),
                            generation: record.localAdmissionGeneration + 1,
                        }),
                    );
                }
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        return Object.freeze(result);
    }

    async markAdmissionSuppliedInTransaction(
        transaction: StoreTransaction,
        identity: Uint8Array,
        admission: MurmurContactAdmission,
    ): Promise<void> {
        const bytes = await transaction.get(contactIdentityKey(identity));
        if (bytes === undefined) throw new Error("Unknown contact");
        const record = decodeContactRecord(bytes);
        try {
            if (admission.generation <= record.localAdmissionGeneration) {
                throw new Error("Contact admission generation did not advance");
            }
            const { supplyRequestEventId: _supplyRequestEventId, ...withoutSupplyRequest } = record;
            await writeContact(transaction, {
                ...withoutSupplyRequest,
                localAdmissionGeneration: admission.generation,
            });
        } finally {
            zeroBytes(record.identity);
            zeroBytes(record.sessionId);
            zeroBytes(bytes);
        }
    }

    async markRemoving(identity: Uint8Array, deliveryId: string): Promise<ContactRecord> {
        return this.#store.transaction((transaction) =>
            this.markRemovingInTransaction(transaction, identity, deliveryId),
        );
    }

    /** Prepare one bounded profile replacement for every currently active contact. */
    async prepareProfileUpdate(
        profile: MurmurContactProfile,
    ): Promise<PreparedContactProfileUpdate> {
        const localProfile = validateContactProfile(profile);
        const storedProfile = await this.#store.get(CONTACT_LOCAL_PROFILE_KEY);
        let previousRevision = 0;
        try {
            if (storedProfile !== undefined) {
                previousRevision = decodeContactLocalProfileRecord(storedProfile).revision;
            }
        } finally {
            if (storedProfile !== undefined) zeroBytes(storedProfile);
        }
        if (previousRevision >= Number.MAX_SAFE_INTEGER) {
            throw new Error("Contact profile revision exhausted");
        }
        const page = await this.#store.scan(CONTACT_IDENTITY_PREFIX, {
            limit: CONTACT_SCAN_LIMIT + 1,
        });
        const targets: ContactProfileUpdateTarget[] = [];
        try {
            if (page.size > CONTACT_SCAN_LIMIT) {
                throw new Error("Contact profile update exceeds the contact bound");
            }
            for (const bytes of page.values()) {
                const record = decodeContactRecord(bytes);
                try {
                    if (record.status === "active") {
                        targets.push(
                            Object.freeze({
                                identity: record.identity.slice(),
                                sessionId: record.sessionId.slice(),
                            }),
                        );
                    }
                } finally {
                    zeroBytes(record.identity);
                    zeroBytes(record.sessionId);
                }
            }
        } finally {
            for (const bytes of page.values()) zeroBytes(bytes);
        }
        return Object.freeze({
            revision: previousRevision + 1,
            profile: localProfile,
            targets: Object.freeze(targets),
        });
    }

    /** Commit the local profile and every mirrored active-contact record atomically. */
    async commitProfileUpdateInTransaction(
        transaction: StoreTransaction,
        prepared: PreparedContactProfileUpdate,
    ): Promise<void> {
        const storedProfile = await transaction.get(CONTACT_LOCAL_PROFILE_KEY);
        try {
            const previousRevision =
                storedProfile === undefined
                    ? 0
                    : decodeContactLocalProfileRecord(storedProfile).revision;
            if (previousRevision + 1 !== prepared.revision) {
                throw new Error("Contact profile changed before publication");
            }
        } finally {
            if (storedProfile !== undefined) zeroBytes(storedProfile);
        }
        for (const target of prepared.targets) {
            const bytes = await transaction.get(contactIdentityKey(target.identity));
            if (bytes === undefined) throw new Error("Contact changed before profile publication");
            const record = decodeContactRecord(bytes);
            try {
                if (record.status !== "active" || !equalBytes(record.sessionId, target.sessionId)) {
                    throw new Error("Contact changed before profile publication");
                }
                await writeContact(transaction, {
                    ...record,
                    localProfile: prepared.profile,
                    localProfileRevision: prepared.revision,
                });
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        await setAndZero(
            transaction,
            CONTACT_LOCAL_PROFILE_KEY,
            encodeContactLocalProfileRecord({
                version: 1,
                revision: prepared.revision,
                profile: prepared.profile,
            }),
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
        if (bytes === undefined) {
            const socialBytes = await this.#store.get(contactSocialKey(identity));
            if (socialBytes === undefined) return undefined;
            const social = decodeContactSocialRecord(socialBytes);
            try {
                return Object.freeze({
                    identity: social.identity.slice(),
                    sessionId: new Uint8Array(),
                    localProfile: social.localProfile,
                    profile: social.profile,
                    status: "active" as const,
                    technicalReset: true as const,
                });
            } finally {
                zeroBytes(social.identity);
                zeroBytes(socialBytes);
            }
        }
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
        const socialPage = await this.#store.scan(CONTACT_SOCIAL_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        for (const bytes of socialPage.values()) {
            const record = decodeContactSocialRecord(bytes);
            try {
                contacts.push(
                    Object.freeze({
                        identity: record.identity.slice(),
                        sessionId: new Uint8Array(),
                        localProfile: record.localProfile,
                        profile: record.profile,
                        status: "active" as const,
                        technicalReset: true as const,
                    }),
                );
            } finally {
                zeroBytes(record.identity);
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

    async outgoingRequest(identity: Uint8Array): Promise<MurmurOutgoingContactRequest | undefined> {
        const page = await this.#store.scan(CONTACT_HANDSHAKE_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        let request: MurmurOutgoingContactRequest | undefined;
        for (const bytes of page.values()) {
            const record = decodeContactHandshakeRecord(bytes);
            try {
                if (
                    request === undefined &&
                    record.direction === "outgoing" &&
                    equalBytes(record.identity, identity)
                ) {
                    request = publicOutgoingRequest(record);
                }
            } finally {
                zeroBytes(record.identity);
                zeroBytes(record.sessionId);
                zeroBytes(bytes);
            }
        }
        return request;
    }

    async outgoingRequests(): Promise<readonly MurmurOutgoingContactRequest[]> {
        const page = await this.#store.scan(CONTACT_HANDSHAKE_PREFIX, {
            limit: CONTACT_SCAN_LIMIT,
        });
        const requests: MurmurOutgoingContactRequest[] = [];
        for (const bytes of page.values()) {
            const record = decodeContactHandshakeRecord(bytes);
            try {
                if (record.direction === "outgoing") {
                    requests.push(publicOutgoingRequest(record));
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
        const updated: MurmurContactUpdated[] = [];
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
                } else if (event.type === "updated") {
                    updated.push(
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
            updated: Object.freeze(updated),
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
