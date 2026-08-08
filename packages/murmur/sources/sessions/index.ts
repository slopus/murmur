import { sha256 } from "@noble/hashes/sha2";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    type DeliveryFetch,
    type DeliveryTransport,
} from "../delivery/index.js";
import {
    decodeIdentityRoot,
    destroyIdentity,
    encodeIdentityRoot,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../crypto/index.js";
import {
    DISCOVERY_INVITATION_TTL_MILLISECONDS,
    HttpDiscoveryTransport,
    createDiscoveryBundle,
    parseDiscoveryBundle,
    serializeDiscoveryBundle,
    type DiscoveryBundle,
    type DiscoveryTransport,
} from "../identity/discovery/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    mlsKeyPackageReference,
    serializeMlsKeyPackageBundle,
} from "../mls/index.js";
import type { MurmurStore } from "../storage/index.js";
import { equalBytes, zeroBytes } from "../utils/index.js";
import { ContactEngine, type PreparedContactEvents } from "../contacts/impl/contactEngine.js";
import {
    contactSessionDescriptor,
    encodeContactPacket,
    isContactSessionDescriptor,
    type MurmurContact,
    type MurmurContactProfile,
    type MurmurContactRequested,
} from "../contacts/index.js";
import {
    createMurmurServiceSessionDescriptor,
    createMurmurServiceStorage,
    validateMurmurServiceRegistration,
    type MurmurService,
    type MurmurServiceRegistration,
    type MurmurServiceStorage,
} from "../services/index.js";
import {
    SessionEngine,
    type PreparedUpdates,
    type SessionRouteDecision,
} from "./impl/sessionEngine.js";
import type {
    CreateMurmurSessionOptions,
    MurmurSession,
    MurmurSessionIssue,
    MurmurSessionLimits,
    MurmurSessionListOptions,
    MurmurSessionPage,
    MurmurSessionProposal,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";

export type {
    CreateMurmurSessionOptions,
    MurmurSession,
    MurmurSessionIssue,
    MurmurSessionLimits,
    MurmurSessionListOptions,
    MurmurSessionPage,
    MurmurSessionProposal,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";

const IDENTITY_KEY = "murmur/identity/root";
const DEFAULT_KEY_PACKAGES = 1;
const SYNC_RECONNECT_DELAY_MILLISECONDS = 1_000;

/** Construction inputs for the stateful Murmur MLS client. */
export interface MurmurClientOptions {
    readonly relay?: string | URL;
    readonly transport?: DeliveryTransport;
    readonly discoveryTransport?: DiscoveryTransport;
    readonly fetch?: DeliveryFetch;
    readonly store: MurmurStore;
    readonly identity?: IdentityKeyPair;
    readonly limits?: MurmurSessionLimits;
    readonly now?: () => number;
    /** Optional typed services available to claim and process sessions. */
    readonly services?: readonly MurmurServiceRegistration[];
}

/** Stateful identity, discovery, bootstrap, and opaque MLS-session facade. */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #engine: SessionEngine;
    readonly #store: MurmurStore;
    readonly #contacts: ContactEngine;
    readonly #services = new Map<string, MurmurService>();
    readonly #discoveryTransport: DiscoveryTransport | undefined;
    readonly #now: () => number;
    #closed = false;
    #operationTail: Promise<void> = Promise.resolve();
    #pendingOperations = 0;
    #syncActive = false;
    #syncWakePending = false;
    #syncWakeResolve: (() => void) | undefined;
    #syncRetryTimer: ReturnType<typeof setTimeout> | undefined;
    #updatesActive = false;

    private constructor(
        identity: IdentityKeyPair,
        store: MurmurStore,
        transport: DeliveryTransport,
        discoveryTransport: DiscoveryTransport | undefined,
        limits: MurmurSessionLimits,
        now: () => number,
        services: readonly MurmurServiceRegistration[],
    ) {
        this.#identity = identity;
        this.#store = store;
        this.#now = now;
        this.#discoveryTransport = discoveryTransport;
        this.#engine = new SessionEngine(identity, store, transport, limits, now);
        this.#contacts = new ContactEngine(store, identity.publicKey, now);
        for (const registration of services) {
            this.#services.set(registration.id, registration.service);
        }
    }

    /** Open or create one durable single-device Murmur identity. */
    static async open(options: MurmurClientOptions): Promise<MurmurClient> {
        if ((options.relay === undefined) === (options.transport === undefined)) {
            throw new Error("Provide exactly one relay URL or delivery transport");
        }
        const services = options.services ?? [];
        const serviceIds = new Set<string>();
        for (const registration of services) {
            validateMurmurServiceRegistration(registration);
            if (serviceIds.has(registration.id)) {
                throw new Error("Murmur service IDs must be unique");
            }
            serviceIds.add(registration.id);
        }
        let identity: IdentityKeyPair | undefined;
        try {
            await options.store.transaction(async (transaction) => {
                const stored = await transaction.get(IDENTITY_KEY);
                if (stored !== undefined) {
                    try {
                        identity = decodeIdentityRoot(stored);
                        if (
                            options.identity !== undefined &&
                            !equalBytes(identity.publicKey, options.identity.publicKey)
                        ) {
                            destroyIdentity(identity);
                            identity = undefined;
                            throw new Error(
                                "Stored Murmur identity differs from supplied identity",
                            );
                        }
                        return;
                    } finally {
                        zeroBytes(stored);
                    }
                }
                if (options.identity === undefined) {
                    identity = generateIdentityKeyPair();
                } else {
                    const encoded = encodeIdentityRoot(options.identity);
                    try {
                        identity = decodeIdentityRoot(encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                }
                const encoded = encodeIdentityRoot(identity);
                try {
                    await transaction.set(IDENTITY_KEY, encoded);
                } finally {
                    zeroBytes(encoded);
                }
            });
            if (identity === undefined) throw new Error("Murmur identity did not open");
            const transport =
                options.transport ??
                new HttpDeliveryTransport(
                    options.relay as string | URL,
                    options.fetch === undefined ? {} : { fetch: options.fetch },
                );
            const discoveryTransport =
                options.discoveryTransport ??
                (options.relay === undefined
                    ? undefined
                    : new HttpDiscoveryTransport(
                          options.relay,
                          options.fetch === undefined ? {} : { fetch: options.fetch },
                      ));
            return new MurmurClient(
                identity,
                options.store,
                transport,
                discoveryTransport,
                options.limits ?? {},
                options.now ?? Date.now,
                services,
            );
        } catch (error: unknown) {
            if (identity !== undefined) destroyIdentity(identity);
            throw error;
        }
    }

    /** Defensive copy of the single public identity key. */
    get identity(): Uint8Array {
        this.#assertOpen();
        return this.#identity.publicKey.slice();
    }

    /** Register one optional typed service under its durable stable ID. */
    registerService(registration: MurmurServiceRegistration): void {
        this.#assertOpen();
        validateMurmurServiceRegistration(registration);
        if (this.#services.has(registration.id)) {
            throw new Error("Murmur service is already registered");
        }
        this.#services.set(registration.id, registration.service);
    }

    /** Disable one optional service without changing its durable state. */
    unregisterService(id: string): void {
        this.#assertOpen();
        this.#services.delete(id);
    }

    /** Open JSON persistence restricted to one service namespace. */
    serviceStorage(id: string): MurmurServiceStorage {
        this.#assertOpen();
        return createMurmurServiceStorage(this.#store, id);
    }

    /** Create and durably retain fresh one-use KeyPackages in a signed bundle. */
    async discovery(): Promise<DiscoveryBundle> {
        return this.#exclusive(() => this.#createDiscovery());
    }

    /** Upload a five-minute bundle and return its 32-byte SHA-256 lookup capability. */
    async createInvitation(signal?: AbortSignal): Promise<Uint8Array> {
        return this.#exclusive(async () => {
            if (this.#discoveryTransport === undefined) {
                throw new Error("No discovery transport is configured");
            }
            const bundle = await this.#createDiscovery();
            const references = bundle.keyPackages.map(mlsKeyPackageReference);
            const bytes = serializeDiscoveryBundle(bundle);
            try {
                const outcome = await this.#discoveryTransport.upload(bytes, signal);
                if (
                    outcome.expiresAt !== bundle.expiresAt ||
                    !equalBytes(outcome.digest, sha256(bytes))
                ) {
                    throw new Error("Discovery relay returned invalid invitation metadata");
                }
                return outcome.digest.slice();
            } catch (error: unknown) {
                await this.#engine.deleteKeyPackages(references);
                throw error;
            } finally {
                zeroBytes(bytes);
            }
        });
    }

    /** Download, hash-check, and authenticate a five-minute invitation capability. */
    async resolveInvitation(digest: Uint8Array, signal?: AbortSignal): Promise<DiscoveryBundle> {
        return this.#tracked(async () => {
            if (this.#discoveryTransport === undefined) {
                throw new Error("No discovery transport is configured");
            }
            if (!(digest instanceof Uint8Array) || digest.length !== 32) {
                throw new Error("Invalid invitation digest");
            }
            const bytes = await this.#discoveryTransport.download(digest, signal);
            try {
                if (!equalBytes(sha256(bytes), digest)) {
                    throw new Error("Downloaded invitation digest does not match");
                }
                return parseDiscoveryBundle(bytes, { now: this.#now() });
            } finally {
                zeroBytes(bytes);
            }
        });
    }

    /** Resolve an invitation and durably begin the built-in mutual contact hello. */
    async requestContact(
        invitation: Uint8Array,
        profile: MurmurContactProfile,
        signal?: AbortSignal,
    ): Promise<MurmurSession> {
        const bundle = await this.resolveInvitation(invitation, signal);
        const session = await this.#exclusive(() =>
            this.#engine.create(
                {
                    descriptor: contactSessionDescriptor(),
                    members: [bundle],
                },
                { version: 1, owner: "contact" },
                (transaction, id) =>
                    this.#contacts.recordOutgoingInTransaction(
                        transaction,
                        id,
                        bundle.identityKey,
                        profile,
                    ),
            ),
        );
        this.#signalSync();
        return session;
    }

    /** Persist the local profile decision, activate the pending contact, and queue hello. */
    async acceptContact(sessionId: Uint8Array, profile: MurmurContactProfile): Promise<void> {
        await this.#exclusive(async () => {
            const packet = encodeContactPacket({ version: 1, type: "hello", profile });
            try {
                await this.#engine.acceptOwnedContact(
                    sessionId,
                    packet,
                    (transaction, deliveryId) =>
                        this.#contacts.acceptInTransaction(
                            transaction,
                            sessionId,
                            profile,
                            deliveryId,
                        ),
                );
            } finally {
                zeroBytes(packet);
            }
        });
        this.#signalSync();
    }

    /** Reject and destroy one pending contact session. */
    async rejectContact(sessionId: Uint8Array): Promise<void> {
        await this.#exclusive(() =>
            this.#engine.destroyOwned(sessionId, "contact", (transaction) =>
                this.#contacts.rejectInTransaction(transaction, sessionId),
            ),
        );
    }

    /** Queue a typed removal and retain the contact until its authenticated echo. */
    async removeContact(identity: Uint8Array): Promise<void> {
        await this.#exclusive(async () => {
            const contact = await this.#contacts.contact(identity);
            if (contact === undefined) throw new Error("Unknown contact");
            const packet = encodeContactPacket({ version: 1, type: "remove" });
            try {
                await this.#engine.sendOwnedContact(
                    contact.sessionId,
                    packet,
                    async (transaction, deliveryId) => {
                        await this.#contacts.markRemovingInTransaction(
                            transaction,
                            identity,
                            deliveryId,
                        );
                    },
                );
            } finally {
                zeroBytes(packet);
            }
        });
        this.#signalSync();
    }

    /** Read one confirmed contact from durable local state. */
    async contact(identity: Uint8Array): Promise<MurmurContact | undefined> {
        return this.#tracked(() => this.#contacts.contact(identity));
    }

    /** Read the bounded durable contact list without relay connectivity. */
    async contacts(): Promise<readonly MurmurContact[]> {
        return this.#tracked(() => this.#contacts.contacts());
    }

    /** Read validated incoming contact requests awaiting a decision. */
    async contactRequests(): Promise<readonly MurmurContactRequested[]> {
        return this.#tracked(() => this.#contacts.requests());
    }

    async createSession(options: CreateMurmurSessionOptions): Promise<MurmurSession> {
        const owner =
            options.service === undefined
                ? undefined
                : ({ version: 1, owner: "service", serviceId: options.service } as const);
        if (options.service !== undefined && !this.#services.has(options.service)) {
            throw new Error("Session service is not registered");
        }
        const session = await this.#exclusive(() => this.#engine.create(options, owner));
        this.#signalSync();
        return session;
    }

    async session(id: Uint8Array): Promise<MurmurSession | undefined> {
        return this.#tracked(() => this.#engine.get(id));
    }

    async sessions(options: MurmurSessionListOptions = {}): Promise<MurmurSessionPage> {
        return this.#tracked(() => this.#engine.list(options));
    }

    async activateSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.activate(id));
        this.#signalSync();
    }

    async ignoreSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.ignore(id));
    }

    /** Abandon a blocked local membership operation and destroy the whole session. */
    async abandonSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.abandon(id));
    }

    async send(id: Uint8Array, bytes: Uint8Array): Promise<string> {
        const deliveryId = await this.#exclusive(() => this.#engine.send(id, bytes));
        this.#signalSync();
        return deliveryId;
    }

    async addMember(id: Uint8Array, bundle: DiscoveryBundle): Promise<void> {
        await this.#exclusive(() => this.#engine.add(id, bundle));
        this.#signalSync();
    }

    async removeMember(id: Uint8Array, identity: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.remove(id, identity));
        this.#signalSync();
    }

    async transferCommitter(id: Uint8Array, identity: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.transferCommitter(id, identity));
        this.#signalSync();
    }

    async proposals(id: Uint8Array): Promise<readonly MurmurSessionProposal[]> {
        return this.#tracked(() => this.#engine.proposals(id));
    }

    async acceptProposals(id: Uint8Array, proposalIds: readonly string[]): Promise<void> {
        await this.#exclusive(() => this.#engine.acceptProposals(id, proposalIds));
        this.#signalSync();
    }

    async issues(): Promise<readonly MurmurSessionIssue[]> {
        return this.#tracked(() => this.#engine.issues());
    }

    async synchronize(
        options: MurmurSynchronizeOptions = {},
        lifecycle: Pick<
            MurmurSyncOptions,
            "onUpdates" | "onContactRequested" | "onContactAdded" | "onContactRemoved"
        > = {},
    ): Promise<MurmurSynchronizeResult> {
        if (this.#syncActive) {
            throw new Error("Cannot page synchronization while SSE sync is active");
        }
        const result = await this.#exclusive(() => this.#engine.synchronize(options));
        await this.#exclusive(() => this.#queueContactHellos());
        await this.#deliverUpdates(lifecycle);
        return result;
    }

    /**
     * Maintain one recipient-authenticated SSE connection until aborted.
     *
     * Streamed deliveries are transactionally processed and acknowledged in
     * inbox order. Durable outbound work wakes this loop for publication.
     */
    async sync(options: MurmurSyncOptions = {}): Promise<void> {
        this.#assertOpen();
        if (this.#syncActive) throw new Error("Murmur synchronization is active");
        const signal = options.abort ?? new AbortController().signal;
        if (signal.aborted) return;
        this.#syncActive = true;
        this.#pendingOperations += 1;
        const wakeOnAbort = (): void => this.#signalSync();
        signal.addEventListener("abort", wakeOnAbort, { once: true });
        try {
            await this.#flushSync(SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
            await this.#deliverUpdates(options);
            while (!signal.aborted) {
                let connected = false;
                let disconnectedBy: unknown;
                const stream = this.#engine.streamInbox({
                    signal,
                    onConnected: async () => {
                        connected = true;
                        await options.onConnected?.();
                    },
                });
                const iterator = stream[Symbol.asyncIterator]();
                let next = iterator.next();
                try {
                    for (;;) {
                        const outcome = await Promise.race([
                            next.then((result) => ({ type: "event" as const, result })),
                            this.#waitSyncWake().then(() => ({ type: "wake" as const })),
                        ]);
                        if (outcome.type === "wake") {
                            if (signal.aborted) break;
                            await this.#flushSync(SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
                            await this.#deliverUpdates(options);
                            continue;
                        }
                        if (outcome.result.done) break;
                        const result = await this.#exclusive(() =>
                            this.#engine.completeStreamEvent(outcome.result.value, signal),
                        );
                        if (result.transientPublicationFailures > 0) {
                            this.#scheduleSyncWake(SYNC_RECONNECT_DELAY_MILLISECONDS);
                        }
                        await this.#deliverUpdates(options);
                        if (signal.aborted) break;
                        next = iterator.next();
                    }
                } catch (error: unknown) {
                    disconnectedBy = error;
                    if (signal.aborted) break;
                    if (
                        !(error instanceof DeliveryTransportError) ||
                        (error.status !== 0 && error.status !== 429 && error.status < 500)
                    ) {
                        throw error;
                    }
                } finally {
                    try {
                        await iterator.return?.();
                    } finally {
                        if (connected) await options.onDisconnected?.(disconnectedBy);
                    }
                }
                if (!signal.aborted) {
                    await this.#syncDelay(SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
                }
            }
        } finally {
            signal.removeEventListener("abort", wakeOnAbort);
            this.#syncActive = false;
            this.#syncWakePending = false;
            this.#syncWakeResolve = undefined;
            if (this.#syncRetryTimer !== undefined) {
                clearTimeout(this.#syncRetryTimer);
                this.#syncRetryTimer = undefined;
            }
            this.#pendingOperations -= 1;
        }
    }

    /** Destroy in-memory identity material. Durable state remains application-owned. */
    close(): void {
        if (this.#closed) return;
        if (this.#pendingOperations > 0) {
            throw new Error("Cannot close Murmur while an operation is pending");
        }
        this.#closed = true;
        destroyIdentity(this.#identity);
    }

    async #createDiscovery(): Promise<DiscoveryBundle> {
        const now = this.#now();
        const expiresAt = now + DISCOVERY_INVITATION_TTL_MILLISECONDS;
        const bundles: ReturnType<typeof createMlsKeyPackage>[] = [];
        const stored: {
            reference: Uint8Array;
            bytes: Uint8Array;
            expiresAt: number;
        }[] = [];
        try {
            for (let index = 0; index < DEFAULT_KEY_PACKAGES; index += 1) {
                const bundle = createMlsKeyPackage(this.#identity, Math.floor(now / 1_000));
                bundles.push(bundle);
                stored.push({
                    reference: mlsKeyPackageReference(bundle.keyPackage),
                    bytes: serializeMlsKeyPackageBundle(bundle),
                    expiresAt,
                });
            }
            await this.#engine.storeKeyPackages(stored);
            return createDiscoveryBundle(
                this.#identity,
                bundles.map((bundle) => bundle.keyPackage),
                { createdAt: now, expiresAt },
            );
        } finally {
            for (const value of stored) zeroBytes(value.bytes);
            for (const bundle of bundles) destroyMlsKeyPackageBundle(bundle);
        }
    }

    #signalSync(): void {
        if (!this.#syncActive) return;
        this.#syncWakePending = true;
        this.#syncWakeResolve?.();
        this.#syncWakeResolve = undefined;
    }

    async #deliverUpdates(
        lifecycle: Pick<
            MurmurSyncOptions,
            "onUpdates" | "onContactRequested" | "onContactAdded" | "onContactRemoved"
        >,
    ): Promise<number> {
        if (this.#updatesActive) return 0;
        this.#updatesActive = true;
        this.#pendingOperations += 1;
        let delivered = 0;
        try {
            for (;;) {
                await this.#exclusive(() => this.#queueContactHellos());
                const prepared = await this.#exclusive(() => this.#engine.prepareUpdates());
                const decisions: SessionRouteDecision[] = [];
                const consumedKeys = new Set<string>();
                const globalUpdates: MurmurUpdate[] = [];
                const removedSessions: Uint8Array[] = [];
                let contactEvents: PreparedContactEvents | undefined;
                let deferredRoutes = false;
                let deferredUpdates = false;
                try {
                    for (const route of prepared.routes) {
                        let owner: SessionRouteDecision["owner"] | undefined;
                        if (
                            isContactSessionDescriptor(route.session.descriptor) &&
                            route.session.members.length === 2
                        ) {
                            owner = { version: 1, owner: "contact" };
                        } else {
                            for (const [serviceId, service] of [...this.#services].sort(
                                ([left], [right]) => left.localeCompare(right),
                            )) {
                                if (
                                    await service.onNewSession(
                                        createMurmurServiceSessionDescriptor(route.session),
                                    )
                                ) {
                                    owner = {
                                        version: 1,
                                        owner: "service",
                                        serviceId,
                                    };
                                    break;
                                }
                            }
                        }
                        if (owner === undefined && this.#services.size === 0) {
                            deferredRoutes = true;
                        } else {
                            decisions.push({
                                key: route.key,
                                sessionId: route.session.id.slice(),
                                owner: owner ?? { version: 1, owner: "ignored" },
                            });
                        }
                    }
                    for (const update of prepared.updates) {
                        if (update.owner?.owner === "contact") {
                            if ((await this.#contacts.process(update)) === "remove") {
                                removedSessions.push(update.sessionId.slice());
                            }
                            consumedKeys.add(update.key);
                            continue;
                        }
                        if (update.owner?.owner === "ignored") {
                            consumedKeys.add(update.key);
                            continue;
                        }
                        if (update.owner === undefined && lifecycle.onUpdates === undefined) {
                            deferredUpdates = true;
                            continue;
                        }
                        const publicUpdate: MurmurUpdate = Object.freeze({
                            id: update.id,
                            sessionId: update.sessionId.slice(),
                            sender: update.sender.slice(),
                            bytes: update.bytes.slice(),
                            ...(update.owner?.owner === "service"
                                ? { service: update.owner.serviceId }
                                : {}),
                        });
                        if (update.owner?.owner === "service") {
                            const service = this.#services.get(update.owner.serviceId);
                            if (service === undefined) {
                                consumedKeys.add(update.key);
                                continue;
                            }
                            await service.onUpdate(publicUpdate);
                        }
                        globalUpdates.push(publicUpdate);
                        consumedKeys.add(update.key);
                    }
                    contactEvents = await this.#contacts.prepareEvents();
                    if (
                        decisions.length === 0 &&
                        consumedKeys.size === 0 &&
                        contactEvents.keys.length === 0
                    ) {
                        break;
                    }
                    if (globalUpdates.length > 0) {
                        await lifecycle.onUpdates?.(Object.freeze(globalUpdates));
                    }
                    if (contactEvents.requested.length > 0) {
                        await lifecycle.onContactRequested?.(contactEvents.requested);
                    }
                    if (contactEvents.added.length > 0) {
                        await lifecycle.onContactAdded?.(contactEvents.added);
                    }
                    if (contactEvents.removed.length > 0) {
                        await lifecycle.onContactRemoved?.(contactEvents.removed);
                    }
                    for (const sessionId of removedSessions) {
                        await this.#exclusive(() =>
                            this.#engine.destroyOwned(sessionId, "contact"),
                        );
                    }
                    const committedContactEvents = contactEvents;
                    await this.#exclusive(() =>
                        this.#engine.commitUpdates(
                            prepared,
                            decisions,
                            consumedKeys,
                            async (transaction) =>
                                this.#contacts.deletePreparedEvents(
                                    transaction,
                                    committedContactEvents,
                                ),
                        ),
                    );
                    delivered += consumedKeys.size;
                    if (deferredRoutes || deferredUpdates) break;
                } finally {
                    for (const decision of decisions) zeroBytes(decision.sessionId);
                    for (const sessionId of removedSessions) zeroBytes(sessionId);
                    this.#zeroPreparedUpdates(prepared);
                }
            }
            return delivered;
        } finally {
            this.#pendingOperations -= 1;
            this.#updatesActive = false;
        }
    }

    #zeroPreparedUpdates(prepared: PreparedUpdates): void {
        for (const route of prepared.routes) {
            zeroBytes(route.session.id);
            zeroBytes(route.session.descriptor);
            zeroBytes(route.session.committer);
            for (const member of route.session.members) zeroBytes(member);
        }
        for (const update of prepared.updates) {
            zeroBytes(update.sessionId);
            zeroBytes(update.sender);
            zeroBytes(update.bytes);
        }
    }

    async #queueContactHellos(): Promise<void> {
        const handshakes = await this.#contacts.outgoingWithoutHello();
        for (const handshake of handshakes) {
            try {
                if (handshake.localProfile === undefined) continue;
                const session = await this.#engine.get(handshake.sessionId);
                if (session?.status !== "active") continue;
                const packet = encodeContactPacket({
                    version: 1,
                    type: "hello",
                    profile: handshake.localProfile,
                });
                try {
                    await this.#engine.sendOwnedContact(
                        handshake.sessionId,
                        packet,
                        (transaction, deliveryId) =>
                            this.#contacts.recordLocalHelloInTransaction(
                                transaction,
                                handshake.sessionId,
                                deliveryId,
                            ),
                    );
                } finally {
                    zeroBytes(packet);
                }
            } finally {
                zeroBytes(handshake.identity);
                zeroBytes(handshake.sessionId);
            }
        }
    }

    #waitSyncWake(): Promise<void> {
        if (this.#syncWakePending) {
            this.#syncWakePending = false;
            return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
            this.#syncWakeResolve = () => {
                this.#syncWakePending = false;
                resolve();
            };
        });
    }

    async #flushSync(milliseconds: number, signal: AbortSignal): Promise<void> {
        const retry = await this.#exclusive(async () => {
            await this.#queueContactHellos();
            return this.#engine.flush(signal);
        });
        if (retry) {
            this.#scheduleSyncWake(milliseconds);
        } else if (this.#syncRetryTimer !== undefined) {
            clearTimeout(this.#syncRetryTimer);
            this.#syncRetryTimer = undefined;
        }
    }

    #scheduleSyncWake(milliseconds: number): void {
        if (this.#syncRetryTimer !== undefined || !this.#syncActive) return;
        this.#syncRetryTimer = setTimeout(() => {
            this.#syncRetryTimer = undefined;
            this.#signalSync();
        }, milliseconds);
    }

    #syncDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
        return new Promise((resolve) => {
            const finish = (): void => {
                clearTimeout(timeout);
                signal.removeEventListener("abort", finish);
                resolve();
            };
            const timeout = setTimeout(finish, milliseconds);
            signal.addEventListener("abort", finish, { once: true });
        });
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Murmur client is closed");
    }

    async #tracked<T>(operation: () => Promise<T>): Promise<T> {
        this.#assertOpen();
        this.#pendingOperations += 1;
        try {
            return await operation();
        } finally {
            this.#pendingOperations -= 1;
        }
    }

    async #exclusive<T>(operation: () => Promise<T>): Promise<T> {
        this.#assertOpen();
        this.#pendingOperations += 1;
        const prior = this.#operationTail;
        let release!: () => void;
        this.#operationTail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await prior;
        try {
            this.#assertOpen();
            return await operation();
        } finally {
            this.#pendingOperations -= 1;
            release();
        }
    }
}
