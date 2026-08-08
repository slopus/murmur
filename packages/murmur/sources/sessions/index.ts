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
import { SessionEngine, type PreparedUpdates } from "./impl/sessionEngine.js";
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
}

/** Stateful identity, discovery, bootstrap, and opaque MLS-session facade. */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #engine: SessionEngine;
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
    ) {
        this.#identity = identity;
        this.#now = now;
        this.#discoveryTransport = discoveryTransport;
        this.#engine = new SessionEngine(identity, store, transport, limits, now);
    }

    /** Open or create one durable single-device Murmur identity. */
    static async open(options: MurmurClientOptions): Promise<MurmurClient> {
        if ((options.relay === undefined) === (options.transport === undefined)) {
            throw new Error("Provide exactly one relay URL or delivery transport");
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

    async createSession(options: CreateMurmurSessionOptions): Promise<MurmurSession> {
        const session = await this.#exclusive(() => this.#engine.create(options));
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
        lifecycle: Pick<MurmurSyncOptions, "onUpdates"> = {},
    ): Promise<MurmurSynchronizeResult> {
        if (this.#syncActive) {
            throw new Error("Cannot page synchronization while SSE sync is active");
        }
        const result = await this.#exclusive(() => this.#engine.synchronize(options));
        await this.#deliverUpdates(lifecycle.onUpdates);
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
            await this.#deliverUpdates(options.onUpdates);
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
                            await this.#deliverUpdates(options.onUpdates);
                            continue;
                        }
                        if (outcome.result.done) break;
                        const result = await this.#exclusive(() =>
                            this.#engine.completeStreamEvent(outcome.result.value, signal),
                        );
                        if (result.transientPublicationFailures > 0) {
                            this.#scheduleSyncWake(SYNC_RECONNECT_DELAY_MILLISECONDS);
                        }
                        await this.#deliverUpdates(options.onUpdates);
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

    async #deliverUpdates(handler: MurmurSyncOptions["onUpdates"]): Promise<number> {
        if (handler === undefined) return 0;
        if (this.#updatesActive) return 0;
        this.#updatesActive = true;
        this.#pendingOperations += 1;
        let delivered = 0;
        try {
            for (;;) {
                const prepared = await this.#exclusive(() => this.#engine.prepareUpdates());
                if (prepared.updates.length === 0) break;
                const updates: readonly MurmurUpdate[] = Object.freeze(
                    prepared.updates.map((update) =>
                        Object.freeze({
                            id: update.id,
                            sessionId: update.sessionId.slice(),
                            sender: update.sender.slice(),
                            bytes: update.bytes.slice(),
                        }),
                    ),
                );
                try {
                    await handler?.(updates);
                    await this.#exclusive(() => this.#engine.commitUpdates(prepared));
                    delivered += updates.length;
                } finally {
                    this.#zeroPreparedUpdates(prepared);
                }
                if (prepared.exhausted) break;
            }
            return delivered;
        } finally {
            this.#pendingOperations -= 1;
            this.#updatesActive = false;
        }
    }

    #zeroPreparedUpdates(prepared: PreparedUpdates): void {
        for (const update of prepared.updates) {
            zeroBytes(update.sessionId);
            zeroBytes(update.sender);
            zeroBytes(update.bytes);
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
        const retry = await this.#exclusive(() => this.#engine.flush(signal));
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
