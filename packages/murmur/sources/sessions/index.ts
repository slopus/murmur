import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    InboxContinuityLossError,
    WebSocketDeliveryTransport,
    createSignedDelivery,
    type DeliveryFetch,
    type DeliveryDeviceRoster,
    type RelaySessionProvider,
    type DeliveryTransport,
    type WebSocketDeliveryTransportOptions,
} from "../delivery/index.js";
import {
    decodeIdentityRoot,
    destroyIdentity,
    encodeIdentityRoot,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../crypto/index.js";
import {
    createMlsKeyPackage,
    decodeMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
    serializeMlsKeyPackageBundle,
} from "../mls/index.js";
import type { MurmurStore } from "../storage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import {
    createMurmurServiceSessionDescriptor,
    validateMurmurServiceRegistration,
    type MurmurService,
    type MurmurServiceRegistration,
} from "../services/index.js";
import {
    ACCOUNT_PEER_ROSTER_PREFIX,
    ACCOUNT_ROSTER_KEY,
    deletePreparedAccountEvents,
    encodeDeviceRosterMutation,
    observeDeviceRoster,
    parseDeviceRoster,
    prepareAccountEvents,
    serializeDeviceRoster,
    type MurmurDeviceRoster,
    type MurmurDeviceRosterEntry,
    type MurmurDormantDevice,
    type PreparedAccountEvents,
} from "../accounts/index.js";
import { randomBytes } from "../crypto/index.js";
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
    MurmurSessionMember,
    MurmurSessionPolicies,
    MurmurResetEvent,
    MurmurResetSession,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";
import { MurmurResetRequiredError } from "./types.js";

export type {
    CreateMurmurSessionOptions,
    MurmurSession,
    MurmurSessionIssue,
    MurmurSessionLimits,
    MurmurSessionListOptions,
    MurmurSessionPage,
    MurmurSessionMember,
    MurmurSessionPolicies,
    MurmurResetEvent,
    MurmurResetSession,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";
export { MurmurResetRequiredError } from "./types.js";

const IDENTITY_KEY = "murmur/identity/root";
const ACCOUNT_ROOT_KEY = "murmur/accounts/v1/root";
const RESET_PENDING_KEY = "murmur/reset/v1/pending";
const ACCOUNT_DEVICE_ACTIVITY_PREFIX = "murmur/accounts/v1/device-activity/";
const MURMUR_KEY_PREFIX = "murmur/";
const RESET_PURGE_SCAN_LIMIT = 10_000;
const DEVICE_DORMANCY_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;
// KeyPackages outlive the six-month delivery window by thirty days.
const KEY_PACKAGE_LIFETIME_SECONDS = 210 * 24 * 60 * 60;
const SYNC_RECONNECT_DELAY_MILLISECONDS = 1_000;

function encodeResetEvent(reset: MurmurResetEvent): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        id: reset.id,
        reason: reset.reason,
        generation: encodeBase64Url(reset.generation),
        head: reset.head,
        headSequence: reset.headSequence,
        sessions: reset.sessions.map((session) => ({
            id: encodeBase64Url(session.id),
            status: session.status,
            descriptor: encodeBase64Url(session.descriptor),
            members: session.members.map(encodeBase64Url),
            owner: encodeBase64Url(session.owner),
            admins: session.admins.map(encodeBase64Url),
            policies: session.policies,
        })),
    } as never);
}

function resetBytes(value: unknown, length: number | undefined, name: string): Uint8Array {
    if (typeof value !== "string") throw new Error(`Invalid stored reset ${name}`);
    const bytes = decodeBase64Url(value);
    if (
        (length === undefined
            ? bytes.length < 1 || bytes.length > 1_048_576
            : bytes.length !== length) ||
        encodeBase64Url(bytes) !== value
    ) {
        throw new Error(`Invalid stored reset ${name}`);
    }
    return bytes;
}

function decodeResetEvent(bytes: Uint8Array): MurmurResetEvent {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid stored reset event");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid stored reset event");
    }
    const input = parsed as Record<string, unknown>;
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !/^[A-Za-z0-9_-]{22}$/.test(input.id) ||
        input.reason !== "inbox_continuity_lost" ||
        (input.head !== null &&
            (typeof input.head !== "string" ||
                !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
                    input.head,
                ))) ||
        typeof input.headSequence !== "number" ||
        !Number.isSafeInteger(input.headSequence) ||
        input.headSequence < 0 ||
        !Array.isArray(input.sessions) ||
        Object.keys(input).some(
            (field) =>
                ![
                    "version",
                    "id",
                    "reason",
                    "generation",
                    "head",
                    "headSequence",
                    "sessions",
                ].includes(field),
        )
    ) {
        throw new Error("Invalid stored reset event");
    }
    const generation = resetBytes(input.generation, 32, "generation");
    const sessions = input.sessions.map((candidate): MurmurResetSession => {
        if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
            throw new Error("Invalid stored reset session");
        }
        const session = candidate as Record<string, unknown>;
        const policies = session.policies;
        if (
            !["creating", "pending", "active", "removed"].includes(session.status as string) ||
            !Array.isArray(session.members) ||
            !Array.isArray(session.admins) ||
            policies === null ||
            typeof policies !== "object" ||
            Array.isArray(policies) ||
            typeof (policies as Record<string, unknown>).adminsAssignAdmins !== "boolean" ||
            typeof (policies as Record<string, unknown>).anyoneCanAddMembers !== "boolean" ||
            Object.keys(policies).some(
                (field) => !["adminsAssignAdmins", "anyoneCanAddMembers"].includes(field),
            ) ||
            Object.keys(session).some(
                (field) =>
                    ![
                        "id",
                        "status",
                        "descriptor",
                        "members",
                        "owner",
                        "admins",
                        "policies",
                    ].includes(field),
            )
        ) {
            throw new Error("Invalid stored reset session");
        }
        return Object.freeze({
            id: resetBytes(session.id, undefined, "session ID"),
            status: session.status as MurmurSession["status"],
            descriptor: resetBytes(session.descriptor, undefined, "descriptor"),
            members: Object.freeze(
                session.members.map((member) => resetBytes(member, 32, "member")),
            ),
            owner: resetBytes(session.owner, 32, "owner"),
            admins: Object.freeze(session.admins.map((admin) => resetBytes(admin, 32, "admin"))),
            policies: Object.freeze({
                adminsAssignAdmins:
                    (policies as Record<string, unknown>).adminsAssignAdmins === true,
                anyoneCanAddMembers:
                    (policies as Record<string, unknown>).anyoneCanAddMembers === true,
            }),
        });
    });
    const reset = Object.freeze({
        id: input.id,
        reason: "inbox_continuity_lost" as const,
        generation,
        head: input.head as string | null,
        headSequence: input.headSequence,
        sessions: Object.freeze(sessions),
    });
    if (!equalBytes(encodeResetEvent(reset), bytes)) {
        throw new Error("Non-canonical stored reset event");
    }
    return reset;
}

/** Construction inputs for the stateful Murmur MLS client. */
export interface MurmurClientOptions {
    /** Relay base URL used to construct the built-in HTTP delivery transport. */
    readonly relay?: string | URL;
    /** Custom delivery transport, mutually exclusive with `relay` and `sessionProvider`. */
    readonly transport?: DeliveryTransport;
    /** Application-authenticated issuer for an additive negotiated WebSocket relay. */
    readonly sessionProvider?: RelaySessionProvider;
    /** Connection and retry policy for the negotiated WebSocket delivery transport. */
    readonly webSocket?: WebSocketDeliveryTransportOptions;
    /** Fetch implementation used by the built-in HTTP delivery transport. */
    readonly fetch?: DeliveryFetch;
    /** Exclusive durable state store for this client identity. */
    readonly store: MurmurStore;
    /**
     * Account identity root used to initialize an empty per-device store.
     *
     * When the store already contains an identity, the supplied public key must match it.
     */
    readonly identity?: IdentityKeyPair;
    /** Optional resource bounds; omitted fields use Murmur's defaults. */
    readonly limits?: MurmurSessionLimits;
    /** Clock override used for protocol timestamps and expiry checks. Defaults to `Date.now`. */
    readonly now?: () => number;
    /** Optional typed services available to claim and process sessions. */
    readonly services?: readonly MurmurServiceRegistration[];
}

/** Stateful identity, bootstrap, and opaque MLS-session facade. */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #engine: SessionEngine;
    readonly #services = new Map<string, MurmurService>();
    readonly #store: MurmurStore;
    readonly #now: () => number;
    readonly #account: IdentityKeyPair;
    readonly #transport: DeliveryTransport;
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
        limits: MurmurSessionLimits,
        now: () => number,
        services: readonly MurmurServiceRegistration[],
        account: IdentityKeyPair,
    ) {
        this.#identity = identity;
        this.#store = store;
        this.#now = now;
        this.#account = account;
        this.#transport = transport;
        this.#engine = new SessionEngine(
            identity,
            store,
            transport,
            limits,
            now,
            account.publicKey,
        );
        for (const registration of services) {
            this.#services.set(registration.id, registration.service);
        }
    }

    /** Open or create one durable per-device Murmur identity and its account state. */
    static async open(options: MurmurClientOptions): Promise<MurmurClient> {
        const deliveryChoices = [
            options.relay !== undefined,
            options.transport !== undefined,
            options.sessionProvider !== undefined,
        ].filter(Boolean).length;
        if (deliveryChoices !== 1) {
            throw new Error(
                "Provide exactly one relay URL, delivery transport, or relay-session provider",
            );
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
        let account: IdentityKeyPair | undefined;
        try {
            await options.store.transaction(async (transaction) => {
                const stored = await transaction.get(IDENTITY_KEY);
                if (stored !== undefined) {
                    try {
                        identity = decodeIdentityRoot(stored);
                    } finally {
                        zeroBytes(stored);
                    }
                } else {
                    identity = generateIdentityKeyPair();
                    const encoded = encodeIdentityRoot(identity);
                    try {
                        await transaction.set(IDENTITY_KEY, encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                }

                const storedAccount = await transaction.get(ACCOUNT_ROOT_KEY);
                if (storedAccount !== undefined) {
                    try {
                        account = decodeIdentityRoot(storedAccount);
                        if (
                            options.identity !== undefined &&
                            !equalBytes(account.publicKey, options.identity.publicKey)
                        ) {
                            throw new Error("Stored Murmur account differs from supplied identity");
                        }
                    } finally {
                        zeroBytes(storedAccount);
                    }
                } else {
                    if (options.identity === undefined) {
                        account = generateIdentityKeyPair();
                    } else {
                        const encoded = encodeIdentityRoot(options.identity);
                        try {
                            account = decodeIdentityRoot(encoded);
                        } finally {
                            zeroBytes(encoded);
                        }
                    }
                    const encoded = encodeIdentityRoot(account);
                    try {
                        await transaction.set(ACCOUNT_ROOT_KEY, encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                }
            });
            if (identity === undefined || account === undefined) {
                throw new Error("Murmur account did not open");
            }
            const transport =
                options.transport ??
                (options.sessionProvider === undefined
                    ? new HttpDeliveryTransport(
                          options.relay as string | URL,
                          options.fetch === undefined ? {} : { fetch: options.fetch },
                      )
                    : new WebSocketDeliveryTransport(
                          identity,
                          options.sessionProvider,
                          options.webSocket,
                      ));
            const client = new MurmurClient(
                identity,
                options.store,
                transport,
                options.limits ?? {},
                options.now ?? Date.now,
                services,
                account,
            );
            await client.#ensureRegistered();
            return client;
        } catch (error: unknown) {
            if (identity !== undefined) destroyIdentity(identity);
            if (account !== undefined) destroyIdentity(account);
            throw error;
        }
    }

    /** Defensive copy of the stable public account identity key. */
    get identity(): Uint8Array {
        this.#assertOpen();
        return this.#account.publicKey.slice();
    }

    /** Defensive copy of this store's independently generated device inbox key. */
    get deviceKey(): Uint8Array {
        this.#assertOpen();
        return this.#identity.publicKey.slice();
    }

    /** Stable account identity shared by every restored device. */
    get accountKey(): Uint8Array {
        this.#assertOpen();
        return this.#account.publicKey.slice();
    }

    /** Read this account's authenticated device roster entries. */
    async devices(): Promise<readonly MurmurDeviceRosterEntry[]> {
        return this.#tracked(async () => {
            const roster = await this.#ownRoster();
            return roster === undefined
                ? []
                : roster.devices.map((entry) =>
                      Object.freeze({
                          ...entry,
                          deviceKey: entry.deviceKey.slice(),
                      }),
                  );
        });
    }

    /** List active sibling devices with no authenticated activity for six months. */
    async dormantDevices(): Promise<readonly MurmurDormantDevice[]> {
        return this.#tracked(async () => {
            const roster = await this.#ownRoster();
            if (roster === undefined) return [];
            const now = this.#now();
            const dormant: MurmurDormantDevice[] = [];
            for (const entry of roster.devices) {
                if (equalBytes(entry.deviceKey, this.#identity.publicKey)) {
                    continue;
                }
                const bytes = await this.#store.get(
                    `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(entry.deviceKey)}`,
                );
                let lastActivityAt = 0;
                try {
                    if (bytes !== undefined) {
                        const encoded = utf8Decode(bytes);
                        if (!/^\d{16}$/.test(encoded)) {
                            throw new Error("Invalid stored device activity");
                        }
                        lastActivityAt = Number(encoded);
                    }
                } finally {
                    if (bytes !== undefined) zeroBytes(bytes);
                }
                const dormantSince = lastActivityAt + DEVICE_DORMANCY_MILLISECONDS;
                if (now >= dormantSince) {
                    dormant.push(
                        Object.freeze({
                            device: entry.deviceKey.slice(),
                            lastActivityAt,
                            dormantSince,
                        }),
                    );
                }
            }
            return Object.freeze(dormant);
        });
    }

    async #ownRoster(): Promise<MurmurDeviceRoster | undefined> {
        const bytes = await this.#store.get(ACCOUNT_ROSTER_KEY);
        if (bytes === undefined) return undefined;
        try {
            return parseDeviceRoster(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #observeRoster(
        eventId: string,
        roster: MurmurDeviceRoster | DeliveryDeviceRoster,
    ): Promise<void> {
        const bytes = serializeDeviceRoster(roster);
        try {
            await this.#store.transaction((transaction) =>
                observeDeviceRoster(transaction, this.#account.publicKey, eventId, bytes),
            );
        } finally {
            zeroBytes(bytes);
        }
    }

    async #ensureRegistered(forceReset: boolean = false): Promise<void> {
        const current = await this.#transport.readDeviceRoster?.(this.#account.publicKey);
        const currentEntry = current?.devices.find((entry) =>
            equalBytes(entry.deviceKey, this.#identity.publicKey),
        );
        if (!forceReset && current !== undefined && currentEntry !== undefined) {
            await this.#observeRoster(`lookup-${current.revision}`, current);
            return;
        }
        const bundle = createMlsKeyPackage(
            this.#identity,
            Math.floor(this.#now() / 1_000),
            KEY_PACKAGE_LIFETIME_SECONDS,
            this.#account.publicKey,
        );
        try {
            const reference = mlsKeyPackageReference(bundle.keyPackage);
            const stored = serializeMlsKeyPackageBundle(bundle);
            try {
                await this.#engine.storeKeyPackages([
                    {
                        reference,
                        bytes: stored,
                        expiresAt: Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                        reusable: true,
                    },
                ]);
            } finally {
                zeroBytes(reference);
                zeroBytes(stored);
            }
            const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
            const recipients = [
                ...new Map(
                    [
                        ...(current?.devices.map((entry) => entry.deviceKey) ?? []),
                        this.#identity.publicKey,
                    ].map((device) => [encodeBase64Url(device), device]),
                ).values(),
            ];
            const now = this.#now();
            const delivery = createSignedDelivery(
                this.#account,
                recipients,
                encodeDeviceRosterMutation({
                    version: 1,
                    type: "register",
                    deviceKey: this.#identity.publicKey,
                    resetGeneration:
                        currentEntry === undefined ? 0 : currentEntry.resetGeneration + 1,
                    keyPackage,
                }),
                { createdAt: now, expiresAt: now + 180 * 24 * 60 * 60 * 1_000 - 60_000 },
            );
            const roster =
                this.#transport.mutateDeviceRoster === undefined
                    ? {
                          version: 1 as const,
                          accountKey: this.#account.publicKey,
                          revision: (current?.revision ?? 0) + 1,
                          devices: [
                              ...(current?.devices ?? []),
                              {
                                  deviceKey: this.#identity.publicKey,
                                  resetGeneration:
                                      currentEntry === undefined
                                          ? 0
                                          : currentEntry.resetGeneration + 1,
                              },
                          ].sort((left, right) =>
                              encodeBase64Url(left.deviceKey).localeCompare(
                                  encodeBase64Url(right.deviceKey),
                              ),
                          ),
                          admissions: [
                              ...(current?.admissions ?? []),
                              { deviceKey: this.#identity.publicKey, keyPackage },
                          ],
                      }
                    : await this.#transport.mutateDeviceRoster(delivery);
            await this.#observeRoster(delivery.id, roster);
        } finally {
            destroyMlsKeyPackageBundle(bundle);
        }
    }

    /** Remove any account device, including this device, using the account identity key. */
    async removeDevice(deviceKey: Uint8Array): Promise<void> {
        await this.#exclusive(async () => {
            const roster = await this.#ownRoster();
            if (roster === undefined) throw new Error("Account has no device roster");
            const entry = roster.devices.find((candidate) =>
                equalBytes(candidate.deviceKey, deviceKey),
            );
            if (entry === undefined) throw new Error("Device is not registered");
            if (this.#transport.mutateDeviceRoster === undefined) {
                throw new Error("Delivery transport does not support device rosters");
            }
            const recipients = roster.devices
                .filter((candidate) => !equalBytes(candidate.deviceKey, deviceKey))
                .map((candidate) => candidate.deviceKey);
            const now = this.#now();
            const delivery = createSignedDelivery(
                this.#account,
                recipients,
                encodeDeviceRosterMutation({
                    version: 1,
                    type: "remove",
                    deviceKey,
                    resetGeneration: entry.resetGeneration,
                }),
                { createdAt: now, expiresAt: now + 180 * 24 * 60 * 60 * 1_000 - 60_000 },
            );
            const updated = await this.#transport.mutateDeviceRoster(delivery);
            await this.#observeRoster(delivery.id, updated);
        });
        this.#signalSync();
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

    /** Create and durably retain one bare MLS KeyPackage for direct session admission. */
    async createKeyPackage(): Promise<MurmurSessionMember> {
        return this.#exclusive(async () => {
            const bundle = createMlsKeyPackage(
                this.#identity,
                Math.floor(this.#now() / 1_000),
                KEY_PACKAGE_LIFETIME_SECONDS,
                this.#account.publicKey,
            );
            try {
                const reference = mlsKeyPackageReference(bundle.keyPackage);
                const bytes = serializeMlsKeyPackageBundle(bundle);
                try {
                    await this.#engine.storeKeyPackages([
                        {
                            reference,
                            bytes,
                            expiresAt: Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                        },
                    ]);
                } finally {
                    zeroBytes(reference);
                    zeroBytes(bytes);
                }
                return Object.freeze({
                    identity: this.#account.publicKey.slice(),
                    keyPackage: encodeMlsKeyPackage(bundle.keyPackage),
                });
            } finally {
                destroyMlsKeyPackageBundle(bundle);
            }
        });
    }

    /** Create a two-or-more-member MLS session from bare MLS admission material. */
    async createSession(options: CreateMurmurSessionOptions): Promise<MurmurSession> {
        const owner =
            options.service === undefined
                ? undefined
                : ({ version: 1, owner: "service", serviceId: options.service } as const);
        if (options.service !== undefined && !this.#services.has(options.service)) {
            throw new Error("Session service is not registered");
        }
        const session = await this.#exclusive(() =>
            this.#engine.create(
                {
                    descriptor: options.descriptor,
                    ...(options.adminsAssignAdmins === undefined
                        ? {}
                        : { adminsAssignAdmins: options.adminsAssignAdmins }),
                    ...(options.anyoneCanAddMembers === undefined
                        ? {}
                        : { anyoneCanAddMembers: options.anyoneCanAddMembers }),
                    members: options.members.map((member) => {
                        const keyPackage = decodeMlsKeyPackage(member.keyPackage);
                        if (!equalBytes(keyPackage.leafNode.credential.identity, member.identity)) {
                            throw new Error("Session member account does not match its KeyPackage");
                        }
                        return { identity: keyPackage.leafNode.signatureKey, keyPackage };
                    }),
                },
                owner,
            ),
        );
        this.#signalSync();
        return session;
    }

    /** Return a defensive snapshot of one local session, or `undefined` when it is unknown. */
    async session(id: Uint8Array): Promise<MurmurSession | undefined> {
        return this.#tracked(() => this.#engine.get(id));
    }

    /** List one bounded page of local sessions in durable key order. */
    async sessions(options: MurmurSessionListOptions = {}): Promise<MurmurSessionPage> {
        return this.#tracked(() => this.#engine.list(options));
    }

    /** Activate an application-owned pending session and release its buffered updates. */
    async activateSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.activate(id));
        this.#signalSync();
    }

    /** Terminally reject and destroy an application-owned pending session. */
    async ignoreSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.ignore(id));
    }

    /** Abandon a blocked local membership operation and destroy the whole session. */
    async abandonSession(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.abandon(id));
    }

    /**
     * Encrypt and durably queue application bytes without waiting for relay or peer state.
     *
     * Sends made while a membership Commit is staged use its post-Commit epoch and publish
     * only after that Commit is adopted from its relay echo and every required Welcome publishes.
     */
    async send(id: Uint8Array, bytes: Uint8Array): Promise<string> {
        const deliveryId = await this.#exclusive(() => this.#engine.send(id, bytes));
        this.#signalSync();
        return deliveryId;
    }

    /** Durably request one MLS member addition from bare admission material. */
    async addMember(id: Uint8Array, member: MurmurSessionMember): Promise<void> {
        await this.#exclusive(() => {
            const keyPackage = decodeMlsKeyPackage(member.keyPackage);
            if (!equalBytes(keyPackage.leafNode.credential.identity, member.identity)) {
                throw new Error("Session member account does not match its KeyPackage");
            }
            return this.#engine.add(id, {
                identity: keyPackage.leafNode.signatureKey,
                keyPackage,
            });
        });
        this.#signalSync();
    }

    /** Durably request removal of one non-owner account and return before convergence. */
    async removeMember(id: Uint8Array, identity: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.remove(id, identity));
        this.#signalSync();
    }

    /** Durably request an admin grant and return before its Commit is published. */
    async grantAdmin(id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.grantAdmin(id, account));
        this.#signalSync();
    }

    /** Durably request an owner-authorized admin revocation. */
    async revokeAdmin(id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.revokeAdmin(id, account));
        this.#signalSync();
    }

    /** Durably request owner-controlled policy changes. */
    async setPolicies(id: Uint8Array, policies: MurmurSessionPolicies): Promise<void> {
        await this.#exclusive(() => this.#engine.setPolicies(id, policies));
        this.#signalSync();
    }

    /** Durably request removal of every local-account device from one session. */
    async leave(id: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#engine.leave(id));
        this.#signalSync();
    }

    /** Return the bounded, durable diagnostics retained for terminal session failures. */
    async issues(): Promise<readonly MurmurSessionIssue[]> {
        return this.#tracked(() => this.#engine.issues());
    }

    async #pendingReset(): Promise<MurmurResetEvent | undefined> {
        const bytes = await this.#store.get(RESET_PENDING_KEY);
        if (bytes === undefined) return undefined;
        try {
            return decodeResetEvent(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #recordReset(loss: InboxContinuityLossError): Promise<MurmurResetEvent> {
        const existing = await this.#pendingReset();
        if (existing !== undefined) return existing;
        const sessions: MurmurResetSession[] = [];
        let cursor: string | null = null;
        do {
            const page = await this.#engine.list(cursor === null ? {} : { after: cursor });
            for (const session of page.sessions) {
                sessions.push(
                    Object.freeze({
                        id: session.id.slice(),
                        status: session.status,
                        descriptor: session.descriptor.slice(),
                        members: Object.freeze(session.members.map((member) => member.slice())),
                        owner: session.owner.slice(),
                        admins: Object.freeze(session.admins.map((admin) => admin.slice())),
                        policies: Object.freeze({ ...session.policies }),
                    }),
                );
            }
            cursor = page.cursor;
        } while (cursor !== null);
        const reset: MurmurResetEvent = Object.freeze({
            id: encodeBase64Url(randomBytes(16)),
            reason: "inbox_continuity_lost",
            generation: loss.generation.slice(),
            head: loss.head,
            headSequence: loss.headSequence,
            sessions: Object.freeze(sessions),
        });
        const encoded = encodeResetEvent(reset);
        try {
            await this.#store.transaction(async (transaction) => {
                const pending = await transaction.get(RESET_PENDING_KEY);
                try {
                    if (pending === undefined) await transaction.set(RESET_PENDING_KEY, encoded);
                } finally {
                    if (pending !== undefined) zeroBytes(pending);
                }
            });
        } finally {
            zeroBytes(encoded);
        }
        return (await this.#pendingReset())!;
    }

    #preserveAcrossReset(key: string): boolean {
        return (
            key === IDENTITY_KEY ||
            key === ACCOUNT_ROOT_KEY ||
            key === ACCOUNT_ROSTER_KEY ||
            key.startsWith(ACCOUNT_PEER_ROSTER_PREFIX) ||
            key.startsWith(ACCOUNT_DEVICE_ACTIVITY_PREFIX) ||
            key === RESET_PENDING_KEY
        );
    }

    async #purgeReset(reset: MurmurResetEvent): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            let after: string | undefined;
            for (;;) {
                const page = await transaction.scan(MURMUR_KEY_PREFIX, {
                    ...(after === undefined ? {} : { after }),
                    limit: RESET_PURGE_SCAN_LIMIT,
                });
                if (page.size === 0) break;
                for (const [key, value] of page) {
                    after = key;
                    try {
                        if (!this.#preserveAcrossReset(key)) await transaction.delete(key);
                    } finally {
                        zeroBytes(value);
                    }
                }
                if (page.size < RESET_PURGE_SCAN_LIMIT) break;
            }
            await this.#engine.adoptInboxBaselineInTransaction(
                transaction,
                reset.generation,
                reset.head,
                reset.headSequence,
            );
            await transaction.delete(RESET_PENDING_KEY);
        });
        try {
            await this.#engine.acknowledgeInboxBaseline(reset.head);
        } catch {
            // The committed cursor causes the next synchronization to retry this signed ACK.
        }
        await this.#ensureRegistered(true);
    }

    async #completeReset(
        reset: MurmurResetEvent,
        onReset: MurmurSyncOptions["onReset"],
    ): Promise<never> {
        if (onReset === undefined) throw new MurmurResetRequiredError(reset, false);
        await onReset(reset);
        await this.#exclusive(async () => {
            await this.#purgeReset(reset);
        });
        throw new MurmurResetRequiredError(reset, true);
    }

    /**
     * Run one bounded publish-and-inbox synchronization cycle.
     *
     * Lifecycle callbacks obey the same durable retry rules as `sync()`. This
     * foreground form cannot run while the persistent synchronization loop is active.
     */
    async synchronize(
        options: MurmurSynchronizeOptions = {},
        lifecycle: Pick<
            MurmurSyncOptions,
            "onUpdates" | "onDeviceAdded" | "onDeviceRevoked" | "onReset" | "onDeviceDormant"
        > = {},
    ): Promise<MurmurSynchronizeResult> {
        if (this.#syncActive) {
            throw new Error("Cannot page synchronization while SSE sync is active");
        }
        const pendingReset = await this.#pendingReset();
        if (pendingReset !== undefined) {
            return this.#completeReset(pendingReset, lifecycle.onReset);
        }
        await this.#exclusive(() => this.#queueAccountWork());
        let result: MurmurSynchronizeResult;
        try {
            result = await this.#exclusive(() => this.#engine.synchronize(options));
        } catch (error: unknown) {
            if (!(error instanceof InboxContinuityLossError)) throw error;
            const reset = await this.#exclusive(() => this.#recordReset(error));
            return this.#completeReset(reset, lifecycle.onReset);
        }
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
            const pendingReset = await this.#pendingReset();
            if (pendingReset !== undefined) {
                await this.#completeReset(pendingReset, options.onReset);
            }
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
                    if (error instanceof InboxContinuityLossError) {
                        const reset = await this.#exclusive(() => this.#recordReset(error));
                        await this.#completeReset(reset, options.onReset);
                    }
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
        destroyIdentity(this.#account);
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
            "onUpdates" | "onDeviceAdded" | "onDeviceRevoked" | "onDeviceDormant"
        >,
    ): Promise<number> {
        if (this.#updatesActive) return 0;
        this.#updatesActive = true;
        this.#pendingOperations += 1;
        let delivered = 0;
        try {
            if (lifecycle.onDeviceDormant !== undefined) {
                const dormant = await this.dormantDevices();
                if (dormant.length > 0) await lifecycle.onDeviceDormant(dormant);
            }
            for (;;) {
                await this.#exclusive(() => this.#queueAccountWork());
                const prepared = await this.#exclusive(() => this.#engine.prepareUpdates());
                const decisions: SessionRouteDecision[] = [];
                const consumedKeys = new Set<string>();
                const globalUpdates: MurmurUpdate[] = [];
                let accountEvents: PreparedAccountEvents | undefined;
                let deferredRoutes = false;
                let deferredUpdates = false;
                try {
                    for (const route of prepared.routes) {
                        let owner: SessionRouteDecision["owner"] | undefined;
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
                    accountEvents = await prepareAccountEvents(this.#store);
                    if (
                        decisions.length === 0 &&
                        consumedKeys.size === 0 &&
                        accountEvents.keys.length === 0
                    ) {
                        break;
                    }
                    if (globalUpdates.length > 0) {
                        await lifecycle.onUpdates?.(Object.freeze(globalUpdates));
                    }
                    if (accountEvents.added.length > 0) {
                        await lifecycle.onDeviceAdded?.(accountEvents.added);
                    }
                    if (accountEvents.revoked.length > 0) {
                        await lifecycle.onDeviceRevoked?.(accountEvents.revoked);
                    }
                    const committedAccountEvents = accountEvents;
                    await this.#exclusive(() =>
                        this.#engine.commitUpdates(
                            prepared,
                            decisions,
                            consumedKeys,
                            async (transaction) => {
                                await deletePreparedAccountEvents(
                                    transaction,
                                    committedAccountEvents,
                                );
                            },
                        ),
                    );
                    delivered += consumedKeys.size;
                    if (deferredRoutes || deferredUpdates) break;
                } finally {
                    for (const decision of decisions) zeroBytes(decision.sessionId);
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
            zeroBytes(route.session.owner);
            for (const admin of route.session.admins) zeroBytes(admin);
            for (const member of route.session.members) zeroBytes(member);
        }
        for (const update of prepared.updates) {
            zeroBytes(update.sessionId);
            zeroBytes(update.sender);
            zeroBytes(update.bytes);
        }
    }

    /** Refresh relay-owned account state before automatic MLS convergence. */
    async #queueAccountWork(): Promise<void> {
        await this.#store.set(
            `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(this.#identity.publicKey)}`,
            utf8Encode(String(this.#now()).padStart(16, "0")),
        );
        const roster = await this.#transport.readDeviceRoster?.(this.#account.publicKey);
        if (roster !== undefined) await this.#observeRoster(`lookup-${roster.revision}`, roster);
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
            await this.#queueAccountWork();
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
