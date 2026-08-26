import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    InboxContinuityLossError,
    WebSocketDeliveryTransport,
    type DeliveryFetch,
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
    verifyMlsKeyPackage,
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
    accountSyncSessionDescriptor,
    authorizeDeviceProvisioning,
    completeDeviceProvisioning,
    createDeviceLinkMaterial,
    createInitialDeviceRoster,
    decodeAccountSyncPacket,
    deletePreparedAccountEvents,
    encodeAccountSyncPacket,
    encodeDeviceCredential,
    isAccountSyncSessionDescriptor,
    isActiveDevice,
    observeDeviceRoster,
    parseDeviceLinkMaterial,
    parseDeviceLinkRequest,
    parseDeviceRoster,
    parseProvisioningEnvelope,
    prepareAccountEvents,
    serializeDeviceLinkMaterial,
    serializeDeviceLinkRequest,
    serializeDeviceRoster,
    serializeProvisioningEnvelope,
    revokeDeviceFromRoster,
    resetDeviceInRoster,
    type MurmurDeviceRoster,
    type MurmurDeviceRosterEntry,
    type MurmurDormantDevice,
    type PreparedAccountEvents,
} from "../accounts/index.js";
import { randomBytes } from "../crypto/index.js";
import type { StoreTransaction } from "../storage/index.js";
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
const DEVICE_CREDENTIAL_KEY = "murmur/accounts/v1/device-credential";
const LINK_MATERIAL_KEY = "murmur/accounts/v1/link-material";
const ACCOUNT_SESSION_KEY = "murmur/accounts/v1/sync-session";
const ACCOUNT_ADMISSION_SENT_KEY = "murmur/accounts/v1/admission-sent";
const ACCOUNT_BROADCAST_KEY = "murmur/accounts/v1/roster-broadcast";
const RESET_PENDING_KEY = "murmur/reset/v1/pending";
const RESET_READMISSION_PREFIX = "murmur/reset/v1/re-admissions/";
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
     * Identity root used to initialize an empty store.
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
    #account: IdentityKeyPair | undefined;
    #deviceCredential: Uint8Array | undefined;
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
        account: IdentityKeyPair | undefined,
        deviceCredential: Uint8Array | undefined,
    ) {
        this.#identity = identity;
        this.#store = store;
        this.#now = now;
        this.#account = account;
        this.#deviceCredential = deviceCredential;
        this.#engine = new SessionEngine(
            identity,
            store,
            transport,
            limits,
            now,
            deviceCredential ?? identity.publicKey,
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
        let deviceCredential: Uint8Array | undefined;
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
                    } finally {
                        zeroBytes(stored);
                    }
                } else {
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
                }

                const storedAccount = await transaction.get(ACCOUNT_ROOT_KEY);
                if (storedAccount !== undefined) {
                    try {
                        account = decodeIdentityRoot(storedAccount);
                    } finally {
                        zeroBytes(storedAccount);
                    }
                }
                deviceCredential = await transaction.get(DEVICE_CREDENTIAL_KEY);
            });
            if (identity === undefined) throw new Error("Murmur identity did not open");
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
                deviceCredential,
            );
            return client;
        } catch (error: unknown) {
            if (identity !== undefined) destroyIdentity(identity);
            if (account !== undefined) destroyIdentity(account);
            if (deviceCredential !== undefined) zeroBytes(deviceCredential);
            throw error;
        }
    }

    /** Defensive copy of the single public identity key. */
    get identity(): Uint8Array {
        this.#assertOpen();
        return this.#identity.publicKey.slice();
    }

    /** Stable account signing key; equals the device identity until devices link. */
    get accountKey(): Uint8Array {
        this.#assertOpen();
        return (this.#account ?? this.#identity).publicKey.slice();
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
                          authorization: entry.authorization.slice(),
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
                if (
                    entry.status !== "active" ||
                    equalBytes(entry.deviceKey, this.#identity.publicKey)
                ) {
                    continue;
                }
                const bytes = await this.#store.get(
                    `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(entry.deviceKey)}`,
                );
                let lastActivityAt = roster.issuedAt;
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

    /**
     * Begin linking this fresh device to an existing account.
     *
     * Returns short-lived request bytes for the application to transport to an
     * active device, for example rendered as a QR code. The matching ephemeral
     * secret is retained durably until {@link completeDeviceLink}.
     */
    async linkDevice(): Promise<Uint8Array> {
        return this.#exclusive(async () => {
            if (this.#account !== undefined || (await this.#ownRoster()) !== undefined) {
                throw new Error("Device already belongs to an account");
            }
            const bundle = createMlsKeyPackage(this.#identity, Math.floor(this.#now() / 1_000));
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
                const material = createDeviceLinkMaterial(
                    this.#identity,
                    encodeMlsKeyPackage(bundle.keyPackage),
                    this.#now(),
                );
                const stored = serializeDeviceLinkMaterial(material);
                try {
                    await this.#store.transaction((transaction) =>
                        transaction.set(LINK_MATERIAL_KEY, stored),
                    );
                } finally {
                    zeroBytes(material.ephemeralSecretKey);
                    zeroBytes(stored);
                }
                return serializeDeviceLinkRequest(material.request);
            } finally {
                destroyMlsKeyPackageBundle(bundle);
            }
        });
    }

    /**
     * Authorize one verified device-link request from an active device.
     *
     * Signs the next roster revision, adds the new device to the built-in
     * account synchronization session, and returns encrypted envelope bytes the
     * application transports back to the new device. Session membership then
     * converges automatically.
     */
    async authorizeDevice(requestBytes: Uint8Array): Promise<Uint8Array> {
        const envelope = await this.#exclusive(async () => {
            const request = parseDeviceLinkRequest(requestBytes, this.#now());
            const account = this.#account ?? this.#identity;
            let roster = await this.#ownRoster();
            if (roster === undefined) {
                roster = createInitialDeviceRoster(
                    account,
                    this.#identity,
                    this.#now(),
                    randomBytes(16),
                );
            }
            const authorized = authorizeDeviceProvisioning({
                request,
                account,
                authorDevice: this.#identity,
                roster,
                now: this.#now(),
            });
            const keyPackage = decodeMlsKeyPackage(request.keyPackage);
            await this.#store.transaction(async (transaction) => {
                await observeDeviceRoster(
                    transaction,
                    account.publicKey,
                    `local-${encodeBase64Url(randomBytes(12))}`,
                    account.publicKey,
                    this.#identity.publicKey,
                    serializeDeviceRoster(authorized.roster),
                );
            });
            const sessionId = await this.#store.get(ACCOUNT_SESSION_KEY);
            if (sessionId === undefined) {
                await this.#engine.create(
                    {
                        descriptor: accountSyncSessionDescriptor(),
                        members: [{ identity: request.deviceKey, keyPackage }],
                    },
                    { version: 1, owner: "account" },
                    async (transaction, id) => {
                        await transaction.set(ACCOUNT_SESSION_KEY, id.slice());
                    },
                );
            } else {
                try {
                    await this.#engine.add(sessionId, {
                        identity: request.deviceKey,
                        keyPackage,
                    });
                } finally {
                    zeroBytes(sessionId);
                }
            }
            const envelopeBytes = serializeProvisioningEnvelope(authorized.envelope);
            await this.#engine.publishProvisioningEnvelope(request.deviceKey, envelopeBytes);
            return envelopeBytes;
        });
        this.#signalSync();
        return envelope;
    }

    /**
     * Complete linking on the new device from transported envelope bytes.
     *
     * Adopts the account root, roster, and account-authorized device credential.
     * The device then automatically joins the account synchronization session
     * and receives Welcomes for every converged session.
     */
    async completeDeviceLink(envelopeBytes: Uint8Array): Promise<void> {
        await this.#exclusive(() => this.#completeDeviceLinkBytes(envelopeBytes));
        this.#signalSync();
    }

    async #completeDeviceLinkBytes(envelopeBytes: Uint8Array): Promise<void> {
        const stored = await this.#store.get(LINK_MATERIAL_KEY);
        if (stored === undefined) throw new Error("No pending device link");
        let material: ReturnType<typeof parseDeviceLinkMaterial>;
        try {
            material = parseDeviceLinkMaterial(stored, this.#now());
        } finally {
            zeroBytes(stored);
        }
        try {
            const envelope = parseProvisioningEnvelope(envelopeBytes);
            const provisioned = completeDeviceProvisioning(material, envelope, this.#now());
            const credential = encodeDeviceCredential(provisioned.roster, this.#identity.publicKey);
            const accountRoot = encodeIdentityRoot(provisioned.account);
            const rosterBytes = serializeDeviceRoster(provisioned.roster);
            try {
                await this.#store.transaction(async (transaction) => {
                    await transaction.set(ACCOUNT_ROOT_KEY, accountRoot);
                    await transaction.set(DEVICE_CREDENTIAL_KEY, credential);
                    await observeDeviceRoster(
                        transaction,
                        provisioned.account.publicKey,
                        `link-${encodeBase64Url(envelope.requestId)}`,
                        provisioned.account.publicKey,
                        envelope.authorDeviceKey,
                        rosterBytes,
                    );
                    await transaction.delete(LINK_MATERIAL_KEY);
                    await this.#engine.deletePendingProvisioningEnvelope(transaction);
                });
            } finally {
                zeroBytes(accountRoot);
                zeroBytes(rosterBytes);
            }
            this.#account = provisioned.account;
            this.#deviceCredential = credential.slice();
            this.#engine.adoptDeviceCredential(credential);
        } finally {
            zeroBytes(material.ephemeralSecretKey);
        }
    }

    /**
     * Revoke another account device from any active device.
     *
     * Signs the next roster revision, then automatically drives MLS Removes in
     * every known session and publishes the authenticated roster to peers.
     */
    async revokeDevice(deviceKey: Uint8Array): Promise<void> {
        await this.#exclusive(async () => {
            const account = this.#account ?? this.#identity;
            const roster = await this.#ownRoster();
            if (roster === undefined) throw new Error("Account has no device roster");
            const revoked = revokeDeviceFromRoster(
                roster,
                account,
                this.#identity,
                deviceKey,
                this.#now(),
                randomBytes(16),
            );
            const rosterBytes = serializeDeviceRoster(revoked);
            await this.#store.transaction(async (transaction) => {
                await observeDeviceRoster(
                    transaction,
                    account.publicKey,
                    `local-${encodeBase64Url(randomBytes(12))}`,
                    account.publicKey,
                    this.#identity.publicKey,
                    rosterBytes,
                );
                await this.#queueRosterBroadcast(transaction, rosterBytes);
            });
        });
        this.#signalSync();
    }

    async #queueRosterBroadcast(
        transaction: StoreTransaction,
        rosterBytes: Uint8Array,
        keyPackage?: Uint8Array,
    ): Promise<void> {
        await transaction.set(
            ACCOUNT_BROADCAST_KEY,
            canonicalJsonBytes({
                version: 1,
                roster: encodeBase64Url(rosterBytes),
                keyPackage: keyPackage === undefined ? null : encodeBase64Url(keyPackage),
            }),
        );
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
                this.#deviceCredential ?? this.#identity.publicKey,
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
                    identity: (this.#account ?? this.#identity).publicKey.slice(),
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
                    members: options.members.map((member) => ({
                        identity: member.identity,
                        keyPackage: decodeMlsKeyPackage(member.keyPackage),
                    })),
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
        await this.#exclusive(() =>
            this.#engine.add(id, {
                identity: member.identity,
                keyPackage: decodeMlsKeyPackage(member.keyPackage),
            }),
        );
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
            key === DEVICE_CREDENTIAL_KEY ||
            key === ACCOUNT_ROSTER_KEY ||
            key.startsWith(ACCOUNT_PEER_ROSTER_PREFIX) ||
            key.startsWith(ACCOUNT_DEVICE_ACTIVITY_PREFIX) ||
            key === RESET_PENDING_KEY
        );
    }

    async #resetAnnouncementRecipients(reset: MurmurResetEvent): Promise<readonly Uint8Array[]> {
        const recipients = new Map<string, Uint8Array>();
        const rosterAccounts = new Set<string>();
        const addRoster = (roster: MurmurDeviceRoster): void => {
            rosterAccounts.add(encodeBase64Url(roster.accountKey));
            for (const entry of roster.devices) {
                if (
                    entry.status === "active" &&
                    !equalBytes(entry.deviceKey, this.#identity.publicKey)
                ) {
                    recipients.set(encodeBase64Url(entry.deviceKey), entry.deviceKey.slice());
                }
            }
        };
        const own = await this.#ownRoster();
        if (own !== undefined) addRoster(own);
        let after: string | undefined;
        for (;;) {
            const page = await this.#store.scan(ACCOUNT_PEER_ROSTER_PREFIX, {
                ...(after === undefined ? {} : { after }),
                limit: RESET_PURGE_SCAN_LIMIT,
            });
            if (page.size === 0) break;
            for (const [key, bytes] of page) {
                after = key;
                try {
                    addRoster(parseDeviceRoster(bytes));
                } finally {
                    zeroBytes(bytes);
                }
            }
            if (page.size < RESET_PURGE_SCAN_LIMIT) break;
        }
        const ownAccount = (this.#account ?? this.#identity).publicKey;
        for (const session of reset.sessions) {
            for (const member of session.members) {
                const encoded = encodeBase64Url(member);
                if (
                    !equalBytes(member, ownAccount) &&
                    !rosterAccounts.has(encoded) &&
                    !equalBytes(member, this.#identity.publicKey)
                ) {
                    // Before multidevice linking, an account key is its exact inbox identity.
                    recipients.set(encoded, member.slice());
                }
            }
        }
        return Object.freeze([...recipients.values()]);
    }

    async #purgeReset(reset: MurmurResetEvent): Promise<void> {
        const account = this.#account ?? this.#identity;
        const currentRoster =
            (await this.#ownRoster()) ??
            createInitialDeviceRoster(account, this.#identity, this.#now(), randomBytes(16));
        const roster = resetDeviceInRoster(
            currentRoster,
            account,
            this.#identity,
            this.#identity.publicKey,
            this.#now(),
            randomBytes(16),
        );
        const rosterBytes = serializeDeviceRoster(roster);
        const recipients = await this.#resetAnnouncementRecipients(reset);
        const bundle = createMlsKeyPackage(
            this.#identity,
            Math.floor(this.#now() / 1_000),
            KEY_PACKAGE_LIFETIME_SECONDS,
            this.#deviceCredential ?? this.#identity.publicKey,
        );
        const reference = mlsKeyPackageReference(bundle.keyPackage);
        const bundleBytes = serializeMlsKeyPackageBundle(bundle);
        const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
        let announcement: Uint8Array | undefined;
        try {
            announcement = encodeAccountSyncPacket({
                version: 1,
                type: "admission",
                roster: rosterBytes,
                keyPackage,
            });
            const announcementBytes = announcement;
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
                await transaction.set(ACCOUNT_ROSTER_KEY, rosterBytes);
                await this.#queueRosterBroadcast(transaction, rosterBytes, keyPackage);
                await this.#engine.storeKeyPackagesInTransaction(transaction, [
                    {
                        reference,
                        bytes: bundleBytes,
                        expiresAt: Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                        reusable: true,
                    },
                ]);
                await this.#engine.queueAccountResetAnnouncementsInTransaction(
                    transaction,
                    recipients,
                    announcementBytes,
                );
                for (const session of reset.sessions) {
                    await transaction.set(
                        `${RESET_READMISSION_PREFIX}${encodeBase64Url(session.id)}`,
                        session.descriptor,
                    );
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
        } finally {
            zeroBytes(rosterBytes);
            zeroBytes(reference);
            zeroBytes(bundleBytes);
            zeroBytes(keyPackage);
            if (announcement !== undefined) zeroBytes(announcement);
            for (const recipient of recipients) zeroBytes(recipient);
            destroyMlsKeyPackageBundle(bundle);
        }
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
        if (this.#account !== undefined) destroyIdentity(this.#account);
        if (this.#deviceCredential !== undefined) zeroBytes(this.#deviceCredential);
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
                const claimedAccountSessions: Uint8Array[] = [];
                let accountEvents: PreparedAccountEvents | undefined;
                let deferredRoutes = false;
                let deferredUpdates = false;
                try {
                    for (const route of prepared.routes) {
                        let owner: SessionRouteDecision["owner"] | undefined;
                        if (isAccountSyncSessionDescriptor(route.session.descriptor)) {
                            const roster = await this.#ownRoster();
                            const accountKey = (this.#account ?? this.#identity).publicKey;
                            const claimed =
                                roster !== undefined &&
                                route.session.members.every(
                                    (member) =>
                                        equalBytes(member, accountKey) ||
                                        isActiveDevice(roster, member),
                                );
                            owner = { version: 1, owner: claimed ? "account" : "ignored" };
                            if (claimed) {
                                claimedAccountSessions.push(route.session.id.slice());
                            }
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
                        if (update.owner?.owner === "account") {
                            await this.#processAccountPacket(update);
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
                    for (const sessionId of claimedAccountSessions) {
                        await this.#exclusive(async () => {
                            const session = await this.#engine.get(sessionId);
                            if (session?.status === "pending") {
                                await this.#engine.activateOwned(sessionId, "account");
                            }
                            await this.#store.transaction((transaction) =>
                                transaction.set(ACCOUNT_SESSION_KEY, sessionId.slice()),
                            );
                        });
                    }
                    delivered += consumedKeys.size;
                    if (deferredRoutes || deferredUpdates) break;
                } finally {
                    for (const decision of decisions) zeroBytes(decision.sessionId);
                    for (const sessionId of claimedAccountSessions) zeroBytes(sessionId);
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

    /** Validate and apply one authenticated packet from the account-sync session. */
    async #processAccountPacket(update: MurmurUpdate): Promise<void> {
        const account = this.#account ?? this.#identity;
        try {
            const packet = decodeAccountSyncPacket(update.bytes);
            const roster = parseDeviceRoster(packet.roster);
            if (!equalBytes(roster.accountKey, account.publicKey)) {
                throw new Error("Account packet names a foreign account");
            }
            let admission:
                | { readonly device: Uint8Array; readonly keyPackage: Uint8Array }
                | undefined;
            if (packet.type === "admission") {
                const keyPackage = decodeMlsKeyPackage(packet.keyPackage);
                if (!verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000))) {
                    throw new Error("Account admission KeyPackage is invalid");
                }
                admission = {
                    device: keyPackage.leafNode.signatureKey,
                    keyPackage: packet.keyPackage,
                };
            }
            await this.#store.transaction(async (transaction) => {
                await observeDeviceRoster(
                    transaction,
                    account.publicKey,
                    update.id,
                    roster.accountKey,
                    roster.authorDeviceKey,
                    packet.roster,
                    admission,
                );
                await this.#queueRosterBroadcast(transaction, packet.roster, admission?.keyPackage);
            });
        } catch {
            return;
        }
    }

    /** Queue automatic account work: link completion, admission, roster broadcast. */
    async #queueAccountWork(): Promise<void> {
        await this.#store.set(
            `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(this.#identity.publicKey)}`,
            utf8Encode(String(this.#now()).padStart(16, "0")),
        );
        let queued = false;
        const pendingEnvelope = await this.#engine.pendingProvisioningEnvelope();
        if (pendingEnvelope !== undefined) {
            try {
                const linkMaterial = await this.#store.get(LINK_MATERIAL_KEY);
                if (linkMaterial !== undefined) zeroBytes(linkMaterial);
                if (this.#account === undefined && linkMaterial !== undefined) {
                    await this.#completeDeviceLinkBytes(pendingEnvelope);
                    queued = true;
                } else {
                    await this.#engine.deletePendingProvisioningEnvelope();
                }
            } catch {
                // An invalid or expired envelope must not wedge the sync loop.
                await this.#engine.deletePendingProvisioningEnvelope();
            } finally {
                zeroBytes(pendingEnvelope);
            }
        }
        if (this.#account !== undefined && this.#deviceCredential !== undefined) {
            const sent = await this.#store.get(ACCOUNT_ADMISSION_SENT_KEY);
            const sessionId = await this.#store.get(ACCOUNT_SESSION_KEY);
            if (sent === undefined && sessionId !== undefined) {
                const session = await this.#engine.get(sessionId);
                const roster = await this.#ownRoster();
                if (session?.status === "active" && roster !== undefined) {
                    const bundle = createMlsKeyPackage(
                        this.#identity,
                        Math.floor(this.#now() / 1_000),
                        KEY_PACKAGE_LIFETIME_SECONDS,
                        this.#deviceCredential,
                    );
                    try {
                        const reference = mlsKeyPackageReference(bundle.keyPackage);
                        const bytes = serializeMlsKeyPackageBundle(bundle);
                        try {
                            // Reusable: convergence joins one Welcome per known session.
                            await this.#engine.storeKeyPackages([
                                {
                                    reference,
                                    bytes,
                                    expiresAt: Number(
                                        (bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n,
                                    ),
                                    reusable: true,
                                },
                            ]);
                        } finally {
                            zeroBytes(reference);
                            zeroBytes(bytes);
                        }
                        const packet = encodeAccountSyncPacket({
                            version: 1,
                            type: "admission",
                            roster: serializeDeviceRoster(roster),
                            keyPackage: encodeMlsKeyPackage(bundle.keyPackage),
                        });
                        await this.#engine.send(sessionId, packet);
                        await this.#store.transaction((transaction) =>
                            transaction.set(ACCOUNT_ADMISSION_SENT_KEY, new Uint8Array([1])),
                        );
                        queued = true;
                    } finally {
                        destroyMlsKeyPackageBundle(bundle);
                    }
                }
            }
            if (sessionId !== undefined) zeroBytes(sessionId);
        }
        if (await this.#drainRosterBroadcast()) queued = true;
        if (queued) this.#signalSync();
    }

    /** Publish the pending authenticated roster to every active non-account session. */
    async #drainRosterBroadcast(): Promise<boolean> {
        const pending = await this.#store.get(ACCOUNT_BROADCAST_KEY);
        if (pending === undefined) return false;
        let roster: Uint8Array;
        let keyPackage: Uint8Array | undefined;
        try {
            const input = JSON.parse(utf8Decode(pending)) as Record<string, unknown>;
            if (input.version !== 1 || typeof input.roster !== "string") {
                throw new Error("Invalid roster broadcast");
            }
            roster = decodeBase64Url(input.roster);
            keyPackage =
                input.keyPackage === null || typeof input.keyPackage !== "string"
                    ? undefined
                    : decodeBase64Url(input.keyPackage);
        } catch {
            await this.#store.delete(ACCOUNT_BROADCAST_KEY);
            return false;
        } finally {
            zeroBytes(pending);
        }
        const accountSessionId = await this.#store.get(ACCOUNT_SESSION_KEY);
        let complete = true;
        let targets = 0;
        let cursor: string | null = null;
        do {
            const page = await this.#engine.list(cursor === null ? {} : { after: cursor });
            for (const session of page.sessions) {
                if (session.status !== "active") continue;
                if (accountSessionId !== undefined && equalBytes(session.id, accountSessionId)) {
                    continue;
                }
                targets += 1;
                try {
                    await this.#engine.sendAccountRoster(session.id, roster, keyPackage);
                } catch {
                    complete = false;
                }
            }
            cursor = page.cursor;
        } while (cursor !== null);
        if (accountSessionId !== undefined) zeroBytes(accountSessionId);
        if (targets === 0) complete = false;
        if (complete) await this.#store.delete(ACCOUNT_BROADCAST_KEY);
        return targets > 0;
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
