import { sha256 } from "@noble/hashes/sha2";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
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
    DISCOVERY_INVITATION_TTL_MILLISECONDS,
    HttpDiscoveryTransport,
    createAccountDiscoveryBundle,
    createInvitationUploadAuthorization,
    createSignedInvitationRevocation,
    createDiscoveryBundle,
    parseDiscoveryBundle,
    serializeDiscoveryBundle,
    type DiscoveryBundle,
    type DiscoveryTransport,
    type DiscoveryUploadOutcome,
} from "../identity/discovery/index.js";
import { InvitationState } from "../identity/discovery/impl/invitationState.js";
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
    zeroBytes,
} from "../utils/index.js";
import {
    ContactEngine,
    type ContactAdmissionSelection,
    type PreparedContactEvents,
} from "../contacts/impl/contactEngine.js";
import {
    CONTACT_ADMISSION_TARGET_KEY_PACKAGES,
    contactSessionDescriptor,
    encodeContactPacket,
    isContactSessionDescriptor,
    type MurmurContact,
    type MurmurContactAdmission,
    type MurmurContactProfile,
    type MurmurContactRequested,
    type MurmurOutgoingContactRequest,
} from "../contacts/index.js";
import {
    createMurmurServiceSessionDescriptor,
    validateMurmurServiceRegistration,
    type MurmurService,
    type MurmurServiceRegistration,
} from "../services/index.js";
import {
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
    type MurmurDeviceRoster,
    type MurmurDeviceRosterEntry,
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
    MurmurSessionPolicies,
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
    MurmurSessionPolicies,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";

const IDENTITY_KEY = "murmur/identity/root";
const INVITATION_REVOCATION_KEY = "murmur/invitations/revocation-root";
const ACCOUNT_ROOT_KEY = "murmur/accounts/v1/root";
const DEVICE_CREDENTIAL_KEY = "murmur/accounts/v1/device-credential";
const LINK_MATERIAL_KEY = "murmur/accounts/v1/link-material";
const ACCOUNT_SESSION_KEY = "murmur/accounts/v1/sync-session";
const ACCOUNT_ADMISSION_SENT_KEY = "murmur/accounts/v1/admission-sent";
const ACCOUNT_BROADCAST_KEY = "murmur/accounts/v1/roster-broadcast";
const DEFAULT_KEY_PACKAGES = 1;
const CONTACT_ADMISSION_GENERATION = 1;
const LAST_RESORT_KEY_PACKAGE_LIFETIME_SECONDS = 10 * 365 * 24 * 60 * 60;
const KEY_PACKAGE_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const SYNC_RECONNECT_DELAY_MILLISECONDS = 1_000;

interface CreatedContactAdmission {
    readonly admission: MurmurContactAdmission;
    readonly references: readonly Uint8Array[];
}

/** Construction inputs for the stateful Murmur MLS client. */
export interface MurmurClientOptions {
    readonly relay?: string | URL;
    readonly transport?: DeliveryTransport;
    /** Application-authenticated issuer for an additive negotiated WebSocket relay. */
    readonly sessionProvider?: RelaySessionProvider;
    readonly webSocket?: WebSocketDeliveryTransportOptions;
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
    readonly #invitationRevocation: IdentityKeyPair;
    readonly #invitations: InvitationState;
    readonly #engine: SessionEngine;
    #contacts: ContactEngine;
    readonly #services = new Map<string, MurmurService>();
    readonly #discoveryTransport: DiscoveryTransport | undefined;
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
        invitationRevocation: IdentityKeyPair,
        store: MurmurStore,
        transport: DeliveryTransport,
        discoveryTransport: DiscoveryTransport | undefined,
        limits: MurmurSessionLimits,
        now: () => number,
        services: readonly MurmurServiceRegistration[],
        account: IdentityKeyPair | undefined,
        deviceCredential: Uint8Array | undefined,
    ) {
        this.#identity = identity;
        this.#invitationRevocation = invitationRevocation;
        this.#store = store;
        this.#now = now;
        this.#discoveryTransport = discoveryTransport;
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
        this.#invitations = new InvitationState(store, now);
        this.#contacts = new ContactEngine(store, account?.publicKey ?? identity.publicKey, now);
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
        let invitationRevocation: IdentityKeyPair | undefined;
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

                const storedRevocation = await transaction.get(INVITATION_REVOCATION_KEY);
                if (storedRevocation === undefined) {
                    invitationRevocation = generateIdentityKeyPair();
                    const encoded = encodeIdentityRoot(invitationRevocation);
                    try {
                        await transaction.set(INVITATION_REVOCATION_KEY, encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                } else {
                    try {
                        invitationRevocation = decodeIdentityRoot(storedRevocation);
                    } finally {
                        zeroBytes(storedRevocation);
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
            if (invitationRevocation === undefined) {
                throw new Error("Murmur invitation revocation authority did not open");
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
            const discoveryTransport =
                options.discoveryTransport ??
                (options.relay === undefined
                    ? undefined
                    : new HttpDiscoveryTransport(
                          options.relay,
                          options.fetch === undefined ? {} : { fetch: options.fetch },
                      ));
            const client = new MurmurClient(
                identity,
                invitationRevocation,
                options.store,
                transport,
                discoveryTransport,
                options.limits ?? {},
                options.now ?? Date.now,
                services,
                account,
                deviceCredential,
            );
            const pendingReferences = await client.#invitations.pendingReferences();
            try {
                if (pendingReferences.length > 0) {
                    await client.#engine.deleteKeyPackages(pendingReferences);
                }
            } finally {
                for (const reference of pendingReferences) zeroBytes(reference);
            }
            return client;
        } catch (error: unknown) {
            if (identity !== undefined) destroyIdentity(identity);
            if (invitationRevocation !== undefined) destroyIdentity(invitationRevocation);
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
     * application transports back to the new device. Session membership across
     * contacts and services then converges automatically.
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
     * and receives Welcomes for every converged contact and service session.
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
            this.#contacts = new ContactEngine(
                this.#store,
                provisioned.account.publicKey,
                this.#now,
            );
        } finally {
            zeroBytes(material.ephemeralSecretKey);
        }
    }

    /**
     * Revoke another account device from any active device.
     *
     * Signs the next roster revision, then automatically drives MLS Removes in
     * every known session and publishes the authenticated roster to contacts.
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
            const transport = this.#discoveryTransport;
            const bundle = await this.#createDiscovery();
            const references = bundle.keyPackages.map(mlsKeyPackageReference);
            const bytes = serializeDiscoveryBundle(bundle);
            const digest = sha256(bytes);
            const revocable = transport.uploadOwned !== undefined && transport.revoke !== undefined;
            let authorization: ReturnType<typeof createInvitationUploadAuthorization> | undefined;
            try {
                if (revocable) {
                    await this.#invitations.record(digest, references, bundle.expiresAt);
                    authorization = createInvitationUploadAuthorization(
                        this.#identity,
                        this.#invitationRevocation,
                        digest,
                        bundle.expiresAt,
                        this.#now(),
                    );
                }
                let outcome: DiscoveryUploadOutcome;
                if (authorization === undefined) {
                    outcome = await transport.upload(bytes, signal);
                } else {
                    if (transport.uploadOwned === undefined) {
                        throw new Error(
                            "Discovery transport does not support revocable invitations",
                        );
                    }
                    outcome = await transport.uploadOwned(bytes, authorization, signal);
                }
                if (outcome.expiresAt !== bundle.expiresAt || !equalBytes(outcome.digest, digest)) {
                    throw new Error("Discovery relay returned invalid invitation metadata");
                }
                return outcome.digest.slice();
            } catch (error: unknown) {
                const cleanupErrors: unknown[] = [];
                let pendingMarked = false;
                if (revocable) {
                    try {
                        const pendingReferences = await this.#invitations.begin(digest);
                        try {
                            pendingMarked = true;
                        } finally {
                            for (const reference of pendingReferences) zeroBytes(reference);
                        }
                    } catch (cleanupError: unknown) {
                        cleanupErrors.push(cleanupError);
                    }
                }
                let keysDeleted = false;
                try {
                    await this.#engine.deleteKeyPackages(references);
                    keysDeleted = true;
                } catch (cleanupError: unknown) {
                    cleanupErrors.push(cleanupError);
                }
                if (revocable && pendingMarked && keysDeleted) {
                    try {
                        await this.#invitations.complete(digest);
                    } catch (cleanupError: unknown) {
                        cleanupErrors.push(cleanupError);
                    }
                }
                if (cleanupErrors.length > 0) {
                    throw new AggregateError(
                        [error, ...cleanupErrors],
                        "Invitation creation failed and local cleanup did not complete",
                    );
                }
                throw error;
            } finally {
                zeroBytes(bytes);
                zeroBytes(digest);
                for (const reference of references) zeroBytes(reference);
                if (authorization !== undefined) {
                    zeroBytes(authorization.owner);
                    zeroBytes(authorization.revocationKey);
                    zeroBytes(authorization.digest);
                    zeroBytes(authorization.signature);
                }
            }
        });
    }

    /** Revoke one owner-created relay invitation idempotently. */
    async revokeInvitation(invitation: Uint8Array, signal?: AbortSignal): Promise<void> {
        await this.#revokeInvitations(invitation, signal);
    }

    /** Revoke every outstanding relay invitation under this durable authority. */
    async revokeInvitations(signal?: AbortSignal): Promise<void> {
        await this.#revokeInvitations(null, signal);
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
        const session = await this.#exclusive(async () => {
            const existing = await this.#contacts.outgoingRequest(bundle.identityKey);
            if (existing !== undefined) {
                try {
                    const existingSession = await this.#engine.get(existing.sessionId);
                    if (existingSession !== undefined) {
                        await this.#queueContactHellos();
                        return existingSession;
                    }
                    await this.#contacts.reject(existing.sessionId);
                } finally {
                    zeroBytes(existing.identity);
                    zeroBytes(existing.sessionId);
                }
            }
            const created = await this.#createContactAdmission(CONTACT_ADMISSION_GENERATION);
            let createdSession: MurmurSession;
            try {
                createdSession = await this.#engine.create(
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
                            created.admission,
                        ),
                );
            } catch (error: unknown) {
                await this.#engine.deleteKeyPackages(created.references);
                throw error;
            } finally {
                for (const reference of created.references) zeroBytes(reference);
            }
            await this.#queueContactHellos();
            return createdSession;
        });
        this.#signalSync();
        return session;
    }

    /** Persist the local profile decision, activate the pending contact, and queue hello. */
    async acceptContact(sessionId: Uint8Array, profile: MurmurContactProfile): Promise<void> {
        await this.#exclusive(async () => {
            const created = await this.#createContactAdmission(CONTACT_ADMISSION_GENERATION);
            let packet: Uint8Array | undefined;
            try {
                packet = encodeContactPacket({
                    version: 2,
                    type: "hello",
                    profile,
                    admission: created.admission,
                });
                await this.#engine.acceptOwnedContact(
                    sessionId,
                    packet,
                    (transaction, deliveryId) =>
                        this.#contacts.acceptInTransaction(
                            transaction,
                            sessionId,
                            profile,
                            created.admission,
                            deliveryId,
                        ),
                );
            } catch (error: unknown) {
                await this.#engine.deleteKeyPackages(created.references);
                throw error;
            } finally {
                if (packet !== undefined) zeroBytes(packet);
                for (const reference of created.references) zeroBytes(reference);
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
            const packet = encodeContactPacket({ version: 2, type: "remove" });
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

    /** Atomically replace and publish the local profile to every active contact. */
    async updateContactProfile(profile: MurmurContactProfile): Promise<void> {
        await this.#exclusive(async () => {
            const prepared = await this.#contacts.prepareProfileUpdate(profile);
            const packet = encodeContactPacket({
                version: 2,
                type: "profile_update",
                revision: prepared.revision,
                profile: prepared.profile,
            });
            try {
                await this.#engine.sendOwnedContacts(
                    prepared.targets.map((target) => ({
                        id: target.sessionId,
                        bytes: packet,
                    })),
                    (transaction) =>
                        this.#contacts.commitProfileUpdateInTransaction(transaction, prepared),
                );
            } finally {
                zeroBytes(packet);
                for (const target of prepared.targets) {
                    zeroBytes(target.identity);
                    zeroBytes(target.sessionId);
                }
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

    /** Read durable outgoing contact requests awaiting the remote decision. */
    async outgoingContactRequests(): Promise<readonly MurmurOutgoingContactRequest[]> {
        return this.#tracked(() => this.#contacts.outgoingRequests());
    }

    /**
     * Create a two-or-more-member MLS session from confirmed contact identities.
     *
     * Contact admission material is cached and refillable, so peers need not be
     * online. Direct discovery members remain available for low-level bootstrap.
     */
    async createSession(options: CreateMurmurSessionOptions): Promise<MurmurSession> {
        const owner =
            options.service === undefined
                ? undefined
                : ({ version: 1, owner: "service", serviceId: options.service } as const);
        if (options.service !== undefined && !this.#services.has(options.service)) {
            throw new Error("Session service is not registered");
        }
        const session = await this.#exclusive(async () => {
            if ("contacts" in options && options.contacts !== undefined) {
                const selections: ContactAdmissionSelection[] = [];
                try {
                    for (const identity of options.contacts) {
                        selections.push(await this.#contacts.selectAdmission(identity));
                    }
                    return await this.#engine.create(
                        {
                            descriptor: options.descriptor,
                            ...(options.adminsAssignAdmins === undefined
                                ? {}
                                : { adminsAssignAdmins: options.adminsAssignAdmins }),
                            ...(options.anyoneCanAddMembers === undefined
                                ? {}
                                : { anyoneCanAddMembers: options.anyoneCanAddMembers }),
                            members: selections.map((selection) => ({
                                identity: selection.identity,
                                keyPackage: decodeMlsKeyPackage(selection.keyPackage),
                            })),
                        },
                        owner,
                        async (transaction) => {
                            for (const selection of selections) {
                                await this.#contacts.consumeAdmissionInTransaction(
                                    transaction,
                                    selection,
                                );
                            }
                        },
                    );
                } finally {
                    for (const selection of selections) {
                        zeroBytes(selection.identity);
                        zeroBytes(selection.sessionId);
                        zeroBytes(selection.keyPackage);
                        zeroBytes(selection.reference);
                    }
                }
            }
            return this.#engine.create(
                {
                    descriptor: options.descriptor,
                    ...(options.adminsAssignAdmins === undefined
                        ? {}
                        : { adminsAssignAdmins: options.adminsAssignAdmins }),
                    ...(options.anyoneCanAddMembers === undefined
                        ? {}
                        : { anyoneCanAddMembers: options.anyoneCanAddMembers }),
                    members: options.members,
                },
                owner,
            );
        });
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

    /**
     * Encrypt and durably queue application bytes without waiting for relay or peer state.
     *
     * Sends made while a membership Commit is staged use its post-Commit epoch and publish
     * only after that Commit's Welcome dependencies.
     */
    async send(id: Uint8Array, bytes: Uint8Array): Promise<string> {
        const deliveryId = await this.#exclusive(() => this.#engine.send(id, bytes));
        this.#signalSync();
        return deliveryId;
    }

    /** Add one confirmed contact while offline, or use direct discovery material. */
    async addMember(id: Uint8Array, contact: Uint8Array | DiscoveryBundle): Promise<void> {
        await this.#exclusive(async () => {
            if (contact instanceof Uint8Array) {
                const selection = await this.#contacts.selectAdmission(contact);
                try {
                    await this.#engine.add(
                        id,
                        {
                            identity: selection.identity,
                            keyPackage: decodeMlsKeyPackage(selection.keyPackage),
                        },
                        (transaction) =>
                            this.#contacts.consumeAdmissionInTransaction(transaction, selection),
                    );
                } finally {
                    zeroBytes(selection.identity);
                    zeroBytes(selection.sessionId);
                    zeroBytes(selection.keyPackage);
                    zeroBytes(selection.reference);
                }
                return;
            }
            await this.#engine.add(id, contact);
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

    async issues(): Promise<readonly MurmurSessionIssue[]> {
        return this.#tracked(() => this.#engine.issues());
    }

    async synchronize(
        options: MurmurSynchronizeOptions = {},
        lifecycle: Pick<
            MurmurSyncOptions,
            | "onUpdates"
            | "onContactRequested"
            | "onContactAdded"
            | "onContactUpdated"
            | "onContactRemoved"
            | "onDeviceAdded"
            | "onDeviceRevoked"
            | "onContactRosterChanged"
        > = {},
    ): Promise<MurmurSynchronizeResult> {
        if (this.#syncActive) {
            throw new Error("Cannot page synchronization while SSE sync is active");
        }
        await this.#exclusive(() => this.#queueContactMaintenance());
        await this.#exclusive(() => this.#queueAccountWork());
        const result = await this.#exclusive(() => this.#engine.synchronize(options));
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
        destroyIdentity(this.#invitationRevocation);
        if (this.#account !== undefined) destroyIdentity(this.#account);
        if (this.#deviceCredential !== undefined) zeroBytes(this.#deviceCredential);
    }

    async #revokeInvitations(digest: Uint8Array | null, signal?: AbortSignal): Promise<void> {
        await this.#exclusive(async () => {
            if (this.#discoveryTransport?.revoke === undefined) {
                throw new Error(
                    "Invitation revocation is not supported by the discovery transport",
                );
            }
            if (digest !== null && (!(digest instanceof Uint8Array) || digest.length !== 32)) {
                throw new Error("Invalid invitation digest");
            }
            const references = await this.#invitations.begin(digest);
            try {
                if (references.length > 0) await this.#engine.deleteKeyPackages(references);
            } finally {
                for (const reference of references) zeroBytes(reference);
            }
            const request = createSignedInvitationRevocation(
                this.#invitationRevocation,
                digest,
                this.#now(),
            );
            try {
                await this.#discoveryTransport.revoke(request, signal);
            } finally {
                zeroBytes(request.revocationKey);
                if (request.digest !== null) zeroBytes(request.digest);
                zeroBytes(request.signature);
            }
            await this.#invitations.complete(digest);
        });
    }

    async #createContactAdmission(generation: number): Promise<CreatedContactAdmission> {
        const nowSeconds = Math.floor(this.#now() / 1_000);
        const bundles: ReturnType<typeof createMlsKeyPackage>[] = [];
        const stored: {
            reference: Uint8Array;
            bytes: Uint8Array;
            expiresAt: number;
            reusable?: boolean;
        }[] = [];
        try {
            for (let index = 0; index < CONTACT_ADMISSION_TARGET_KEY_PACKAGES; index += 1) {
                bundles.push(
                    createMlsKeyPackage(
                        this.#identity,
                        nowSeconds,
                        KEY_PACKAGE_LIFETIME_SECONDS,
                        this.#deviceCredential ?? this.#identity.publicKey,
                    ),
                );
            }
            bundles.push(
                createMlsKeyPackage(
                    this.#identity,
                    nowSeconds,
                    LAST_RESORT_KEY_PACKAGE_LIFETIME_SECONDS,
                    this.#deviceCredential ?? this.#identity.publicKey,
                ),
            );
            for (let index = 0; index < bundles.length; index += 1) {
                const bundle = bundles[index]!;
                const reference = mlsKeyPackageReference(bundle.keyPackage);
                stored.push({
                    reference,
                    bytes: serializeMlsKeyPackageBundle(bundle),
                    expiresAt: Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                    ...(index === bundles.length - 1 ? { reusable: true } : {}),
                });
            }
            await this.#engine.storeKeyPackages(stored);
            return {
                admission: Object.freeze({
                    generation,
                    oneTimeKeyPackages: Object.freeze(
                        bundles
                            .slice(0, -1)
                            .map((bundle) => encodeMlsKeyPackage(bundle.keyPackage)),
                    ),
                    lastResortKeyPackage: encodeMlsKeyPackage(
                        bundles[bundles.length - 1]!.keyPackage,
                    ),
                }),
                references: Object.freeze(stored.map((value) => value.reference.slice())),
            };
        } finally {
            for (const value of stored) {
                zeroBytes(value.reference);
                zeroBytes(value.bytes);
            }
            for (const bundle of bundles) destroyMlsKeyPackageBundle(bundle);
        }
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
                const bundle = createMlsKeyPackage(
                    this.#identity,
                    Math.floor(now / 1_000),
                    KEY_PACKAGE_LIFETIME_SECONDS,
                    this.#deviceCredential ?? this.#identity.publicKey,
                );
                bundles.push(bundle);
                stored.push({
                    reference: mlsKeyPackageReference(bundle.keyPackage),
                    bytes: serializeMlsKeyPackageBundle(bundle),
                    expiresAt,
                });
            }
            await this.#engine.storeKeyPackages(stored);
            if (this.#account !== undefined) {
                const roster = await this.#ownRoster();
                if (roster === undefined) {
                    throw new Error("Account device is missing its roster");
                }
                return createAccountDiscoveryBundle(
                    this.#account,
                    this.#identity,
                    roster,
                    bundles.map((bundle) => bundle.keyPackage),
                    { createdAt: now, expiresAt },
                );
            }
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
            | "onUpdates"
            | "onContactRequested"
            | "onContactAdded"
            | "onContactUpdated"
            | "onContactRemoved"
            | "onDeviceAdded"
            | "onDeviceRevoked"
            | "onContactRosterChanged"
        >,
    ): Promise<number> {
        if (this.#updatesActive) return 0;
        this.#updatesActive = true;
        this.#pendingOperations += 1;
        let delivered = 0;
        try {
            for (;;) {
                await this.#exclusive(() => this.#queueContactMaintenance());
                await this.#exclusive(() => this.#queueAccountWork());
                const prepared = await this.#exclusive(() => this.#engine.prepareUpdates());
                const decisions: SessionRouteDecision[] = [];
                const consumedKeys = new Set<string>();
                const globalUpdates: MurmurUpdate[] = [];
                const removedSessions: Uint8Array[] = [];
                const claimedAccountSessions: Uint8Array[] = [];
                let contactEvents: PreparedContactEvents | undefined;
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
                        } else if (
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
                    contactEvents = await this.#contacts.prepareEvents();
                    accountEvents = await prepareAccountEvents(this.#store);
                    if (
                        decisions.length === 0 &&
                        consumedKeys.size === 0 &&
                        contactEvents.keys.length === 0 &&
                        accountEvents.keys.length === 0
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
                    if (contactEvents.updated.length > 0) {
                        await lifecycle.onContactUpdated?.(contactEvents.updated);
                    }
                    if (contactEvents.removed.length > 0) {
                        await lifecycle.onContactRemoved?.(contactEvents.removed);
                    }
                    if (accountEvents.added.length > 0) {
                        await lifecycle.onDeviceAdded?.(accountEvents.added);
                    }
                    if (accountEvents.revoked.length > 0) {
                        await lifecycle.onDeviceRevoked?.(accountEvents.revoked);
                    }
                    if (accountEvents.contacts.length > 0) {
                        await lifecycle.onContactRosterChanged?.(accountEvents.contacts);
                    }
                    for (const sessionId of removedSessions) {
                        await this.#exclusive(() =>
                            this.#engine.destroyOwned(sessionId, "contact"),
                        );
                    }
                    const committedContactEvents = contactEvents;
                    const committedAccountEvents = accountEvents;
                    await this.#exclusive(() =>
                        this.#engine.commitUpdates(
                            prepared,
                            decisions,
                            consumedKeys,
                            async (transaction) => {
                                await this.#contacts.deletePreparedEvents(
                                    transaction,
                                    committedContactEvents,
                                );
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
                    for (const sessionId of removedSessions) zeroBytes(sessionId);
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
        let cursor: string | null = null;
        do {
            const page = await this.#engine.list(cursor === null ? {} : { after: cursor });
            for (const session of page.sessions) {
                if (session.status !== "active") continue;
                if (accountSessionId !== undefined && equalBytes(session.id, accountSessionId)) {
                    continue;
                }
                try {
                    await this.#engine.sendAccountRoster(session.id, roster, keyPackage);
                } catch {
                    complete = false;
                }
            }
            cursor = page.cursor;
        } while (cursor !== null);
        if (accountSessionId !== undefined) zeroBytes(accountSessionId);
        if (complete) await this.#store.delete(ACCOUNT_BROADCAST_KEY);
        return true;
    }

    async #queueContactHellos(): Promise<boolean> {
        let queued = false;
        const handshakes = await this.#contacts.outgoingWithoutHello();
        for (const handshake of handshakes) {
            try {
                if (
                    handshake.localProfile === undefined ||
                    handshake.localAdmission === undefined
                ) {
                    continue;
                }
                const packet = encodeContactPacket({
                    version: 2,
                    type: "hello",
                    profile: handshake.localProfile,
                    admission: handshake.localAdmission,
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
                    queued = true;
                } finally {
                    zeroBytes(packet);
                }
            } finally {
                zeroBytes(handshake.identity);
                zeroBytes(handshake.sessionId);
            }
        }
        return queued;
    }

    async #queueContactMaintenance(): Promise<void> {
        let queued = await this.#queueContactHellos();
        for (const request of await this.#contacts.refillRequests()) {
            const packet = encodeContactPacket({
                version: 2,
                type: "admission_request",
                generation: request.generation,
            });
            try {
                await this.#engine.sendOwnedContact(
                    request.sessionId,
                    packet,
                    (transaction, deliveryId) =>
                        this.#contacts.markRefillRequestedInTransaction(
                            transaction,
                            request.identity,
                            deliveryId,
                        ),
                );
                queued = true;
            } finally {
                zeroBytes(request.identity);
                zeroBytes(request.sessionId);
                zeroBytes(packet);
            }
        }
        for (const request of await this.#contacts.supplyRequests()) {
            const created = await this.#createContactAdmission(request.generation);
            let packet: Uint8Array | undefined;
            try {
                packet = encodeContactPacket({
                    version: 2,
                    type: "admission_response",
                    admission: created.admission,
                });
                await this.#engine.sendOwnedContact(request.sessionId, packet, (transaction) =>
                    this.#contacts.markAdmissionSuppliedInTransaction(
                        transaction,
                        request.identity,
                        created.admission,
                    ),
                );
                queued = true;
            } catch (error: unknown) {
                await this.#engine.deleteKeyPackages(created.references);
                throw error;
            } finally {
                zeroBytes(request.identity);
                zeroBytes(request.sessionId);
                if (packet !== undefined) zeroBytes(packet);
                for (const reference of created.references) zeroBytes(reference);
            }
        }
        if (queued) this.#signalSync();
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
            await this.#queueContactMaintenance();
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
