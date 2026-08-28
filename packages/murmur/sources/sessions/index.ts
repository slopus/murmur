import {
    DeliveryStaleRosterError,
    DeliveryTransportError,
    HttpDeliveryTransport,
    InboxContinuityLossError,
    WebSocketDeliveryTransport,
    createSignedDelivery,
    encodeAccountDeletionRequest,
    parseSignedDelivery,
    signedDeliveryToJson,
    type DeliveryFetch,
    type DeliveryDeviceRoster,
    type DeliveryDirectoryClaim,
    type RelaySessionProvider,
    type DeliveryTransport,
    type SignedDelivery,
    type WebSocketDeliveryTransportOptions,
} from "../delivery/index.js";
import {
    decodeIdentityRoot,
    destroyIdentity,
    encodeIdentityRoot,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../crypto/index.js";
import { createAccountSecret as wrapAccountSecret } from "../identity/index.js";
import type { CreatedAccountSecret } from "../identity/index.js";
import {
    createMlsKeyPackage,
    decodeMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
    serializeMlsKeyPackageBundle,
    verifyMlsKeyPackage,
} from "../mls/index.js";
import type { Context } from "@steve.kite/stdlib";

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
    DIRECTORY_INITIALIZED_KEY,
    DIRECTORY_LAST_RESORT_KEY,
    DIRECTORY_ONE_TIME_PREFIX,
    DIRECTORY_PENDING_PREFIX,
    DIRECTORY_SPENT_PREFIX,
    decodeDirectoryLocalPrekey,
    encodeDirectoryLocalPrekey,
    encodeDirectoryPrekeyUpload,
    encodeDirectorySpentNotification,
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
    type DirectoryLocalPrekey,
    type MurmurDirectoryOneTimePrekey,
} from "../accounts/index.js";
import { randomBytes, validateIdentityPublicKey } from "../crypto/index.js";
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
    MurmurSessionAdmission,
    MurmurAccountClaim,
    MurmurClaimedSessionMember,
    MurmurSessionPolicyChanges,
    MurmurSessionChangedEvent,
    MurmurEffectBlocked,
    MurmurCallbackName,
    MurmurResetEvent,
    MurmurResetSession,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";
import { MurmurCallbackError, MurmurError, MurmurResetRequiredError } from "./types.js";

export type {
    CreateMurmurSessionOptions,
    MurmurSession,
    MurmurSessionIssue,
    MurmurSessionLimits,
    MurmurSessionListOptions,
    MurmurSessionPage,
    MurmurSessionMember,
    MurmurSessionAdmission,
    MurmurAccountClaim,
    MurmurClaimedSessionMember,
    MurmurSessionPolicies,
    MurmurSessionPolicyChanges,
    MurmurSessionSendPolicy,
    MurmurSessionDeletedEvent,
    MurmurSessionChangedEvent,
    MurmurEffectBlocked,
    MurmurCallbackName,
    MurmurErrorCode,
    MurmurIssueRecovery,
    MurmurResetEvent,
    MurmurResetSession,
    MurmurSyncOptions,
    MurmurSynchronizeOptions,
    MurmurSynchronizeResult,
    MurmurUpdate,
} from "./types.js";
export { MurmurCallbackError, MurmurError, MurmurResetRequiredError } from "./types.js";

const IDENTITY_KEY = "murmur/identity/root";
const ACCOUNT_ROOT_KEY = "murmur/accounts/v1/root";
const ACCOUNT_DELETION_KEY = "murmur/accounts/v1/deletion";
const RESET_PENDING_KEY = "murmur/reset/v1/pending";
const RESET_READMISSION_PREFIX = "murmur/reset/v1/re-admissions/";
const ACCOUNT_DEVICE_ACTIVITY_PREFIX = "murmur/accounts/v1/device-activity/";
const MURMUR_KEY_PREFIX = "murmur/";
const RESET_PURGE_SCAN_LIMIT = 10_000;
const PEER_ROSTER_REFRESH_INTERVAL = 8;
const DEVICE_DORMANCY_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;
// KeyPackages outlive the six-month delivery window by thirty days.
const KEY_PACKAGE_LIFETIME_SECONDS = 210 * 24 * 60 * 60;
const SYNC_RECONNECT_DELAY_MILLISECONDS = 1_000;
const DIRECTORY_ONE_TIME_POOL_SIZE = 4;
const DIRECTORY_NOTIFICATION_TTL_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000 - 60_000;

function compareDirectoryReferences(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return 0;
}

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
            ((policies as Record<string, unknown>).sendPolicy !== "everyone" &&
                (policies as Record<string, unknown>).sendPolicy !== "admins") ||
            Object.keys(policies).some(
                (field) =>
                    !["adminsAssignAdmins", "anyoneCanAddMembers", "sendPolicy"].includes(field),
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
                sendPolicy: (policies as Record<string, unknown>).sendPolicy as
                    | "everyone"
                    | "admins",
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
    /**
     * Produce opaque application-encrypted metadata for this device's owner-only roster entry.
     *
     * Murmur calls this after loading the stable device key so the application can bind its
     * ciphertext to that key. Murmur and the relay never decrypt the result. Omission preserves
     * existing metadata and registers a new device with an empty value.
     */
    readonly encryptDeviceMetadata?: (
        ctx: Context,
        deviceKey: Uint8Array,
    ) => Uint8Array | Promise<Uint8Array>;
    /** Optional resource bounds; omitted fields use Murmur's defaults. */
    readonly limits?: MurmurSessionLimits;
    /** Clock override used for protocol timestamps and expiry checks. Defaults to `Date.now`. */
    readonly now?: () => number;
    /** Optional typed services available to claim and process sessions. */
    readonly services?: readonly MurmurServiceRegistration[];
    /**
     * Whether opening immediately registers with the relay. Defaults to `"immediate"`.
     * Use `"deferred"` to inspect durable local state offline; `connect()` or the next
     * synchronization operation performs registration later.
     */
    readonly connection?: "immediate" | "deferred";
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
    readonly #encryptedDeviceMetadata: Uint8Array | undefined;
    #closed = false;
    #operationTail: Promise<void> = Promise.resolve();
    #pendingOperations = 0;
    #syncActive = false;
    #syncWakePending = false;
    #syncWakeResolve: (() => void) | undefined;
    #deviceRosterChangeVersion = 0;
    #consumedDeviceRosterChangeVersion = 0;
    #syncRetryTimer: ReturnType<typeof setTimeout> | undefined;
    #updatesActive = false;
    #reportedIssueVersion = -1;
    #reportedIssueFingerprint: string | undefined;
    #accountDeletionActive = false;
    #peerRosterRefreshOrdinal = 0;
    #peerRosterCursor = 0;
    #networkReady = false;
    #disposeAbort: AbortController | undefined;
    #idleResolvers = new Set<() => void>();
    #callbackDepth = 0;

    private constructor(
        identity: IdentityKeyPair,
        store: MurmurStore,
        transport: DeliveryTransport,
        limits: MurmurSessionLimits,
        now: () => number,
        services: readonly MurmurServiceRegistration[],
        account: IdentityKeyPair,
        encryptedDeviceMetadata: Uint8Array | undefined,
    ) {
        this.#identity = identity;
        this.#store = store;
        this.#now = now;
        this.#account = account;
        this.#transport = transport;
        this.#encryptedDeviceMetadata = encryptedDeviceMetadata?.slice();
        this.#engine = new SessionEngine(
            identity,
            store,
            transport,
            limits,
            now,
            account.publicKey,
            account,
        );
        for (const registration of services) {
            this.#services.set(registration.id, registration.service);
        }
    }

    /** Open or create one durable per-device Murmur identity and its account state. */
    static async open(ctx: Context, options: MurmurClientOptions): Promise<MurmurClient> {
        if (
            options.connection !== undefined &&
            options.connection !== "immediate" &&
            options.connection !== "deferred"
        ) {
            throw new MurmurError("invalid_configuration", "Invalid connection mode");
        }
        const deliveryChoices = [
            options.relay !== undefined,
            options.transport !== undefined,
            options.sessionProvider !== undefined,
        ].filter(Boolean).length;
        if (deliveryChoices !== 1) {
            throw new MurmurError(
                "invalid_configuration",
                "Provide exactly one relay URL, delivery transport, or relay-session provider",
            );
        }
        const services = options.services ?? [];
        const serviceIds = new Set<string>();
        for (const registration of services) {
            validateMurmurServiceRegistration(registration);
            if (serviceIds.has(registration.id)) {
                throw new MurmurError("invalid_configuration", "Murmur service IDs must be unique");
            }
            serviceIds.add(registration.id);
        }
        let identity: IdentityKeyPair | undefined;
        let account: IdentityKeyPair | undefined;
        try {
            await options.store.tx(ctx, async (transaction) => {
                const stored = await options.store.get(transaction, IDENTITY_KEY);
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
                        await options.store.set(transaction, IDENTITY_KEY, encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                }

                const storedAccount = await options.store.get(transaction, ACCOUNT_ROOT_KEY);
                if (storedAccount !== undefined) {
                    try {
                        account = decodeIdentityRoot(storedAccount);
                        if (
                            options.identity !== undefined &&
                            !equalBytes(account.publicKey, options.identity.publicKey)
                        ) {
                            throw new MurmurError(
                                "invalid_configuration",
                                "Stored Murmur account differs from supplied identity",
                            );
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
                        await options.store.set(transaction, ACCOUNT_ROOT_KEY, encoded);
                    } finally {
                        zeroBytes(encoded);
                    }
                }
            });
            if (identity === undefined || account === undefined) {
                throw new Error("Murmur account did not open");
            }
            const encryptedDeviceMetadata =
                options.encryptDeviceMetadata === undefined
                    ? undefined
                    : await options.encryptDeviceMetadata(ctx, identity.publicKey.slice());
            if (
                encryptedDeviceMetadata !== undefined &&
                !(encryptedDeviceMetadata instanceof Uint8Array)
            ) {
                throw new MurmurError(
                    "invalid_argument",
                    "Encrypted device metadata must be bytes",
                );
            }
            if (
                encryptedDeviceMetadata !== undefined &&
                encryptedDeviceMetadata.length > 16 * 1024
            ) {
                throw new MurmurError(
                    "resource_exhausted",
                    "Encrypted device metadata exceeds 16 KiB",
                );
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
                encryptedDeviceMetadata,
            );
            if (options.connection !== "deferred") await client.connect(ctx);
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

    /** Register this device and replenish its directory entry after a deferred open. */
    async connect(ctx: Context): Promise<void> {
        await this.#exclusive(ctx, () => this.#connect(ctx));
    }

    /** Wrap this client's account root without exposing the secret key. */
    async createAccountSecret(password: string): Promise<CreatedAccountSecret> {
        this.#assertOpen();
        this.#pendingOperations += 1;
        try {
            return await wrapAccountSecret(this.#account, password);
        } finally {
            this.#finishOperation();
        }
    }

    /** Read this account's authenticated device roster entries. */
    async devices(ctx: Context): Promise<readonly MurmurDeviceRosterEntry[]> {
        return this.#tracked(ctx, async () => {
            const remote = await this.#transport.readDeviceRoster?.(ctx, this.#account.publicKey);
            if (remote !== undefined) {
                await this.#observeRoster(ctx, `lookup-${remote.revision}`, remote);
            }
            const roster = remote ?? (await this.#ownRoster(ctx));
            return roster === undefined
                ? []
                : roster.devices.map((entry) =>
                      Object.freeze({
                          ...entry,
                          deviceKey: entry.deviceKey.slice(),
                          encryptedMetadata: entry.encryptedMetadata.slice(),
                      }),
                  );
        });
    }

    /** List active sibling devices with no authenticated activity for six months. */
    async dormantDevices(ctx: Context): Promise<readonly MurmurDormantDevice[]> {
        return this.#tracked(ctx, async () => {
            const roster = await this.#ownRoster(ctx);
            if (roster === undefined) return [];
            const now = this.#now();
            const dormant: MurmurDormantDevice[] = [];
            for (const entry of roster.devices) {
                if (equalBytes(entry.deviceKey, this.#identity.publicKey)) {
                    continue;
                }
                const bytes = await this.#store.get(
                    ctx,
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

    async #ownRoster(ctx: Context): Promise<MurmurDeviceRoster | undefined> {
        const bytes = await this.#store.get(ctx, ACCOUNT_ROSTER_KEY);
        if (bytes === undefined) return undefined;
        try {
            return parseDeviceRoster(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #localDirectoryPrekey(
        ctx: Context,
        key: string,
    ): Promise<DirectoryLocalPrekey | undefined> {
        const bytes = await this.#store.get(ctx, key);
        if (bytes === undefined) return undefined;
        try {
            return decodeDirectoryLocalPrekey(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #directoryOneTimePrekeys(
        ctx: Context,
        count: number,
        pending: boolean,
    ): Promise<readonly MurmurDirectoryOneTimePrekey[]> {
        const now = this.#now();
        const bundles: ReturnType<typeof createMlsKeyPackage>[] = [];
        const stored: {
            readonly reference: Uint8Array;
            readonly bytes: Uint8Array;
            readonly expiresAt: number;
        }[] = [];
        const prekeys: MurmurDirectoryOneTimePrekey[] = [];
        try {
            for (let index = 0; index < count; index += 1) {
                const bundle = createMlsKeyPackage(
                    this.#identity,
                    Math.floor(now / 1_000),
                    KEY_PACKAGE_LIFETIME_SECONDS,
                    this.#account.publicKey,
                );
                bundles.push(bundle);
                const reference = mlsKeyPackageReference(bundle.keyPackage);
                const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
                const privateBytes = serializeMlsKeyPackageBundle(bundle);
                const notificationExpiresAt = now + DIRECTORY_NOTIFICATION_TTL_MILLISECONDS;
                const expiresAt = Math.min(
                    Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                    notificationExpiresAt,
                );
                stored.push({ reference, bytes: privateBytes, expiresAt });
                prekeys.push({
                    reference,
                    keyPackage,
                    expiresAt,
                    spentNotification: createSignedDelivery(
                        this.#identity,
                        [this.#identity.publicKey],
                        encodeDirectorySpentNotification(reference),
                        {
                            createdAt: now,
                            expiresAt: notificationExpiresAt,
                            senderAccount: this.#account.publicKey,
                        },
                    ),
                });
            }
            await this.#engine.storeKeyPackages(ctx, stored);
            await this.#store.tx(ctx, async (transaction) => {
                for (const prekey of prekeys) {
                    const metadata = encodeDirectoryLocalPrekey(prekey);
                    const suffix = encodeBase64Url(prekey.reference);
                    try {
                        await this.#store.set(
                            transaction,
                            `${DIRECTORY_ONE_TIME_PREFIX}${suffix}`,
                            metadata,
                        );
                        if (pending) {
                            await this.#store.set(
                                transaction,
                                `${DIRECTORY_PENDING_PREFIX}${suffix}`,
                                metadata,
                            );
                        }
                    } finally {
                        zeroBytes(metadata);
                    }
                }
            });
            return prekeys.sort((left, right) =>
                compareDirectoryReferences(left.reference, right.reference),
            );
        } finally {
            for (const value of stored) zeroBytes(value.bytes);
            for (const bundle of bundles) destroyMlsKeyPackageBundle(bundle);
        }
    }

    async #createDirectoryLastResort(ctx: Context): Promise<DirectoryLocalPrekey> {
        const bundle = createMlsKeyPackage(
            this.#identity,
            Math.floor(this.#now() / 1_000),
            KEY_PACKAGE_LIFETIME_SECONDS,
            this.#account.publicKey,
        );
        try {
            const reference = mlsKeyPackageReference(bundle.keyPackage);
            const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
            const expiresAt = Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n);
            const privateBytes = serializeMlsKeyPackageBundle(bundle);
            try {
                await this.#engine.storeKeyPackages(ctx, [
                    { reference, bytes: privateBytes, expiresAt, reusable: true },
                ]);
            } finally {
                zeroBytes(privateBytes);
            }
            const lastResort = { reference, keyPackage, expiresAt };
            const metadata = encodeDirectoryLocalPrekey(lastResort);
            try {
                await this.#store.set(ctx, DIRECTORY_LAST_RESORT_KEY, metadata);
            } finally {
                zeroBytes(metadata);
            }
            return lastResort;
        } finally {
            destroyMlsKeyPackageBundle(bundle);
        }
    }

    async #directoryUpload(
        ctx: Context,
        mode: "replenish" | "rotate",
        lastResort: DirectoryLocalPrekey,
        oneTimePrekeys: readonly MurmurDirectoryOneTimePrekey[],
    ): Promise<void> {
        if (this.#transport.uploadDirectoryPrekeys === undefined) return;
        const roster = await this.#ownRoster(ctx);
        const entry = roster?.devices.find((device) =>
            equalBytes(device.deviceKey, this.#identity.publicKey),
        );
        if (entry === undefined) {
            throw new MurmurError(
                "invalid_state",
                "Local device is absent from its account roster",
            );
        }
        const now = this.#now();
        const delivery = createSignedDelivery(
            this.#account,
            [],
            encodeDirectoryPrekeyUpload({
                version: 1,
                type: "directory_prekey_upload",
                mode,
                deviceKey: this.#identity.publicKey,
                resetGeneration: entry.resetGeneration,
                oneTimePrekeys,
                lastResort,
            }),
            { createdAt: now, expiresAt: now + DIRECTORY_NOTIFICATION_TTL_MILLISECONDS },
        );
        await this.#transport.uploadDirectoryPrekeys(ctx, delivery);
        if (roster !== undefined) {
            const updated: MurmurDeviceRoster = {
                ...roster,
                admissions: roster.admissions.map((admission) =>
                    equalBytes(admission.deviceKey, this.#identity.publicKey)
                        ? {
                              deviceKey: admission.deviceKey,
                              keyPackage: lastResort.keyPackage,
                          }
                        : admission,
                ),
            };
            const bytes = serializeDeviceRoster(updated);
            try {
                await this.#store.set(ctx, ACCOUNT_ROSTER_KEY, bytes);
            } finally {
                zeroBytes(bytes);
            }
        }
    }

    async #directoryMetadata(
        ctx: Context,
        prefix: string,
    ): Promise<Map<string, DirectoryLocalPrekey>> {
        const page = await this.#store.scan(ctx, prefix, { limit: 512 });
        const values = new Map<string, DirectoryLocalPrekey>();
        try {
            for (const [key, bytes] of page) values.set(key, decodeDirectoryLocalPrekey(bytes));
            return values;
        } finally {
            for (const bytes of page.values()) zeroBytes(bytes);
        }
    }

    #spentNotification(prekey: DirectoryLocalPrekey): MurmurDirectoryOneTimePrekey {
        const now = this.#now();
        const expiresAt = Math.min(prekey.expiresAt, now + DIRECTORY_NOTIFICATION_TTL_MILLISECONDS);
        return {
            ...prekey,
            expiresAt,
            spentNotification: createSignedDelivery(
                this.#identity,
                [this.#identity.publicKey],
                encodeDirectorySpentNotification(prekey.reference),
                { createdAt: now, expiresAt, senderAccount: this.#account.publicKey },
            ),
        };
    }

    async #replenishDirectoryEntry(ctx: Context, lastResort: DirectoryLocalPrekey): Promise<void> {
        const spentPage = await this.#store.scan(ctx, DIRECTORY_SPENT_PREFIX, { limit: 256 });
        const pendingSpent: string[] = [];
        try {
            for (const [key, bytes] of spentPage) {
                if (utf8Decode(bytes) === "pending") pendingSpent.push(key);
            }
        } finally {
            for (const bytes of spentPage.values()) zeroBytes(bytes);
        }
        if (pendingSpent.length === 0) return;
        let pending = await this.#directoryMetadata(ctx, DIRECTORY_PENDING_PREFIX);
        if (pending.size < pendingSpent.length) {
            await this.#directoryOneTimePrekeys(ctx, pendingSpent.length - pending.size, true);
            pending = await this.#directoryMetadata(ctx, DIRECTORY_PENDING_PREFIX);
        }
        const selected = [...pending.entries()].slice(0, pendingSpent.length);
        await this.#directoryUpload(
            ctx,
            "replenish",
            lastResort,
            selected
                .map(([, prekey]) => this.#spentNotification(prekey))
                .sort((left, right) => compareDirectoryReferences(left.reference, right.reference)),
        );
        await this.#store.tx(ctx, async (transaction) => {
            for (const [key] of selected) await this.#store.delete(transaction, key);
            for (const key of pendingSpent)
                await this.#store.set(transaction, key, utf8Encode("replenished"));
        });
    }

    async #ensureDirectoryEntry(ctx: Context): Promise<void> {
        if (this.#transport.uploadDirectoryPrekeys === undefined) return;
        let lastResort = await this.#localDirectoryPrekey(ctx, DIRECTORY_LAST_RESORT_KEY);
        if (lastResort === undefined) {
            const roster = await this.#ownRoster(ctx);
            const admission = roster?.admissions.find((entry) =>
                equalBytes(entry.deviceKey, this.#identity.publicKey),
            );
            if (admission === undefined) {
                throw new MurmurError("invalid_state", "Local device admission is missing");
            }
            const keyPackage = decodeMlsKeyPackage(admission.keyPackage);
            if (
                !verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000)) ||
                !equalBytes(keyPackage.leafNode.signatureKey, this.#identity.publicKey) ||
                !equalBytes(keyPackage.leafNode.credential.identity, this.#account.publicKey)
            ) {
                throw new MurmurError("invalid_state", "Local last-resort KeyPackage is invalid");
            }
            lastResort = {
                reference: mlsKeyPackageReference(keyPackage),
                keyPackage: admission.keyPackage,
                expiresAt: Number((keyPackage.leafNode.notAfter + 1n) * 1_000n),
            };
            const metadata = encodeDirectoryLocalPrekey(lastResort);
            try {
                await this.#store.set(ctx, DIRECTORY_LAST_RESORT_KEY, metadata);
            } finally {
                zeroBytes(metadata);
            }
        }
        const initialized = await this.#store.get(ctx, DIRECTORY_INITIALIZED_KEY);
        if (initialized !== undefined) {
            zeroBytes(initialized);
            if (lastResort.expiresAt <= this.#now()) {
                await this.#rotateDirectoryEntry(ctx);
            } else {
                await this.#replenishDirectoryEntry(ctx, lastResort);
            }
            return;
        }
        const previous = await this.#directoryMetadata(ctx, DIRECTORY_ONE_TIME_PREFIX);
        const oneTimePrekeys = await this.#directoryOneTimePrekeys(
            ctx,
            DIRECTORY_ONE_TIME_POOL_SIZE,
            false,
        );
        await this.#directoryUpload(ctx, "rotate", lastResort, oneTimePrekeys);
        await this.#store.set(ctx, DIRECTORY_INITIALIZED_KEY, new Uint8Array([1]));
        const oldReferences = [...previous.values()].map((entry) => entry.reference);
        if (oldReferences.length > 0) await this.#engine.deleteKeyPackages(ctx, oldReferences);
    }

    async #rotateDirectoryEntry(ctx: Context): Promise<void> {
        if (this.#transport.uploadDirectoryPrekeys === undefined) {
            throw new MurmurError(
                "unsupported",
                "Delivery transport does not support identity-directory uploads",
            );
        }
        const previousOneTime = await this.#directoryMetadata(ctx, DIRECTORY_ONE_TIME_PREFIX);
        const previousLast = await this.#localDirectoryPrekey(ctx, DIRECTORY_LAST_RESORT_KEY);
        const lastResort = await this.#createDirectoryLastResort(ctx);
        const oneTimePrekeys = await this.#directoryOneTimePrekeys(
            ctx,
            DIRECTORY_ONE_TIME_POOL_SIZE,
            false,
        );
        await this.#directoryUpload(ctx, "rotate", lastResort, oneTimePrekeys);
        await this.#store.set(ctx, DIRECTORY_INITIALIZED_KEY, new Uint8Array([1]));
        const references = [
            ...[...previousOneTime.values()].map((entry) => entry.reference),
            ...(previousLast === undefined ? [] : [previousLast.reference]),
        ];
        if (references.length > 0) await this.#engine.deleteKeyPackages(ctx, references);
    }

    #publicAccountClaim(
        requestedIdentity: Uint8Array,
        claim: DeliveryDirectoryClaim,
    ): MurmurAccountClaim {
        if (!equalBytes(requestedIdentity, claim.accountKey)) {
            throw new MurmurError("invalid_state", "Directory claim names a different account");
        }
        const devices = new Set<string>();
        const members = claim.devices.map((device): MurmurClaimedSessionMember => {
            const keyPackage = decodeMlsKeyPackage(device.keyPackage);
            const encodedDevice = encodeBase64Url(device.deviceKey);
            if (
                devices.has(encodedDevice) ||
                !verifyMlsKeyPackage(keyPackage, Math.floor(this.#now() / 1_000)) ||
                !equalBytes(keyPackage.leafNode.signatureKey, device.deviceKey) ||
                !equalBytes(keyPackage.leafNode.credential.identity, requestedIdentity)
            ) {
                throw new MurmurError(
                    "invalid_state",
                    "Directory returned invalid MLS admission material",
                );
            }
            devices.add(encodedDevice);
            return Object.freeze({
                identity: requestedIdentity.slice(),
                device: device.deviceKey.slice(),
                resetGeneration: device.resetGeneration,
                source: device.source,
                keyPackage: device.keyPackage.slice(),
            });
        });
        return Object.freeze({
            identity: requestedIdentity.slice(),
            rosterRevision: claim.rosterRevision,
            members: Object.freeze(members),
        });
    }

    #flattenAdmissions(
        admissions: readonly MurmurSessionAdmission[],
    ): readonly MurmurSessionMember[] {
        const flattened: MurmurSessionMember[] = [];
        for (const admission of admissions) {
            if ("members" in admission) {
                if (
                    admission.members.length < 1 ||
                    admission.members.some(
                        (member) => !equalBytes(member.identity, admission.identity),
                    )
                ) {
                    throw new MurmurError("invalid_argument", "Invalid claimed account admission");
                }
                flattened.push(...admission.members);
            } else {
                flattened.push(admission);
            }
        }
        return flattened;
    }

    async #observeRoster(
        ctx: Context,
        eventId: string,
        roster: MurmurDeviceRoster | DeliveryDeviceRoster,
    ): Promise<void> {
        const bytes = serializeDeviceRoster(roster);
        try {
            await this.#store.tx(ctx, (transaction) =>
                observeDeviceRoster(
                    transaction,
                    this.#store,
                    this.#account.publicKey,
                    eventId,
                    bytes,
                ),
            );
        } finally {
            zeroBytes(bytes);
        }
    }

    async #ensureRegistered(
        ctx: Context,
        forceReset: boolean = false,
        staleAttempts: number = 0,
    ): Promise<void> {
        const current = await this.#transport.readDeviceRoster?.(ctx, this.#account.publicKey);
        const currentEntry = current?.devices.find((entry) =>
            equalBytes(entry.deviceKey, this.#identity.publicKey),
        );
        if (
            !forceReset &&
            current !== undefined &&
            currentEntry !== undefined &&
            (this.#encryptedDeviceMetadata === undefined ||
                equalBytes(currentEntry.encryptedMetadata, this.#encryptedDeviceMetadata))
        ) {
            await this.#observeRoster(ctx, `lookup-${current.revision}`, current);
            return;
        }
        if (!forceReset && current !== undefined && currentEntry !== undefined) {
            if (this.#transport.mutateDeviceRoster === undefined) {
                throw new MurmurError(
                    "unsupported",
                    "Delivery transport does not support device rosters",
                );
            }
            const now = this.#now();
            const delivery = createSignedDelivery(
                this.#account,
                current.devices.map((entry) => entry.deviceKey),
                encodeDeviceRosterMutation({
                    version: 1,
                    type: "update_metadata",
                    deviceKey: this.#identity.publicKey,
                    resetGeneration: currentEntry.resetGeneration,
                    encryptedMetadata: this.#encryptedDeviceMetadata!,
                }),
                { createdAt: now, expiresAt: now + 180 * 24 * 60 * 60 * 1_000 - 60_000 },
            );
            try {
                const roster = await this.#transport.mutateDeviceRoster(ctx, delivery);
                await this.#observeRoster(ctx, delivery.id, roster);
                return;
            } catch (error: unknown) {
                if (error instanceof DeliveryStaleRosterError && staleAttempts < 7) {
                    await this.#ensureRegistered(ctx, forceReset, staleAttempts + 1);
                    return;
                }
                throw error;
            }
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
                await this.#engine.storeKeyPackages(ctx, [
                    {
                        reference,
                        bytes: stored,
                        expiresAt: Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n),
                        reusable: true,
                    },
                ]);
            } finally {
                zeroBytes(stored);
            }
            const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
            const expiresAt = Number((bundle.keyPackage.leafNode.notAfter + 1n) * 1_000n);
            const directoryMetadata = encodeDirectoryLocalPrekey({
                reference,
                keyPackage,
                expiresAt,
            });
            try {
                await this.#store.set(ctx, DIRECTORY_LAST_RESORT_KEY, directoryMetadata);
            } finally {
                zeroBytes(directoryMetadata);
            }
            await this.#store.delete(ctx, DIRECTORY_INITIALIZED_KEY);
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
                    encryptedMetadata:
                        this.#encryptedDeviceMetadata ??
                        currentEntry?.encryptedMetadata ??
                        new Uint8Array(),
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
                                  lastAccessedAt: now,
                                  encryptedMetadata:
                                      this.#encryptedDeviceMetadata ??
                                      currentEntry?.encryptedMetadata ??
                                      new Uint8Array(),
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
                    : await this.#transport
                          .mutateDeviceRoster(ctx, delivery)
                          .catch(async (error) => {
                              if (error instanceof DeliveryStaleRosterError && staleAttempts < 7) {
                                  await this.#ensureRegistered(ctx, forceReset, staleAttempts + 1);
                                  return undefined;
                              }
                              throw error;
                          });
            if (roster === undefined) return;
            await this.#observeRoster(ctx, delivery.id, roster);
        } finally {
            destroyMlsKeyPackageBundle(bundle);
        }
    }

    /** Remove any account device, including this device, using the account identity key. */
    async removeDevice(ctx: Context, deviceKey: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, async () => {
            const roster = await this.#ownRoster(ctx);
            if (roster === undefined) {
                throw new MurmurError("not_found", "Account has no device roster");
            }
            const entry = roster.devices.find((candidate) =>
                equalBytes(candidate.deviceKey, deviceKey),
            );
            if (entry === undefined) {
                throw new MurmurError("not_found", "Device is not registered");
            }
            if (this.#transport.mutateDeviceRoster === undefined) {
                throw new MurmurError(
                    "unsupported",
                    "Delivery transport does not support device rosters",
                );
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
            const updated = await this.#transport.mutateDeviceRoster(ctx, delivery);
            await this.#observeRoster(ctx, delivery.id, updated);
        });
        this.#signalSync();
    }

    /** Register one optional typed service under its durable stable ID. */
    registerService(registration: MurmurServiceRegistration): void {
        this.#assertOpen();
        validateMurmurServiceRegistration(registration);
        if (this.#services.has(registration.id)) {
            throw new MurmurError("already_exists", "Murmur service is already registered");
        }
        this.#services.set(registration.id, registration.service);
    }

    /** Disable one optional service without changing its durable state. */
    unregisterService(id: string): void {
        this.#assertOpen();
        this.#services.delete(id);
    }

    /** Create and durably retain one bare MLS KeyPackage for direct session admission. */
    async createKeyPackage(ctx: Context): Promise<MurmurSessionMember> {
        return this.#exclusive(ctx, async () => {
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
                    await this.#engine.storeKeyPackages(ctx, [
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

    /** Claim one exact account from the relay directory using an authentication ticket. */
    async claimAccount(
        ctx: Context,
        identityKey: Uint8Array,
        ticket: Uint8Array,
    ): Promise<MurmurAccountClaim> {
        return this.#tracked(ctx, async () => {
            validateIdentityPublicKey({ publicKey: identityKey });
            if (ticket.length < 1 || ticket.length > 8 * 1024) {
                throw new MurmurError("invalid_argument", "Invalid directory claim ticket");
            }
            if (this.#transport.claimDirectory === undefined) {
                throw new MurmurError(
                    "unsupported",
                    "Delivery transport does not support identity-directory claims",
                );
            }
            const claim = await this.#transport.claimDirectory(ctx, identityKey, ticket);
            return this.#publicAccountClaim(identityKey, claim);
        });
    }

    /** Rotate all unclaimed one-use prekeys and this device's multi-use fallback. */
    async rotate(ctx: Context): Promise<void> {
        await this.#exclusive(ctx, () => this.#rotateDirectoryEntry(ctx));
    }

    /** Create a two-or-more-member MLS session from bare MLS admission material. */
    async createSession(ctx: Context, options: CreateMurmurSessionOptions): Promise<MurmurSession> {
        const owner =
            options.service === undefined
                ? ({ version: 1, owner: "account" } as const)
                : ({ version: 1, owner: "service", serviceId: options.service } as const);
        if (options.service !== undefined && !this.#services.has(options.service)) {
            throw new MurmurError("invalid_argument", "Session service is not registered");
        }
        const session = await this.#exclusive(ctx, () =>
            this.#engine.create(
                ctx,
                {
                    descriptor: options.descriptor,
                    ...(options.adminsAssignAdmins === undefined
                        ? {}
                        : { adminsAssignAdmins: options.adminsAssignAdmins }),
                    ...(options.anyoneCanAddMembers === undefined
                        ? {}
                        : { anyoneCanAddMembers: options.anyoneCanAddMembers }),
                    ...(options.sendPolicy === undefined ? {} : { sendPolicy: options.sendPolicy }),
                    members: this.#flattenAdmissions(options.members).map((member) => {
                        const keyPackage = decodeMlsKeyPackage(member.keyPackage);
                        if (!equalBytes(keyPackage.leafNode.credential.identity, member.identity)) {
                            throw new MurmurError(
                                "invalid_argument",
                                "Session member account does not match its KeyPackage",
                            );
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
    async session(ctx: Context, id: Uint8Array): Promise<MurmurSession | undefined> {
        return this.#tracked(ctx, () => this.#engine.get(ctx, id));
    }

    /** List one bounded page of local sessions in durable key order. */
    async sessions(
        ctx: Context,
        options: MurmurSessionListOptions = {},
    ): Promise<MurmurSessionPage> {
        return this.#tracked(ctx, () => this.#engine.list(ctx, options));
    }

    /** Activate an application-owned pending session and release its buffered updates. */
    async activateSession(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.activate(ctx, id));
        this.#signalSync();
    }

    /** Terminally reject and destroy an application-owned pending session. */
    async ignoreSession(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.ignore(ctx, id));
    }

    /** Abandon a blocked local membership operation and destroy the whole session. */
    async abandonSession(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.abandon(ctx, id));
    }

    /** Owner-only durable deletion of one session and its relay-linked pending state. */
    async deleteSession(ctx: Context, id: Uint8Array): Promise<string> {
        const deletionId = await this.#exclusive(ctx, () => this.#engine.delete(ctx, id));
        this.#signalSync();
        return deletionId;
    }

    /**
     * Terminally delete this account at the relay, then atomically destroy all local state.
     *
     * A replay response confirms an earlier accepted request after a crash. Remote MLS history
     * and copies held by other members are not erased by account deletion.
     */
    async deleteAccount(ctx: Context): Promise<void> {
        this.#assertOpen();
        if (this.#transport.deleteAccount === undefined) {
            throw new MurmurError(
                "unsupported",
                "Delivery transport does not support account deletion",
            );
        }
        if (this.#pendingOperations > 0 || this.#syncActive || this.#updatesActive) {
            throw new MurmurError("busy", "Account deletion requires an idle Murmur client");
        }
        this.#accountDeletionActive = true;
        this.#pendingOperations += 1;
        let request: SignedDelivery | undefined;
        try {
            const stored = await this.#store.get(ctx, ACCOUNT_DELETION_KEY);
            if (stored === undefined) {
                const now = this.#now();
                request = createSignedDelivery(this.#account, [], encodeAccountDeletionRequest(), {
                    createdAt: now,
                    expiresAt: now + DIRECTORY_NOTIFICATION_TTL_MILLISECONDS,
                    senderAccount: this.#account.publicKey,
                });
            } else {
                try {
                    request = parseSignedDelivery(JSON.parse(utf8Decode(stored)) as unknown);
                    if (
                        !equalBytes(request.sender, this.#account.publicKey) ||
                        !equalBytes(request.senderAccount, this.#account.publicKey)
                    ) {
                        throw new Error("Stored account deletion names a different account");
                    }
                    const now = this.#now();
                    request = createSignedDelivery(this.#account, [], request.ciphertext, {
                        id: request.id,
                        createdAt: now,
                        expiresAt: now + DIRECTORY_NOTIFICATION_TTL_MILLISECONDS,
                        senderAccount: this.#account.publicKey,
                    });
                } finally {
                    zeroBytes(stored);
                }
            }
            const encoded = canonicalJsonBytes(signedDeliveryToJson(request) as never);
            try {
                await this.#store.set(ctx, ACCOUNT_DELETION_KEY, encoded);
            } finally {
                zeroBytes(encoded);
            }
            try {
                await this.#transport.deleteAccount(ctx, request);
            } catch (error: unknown) {
                if (!(error instanceof DeliveryTransportError && error.code === "replay")) {
                    throw error;
                }
            }
            await this.#store.tx(ctx, async (transaction) => {
                let after: string | undefined;
                for (;;) {
                    const page = await this.#store.scan(transaction, "", {
                        ...(after === undefined ? {} : { after }),
                        limit: RESET_PURGE_SCAN_LIMIT,
                    });
                    if (page.size === 0) break;
                    for (const [key, value] of page) {
                        after = key;
                        try {
                            await this.#store.delete(transaction, key);
                        } finally {
                            zeroBytes(value);
                        }
                    }
                    if (page.size < RESET_PURGE_SCAN_LIMIT) break;
                }
            });
            this.#closed = true;
            this.#services.clear();
            destroyIdentity(this.#identity);
            destroyIdentity(this.#account);
        } finally {
            if (request !== undefined) {
                zeroBytes(request.sender);
                zeroBytes(request.senderAccount);
                zeroBytes(request.ciphertext);
                zeroBytes(request.signature);
            }
            this.#accountDeletionActive = false;
            this.#finishOperation();
        }
    }

    /**
     * Encrypt and durably queue application bytes without waiting for relay or peer state.
     *
     * Sends made while a membership Commit is staged use its post-Commit epoch and publish
     * only after that Commit is adopted from its relay echo and every required Welcome publishes.
     */
    async send(ctx: Context, id: Uint8Array, bytes: Uint8Array): Promise<string> {
        const deliveryId = await this.#exclusive(ctx, () => this.#engine.send(ctx, id, bytes));
        this.#signalSync();
        return deliveryId;
    }

    /** Durably request one MLS member addition from bare admission material. */
    async addMember(ctx: Context, id: Uint8Array, member: MurmurSessionAdmission): Promise<void> {
        await this.#exclusive(ctx, async () => {
            for (const admission of this.#flattenAdmissions([member])) {
                const keyPackage = decodeMlsKeyPackage(admission.keyPackage);
                if (!equalBytes(keyPackage.leafNode.credential.identity, admission.identity)) {
                    throw new MurmurError(
                        "invalid_argument",
                        "Session member account does not match its KeyPackage",
                    );
                }
                await this.#engine.add(ctx, id, {
                    identity: keyPackage.leafNode.signatureKey,
                    keyPackage,
                });
            }
        });
        this.#signalSync();
    }

    /** Durably request removal of one non-owner account and return before convergence. */
    async removeMember(ctx: Context, id: Uint8Array, identity: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.remove(ctx, id, identity));
        this.#signalSync();
    }

    /** Durably request an admin grant and return before its Commit is published. */
    async grantAdmin(ctx: Context, id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.grantAdmin(ctx, id, account));
        this.#signalSync();
    }

    /** Durably request an owner-authorized admin revocation. */
    async revokeAdmin(ctx: Context, id: Uint8Array, account: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.revokeAdmin(ctx, id, account));
        this.#signalSync();
    }

    /** Durably request owner-controlled policy changes. */
    async setPolicies(
        ctx: Context,
        id: Uint8Array,
        policies: MurmurSessionPolicyChanges,
    ): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.setPolicies(ctx, id, policies));
        this.#signalSync();
    }

    /** Durably request removal of every local-account device from one session. */
    async leaveSession(ctx: Context, id: Uint8Array): Promise<void> {
        await this.#exclusive(ctx, () => this.#engine.leave(ctx, id));
        this.#signalSync();
    }

    /** Return the bounded, durable diagnostics retained for terminal session failures. */
    async issues(ctx: Context): Promise<readonly MurmurSessionIssue[]> {
        return this.#tracked(ctx, () => this.#engine.issues(ctx));
    }

    async #pendingReset(ctx: Context): Promise<MurmurResetEvent | undefined> {
        const bytes = await this.#store.get(ctx, RESET_PENDING_KEY);
        if (bytes === undefined) return undefined;
        try {
            return decodeResetEvent(bytes);
        } finally {
            zeroBytes(bytes);
        }
    }

    async #recordReset(ctx: Context, loss: InboxContinuityLossError): Promise<MurmurResetEvent> {
        const existing = await this.#pendingReset(ctx);
        if (existing !== undefined) return existing;
        const sessions: MurmurResetSession[] = [];
        let cursor: string | null = null;
        do {
            const page = await this.#engine.list(ctx, cursor === null ? {} : { after: cursor });
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
            await this.#store.tx(ctx, async (transaction) => {
                const pending = await this.#store.get(transaction, RESET_PENDING_KEY);
                try {
                    if (pending === undefined)
                        await this.#store.set(transaction, RESET_PENDING_KEY, encoded);
                } finally {
                    if (pending !== undefined) zeroBytes(pending);
                }
            });
        } finally {
            zeroBytes(encoded);
        }
        return (await this.#pendingReset(ctx))!;
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

    async #purgeReset(ctx: Context, reset: MurmurResetEvent): Promise<void> {
        await this.#store.tx(ctx, async (transaction) => {
            let after: string | undefined;
            for (;;) {
                const page = await this.#store.scan(transaction, MURMUR_KEY_PREFIX, {
                    ...(after === undefined ? {} : { after }),
                    limit: RESET_PURGE_SCAN_LIMIT,
                });
                if (page.size === 0) break;
                for (const [key, value] of page) {
                    after = key;
                    try {
                        if (!this.#preserveAcrossReset(key))
                            await this.#store.delete(transaction, key);
                    } finally {
                        zeroBytes(value);
                    }
                }
                if (page.size < RESET_PURGE_SCAN_LIMIT) break;
            }
            for (const session of reset.sessions) {
                await this.#store.set(
                    transaction,
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
            await this.#store.delete(transaction, RESET_PENDING_KEY);
        });
        try {
            await this.#engine.acknowledgeInboxBaseline(ctx, reset.head);
        } catch {
            // The committed cursor causes the next synchronization to retry this signed ACK.
        }
        await this.#ensureRegistered(ctx, true);
    }

    async #completeReset(
        ctx: Context,
        reset: MurmurResetEvent,
        onReset: MurmurSyncOptions["onReset"],
    ): Promise<never> {
        if (onReset === undefined) throw new MurmurResetRequiredError(reset, false);
        await this.#invokeCallback("onReset", [reset.id], () => onReset(ctx, reset));
        await this.#exclusive(ctx, async () => {
            await this.#purgeReset(ctx, reset);
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
        ctx: Context,
        options: MurmurSynchronizeOptions = {},
        lifecycle: Pick<
            MurmurSyncOptions,
            | "onUpdates"
            | "onSessionsChanged"
            | "onEffectBlocked"
            | "onIssues"
            | "onDeviceAdded"
            | "onDeviceRevoked"
            | "onReset"
            | "onDeviceDormant"
        > = {},
    ): Promise<MurmurSynchronizeResult> {
        if (this.#syncActive) {
            throw new MurmurError("busy", "Cannot page synchronization while SSE sync is active");
        }
        const pendingReset = await this.#pendingReset(ctx);
        if (pendingReset !== undefined) {
            return this.#completeReset(ctx, pendingReset, lifecycle.onReset);
        }
        await this.#exclusive(ctx, () => this.#queueAccountWork(ctx));
        let result: MurmurSynchronizeResult;
        try {
            result = await this.#exclusive(ctx, () => this.#engine.synchronize(ctx, options));
        } catch (error: unknown) {
            if (!(error instanceof InboxContinuityLossError)) throw error;
            const reset = await this.#exclusive(ctx, () => this.#recordReset(ctx, error));
            return this.#completeReset(ctx, reset, lifecycle.onReset);
        }
        const delivery = await this.#deliverUpdates(ctx, lifecycle);
        return delivery.blocked === undefined ? result : { ...result, blocked: delivery.blocked };
    }

    /**
     * Maintain one recipient-authenticated SSE connection until aborted.
     *
     * Streamed deliveries are transactionally processed and acknowledged in
     * inbox order. Durable outbound work wakes this loop for publication.
     */
    async sync(ctx: Context, options: MurmurSyncOptions = {}): Promise<void> {
        this.#assertOpen();
        if (this.#syncActive) {
            throw new MurmurError("busy", "Murmur synchronization is active");
        }
        if (options.abort?.aborted === true) return;
        const controller = new AbortController();
        const abortFromOptions = (): void => controller.abort(options.abort?.reason);
        options.abort?.addEventListener("abort", abortFromOptions, { once: true });
        const signal = controller.signal;
        this.#disposeAbort = controller;
        this.#syncActive = true;
        this.#pendingOperations += 1;
        const wakeOnAbort = (): void => this.#signalSync();
        signal.addEventListener("abort", wakeOnAbort, { once: true });
        try {
            const pendingReset = await this.#pendingReset(ctx);
            if (pendingReset !== undefined) {
                await this.#completeReset(ctx, pendingReset, options.onReset);
            }
            await this.#flushSync(ctx, SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
            await this.#deliverUpdates(ctx, options);
            while (!signal.aborted) {
                let connected = false;
                let disconnectedBy: unknown;
                const stream = this.#engine.streamInbox(ctx, {
                    signal,
                    onConnected: async (callbackCtx) => {
                        connected = true;
                        if (options.onConnected !== undefined) {
                            await this.#invokeCallback("onConnected", [], () =>
                                options.onConnected!(callbackCtx),
                            );
                        }
                    },
                    onDeviceRosterChanged: (_callbackCtx, accountKey) => {
                        if (!equalBytes(accountKey, this.#account.publicKey)) {
                            throw new MurmurError(
                                "invalid_state",
                                "Relay reported another account's device roster",
                            );
                        }
                        this.#deviceRosterChangeVersion += 1;
                        this.#signalSync();
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
                            await this.#flushSync(ctx, SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
                            await this.#deliverUpdates(ctx, options);
                            await this.#consumeDeviceRosterChanges(ctx, options);
                            continue;
                        }
                        if (outcome.result.done) break;
                        const result = await this.#exclusive(ctx, () =>
                            this.#engine.completeStreamEvent(ctx, outcome.result.value, signal),
                        );
                        if (result.transientPublicationFailures > 0) {
                            this.#scheduleSyncWake(SYNC_RECONNECT_DELAY_MILLISECONDS);
                        }
                        await this.#deliverUpdates(ctx, options);
                        if (signal.aborted) break;
                        next = iterator.next();
                    }
                } catch (error: unknown) {
                    disconnectedBy = error;
                    if (signal.aborted) break;
                    if (error instanceof InboxContinuityLossError) {
                        const reset = await this.#exclusive(ctx, () =>
                            this.#recordReset(ctx, error),
                        );
                        await this.#completeReset(ctx, reset, options.onReset);
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
                        if (connected && options.onDisconnected !== undefined) {
                            await this.#invokeCallback("onDisconnected", [], () =>
                                options.onDisconnected!(ctx, disconnectedBy),
                            );
                        }
                    }
                }
                if (!signal.aborted) {
                    await this.#syncDelay(SYNC_RECONNECT_DELAY_MILLISECONDS, signal);
                }
            }
        } finally {
            options.abort?.removeEventListener("abort", abortFromOptions);
            if (this.#disposeAbort === controller) this.#disposeAbort = undefined;
            signal.removeEventListener("abort", wakeOnAbort);
            this.#syncActive = false;
            this.#syncWakePending = false;
            this.#syncWakeResolve = undefined;
            if (this.#syncRetryTimer !== undefined) {
                clearTimeout(this.#syncRetryTimer);
                this.#syncRetryTimer = undefined;
            }
            this.#finishOperation();
        }
    }

    /** Resolve once every currently active operation and synchronization loop has settled. */
    async idle(): Promise<void> {
        if (this.#pendingOperations === 0) return;
        await new Promise<void>((resolve) => this.#idleResolvers.add(resolve));
    }

    /** Stop synchronization, await active work, then destroy in-memory identity material. */
    async dispose(): Promise<void> {
        if (this.#closed) return;
        if (this.#callbackDepth > 0) {
            throw new MurmurError(
                "invalid_state",
                "Cannot await Murmur disposal from inside a Murmur callback",
            );
        }
        while (!this.#closed) {
            this.#disposeAbort?.abort();
            await this.idle();
            if (this.#pendingOperations === 0) this.close();
        }
    }

    /** Destroy in-memory identity material immediately. Durable state remains application-owned. */
    close(): void {
        if (this.#closed) return;
        if (this.#pendingOperations > 0) {
            throw new MurmurError("busy", "Cannot close Murmur while an operation is pending");
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

    async #consumeDeviceRosterChanges(ctx: Context, options: MurmurSyncOptions): Promise<void> {
        const version = this.#deviceRosterChangeVersion;
        if (version <= this.#consumedDeviceRosterChangeVersion) return;
        const devices = await this.devices(ctx);
        if (options.onDevicesChanged !== undefined) {
            await this.#invokeCallback("onDevicesChanged", [], () =>
                options.onDevicesChanged!(ctx, devices),
            );
        }
        this.#consumedDeviceRosterChangeVersion = version;
        if (this.#deviceRosterChangeVersion > version) this.#signalSync();
    }

    async #deliverUpdates(
        ctx: Context,
        lifecycle: Pick<
            MurmurSyncOptions,
            | "onUpdates"
            | "onSessionsChanged"
            | "onEffectBlocked"
            | "onIssues"
            | "onDeviceAdded"
            | "onDeviceRevoked"
            | "onDeviceDormant"
        >,
    ): Promise<{ readonly delivered: number; readonly blocked?: MurmurEffectBlocked }> {
        if (this.#updatesActive) return { delivered: 0 };
        this.#updatesActive = true;
        this.#pendingOperations += 1;
        let delivered = 0;
        let blockedEffect: MurmurEffectBlocked | undefined;
        try {
            await this.#deliverIssues(ctx, lifecycle.onIssues);
            for (;;) {
                await this.#exclusive(ctx, () => this.#queueAccountWork(ctx));
                const prepared = await this.#exclusive(ctx, () => this.#engine.prepareUpdates(ctx));
                try {
                    const ordered = [
                        ...prepared.routes.map((event) => ({
                            type: "route" as const,
                            id: event.eventId,
                            priority: 0,
                            event,
                        })),
                        ...prepared.sessionChanges.map((event) => ({
                            type: "session" as const,
                            id: event.id,
                            priority: 1,
                            event,
                        })),
                        ...prepared.updates.map((event) => ({
                            type: "update" as const,
                            id: event.id,
                            priority: 2,
                            event,
                        })),
                    ].sort(
                        (left, right) =>
                            left.id.localeCompare(right.id) || left.priority - right.priority,
                    );
                    const head = ordered[0];
                    if (head?.type === "route") {
                        const route = head.event;
                        let owner: SessionRouteDecision["owner"] | undefined;
                        for (const [serviceId, service] of [...this.#services].sort(
                            ([left], [right]) => left.localeCompare(right),
                        )) {
                            if (
                                await this.#invokeCallback(
                                    "service.onNewSession",
                                    [route.eventId],
                                    () =>
                                        service.onNewSession(
                                            ctx,
                                            createMurmurServiceSessionDescriptor(route.session),
                                        ),
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
                            blockedEffect = Object.freeze({
                                reason: "unresolved_route",
                                id: route.eventId,
                                sessionId: route.session.id.slice(),
                            });
                            if (lifecycle.onEffectBlocked !== undefined) {
                                await this.#invokeCallback(
                                    "onEffectBlocked",
                                    [blockedEffect.id],
                                    () => lifecycle.onEffectBlocked!(ctx, blockedEffect!),
                                );
                            }
                            break;
                        }
                        const decision: SessionRouteDecision = {
                            key: route.key,
                            sessionId: route.session.id.slice(),
                            owner: owner ?? { version: 1, owner: "ignored" },
                        };
                        try {
                            await this.#exclusive(ctx, () =>
                                this.#engine.commitUpdates(
                                    ctx,
                                    prepared,
                                    [decision],
                                    new Set(),
                                    new Set(),
                                    new Set(),
                                ),
                            );
                        } finally {
                            zeroBytes(decision.sessionId);
                        }
                        continue;
                    }
                    if (head?.type === "session") {
                        const event = head.event;
                        const publicEvent: MurmurSessionChangedEvent = Object.freeze({
                            id: event.id,
                            ...(event.service === undefined ? {} : { service: event.service }),
                            sessionId: event.sessionId.slice(),
                            status: event.status,
                            descriptor: event.descriptor.slice(),
                            members: Object.freeze(event.members.map((member) => member.slice())),
                            owner: event.owner.slice(),
                            admins: Object.freeze(event.admins.map((admin) => admin.slice())),
                            policies: Object.freeze({ ...event.policies }),
                            ...(event.reAdmission === true ? { reAdmission: true } : {}),
                        });
                        if (lifecycle.onSessionsChanged !== undefined) {
                            await this.#invokeCallback("onSessionsChanged", [publicEvent.id], () =>
                                lifecycle.onSessionsChanged!(ctx, Object.freeze([publicEvent])),
                            );
                        }
                        await this.#exclusive(ctx, () =>
                            this.#engine.commitUpdates(
                                ctx,
                                prepared,
                                [],
                                new Set(),
                                new Set(),
                                new Set([event.key]),
                            ),
                        );
                        delivered += 1;
                        continue;
                    }
                    if (head?.type === "update") {
                        const updates: Extract<(typeof ordered)[number], { type: "update" }>[] = [];
                        for (const item of ordered) {
                            if (item.type !== "update") break;
                            updates.push(item);
                        }
                        const consumedKeys = new Set<string>();
                        const globalUpdates: MurmurUpdate[] = [];
                        let segmentBlocked: (typeof updates)[number]["event"] | undefined;
                        for (const { event: update } of updates) {
                            if (update.owner?.owner === "ignored") {
                                consumedKeys.add(update.key);
                                continue;
                            }
                            if (
                                (update.owner === undefined || update.owner.owner === "account") &&
                                lifecycle.onUpdates === undefined
                            ) {
                                segmentBlocked = update;
                                break;
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
                                const alreadyDelivered = await this.#exclusive(ctx, () =>
                                    this.#engine.serviceUpdateDelivered(ctx, update.id),
                                );
                                if (!alreadyDelivered) {
                                    await this.#invokeCallback(
                                        "service.onUpdate",
                                        [publicUpdate.id],
                                        () => service.onUpdate(ctx, publicUpdate),
                                    );
                                    await this.#exclusive(ctx, () =>
                                        this.#engine.markServiceUpdateDelivered(ctx, update.id),
                                    );
                                }
                            }
                            globalUpdates.push(publicUpdate);
                            consumedKeys.add(update.key);
                        }
                        if (segmentBlocked !== undefined && consumedKeys.size === 0) {
                            blockedEffect = Object.freeze({
                                reason: "missing_update_handler",
                                id: segmentBlocked.id,
                                sessionId: segmentBlocked.sessionId.slice(),
                            });
                            if (lifecycle.onEffectBlocked !== undefined) {
                                await this.#invokeCallback(
                                    "onEffectBlocked",
                                    [blockedEffect.id],
                                    () => lifecycle.onEffectBlocked!(ctx, blockedEffect!),
                                );
                            }
                            break;
                        }
                        if (globalUpdates.length > 0) {
                            if (lifecycle.onUpdates !== undefined) {
                                await this.#invokeCallback(
                                    "onUpdates",
                                    globalUpdates.map((update) => update.id),
                                    () => lifecycle.onUpdates!(ctx, Object.freeze(globalUpdates)),
                                );
                            }
                        }
                        await this.#exclusive(ctx, () =>
                            this.#engine.commitUpdates(
                                ctx,
                                prepared,
                                [],
                                consumedKeys,
                                new Set(),
                                new Set(),
                            ),
                        );
                        delivered += consumedKeys.size;
                        continue;
                    }

                    const consumedDeletionKeys = new Set<string>();
                    for (const deletion of prepared.deletions) {
                        const service = this.#services.get(deletion.service);
                        if (service?.onSessionDeleted !== undefined) {
                            await this.#invokeCallback(
                                "service.onSessionDeleted",
                                [deletion.id],
                                () =>
                                    service.onSessionDeleted!(
                                        ctx,
                                        Object.freeze({
                                            id: deletion.id,
                                            sessionId: deletion.sessionId.slice(),
                                            owner: deletion.owner.slice(),
                                            service: deletion.service,
                                        }),
                                    ),
                            );
                        }
                        consumedDeletionKeys.add(deletion.key);
                    }
                    if (lifecycle.onDeviceDormant !== undefined) {
                        const dormant = await this.dormantDevices(ctx);
                        if (dormant.length > 0) {
                            await this.#invokeCallback("onDeviceDormant", [], () =>
                                lifecycle.onDeviceDormant!(ctx, dormant),
                            );
                        }
                    }
                    const accountEvents: PreparedAccountEvents = await prepareAccountEvents(
                        ctx,
                        this.#store,
                    );
                    if (accountEvents.added.length > 0) {
                        if (lifecycle.onDeviceAdded !== undefined) {
                            await this.#invokeCallback(
                                "onDeviceAdded",
                                accountEvents.added.map((event) => event.id),
                                () => lifecycle.onDeviceAdded!(ctx, accountEvents.added),
                            );
                        }
                    }
                    if (accountEvents.revoked.length > 0) {
                        if (lifecycle.onDeviceRevoked !== undefined) {
                            await this.#invokeCallback(
                                "onDeviceRevoked",
                                accountEvents.revoked.map((event) => event.id),
                                () => lifecycle.onDeviceRevoked!(ctx, accountEvents.revoked),
                            );
                        }
                    }
                    if (consumedDeletionKeys.size === 0 && accountEvents.keys.length === 0) {
                        if (!prepared.exhausted) continue;
                        break;
                    }
                    await this.#exclusive(ctx, () =>
                        this.#engine.commitUpdates(
                            ctx,
                            prepared,
                            [],
                            new Set(),
                            consumedDeletionKeys,
                            new Set(),
                            async (transaction) => {
                                await deletePreparedAccountEvents(
                                    transaction,
                                    this.#store,
                                    accountEvents,
                                );
                            },
                        ),
                    );
                    delivered += consumedDeletionKeys.size;
                } finally {
                    this.#zeroPreparedUpdates(prepared);
                }
            }
            await this.#deliverIssues(ctx, lifecycle.onIssues);
            return blockedEffect === undefined
                ? { delivered }
                : { delivered, blocked: blockedEffect };
        } finally {
            this.#finishOperation();
            this.#updatesActive = false;
        }
    }

    async #deliverIssues(ctx: Context, onIssues: MurmurSyncOptions["onIssues"]): Promise<void> {
        if (onIssues === undefined || this.#reportedIssueVersion === this.#engine.issueVersion) {
            return;
        }
        const issues = await this.#exclusive(ctx, () => this.#engine.issues(ctx));
        const observedVersion = this.#engine.issueVersion;
        const fingerprint = JSON.stringify(
            issues.map((issue) => ({
                id: issue.id,
                code: issue.code,
                sessionId: issue.sessionId === undefined ? null : encodeBase64Url(issue.sessionId),
                kind: issue.kind ?? null,
                operationId: issue.operationId ?? null,
            })),
        );
        try {
            if (issues.length > 0 && fingerprint !== this.#reportedIssueFingerprint) {
                await this.#invokeCallback(
                    "onIssues",
                    issues.map((issue) => issue.id),
                    () =>
                        onIssues(
                            ctx,
                            Object.freeze(
                                issues.map((issue) =>
                                    Object.freeze({
                                        ...issue,
                                        ...(issue.sessionId === undefined
                                            ? {}
                                            : { sessionId: issue.sessionId.slice() }),
                                    }),
                                ),
                            ),
                        ),
                );
            }
            this.#reportedIssueVersion = observedVersion;
            this.#reportedIssueFingerprint = fingerprint;
            if (this.#engine.issueVersion !== observedVersion) this.#signalSync();
        } finally {
            for (const issue of issues) {
                if (issue.sessionId !== undefined) zeroBytes(issue.sessionId);
            }
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
        for (const deletion of prepared.deletions) {
            zeroBytes(deletion.sessionId);
            zeroBytes(deletion.owner);
        }
        for (const change of prepared.sessionChanges) {
            zeroBytes(change.sessionId);
            zeroBytes(change.descriptor);
            zeroBytes(change.owner);
            for (const admin of change.admins) zeroBytes(admin);
            for (const member of change.members) zeroBytes(member);
        }
    }

    /** Refresh relay-owned account state before automatic MLS convergence. */
    async #queueAccountWork(ctx: Context): Promise<void> {
        await this.#connect(ctx);
        await this.#store.set(
            ctx,
            `${ACCOUNT_DEVICE_ACTIVITY_PREFIX}${encodeBase64Url(this.#identity.publicKey)}`,
            utf8Encode(String(this.#now()).padStart(16, "0")),
        );
        const readDeviceRoster = this.#transport.readDeviceRoster;
        const roster = await readDeviceRoster?.call(this.#transport, ctx, this.#account.publicKey);
        if (roster !== undefined)
            await this.#observeRoster(ctx, `lookup-${roster.revision}`, roster);
        this.#peerRosterRefreshOrdinal =
            (this.#peerRosterRefreshOrdinal + 1) % PEER_ROSTER_REFRESH_INTERVAL;
        if (readDeviceRoster !== undefined && this.#peerRosterRefreshOrdinal === 0) {
            const peers = new Map<string, Uint8Array>();
            let cursor: string | undefined;
            do {
                let page: MurmurSessionPage;
                try {
                    page = await this.#engine.list(
                        ctx,
                        cursor === undefined ? {} : { after: cursor },
                    );
                } catch {
                    // Session synchronization owns corruption quarantine. An opportunistic
                    // peer-roster refresh must not preempt that isolated recovery path.
                    peers.clear();
                    break;
                }
                for (const session of page.sessions) {
                    for (const member of session.members) {
                        if (!equalBytes(member, this.#account.publicKey)) {
                            peers.set(encodeBase64Url(member), member);
                        }
                    }
                }
                cursor = page.cursor ?? undefined;
            } while (cursor !== undefined);
            const orderedPeers = [...peers].sort(([left], [right]) => left.localeCompare(right));
            const selected = orderedPeers[this.#peerRosterCursor % orderedPeers.length];
            if (selected !== undefined) {
                this.#peerRosterCursor += 1;
                const [encodedAccount, account] = selected;
                const peerRoster = await readDeviceRoster.call(this.#transport, ctx, account);
                if (peerRoster !== undefined) {
                    await this.#observeRoster(
                        ctx,
                        `lookup-${encodedAccount}-${peerRoster.revision}`,
                        peerRoster,
                    );
                }
            }
        }
        await this.#ensureDirectoryEntry(ctx);
    }

    async #connect(ctx: Context): Promise<void> {
        if (this.#networkReady) return;
        await this.#ensureRegistered(ctx);
        await this.#ensureDirectoryEntry(ctx);
        this.#networkReady = true;
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

    async #flushSync(ctx: Context, milliseconds: number, signal: AbortSignal): Promise<void> {
        const retry = await this.#exclusive(ctx, async () => {
            await this.#queueAccountWork(ctx);
            return this.#engine.flush(ctx, signal);
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
        if (this.#closed) throw new MurmurError("closed", "Murmur client is closed");
        if (this.#accountDeletionActive) {
            throw new MurmurError("busy", "Murmur account deletion is active");
        }
    }

    #finishOperation(): void {
        this.#pendingOperations -= 1;
        if (this.#pendingOperations !== 0) return;
        for (const resolve of this.#idleResolvers) resolve();
        this.#idleResolvers.clear();
    }

    async #invokeCallback<T>(
        callback: MurmurCallbackName,
        eventIds: readonly string[],
        operation: () => T | Promise<T>,
    ): Promise<T> {
        this.#callbackDepth += 1;
        try {
            return await operation();
        } catch (error: unknown) {
            throw new MurmurCallbackError(callback, eventIds, error);
        } finally {
            this.#callbackDepth -= 1;
        }
    }

    async #tracked<T>(ctx: Context, operation: () => Promise<T>): Promise<T> {
        this.#assertOpen();
        this.#pendingOperations += 1;
        try {
            return await operation();
        } finally {
            this.#finishOperation();
        }
    }

    async #exclusive<T>(ctx: Context, operation: () => Promise<T>): Promise<T> {
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
            this.#finishOperation();
            release();
        }
    }
}
