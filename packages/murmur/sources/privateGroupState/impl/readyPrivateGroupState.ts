import type { IdentityKeyPair } from "../../crypto/index.js";
import type { MurmurSession } from "../../sessions/index.js";
import { canonicalJsonBytes, encodeBase64Url, equalBytes, zeroBytes } from "../../utils/index.js";
import type {
    PrivateGroupAcceptedState,
    PrivateGroupAccessToken,
    PrivateGroupAccountCredential,
    PrivateGroupAccountRole,
    PrivateGroupRecordContent,
    PrivateGroupRole,
    PrivateGroupStateConnection,
    PrivateGroupStateSnapshot,
    PrivateGroupStateTransport,
    PrivateGroupTrustedTip,
    StoredPrivateGroupStateRecord,
} from "../types.js";
import { HttpPrivateGroupStateTransport } from "./httpPrivateGroupStateTransport.js";
import { PrivateGroupStateClient } from "./privateGroupStateClient.js";
import type { PrivateGroupSessionState } from "./sessionState.js";

/** Ready app-facing private-group state bound to one authenticated MLS session. */
export interface MurmurPrivateGroupState {
    /** Create revision one from the current session roster and plaintext attributes. */
    create(attributes: Uint8Array): Promise<PrivateGroupStateSnapshot>;
    /** Join an existing canonical state after MLS admission has activated locally. */
    join(): Promise<PrivateGroupStateSnapshot>;
    /** Read and verify the current canonical state against the live MLS snapshot. */
    read(): Promise<PrivateGroupStateSnapshot>;
    /** Replace the accepted tip using the live roster and new plaintext attributes. */
    mutate(attributes: Uint8Array): Promise<PrivateGroupStateSnapshot>;
    /** Zero cached member credentials, tokens, and derived group parameters. */
    close(): void;
}

/** Internal construction seam used by the session facade. */
export interface ReadyPrivateGroupStateOptions {
    readonly identity: IdentityKeyPair;
    readonly state: PrivateGroupSessionState;
    readonly connection: PrivateGroupStateConnection;
    readonly session: () => MurmurSession | undefined | Promise<MurmurSession | undefined>;
    readonly persistTrustedTip: (tip: PrivateGroupTrustedTip) => void | Promise<void>;
    readonly now?: () => number;
}

interface CachedToken {
    readonly role: PrivateGroupRole;
    readonly token: PrivateGroupAccessToken;
}

function destroyCredential(credential: PrivateGroupAccountCredential | undefined): void {
    if (credential === undefined) return;
    zeroBytes(credential.mac.t);
    zeroBytes(credential.mac.u);
    zeroBytes(credential.mac.v);
}

function destroyToken(token: CachedToken | undefined): void {
    if (token !== undefined) zeroBytes(token.token.bytes);
}

function authenticationContext(accountIdentifier: Uint8Array): Uint8Array {
    return canonicalJsonBytes({
        domain: "murmur.private-group-state.account-authentication.v1",
        accountIdentifier: encodeBase64Url(accountIdentifier),
    });
}

function validateReadyOptions(options: ReadyPrivateGroupStateOptions): void {
    if (
        options.state.version !== 1 ||
        !(options.identity.publicKey instanceof Uint8Array) ||
        options.identity.publicKey.length !== 32 ||
        !(options.state.sessionId instanceof Uint8Array) ||
        options.state.sessionId.length !== 32
    ) {
        throw new Error("Invalid ready private-group state identity or session");
    }
    if (
        !(options.state.masterSecret instanceof Uint8Array) ||
        options.state.masterSecret.length !== 32
    ) {
        throw new Error("Private-group master secret must be 32 bytes");
    }
}

function rolesFromSession(session: MurmurSession): readonly PrivateGroupAccountRole[] {
    return session.members.map((accountIdentifier) => ({
        accountIdentifier,
        role: equalBytes(accountIdentifier, session.owner)
            ? "owner"
            : session.admins.some((admin) => equalBytes(admin, accountIdentifier))
              ? "administrator"
              : "member",
    }));
}

async function resolveTransport(
    connection: PrivateGroupStateConnection,
    identity: IdentityKeyPair,
): Promise<PrivateGroupStateTransport> {
    if (connection.transport !== undefined) return connection.transport;
    return await HttpPrivateGroupStateTransport.create(connection.relay, {
        identity,
        ...(connection.fetch === undefined ? {} : { fetch: connection.fetch }),
        ...(connection.maximumResponseBytes === undefined
            ? {}
            : { maximumResponseBytes: connection.maximumResponseBytes }),
        ...(connection.requestTimeoutMilliseconds === undefined
            ? {}
            : { requestTimeoutMilliseconds: connection.requestTimeoutMilliseconds }),
    });
}

class ReadyPrivateGroupState implements MurmurPrivateGroupState {
    readonly #client: PrivateGroupStateClient;
    readonly #sessionId: Uint8Array;
    readonly #accountIdentifier: Uint8Array;
    readonly #session: ReadyPrivateGroupStateOptions["session"];
    readonly #persistTrustedTip: ReadyPrivateGroupStateOptions["persistTrustedTip"];
    readonly #authenticationContext: Uint8Array;
    readonly #now: () => number;
    #credential: PrivateGroupAccountCredential | undefined;
    #token: CachedToken | undefined;
    #current: StoredPrivateGroupStateRecord | undefined;
    #initialized: boolean;
    #operationTail: Promise<void> = Promise.resolve();
    #closed = false;

    constructor(options: ReadyPrivateGroupStateOptions, transport: PrivateGroupStateTransport) {
        validateReadyOptions(options);
        this.#sessionId = options.state.sessionId.slice();
        this.#accountIdentifier = options.identity.publicKey.slice();
        this.#session = options.session;
        this.#persistTrustedTip = options.persistTrustedTip;
        this.#authenticationContext = authenticationContext(this.#accountIdentifier);
        this.#now = options.now ?? Date.now;
        this.#initialized = options.state.trustedTip !== undefined;
        this.#client = new PrivateGroupStateClient({
            accountIdentifier: this.#accountIdentifier,
            groupMasterSecret: options.state.masterSecret,
            transport,
            ...(options.now === undefined ? {} : { now: options.now }),
            ...(options.state.trustedTip === undefined
                ? {}
                : { trustedTip: options.state.trustedTip }),
        });
    }

    async create(attributes: Uint8Array): Promise<PrivateGroupStateSnapshot> {
        return await this.#exclusive(async () => {
            if (this.#initialized) {
                throw new Error("Private-group state is already initialized locally");
            }
            const content = await this.#content(attributes);
            try {
                const accepted = await this.#client.createGroup(
                    await this.#credentialValue(),
                    content,
                );
                return await this.#accept(accepted);
            } finally {
                zeroBytes(content.attributes);
            }
        });
    }

    async join(): Promise<PrivateGroupStateSnapshot> {
        return await this.#exclusive(() => this.#readCurrent());
    }

    async read(): Promise<PrivateGroupStateSnapshot> {
        return await this.#exclusive(() => this.#readCurrent());
    }

    async mutate(attributes: Uint8Array): Promise<PrivateGroupStateSnapshot> {
        return await this.#exclusive(async () => {
            if (this.#current === undefined) {
                const current = await this.#readCurrent();
                zeroBytes(current.attributes);
            }
            const content = await this.#content(attributes);
            try {
                const role = this.#ownRole(content.roles);
                if (role !== "owner" && role !== "administrator") {
                    throw new Error("Private-group mutation requires owner or administrator role");
                }
                const current = this.#current;
                if (current === undefined)
                    throw new Error("Private-group state has no accepted tip");
                const accepted = await this.#client.replaceGroup(
                    await this.#tokenValue(role),
                    current,
                    content,
                );
                return await this.#accept(accepted);
            } finally {
                zeroBytes(content.attributes);
            }
        });
    }

    close(): void {
        if (this.#closed) return;
        this.#closed = true;
        destroyCredential(this.#credential);
        destroyToken(this.#token);
        this.#credential = undefined;
        this.#token = undefined;
        this.#current = undefined;
        zeroBytes(this.#sessionId);
        zeroBytes(this.#accountIdentifier);
        zeroBytes(this.#authenticationContext);
        this.#client.close();
    }

    async #readCurrent(): Promise<PrivateGroupStateSnapshot> {
        const content = await this.#content(new Uint8Array());
        const role = this.#ownRole(content.roles);
        const accepted = await this.#client.readGroup(await this.#tokenValue(role), content);
        return await this.#accept(accepted);
    }

    async #content(attributes: Uint8Array): Promise<PrivateGroupRecordContent> {
        this.#assertOpen();
        if (!(attributes instanceof Uint8Array)) {
            throw new Error("Private-group attributes must be bytes");
        }
        const session = await this.#session();
        if (
            session === undefined ||
            session.status !== "active" ||
            !equalBytes(session.id, this.#sessionId)
        ) {
            throw new Error("Private-group state requires its active authenticated MLS session");
        }
        const roles = rolesFromSession(session);
        this.#ownRole(roles);
        return { attributes: attributes.slice(), session, roles };
    }

    #ownRole(roles: readonly PrivateGroupAccountRole[]): PrivateGroupRole {
        const matches = roles.filter((assignment) =>
            equalBytes(assignment.accountIdentifier, this.#accountIdentifier),
        );
        if (matches.length !== 1) {
            throw new Error("Private-group MLS session does not name this account exactly once");
        }
        return matches[0]!.role;
    }

    async #credentialValue(): Promise<PrivateGroupAccountCredential> {
        const now = this.#safeNow();
        if (this.#credential !== undefined && this.#credential.expiresAt > now) {
            return this.#credential;
        }
        destroyCredential(this.#credential);
        this.#credential = undefined;
        const credential = await this.#client.obtainCredential(this.#authenticationContext);
        if (this.#closed) {
            destroyCredential(credential);
            this.#assertOpen();
        }
        if (credential.expiresAt <= this.#safeNow()) {
            destroyCredential(credential);
            throw new Error("Private-group credential expired during issuance");
        }
        this.#credential = credential;
        return credential;
    }

    async #tokenValue(role: PrivateGroupRole): Promise<PrivateGroupAccessToken> {
        const now = this.#safeNow();
        if (
            this.#token !== undefined &&
            this.#token.role === role &&
            this.#token.token.expiresAt > now
        ) {
            return this.#token.token;
        }
        destroyToken(this.#token);
        this.#token = undefined;
        const token = await this.#client.authorize(await this.#credentialValue(), role, "access");
        if (this.#closed) {
            zeroBytes(token.bytes);
            this.#assertOpen();
        }
        if (token.expiresAt <= this.#safeNow()) {
            zeroBytes(token.bytes);
            throw new Error("Private-group access token expired during authorization");
        }
        this.#token = { role, token };
        return token;
    }

    async #accept(accepted: PrivateGroupAcceptedState): Promise<PrivateGroupStateSnapshot> {
        try {
            const tip = this.#client.trustedTip;
            if (tip === undefined) throw new Error("Private-group client did not retain its tip");
            try {
                await this.#persistTrustedTip(tip);
            } catch (error: unknown) {
                this.close();
                throw error;
            }
            this.#assertOpen();
            this.#current = accepted.record;
            this.#initialized = true;
            return {
                attributes: accepted.attributes.slice(),
                revision: accepted.record.record.revision,
                canonicalVersion: accepted.record.canonicalVersion,
            };
        } finally {
            zeroBytes(accepted.attributes);
        }
    }

    async #exclusive<T>(operation: () => Promise<T>): Promise<T> {
        this.#assertOpen();
        const run = this.#operationTail.then(async () => {
            this.#assertOpen();
            return await operation();
        });
        this.#operationTail = run.then(
            () => undefined,
            () => undefined,
        );
        return await run;
    }

    #safeNow(): number {
        const now = this.#now();
        if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid client clock");
        return now;
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Private-group state handle is closed");
    }
}

/** Build a ready state handle without exposing its member-only session secret. */
export async function createReadyPrivateGroupState(
    options: ReadyPrivateGroupStateOptions,
): Promise<MurmurPrivateGroupState> {
    validateReadyOptions(options);
    const transport = await resolveTransport(options.connection, options.identity);
    return new ReadyPrivateGroupState(options, transport);
}
