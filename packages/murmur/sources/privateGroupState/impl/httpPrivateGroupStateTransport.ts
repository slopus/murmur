import { hashBytes, signBytes, type IdentityKeyPair } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
} from "../../utils/index.js";
import type {
    PrivateGroupAccessToken,
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateRecord,
    PrivateGroupStateTransport,
    StoredPrivateGroupStateRecord,
} from "../types.js";

const DEFAULT_MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MILLISECONDS = 45_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Fetch seam used by the experimental private-group HTTP transport. */
export type PrivateGroupStateFetch = (
    input: RequestInfo | URL,
    init?: RequestInit,
) => Promise<Response>;

/** Construction inputs for the experimental private-group HTTP transport. */
export interface HttpPrivateGroupStateTransportOptions {
    /** Account identity used only to authorize credential issuance. */
    readonly identity: IdentityKeyPair;
    readonly fetch?: PrivateGroupStateFetch;
    readonly maximumResponseBytes?: number;
    readonly requestTimeoutMilliseconds?: number;
}

/** Stable HTTP failure returned by the private-group state relay. */
export class PrivateGroupStateTransportError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string) {
        super(`Private-group state request failed (${status} ${code})`);
        this.name = "PrivateGroupStateTransportError";
        this.status = status;
        this.code = code;
    }
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid private-group relay response");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid private-group relay response");
    }
}

function bytes(value: unknown, expectedLength?: number): Uint8Array {
    if (typeof value !== "string") throw new Error("Invalid private-group relay response");
    const decoded = decodeBase64Url(value);
    if (expectedLength !== undefined && decoded.length !== expectedLength) {
        throw new Error("Invalid private-group relay response");
    }
    return decoded;
}

function safeInteger(value: unknown): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error("Invalid private-group relay response");
    }
    return value;
}

function role(value: unknown): PrivateGroupRole {
    if (value !== "owner" && value !== "administrator" && value !== "member") {
        throw new Error("Invalid private-group relay response");
    }
    return value;
}

function recordToJson(record: PrivateGroupStateRecord): Record<string, unknown> {
    return {
        version: 1,
        opaqueGroupId: encodeBase64Url(record.opaqueGroupId),
        publicParameters: encodeBase64Url(record.publicParameters),
        revision: record.revision,
        previousRevisionHash:
            record.previousRevisionHash === null
                ? null
                : encodeBase64Url(record.previousRevisionHash),
        members: record.members.map((member) => ({
            entry: encodeBase64Url(member.entry),
            role: member.role,
        })),
        sealedState: encodeBase64Url(record.sealedState),
        revisionAuthenticator: encodeBase64Url(record.revisionAuthenticator),
    };
}

function recordFromJson(value: unknown): PrivateGroupStateRecord {
    const input = object(value);
    exact(input, [
        "version",
        "opaqueGroupId",
        "publicParameters",
        "revision",
        "previousRevisionHash",
        "members",
        "sealedState",
        "revisionAuthenticator",
    ]);
    if (input.version !== 1 || !Array.isArray(input.members) || input.members.length > 1024) {
        throw new Error("Invalid private-group relay response");
    }
    return {
        version: 1,
        opaqueGroupId: bytes(input.opaqueGroupId, 32),
        publicParameters: bytes(input.publicParameters),
        revision: safeInteger(input.revision),
        previousRevisionHash:
            input.previousRevisionHash === null ? null : bytes(input.previousRevisionHash, 32),
        members: input.members.map((candidate) => {
            const member = object(candidate);
            exact(member, ["entry", "role"]);
            return { entry: bytes(member.entry), role: role(member.role) };
        }),
        sealedState: bytes(input.sealedState),
        revisionAuthenticator: bytes(input.revisionAuthenticator, 32),
    };
}

function challengeToJson(challenge: PrivateGroupPresentationChallenge): Record<string, unknown> {
    return {
        opaqueGroupId: encodeBase64Url(challenge.opaqueGroupId),
        entry: encodeBase64Url(challenge.entry),
        role: challenge.role,
        operation: challenge.operation,
        replayNonce: encodeBase64Url(challenge.replayNonce),
        context: encodeBase64Url(challenge.context),
        expiresAt: challenge.expiresAt,
    };
}

function challengeFromJson(value: unknown): PrivateGroupPresentationChallenge {
    const input = object(value);
    exact(input, [
        "opaqueGroupId",
        "entry",
        "role",
        "operation",
        "replayNonce",
        "context",
        "expiresAt",
    ]);
    if (input.operation !== "create" && input.operation !== "access") {
        throw new Error("Invalid private-group relay response");
    }
    return {
        opaqueGroupId: bytes(input.opaqueGroupId, 32),
        entry: bytes(input.entry),
        role: role(input.role),
        operation: input.operation,
        replayNonce: bytes(input.replayNonce, 32),
        context: bytes(input.context),
        expiresAt: safeInteger(input.expiresAt),
    };
}

function storedFromJson(value: unknown): StoredPrivateGroupStateRecord {
    const input = object(value);
    exact(input, [
        "record",
        "revisionHash",
        "canonicalVersion",
        "replacesVersion",
        "commitEventId",
    ]);
    if (
        typeof input.canonicalVersion !== "string" ||
        !UUID_V7.test(input.canonicalVersion) ||
        (input.replacesVersion !== null &&
            (typeof input.replacesVersion !== "string" || !UUID_V7.test(input.replacesVersion))) ||
        (input.commitEventId !== null &&
            (typeof input.commitEventId !== "string" || !UUID_V7.test(input.commitEventId)))
    ) {
        throw new Error("Invalid private-group relay response");
    }
    return {
        record: recordFromJson(input.record),
        revisionHash: bytes(input.revisionHash, 32),
        canonicalVersion: input.canonicalVersion,
        replacesVersion: input.replacesVersion,
        commitEventId: input.commitEventId,
    };
}

async function boundedJson(response: Response, maximumBytes: number): Promise<unknown> {
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new Error("Private-group relay response exceeds client limit");
    }
    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("Private-group relay response has no body");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        for (;;) {
            const next = await reader.read();
            if (next.done) break;
            size += next.value.length;
            if (size > maximumBytes || chunks.length >= 65_536) {
                await reader.cancel().catch(() => undefined);
                throw new Error("Private-group relay response exceeds client limit");
            }
            chunks.push(next.value);
        }
    } finally {
        reader.releaseLock();
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.length;
    }
    try {
        return JSON.parse(utf8Decode(body)) as unknown;
    } catch {
        throw new Error("Invalid private-group relay response JSON");
    }
}

/** EXPERIMENTAL fetch-backed private-group state transport. */
export class HttpPrivateGroupStateTransport implements PrivateGroupStateTransport {
    readonly credentialIssuerPublicParameters: Uint8Array;
    readonly #baseUrl: URL;
    readonly #fetch: PrivateGroupStateFetch;
    readonly #identity: IdentityKeyPair;
    readonly #maximumResponseBytes: number;
    readonly #timeoutMilliseconds: number;

    private constructor(
        baseUrl: string | URL,
        credentialIssuerPublicParameters: Uint8Array,
        options: HttpPrivateGroupStateTransportOptions,
    ) {
        this.#baseUrl = new URL(baseUrl);
        if (this.#baseUrl.protocol !== "https:" && this.#baseUrl.protocol !== "http:") {
            throw new Error("Private-group relay URL must use HTTP or HTTPS");
        }
        this.credentialIssuerPublicParameters = credentialIssuerPublicParameters.slice();
        this.#identity = options.identity;
        this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
        this.#maximumResponseBytes = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
        this.#timeoutMilliseconds =
            options.requestTimeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS;
        if (
            !Number.isSafeInteger(this.#maximumResponseBytes) ||
            this.#maximumResponseBytes < 1 ||
            !Number.isSafeInteger(this.#timeoutMilliseconds) ||
            this.#timeoutMilliseconds < 1 ||
            this.#timeoutMilliseconds > 5 * 60_000
        ) {
            throw new Error("Invalid private-group HTTP transport limits");
        }
    }

    /** Fetch relay credential parameters and construct a ready transport. */
    static async create(
        baseUrl: string | URL,
        options: HttpPrivateGroupStateTransportOptions,
    ): Promise<HttpPrivateGroupStateTransport> {
        const temporary = new HttpPrivateGroupStateTransport(baseUrl, new Uint8Array(), options);
        const config = object(await temporary.#request("/v1/private-groups/config", "GET"));
        exact(config, ["credentialIssuerPublicParameters"]);
        return new HttpPrivateGroupStateTransport(
            baseUrl,
            bytes(config.credentialIssuerPublicParameters),
            options,
        );
    }

    credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array {
        return canonicalJsonBytes({
            domain: "murmur.private-group-state.credential-issuance.v1",
            authenticationContext: encodeBase64Url(authenticationContext),
        });
    }

    async issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly authenticationContext: Uint8Array;
    }): Promise<Uint8Array> {
        if (!equalBytes(options.authenticatedAccountIdentifier, this.#identity.publicKey)) {
            throw new Error("Credential account does not match the HTTP transport identity");
        }
        const challengeValue = object(
            await this.#post("/v1/private-groups/credentials/challenge", {
                accountIdentifier: encodeBase64Url(options.authenticatedAccountIdentifier),
            }),
        );
        exact(challengeValue, ["bytes", "expiresAt"]);
        const challenge = bytes(challengeValue.bytes);
        safeInteger(challengeValue.expiresAt);
        const authorization = canonicalJsonBytes({
            domain: "murmur.private-group-state.credential-authorization.v1",
            accountIdentifier: encodeBase64Url(options.authenticatedAccountIdentifier),
            challenge: encodeBase64Url(challenge),
            requestHash: encodeBase64Url(hashBytes(options.request)),
            authenticationContextHash: encodeBase64Url(hashBytes(options.authenticationContext)),
        });
        const value = object(
            await this.#post("/v1/private-groups/credentials", {
                accountIdentifier: encodeBase64Url(options.authenticatedAccountIdentifier),
                request: encodeBase64Url(options.request),
                authenticationContext: encodeBase64Url(options.authenticationContext),
                challenge: encodeBase64Url(challenge),
                signature: encodeBase64Url(signBytes(this.#identity, authorization)),
            }),
        );
        exact(value, ["response"]);
        return bytes(value.response);
    }

    async createPresentationChallenge(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly entry: Uint8Array;
        readonly role: PrivateGroupRole;
        readonly operation: "create" | "access";
    }): Promise<PrivateGroupPresentationChallenge> {
        return challengeFromJson(
            await this.#post(
                "/v1/private-groups/challenges",
                {
                    opaqueGroupId: encodeBase64Url(options.opaqueGroupId),
                    entry: encodeBase64Url(options.entry),
                    role: options.role,
                    operation: options.operation,
                },
                options.opaqueGroupId,
            ),
        );
    }

    async authenticatePresentation(options: {
        readonly challenge: PrivateGroupPresentationChallenge;
        readonly publicParameters: Uint8Array;
        readonly presentation: Uint8Array;
    }): Promise<PrivateGroupAccessToken> {
        const value = object(
            await this.#post(
                "/v1/private-groups/presentations",
                {
                    challenge: challengeToJson(options.challenge),
                    publicParameters: encodeBase64Url(options.publicParameters),
                    presentation: encodeBase64Url(options.presentation),
                },
                options.challenge.opaqueGroupId,
            ),
        );
        exact(value, ["bytes", "expiresAt"]);
        return { bytes: bytes(value.bytes), expiresAt: safeInteger(value.expiresAt) };
    }

    async createRecord(options: {
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        return storedFromJson(
            await this.#post(
                "/v1/private-groups/records/create",
                { record: recordToJson(options.record), token: encodeBase64Url(options.token) },
                options.record.opaqueGroupId,
            ),
        );
    }

    async readRecord(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        return storedFromJson(
            await this.#post(
                "/v1/private-groups/records/read",
                {
                    opaqueGroupId: encodeBase64Url(options.opaqueGroupId),
                    token: encodeBase64Url(options.token),
                },
                options.opaqueGroupId,
            ),
        );
    }

    async replaceRecord(options: {
        readonly replacesVersion: string;
        readonly expectedRevisionHash: Uint8Array;
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        return storedFromJson(
            await this.#post(
                "/v1/private-groups/records/replace",
                {
                    replacesVersion: options.replacesVersion,
                    expectedRevisionHash: encodeBase64Url(options.expectedRevisionHash),
                    record: recordToJson(options.record),
                    token: encodeBase64Url(options.token),
                },
                options.record.opaqueGroupId,
            ),
        );
    }

    async #post(path: string, body: unknown, groupId?: Uint8Array): Promise<unknown> {
        return this.#request(path, "POST", body, groupId);
    }

    async #request(
        path: string,
        method: "GET" | "POST",
        body?: unknown,
        groupId?: Uint8Array,
    ): Promise<unknown> {
        const response = await this.#fetch(new URL(path, this.#baseUrl), {
            method,
            headers: {
                ...(body === undefined ? {} : { "content-type": "application/json" }),
                ...(groupId === undefined
                    ? {}
                    : { "x-murmur-private-group": encodeBase64Url(groupId) }),
            },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            signal: AbortSignal.timeout(this.#timeoutMilliseconds),
        });
        const value = await boundedJson(response, this.#maximumResponseBytes);
        if (!response.ok) {
            const error = object(value);
            exact(error, ["error"]);
            throw new PrivateGroupStateTransportError(
                response.status,
                typeof error.error === "string" ? error.error : "invalid_error",
            );
        }
        return value;
    }
}
