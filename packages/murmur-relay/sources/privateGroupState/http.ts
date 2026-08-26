import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { DuplicateJsonKeyError, parseStrictJson } from "../utils/strictJson.js";
import type { RelayFetchHandler, RelayHttpOptions } from "../http/index.js";
import type { PrivateGroupStateService } from "./index.js";
import type {
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateRecord,
    StoredPrivateGroupStateRecord,
} from "./types.js";

const MAXIMUM_JSON_BYTES = 2 * 1024 * 1024;
const textEncoder = new TextEncoder();

class PrivateGroupHttpError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string) {
        super(code);
        this.name = "PrivateGroupHttpError";
        this.status = status;
        this.code = code;
    }
}

function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new PrivateGroupHttpError(400, "malformed");
    }
    const input = value as Record<string, unknown>;
    if (
        fields.some((field) => !Object.hasOwn(input, field)) ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new PrivateGroupHttpError(400, "malformed");
    }
    return input;
}

function bytes(value: unknown, expectedLength?: number): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((MAXIMUM_JSON_BYTES * 4) / 3)) {
        throw new PrivateGroupHttpError(400, "malformed");
    }
    try {
        return decodeBase64Url(value, expectedLength);
    } catch {
        throw new PrivateGroupHttpError(400, "malformed");
    }
}

function role(value: unknown): PrivateGroupRole {
    if (value !== "owner" && value !== "administrator" && value !== "member") {
        throw new PrivateGroupHttpError(400, "malformed");
    }
    return value;
}

function safeInteger(value: unknown): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new PrivateGroupHttpError(400, "malformed");
    }
    return value;
}

function nullableBytes(value: unknown, expectedLength: number): Uint8Array | null {
    return value === null ? null : bytes(value, expectedLength);
}

function recordFromJson(value: unknown): PrivateGroupStateRecord {
    const input = object(value, [
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
        throw new PrivateGroupHttpError(400, "malformed");
    }
    return {
        version: 1,
        opaqueGroupId: bytes(input.opaqueGroupId, 32),
        publicParameters: bytes(input.publicParameters),
        revision: safeInteger(input.revision),
        previousRevisionHash: nullableBytes(input.previousRevisionHash, 32),
        members: input.members.map((member) => {
            const entry = object(member, ["entry", "role"]);
            return { entry: bytes(entry.entry), role: role(entry.role) };
        }),
        sealedState: bytes(input.sealedState),
        revisionAuthenticator: bytes(input.revisionAuthenticator, 32),
    };
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

function challengeFromJson(value: unknown): PrivateGroupPresentationChallenge {
    const input = object(value, [
        "opaqueGroupId",
        "entry",
        "role",
        "operation",
        "replayNonce",
        "context",
        "expiresAt",
    ]);
    if (input.operation !== "create" && input.operation !== "access") {
        throw new PrivateGroupHttpError(400, "malformed");
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

function storedToJson(stored: StoredPrivateGroupStateRecord): Record<string, unknown> {
    return {
        record: recordToJson(stored.record),
        revisionHash: encodeBase64Url(stored.revisionHash),
        canonicalVersion: stored.canonicalVersion,
        replacesVersion: stored.replacesVersion,
        commitEventId: stored.commitEventId,
    };
}

async function readJson(request: Request): Promise<unknown> {
    const declared = request.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAXIMUM_JSON_BYTES)) {
        throw new PrivateGroupHttpError(413, "limit");
    }
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader !== undefined) {
        try {
            for (;;) {
                const next = await reader.read();
                if (next.done) break;
                size += next.value.length;
                if (size > MAXIMUM_JSON_BYTES || chunks.length > 65_536) {
                    await reader.cancel().catch(() => undefined);
                    throw new PrivateGroupHttpError(413, "limit");
                }
                chunks.push(next.value);
            }
        } finally {
            reader.releaseLock();
        }
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.length;
    }
    try {
        return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(body));
    } catch (error: unknown) {
        if (error instanceof PrivateGroupHttpError) throw error;
        if (error instanceof DuplicateJsonKeyError) {
            throw new PrivateGroupHttpError(400, "duplicate_json_key");
        }
        throw new PrivateGroupHttpError(400, "malformed");
    }
}

function response(
    body: unknown,
    status: number,
    headers: Readonly<Record<string, string>>,
): Response {
    const encoded = JSON.stringify(body);
    if (textEncoder.encode(encoded).length > MAXIMUM_JSON_BYTES) {
        return response({ error: "limit" }, 413, headers);
    }
    return new Response(encoded, {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
        },
    });
}

function corsHeaders(request: Request, options: RelayHttpOptions): Record<string, string> {
    const origin = request.headers.get("origin");
    if (origin === null) return {};
    const allowed = options.allowedOrigins ?? "*";
    if (allowed === "*") return { "access-control-allow-origin": "*" };
    return allowed.includes(origin)
        ? { "access-control-allow-origin": origin, vary: "Origin" }
        : {};
}

function serviceFailure(error: Error): PrivateGroupHttpError {
    if (error.message.includes("Unknown private group")) {
        return new PrivateGroupHttpError(404, "private_group_not_found");
    }
    if (
        error.message.includes("already exists") ||
        error.message.includes("conflict") ||
        error.message.includes("expected version") ||
        error.message.includes("fork") ||
        error.message.includes("stale")
    ) {
        return new PrivateGroupHttpError(409, "private_group_conflict");
    }
    if (error.message.includes("quota") || error.message.includes("limit")) {
        return new PrivateGroupHttpError(429, "private_group_limit");
    }
    if (
        error.message.includes("token") ||
        error.message.includes("credential") ||
        error.message.includes("presentation") ||
        error.message.includes("authorized") ||
        error.message.includes("requires")
    ) {
        return new PrivateGroupHttpError(401, "private_group_unauthorized");
    }
    return new PrivateGroupHttpError(400, "malformed");
}

/** Create the EXPERIMENTAL fetch-compatible private-group state HTTP API. */
export function createPrivateGroupStateFetchHandler(
    service: PrivateGroupStateService,
    options: Pick<RelayHttpOptions, "allowedOrigins"> = {},
): RelayFetchHandler {
    return async (request): Promise<Response> => {
        const headers = corsHeaders(request, options);
        try {
            const path = new URL(request.url).pathname;
            if (request.method === "OPTIONS") {
                return new Response(null, {
                    status: 204,
                    headers: {
                        ...headers,
                        "access-control-allow-methods": "GET, POST, OPTIONS",
                        "access-control-allow-headers": "content-type, x-murmur-private-group",
                    },
                });
            }
            if (request.method === "GET" && path === "/v1/private-groups/config") {
                return response(
                    {
                        credentialIssuerPublicParameters: encodeBase64Url(
                            service.credentialIssuerPublicParameters,
                        ),
                    },
                    200,
                    headers,
                );
            }
            if (request.method !== "POST") {
                return response({ error: "not_found" }, 404, headers);
            }
            const body = await readJson(request);
            if (path === "/v1/private-groups/credentials/challenge") {
                const input = object(body, ["accountIdentifier"]);
                const challenge = service.createCredentialIssuanceChallenge(
                    bytes(input.accountIdentifier, 32),
                );
                return response(
                    { bytes: encodeBase64Url(challenge.bytes), expiresAt: challenge.expiresAt },
                    200,
                    headers,
                );
            }
            if (path === "/v1/private-groups/credentials") {
                const input = object(body, [
                    "accountIdentifier",
                    "request",
                    "authenticationContext",
                    "challenge",
                    "signature",
                ]);
                const issued = await service.issueAuthenticatedCredential({
                    authenticatedAccountIdentifier: bytes(input.accountIdentifier, 32),
                    request: bytes(input.request),
                    authenticationContext: bytes(input.authenticationContext),
                    challenge: bytes(input.challenge),
                    signature: bytes(input.signature, 64),
                });
                return response({ response: encodeBase64Url(issued) }, 200, headers);
            }
            if (path === "/v1/private-groups/challenges") {
                const input = object(body, ["opaqueGroupId", "entry", "role", "operation"]);
                if (input.operation !== "create" && input.operation !== "access") {
                    throw new PrivateGroupHttpError(400, "malformed");
                }
                const challenge = await service.createPresentationChallenge({
                    opaqueGroupId: bytes(input.opaqueGroupId, 32),
                    entry: bytes(input.entry),
                    role: role(input.role),
                    operation: input.operation,
                });
                return response(challengeToJson(challenge), 200, headers);
            }
            if (path === "/v1/private-groups/presentations") {
                const input = object(body, ["challenge", "publicParameters", "presentation"]);
                const token = await service.authenticatePresentation({
                    challenge: challengeFromJson(input.challenge),
                    publicParameters: bytes(input.publicParameters),
                    presentation: bytes(input.presentation),
                });
                return response(
                    { bytes: encodeBase64Url(token.bytes), expiresAt: token.expiresAt },
                    200,
                    headers,
                );
            }
            if (path === "/v1/private-groups/records/create") {
                const input = object(body, ["record", "token"]);
                return response(
                    storedToJson(
                        await service.createRecord({
                            record: recordFromJson(input.record),
                            token: bytes(input.token),
                        }),
                    ),
                    200,
                    headers,
                );
            }
            if (path === "/v1/private-groups/records/read") {
                const input = object(body, ["opaqueGroupId", "token"]);
                return response(
                    storedToJson(
                        await service.readRecord({
                            opaqueGroupId: bytes(input.opaqueGroupId, 32),
                            token: bytes(input.token),
                        }),
                    ),
                    200,
                    headers,
                );
            }
            if (path === "/v1/private-groups/records/replace") {
                const input = object(body, [
                    "replacesVersion",
                    "expectedRevisionHash",
                    "record",
                    "token",
                ]);
                if (typeof input.replacesVersion !== "string") {
                    throw new PrivateGroupHttpError(400, "malformed");
                }
                return response(
                    storedToJson(
                        await service.replaceRecord({
                            replacesVersion: input.replacesVersion,
                            expectedRevisionHash: bytes(input.expectedRevisionHash, 32),
                            record: recordFromJson(input.record),
                            token: bytes(input.token),
                        }),
                    ),
                    200,
                    headers,
                );
            }
            return response({ error: "not_found" }, 404, headers);
        } catch (error: unknown) {
            const failure =
                error instanceof PrivateGroupHttpError
                    ? error
                    : serviceFailure(
                          error instanceof Error ? error : new Error("Unknown private-group error"),
                      );
            return response({ error: failure.code }, failure.status, headers);
        }
    };
}
