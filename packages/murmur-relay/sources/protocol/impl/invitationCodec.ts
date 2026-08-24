import { ed25519 } from "@noble/curves/ed25519";
import { RelayError } from "../errors.js";
import type {
    InvitationUploadAuthorization,
    OwnedInvitationUpload,
    SignedInvitationRevocation,
} from "../types.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { canonicalJson } from "../../utils/canonicalJson.js";

const UPLOAD_DOMAIN = "murmur.relay.invitation-upload.v1";
const REVOCATION_DOMAIN = "murmur.relay.invitation-revocation.v1";
const textEncoder = new TextEncoder();

function objectValue(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exactKeys(
    value: Record<string, unknown>,
    required: readonly string[],
    name: string,
): void {
    if (
        required.some((key) => !Object.hasOwn(value, key)) ||
        Object.keys(value).some((key) => !required.includes(key))
    ) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function bytesValue(value: unknown, name: string, expectedBytes?: number): Uint8Array {
    if (typeof value !== "string") {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        return decodeBase64Url(value, expectedBytes);
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function validatePublicKey(value: Uint8Array, name: string): void {
    try {
        const point = ed25519.Point.fromBytes(value, false);
        point.assertValidity();
        if (
            value.length !== 32 ||
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(point.toBytes(), value)
        ) {
            throw new Error("Invalid point");
        }
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function separated(domain: string, value: unknown): Uint8Array {
    const prefix = textEncoder.encode(`${domain}\0`);
    const body = canonicalJson(value);
    const result = new Uint8Array(prefix.length + body.length);
    result.set(prefix);
    result.set(body, prefix.length);
    return result;
}

/** Strictly parse the additive owner-authorized invitation upload wrapper. */
export function parseOwnedInvitationUpload(value: unknown): OwnedInvitationUpload {
    const input = objectValue(value, "owned invitation upload");
    exactKeys(input, ["version", "bundle", "authorization"], "owned invitation upload");
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid owned invitation upload", { error: "malformed" });
    }
    const authorizationInput = objectValue(input.authorization, "invitation upload authorization");
    exactKeys(
        authorizationInput,
        ["version", "owner", "revocationKey", "digest", "expiresAt", "createdAt", "signature"],
        "invitation upload authorization",
    );
    if (authorizationInput.version !== 1) {
        throw new RelayError(400, "Invalid invitation upload authorization", {
            error: "malformed",
        });
    }
    const authorization: InvitationUploadAuthorization = {
        version: 1,
        owner: bytesValue(authorizationInput.owner, "invitation owner", 32),
        revocationKey: bytesValue(
            authorizationInput.revocationKey,
            "invitation revocation key",
            32,
        ),
        digest: bytesValue(authorizationInput.digest, "invitation digest", 32),
        expiresAt: safeInteger(authorizationInput.expiresAt, "invitation expiration"),
        createdAt: safeInteger(authorizationInput.createdAt, "invitation authorization time"),
        signature: bytesValue(
            authorizationInput.signature,
            "invitation authorization signature",
            64,
        ),
    };
    validatePublicKey(authorization.owner, "invitation owner");
    validatePublicKey(authorization.revocationKey, "invitation revocation key");
    return {
        version: 1,
        bundle: bytesValue(input.bundle, "invitation bundle"),
        authorization,
    };
}

/** Canonical bytes covered by an invitation-owner upload signature. */
export function invitationUploadSigningBytes(
    authorization: InvitationUploadAuthorization,
): Uint8Array {
    return separated(UPLOAD_DOMAIN, {
        version: 1,
        owner: encodeBase64Url(authorization.owner),
        revocationKey: encodeBase64Url(authorization.revocationKey),
        digest: encodeBase64Url(authorization.digest),
        expiresAt: authorization.expiresAt,
        createdAt: authorization.createdAt,
    });
}

/** Verify that the invitation identity authorized its separate revocation key. */
export function verifyInvitationUploadAuthorization(
    authorization: InvitationUploadAuthorization,
): boolean {
    try {
        return ed25519.verify(
            authorization.signature,
            invitationUploadSigningBytes(authorization),
            authorization.owner,
            { zip215: false },
        );
    } catch {
        return false;
    }
}

/** Strictly parse one idempotent invitation revocation request. */
export function parseSignedInvitationRevocation(value: unknown): SignedInvitationRevocation {
    const input = objectValue(value, "invitation revocation");
    exactKeys(
        input,
        ["version", "revocationKey", "digest", "createdAt", "signature"],
        "invitation revocation",
    );
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid invitation revocation", { error: "malformed" });
    }
    const request: SignedInvitationRevocation = {
        version: 1,
        revocationKey: bytesValue(input.revocationKey, "invitation revocation key", 32),
        digest: input.digest === null ? null : bytesValue(input.digest, "invitation digest", 32),
        createdAt: safeInteger(input.createdAt, "invitation revocation time"),
        signature: bytesValue(input.signature, "invitation revocation signature", 64),
    };
    validatePublicKey(request.revocationKey, "invitation revocation key");
    return request;
}

function invitationRevocationSigningBytes(request: SignedInvitationRevocation): Uint8Array {
    return separated(REVOCATION_DOMAIN, {
        version: 1,
        revocationKey: encodeBase64Url(request.revocationKey),
        digest: request.digest === null ? null : encodeBase64Url(request.digest),
        createdAt: request.createdAt,
    });
}

/** Verify one single- or authority-wide invitation revocation signature. */
export function verifyInvitationRevocationSignature(request: SignedInvitationRevocation): boolean {
    try {
        return ed25519.verify(
            request.signature,
            invitationRevocationSigningBytes(request),
            request.revocationKey,
            { zip215: false },
        );
    } catch {
        return false;
    }
}
