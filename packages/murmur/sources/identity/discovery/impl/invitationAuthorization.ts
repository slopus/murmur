import type { IdentityKeyPair } from "../../../crypto/index.js";
import { signBytes, validateIdentityPublicKey } from "../../../crypto/index.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    utf8Encode,
    zeroBytes,
} from "../../../utils/index.js";
import type { InvitationUploadAuthorization, SignedInvitationRevocation } from "../types.js";

const UPLOAD_DOMAIN = "murmur.relay.invitation-upload.v1";
const REVOCATION_DOMAIN = "murmur.relay.invitation-revocation.v1";

function separated(domain: string, value: Parameters<typeof canonicalJsonBytes>[0]): Uint8Array {
    const prefix = utf8Encode(`${domain}\0`);
    const body = canonicalJsonBytes(value);
    const result = new Uint8Array(prefix.length + body.length);
    try {
        result.set(prefix);
        result.set(body, prefix.length);
        return result;
    } finally {
        zeroBytes(prefix);
        zeroBytes(body);
    }
}

function uploadSigningBytes(value: InvitationUploadAuthorization): Uint8Array {
    return separated(UPLOAD_DOMAIN, {
        version: 1,
        owner: encodeBase64Url(value.owner),
        revocationKey: encodeBase64Url(value.revocationKey),
        digest: encodeBase64Url(value.digest),
        expiresAt: value.expiresAt,
        createdAt: value.createdAt,
    });
}

function revocationSigningBytes(value: SignedInvitationRevocation): Uint8Array {
    return separated(REVOCATION_DOMAIN, {
        version: 1,
        revocationKey: encodeBase64Url(value.revocationKey),
        digest: value.digest === null ? null : encodeBase64Url(value.digest),
        createdAt: value.createdAt,
    });
}

/** Bind one exact invitation to a separate durable revocation authority. */
export function createInvitationUploadAuthorization(
    owner: IdentityKeyPair,
    revocation: IdentityKeyPair,
    digest: Uint8Array,
    expiresAt: number,
    createdAt: number = Date.now(),
): InvitationUploadAuthorization {
    validateIdentityPublicKey({ publicKey: revocation.publicKey });
    if (
        !(digest instanceof Uint8Array) ||
        digest.length !== 32 ||
        !Number.isSafeInteger(expiresAt) ||
        !Number.isSafeInteger(createdAt) ||
        createdAt < 0 ||
        expiresAt <= createdAt
    ) {
        throw new Error("Invalid invitation upload authorization");
    }
    const unsigned: InvitationUploadAuthorization = {
        version: 1,
        owner: owner.publicKey.slice(),
        revocationKey: revocation.publicKey.slice(),
        digest: digest.slice(),
        expiresAt,
        createdAt,
        signature: new Uint8Array(64),
    };
    const bytes = uploadSigningBytes(unsigned);
    try {
        return Object.freeze({ ...unsigned, signature: signBytes(owner, bytes) });
    } finally {
        zeroBytes(bytes);
    }
}

/** Authorize one or every outstanding invitation without exposing the private authority. */
export function createSignedInvitationRevocation(
    revocation: IdentityKeyPair,
    digest: Uint8Array | null,
    createdAt: number = Date.now(),
): SignedInvitationRevocation {
    validateIdentityPublicKey({ publicKey: revocation.publicKey });
    if (
        (digest !== null && (!(digest instanceof Uint8Array) || digest.length !== 32)) ||
        !Number.isSafeInteger(createdAt) ||
        createdAt < 0
    ) {
        throw new Error("Invalid invitation revocation request");
    }
    const unsigned: SignedInvitationRevocation = {
        version: 1,
        revocationKey: revocation.publicKey.slice(),
        digest: digest === null ? null : digest.slice(),
        createdAt,
        signature: new Uint8Array(64),
    };
    const bytes = revocationSigningBytes(unsigned);
    try {
        return Object.freeze({ ...unsigned, signature: signBytes(revocation, bytes) });
    } finally {
        zeroBytes(bytes);
    }
}

export function invitationUploadAuthorizationJson(value: InvitationUploadAuthorization): object {
    return {
        version: 1,
        owner: encodeBase64Url(value.owner),
        revocationKey: encodeBase64Url(value.revocationKey),
        digest: encodeBase64Url(value.digest),
        expiresAt: value.expiresAt,
        createdAt: value.createdAt,
        signature: encodeBase64Url(value.signature),
    };
}

export function signedInvitationRevocationJson(value: SignedInvitationRevocation): object {
    return {
        version: 1,
        revocationKey: encodeBase64Url(value.revocationKey),
        digest: value.digest === null ? null : encodeBase64Url(value.digest),
        createdAt: value.createdAt,
        signature: encodeBase64Url(value.signature),
    };
}
