import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";

interface InvitationTimes {
    readonly createdAt: number;
    readonly expiresAt: number;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid invitation bundle");
    }
    return value as Record<string, unknown>;
}

/**
 * Read only the signed time fields needed for relay retention policy.
 *
 * The relay deliberately does not authenticate or interpret the remaining
 * public bundle. Recipients verify the exact digest and complete bundle.
 */
export function validateInvitationTimes(
    bundle: Uint8Array,
    now: number,
    maximumTtlMilliseconds: number,
    maximumFutureSkewMilliseconds: number,
): InvitationTimes {
    let parsed: unknown;
    try {
        parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundle)) as unknown;
    } catch {
        throw new Error("Invalid invitation bundle JSON");
    }
    const value = object(parsed);
    const createdAt = value.createdAt;
    const expiresAt = value.expiresAt;
    if (
        typeof createdAt !== "number" ||
        !Number.isSafeInteger(createdAt) ||
        createdAt < 0 ||
        typeof expiresAt !== "number" ||
        !Number.isSafeInteger(expiresAt) ||
        expiresAt <= createdAt ||
        expiresAt <= now ||
        createdAt > now + maximumFutureSkewMilliseconds ||
        expiresAt - createdAt > maximumTtlMilliseconds ||
        expiresAt - now > maximumTtlMilliseconds
    ) {
        throw new Error("Invitation bundle violates relay time policy");
    }
    return { createdAt, expiresAt };
}

/** Read the signed bundle's claimed identity for owner-authorized cache registration. */
export function invitationOwner(bundle: Uint8Array): Uint8Array {
    let parsed: unknown;
    try {
        parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundle)) as unknown;
    } catch {
        throw new Error("Invalid invitation bundle JSON");
    }
    const value = object(parsed);
    if (value.version !== 1 || typeof value.identityKey !== "string") {
        throw new Error("Invalid invitation owner");
    }
    const owner = decodeBase64Url(value.identityKey, 32);
    if (encodeBase64Url(owner) !== value.identityKey) {
        throw new Error("Invalid invitation owner");
    }
    return owner;
}
