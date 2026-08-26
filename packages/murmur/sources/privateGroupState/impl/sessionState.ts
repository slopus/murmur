import { randomBytes } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    zeroBytes,
} from "../../utils/index.js";
import type { PrivateGroupTrustedTip } from "../types.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAXIMUM_STATE_BYTES = 1024;

/** Versioned member-only state persisted with one MLS session. */
export interface PrivateGroupSessionState {
    readonly version: 1;
    readonly sessionId: Uint8Array;
    readonly masterSecret: Uint8Array;
    readonly trustedTip?: PrivateGroupTrustedTip;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid private-group session state");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid private-group session state");
    }
}

function bytes(value: unknown, length: number): Uint8Array {
    if (typeof value !== "string") throw new Error("Invalid private-group session state");
    let decoded: Uint8Array;
    try {
        decoded = decodeBase64Url(value);
    } catch {
        throw new Error("Invalid private-group session state");
    }
    if (decoded.length !== length || encodeBase64Url(decoded) !== value) {
        throw new Error("Invalid private-group session state");
    }
    return decoded;
}

function trustedTip(value: unknown): PrivateGroupTrustedTip {
    const input = object(value);
    exact(input, ["canonicalVersion", "revision", "revisionHash"]);
    if (
        typeof input.canonicalVersion !== "string" ||
        !UUID_V7.test(input.canonicalVersion) ||
        typeof input.revision !== "number" ||
        !Number.isSafeInteger(input.revision) ||
        input.revision < 1
    ) {
        throw new Error("Invalid private-group session state");
    }
    return {
        canonicalVersion: input.canonicalVersion,
        revision: input.revision,
        revisionHash: bytes(input.revisionHash, 32),
    };
}

function validateSessionId(sessionId: Uint8Array): void {
    if (!(sessionId instanceof Uint8Array) || sessionId.length !== 32) {
        throw new Error("Private-group session ID must be 32 bytes");
    }
}

function validateTip(value: PrivateGroupTrustedTip): void {
    if (
        !UUID_V7.test(value.canonicalVersion) ||
        !Number.isSafeInteger(value.revision) ||
        value.revision < 1 ||
        !(value.revisionHash instanceof Uint8Array) ||
        value.revisionHash.length !== 32
    ) {
        throw new Error("Invalid private-group trusted tip");
    }
}

/** Generate one stable random private-group secret for a newly created session. */
export function createPrivateGroupSessionState(sessionId: Uint8Array): PrivateGroupSessionState {
    validateSessionId(sessionId);
    return {
        version: 1,
        sessionId: sessionId.slice(),
        masterSecret: randomBytes(32),
    };
}

/** Canonically encode member-only private-group session state for durable storage. */
export function encodePrivateGroupSessionState(state: PrivateGroupSessionState): Uint8Array {
    if (state.version !== 1) throw new Error("Invalid private-group session state");
    validateSessionId(state.sessionId);
    if (!(state.masterSecret instanceof Uint8Array) || state.masterSecret.length !== 32) {
        throw new Error("Private-group master secret must be 32 bytes");
    }
    if (state.trustedTip !== undefined) validateTip(state.trustedTip);
    return canonicalJsonBytes({
        version: 1,
        sessionId: encodeBase64Url(state.sessionId),
        masterSecret: encodeBase64Url(state.masterSecret),
        trustedTip:
            state.trustedTip === undefined
                ? null
                : {
                      canonicalVersion: state.trustedTip.canonicalVersion,
                      revision: state.trustedTip.revision,
                      revisionHash: encodeBase64Url(state.trustedTip.revisionHash),
                  },
    });
}

/** Decode one strict, canonical private-group session-state record. */
export function decodePrivateGroupSessionState(value: Uint8Array): PrivateGroupSessionState {
    if (!(value instanceof Uint8Array) || value.length < 1 || value.length > MAXIMUM_STATE_BYTES) {
        throw new Error("Invalid private-group session state");
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value)) as unknown;
    } catch {
        throw new Error("Invalid private-group session state");
    }
    const input = object(parsed);
    exact(input, ["version", "sessionId", "masterSecret", "trustedTip"]);
    if (input.version !== 1) throw new Error("Invalid private-group session state");
    const sessionId = bytes(input.sessionId, 32);
    const masterSecret = bytes(input.masterSecret, 32);
    try {
        const decoded: PrivateGroupSessionState = {
            version: 1,
            sessionId,
            masterSecret,
            ...(input.trustedTip === null ? {} : { trustedTip: trustedTip(input.trustedTip) }),
        };
        const canonical = encodePrivateGroupSessionState(decoded);
        const isCanonical = equalBytes(canonical, value);
        zeroBytes(canonical);
        if (!isCanonical) throw new Error("Invalid private-group session state");
        return decoded;
    } catch (error: unknown) {
        zeroBytes(masterSecret);
        throw error;
    }
}

/** Return a defensive state copy with a validated, non-stale canonical tip. */
export function updatePrivateGroupSessionTrustedTip(
    state: PrivateGroupSessionState,
    next: PrivateGroupTrustedTip,
): PrivateGroupSessionState {
    if (state.version !== 1) throw new Error("Invalid private-group session state");
    validateSessionId(state.sessionId);
    if (!(state.masterSecret instanceof Uint8Array) || state.masterSecret.length !== 32) {
        throw new Error("Private-group master secret must be 32 bytes");
    }
    validateTip(next);
    const current = state.trustedTip;
    if (current !== undefined) {
        validateTip(current);
        const order = next.canonicalVersion.localeCompare(current.canonicalVersion);
        if (order < 0 || next.revision < current.revision) {
            throw new Error("Private-group revision rollback detected");
        }
        if (
            order === 0 &&
            (next.revision !== current.revision ||
                !equalBytes(next.revisionHash, current.revisionHash))
        ) {
            throw new Error("Private-group revision fork detected");
        }
        if (order > 0 && next.revision !== current.revision + 1) {
            throw new Error("Private-group revision gap detected");
        }
    }
    return {
        version: 1,
        sessionId: state.sessionId.slice(),
        masterSecret: state.masterSecret.slice(),
        trustedTip: {
            canonicalVersion: next.canonicalVersion,
            revision: next.revision,
            revisionHash: next.revisionHash.slice(),
        },
    };
}

/** Zero all member-only bytes retained by a private-group session-state value. */
export function destroyPrivateGroupSessionState(state: PrivateGroupSessionState): void {
    zeroBytes(state.masterSecret);
    if (state.trustedTip !== undefined) zeroBytes(state.trustedTip.revisionHash);
}
