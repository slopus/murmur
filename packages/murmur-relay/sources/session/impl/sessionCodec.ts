import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { RelayError } from "../../protocol/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import type {
    CreateRelaySessionTokenOptions,
    RelaySessionClaims,
    SignedRelaySessionRequest,
    SignedRelaySessionRequestJson,
    VerifyRelaySessionTokenOptions,
} from "../types.js";

const SESSION_DOMAIN = "murmur.relay.session.v1";
const TOKEN_DOMAIN = "murmur.relay.ticket.v1";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

interface RelaySessionClaimsJson {
    readonly version: 1;
    readonly protocol: "murmur-websocket-v1";
    readonly device: string;
    readonly endpoint: string;
    readonly admissionPrincipal: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly nonce: string;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, "Invalid relay-session value", { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new RelayError(400, "Invalid relay-session value", { error: "malformed" });
    }
}

function safeInteger(value: unknown): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RelayError(400, "Invalid relay-session timestamp", { error: "malformed" });
    }
    return value;
}

function decode(value: unknown, bytes: number): Uint8Array {
    if (typeof value !== "string") {
        throw new RelayError(400, "Invalid relay-session bytes", { error: "malformed" });
    }
    try {
        return decodeBase64Url(value, bytes);
    } catch {
        throw new RelayError(400, "Invalid relay-session bytes", { error: "malformed" });
    }
}

function validateDevice(device: Uint8Array): void {
    try {
        const point = ed25519.Point.fromBytes(device, false);
        point.assertValidity();
        if (
            device.length !== 32 ||
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(point.toBytes(), device)
        ) {
            throw new Error("Invalid device identity");
        }
    } catch {
        throw new RelayError(400, "Invalid device identity", { error: "malformed" });
    }
}

function domainSeparated(domain: string, value: unknown): Uint8Array {
    const prefix = textEncoder.encode(`${domain}\0`);
    const body = canonicalJson(value);
    const bytes = new Uint8Array(prefix.length + body.length);
    bytes.set(prefix);
    bytes.set(body, prefix.length);
    return bytes;
}

function requestJson(request: SignedRelaySessionRequest): SignedRelaySessionRequestJson {
    return {
        version: 1,
        device: encodeBase64Url(request.device),
        createdAt: request.createdAt,
        nonce: encodeBase64Url(request.nonce),
        signature: encodeBase64Url(request.signature),
    };
}

function requestSigningBytes(request: SignedRelaySessionRequest): Uint8Array {
    const { signature: _signature, ...unsigned } = requestJson(request);
    return domainSeparated(SESSION_DOMAIN, unsigned);
}

/** Strictly decode a device-signed relay-session request. */
export function parseSignedRelaySessionRequest(value: unknown): SignedRelaySessionRequest {
    const input = object(value);
    exact(input, ["version", "device", "createdAt", "nonce", "signature"]);
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid relay-session request", { error: "malformed" });
    }
    const request: SignedRelaySessionRequest = {
        version: 1,
        device: decode(input.device, 32),
        createdAt: safeInteger(input.createdAt),
        nonce: decode(input.nonce, 24),
        signature: decode(input.signature, 64),
    };
    validateDevice(request.device);
    return request;
}

/** Verify that a relay-session requester controls the claimed device root. */
export function verifyRelaySessionRequest(request: SignedRelaySessionRequest): boolean {
    try {
        validateDevice(request.device);
        return ed25519.verify(request.signature, requestSigningBytes(request), request.device, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

function validateSecret(secret: Uint8Array): void {
    if (!(secret instanceof Uint8Array) || secret.length < 32) {
        throw new Error("Relay-session token secret must contain at least 32 bytes");
    }
}

function endpoint(value: string): string {
    if (value.length < 1 || value.length > 2_048) {
        throw new Error("Invalid relay-session endpoint");
    }
    const parsed = new URL(value);
    if (
        (parsed.protocol !== "wss:" && parsed.protocol !== "ws:") ||
        parsed.username !== "" ||
        parsed.password !== "" ||
        parsed.hash !== ""
    ) {
        throw new Error("Invalid relay-session endpoint");
    }
    return parsed.toString();
}

function claimsJson(options: CreateRelaySessionTokenOptions): RelaySessionClaimsJson {
    validateDevice(options.device);
    const normalizedEndpoint = endpoint(options.endpoint);
    if (
        options.admissionPrincipal.length < 1 ||
        options.admissionPrincipal.length > 255 ||
        !Number.isSafeInteger(options.issuedAt) ||
        options.issuedAt < 0 ||
        !Number.isSafeInteger(options.expiresAt) ||
        options.expiresAt <= options.issuedAt
    ) {
        throw new Error("Invalid relay-session token claims");
    }
    const nonce = options.nonce ?? randomBytes(24);
    if (nonce.length !== 24) throw new Error("Invalid relay-session token nonce");
    return {
        version: 1,
        protocol: "murmur-websocket-v1",
        device: encodeBase64Url(options.device),
        endpoint: normalizedEndpoint,
        admissionPrincipal: options.admissionPrincipal,
        issuedAt: options.issuedAt,
        expiresAt: options.expiresAt,
        nonce: encodeBase64Url(nonce),
    };
}

/** Sign one compact, short-lived device capability for WebSocket ingress. */
export function createRelaySessionToken(
    secret: Uint8Array,
    options: CreateRelaySessionTokenOptions,
): string {
    validateSecret(secret);
    const encodedClaims = encodeBase64Url(canonicalJson(claimsJson(options)));
    const signature = hmac(sha256, secret, textEncoder.encode(`${TOKEN_DOMAIN}\0${encodedClaims}`));
    return `${encodedClaims}.${encodeBase64Url(signature)}`;
}

/** Authenticate and decode one compact temporary relay capability. */
export function verifyRelaySessionToken(
    secret: Uint8Array,
    token: string,
    options: VerifyRelaySessionTokenOptions = {},
): RelaySessionClaims {
    validateSecret(secret);
    if (
        token.length < 3 ||
        token.length > 8 * 1024 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
    ) {
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
    const parts = token.split(".");
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
    let supplied: Uint8Array;
    let encodedClaims: Uint8Array;
    try {
        supplied = decodeBase64Url(parts[1], 32);
        encodedClaims = decodeBase64Url(parts[0]);
    } catch {
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
    const expected = hmac(sha256, secret, textEncoder.encode(`${TOKEN_DOMAIN}\0${parts[0]}`));
    if (!equalBytes(expected, supplied)) {
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
    let value: unknown;
    try {
        value = JSON.parse(textDecoder.decode(encodedClaims)) as unknown;
    } catch {
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
    try {
        const input = object(value);
        exact(input, [
            "version",
            "protocol",
            "device",
            "endpoint",
            "admissionPrincipal",
            "issuedAt",
            "expiresAt",
            "nonce",
        ]);
        if (
            input.version !== 1 ||
            input.protocol !== "murmur-websocket-v1" ||
            typeof input.endpoint !== "string" ||
            typeof input.admissionPrincipal !== "string" ||
            input.admissionPrincipal.length < 1 ||
            input.admissionPrincipal.length > 255
        ) {
            throw new Error("Invalid claims");
        }
        const claims: RelaySessionClaims = {
            version: 1,
            protocol: "murmur-websocket-v1",
            device: decode(input.device, 32),
            endpoint: endpoint(input.endpoint),
            admissionPrincipal: input.admissionPrincipal,
            issuedAt: safeInteger(input.issuedAt),
            expiresAt: safeInteger(input.expiresAt),
            nonce: decode(input.nonce, 24),
        };
        validateDevice(claims.device);
        const now = options.now ?? Date.now();
        const futureSkew = options.maximumFutureSkewMilliseconds ?? 30_000;
        if (
            !Number.isSafeInteger(now) ||
            now < 0 ||
            !Number.isSafeInteger(futureSkew) ||
            futureSkew < 0 ||
            claims.issuedAt > now + futureSkew ||
            claims.expiresAt <= now ||
            claims.expiresAt <= claims.issuedAt ||
            (options.expectedEndpoint !== undefined &&
                claims.endpoint !== endpoint(options.expectedEndpoint))
        ) {
            throw new Error("Expired or misplaced claims");
        }
        return claims;
    } catch (error: unknown) {
        if (error instanceof RelayError && error.status === 401) throw error;
        throw new RelayError(401, "Invalid relay-session token", { error: "unauthorized" });
    }
}
