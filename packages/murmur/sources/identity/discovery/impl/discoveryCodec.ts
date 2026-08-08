import type { IdentityKeyPair } from "../../../crypto/index.js";
import { signBytes, validateIdentityPublicKey, verifyBytes } from "../../../crypto/index.js";
import {
    decodeMlsKeyPackage,
    encodeMlsKeyPackage,
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
    type MlsKeyPackage,
} from "../../../mls/keyPackage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
} from "../../../utils/index.js";
import type {
    DiscoveryBundle,
    DiscoveryBundleOptions,
    DiscoveryBundleValidationOptions,
} from "../types.js";

const DOMAIN = "murmur.discovery.bundle.v1";
const MAXIMUM_KEY_PACKAGES = 32;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const MAXIMUM_BUNDLE_BYTES = 4 * 1024 * 1024;
const DEFAULT_LIFETIME_MILLISECONDS = 24 * 60 * 60 * 1_000;
const DEFAULT_MAXIMUM_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1_000;

interface DiscoveryBundleJson {
    readonly version: 1;
    readonly identityKey: string;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly keyPackages: readonly string[];
    readonly signature: string;
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid discovery bundle");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>): void {
    const fields = ["version", "identityKey", "createdAt", "expiresAt", "keyPackages", "signature"];
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid discovery bundle");
    }
}

function unsignedJson(bundle: DiscoveryBundle): Omit<DiscoveryBundleJson, "signature"> {
    return {
        version: 1,
        identityKey: encodeBase64Url(bundle.identityKey),
        createdAt: bundle.createdAt,
        expiresAt: bundle.expiresAt,
        keyPackages: bundle.keyPackages.map((keyPackage) =>
            encodeBase64Url(encodeMlsKeyPackage(keyPackage)),
        ),
    };
}

function signingJsonBytes(value: Omit<DiscoveryBundleJson, "signature">): Uint8Array {
    const prefix = utf8Encode(`${DOMAIN}\0`);
    const body = canonicalJsonBytes(value);
    const bytes = new Uint8Array(prefix.length + body.length);
    bytes.set(prefix);
    bytes.set(body, prefix.length);
    return bytes;
}

function signingBytes(bundle: DiscoveryBundle): Uint8Array {
    return signingJsonBytes(unsignedJson(bundle));
}

function validateHeader(
    bundle: DiscoveryBundle,
    now: number | null,
    maximumFutureSkewMilliseconds: number,
): void {
    if (
        bundle.version !== 1 ||
        bundle.identityKey.length !== 32 ||
        !Number.isSafeInteger(bundle.createdAt) ||
        bundle.createdAt < 0 ||
        !Number.isSafeInteger(bundle.expiresAt) ||
        bundle.expiresAt <= bundle.createdAt ||
        bundle.signature.length !== 64
    ) {
        throw new Error("Invalid discovery bundle");
    }
    validateIdentityPublicKey({ publicKey: bundle.identityKey });
    if (
        now !== null &&
        (!Number.isSafeInteger(now) ||
            now < 0 ||
            !Number.isSafeInteger(maximumFutureSkewMilliseconds) ||
            maximumFutureSkewMilliseconds < 0 ||
            maximumFutureSkewMilliseconds > 60 * 60 * 1_000 ||
            (bundle.createdAt > now && bundle.createdAt - now > maximumFutureSkewMilliseconds) ||
            now >= bundle.expiresAt)
    ) {
        throw new Error("Discovery bundle is not current");
    }
}

function validateKeyPackages(bundle: DiscoveryBundle, nowSeconds: number | null): void {
    if (bundle.keyPackages.length < 1 || bundle.keyPackages.length > MAXIMUM_KEY_PACKAGES) {
        throw new Error("Invalid discovery bundle");
    }
    const references = new Set<string>();
    let totalBytes = 0;
    for (const keyPackage of bundle.keyPackages) {
        const encoded = encodeMlsKeyPackage(keyPackage);
        totalBytes += encoded.length;
        if (
            encoded.length > MAXIMUM_KEY_PACKAGE_BYTES ||
            totalBytes > MAXIMUM_BUNDLE_BYTES ||
            !verifyMlsKeyPackage(keyPackage, nowSeconds) ||
            !equalBytes(keyPackage.leafNode.signatureKey, bundle.identityKey) ||
            !equalBytes(keyPackage.leafNode.credential.identity, bundle.identityKey) ||
            BigInt(bundle.expiresAt) > (keyPackage.leafNode.notAfter + 1n) * 1_000n
        ) {
            throw new Error("Invalid discovery KeyPackage");
        }
        const reference = encodeBase64Url(mlsKeyPackageReference(keyPackage));
        if (references.has(reference)) {
            throw new Error("Duplicate discovery KeyPackage");
        }
        references.add(reference);
    }
}

function validate(
    bundle: DiscoveryBundle,
    now: number | null,
    maximumFutureSkewMilliseconds: number,
): void {
    validateHeader(bundle, now, maximumFutureSkewMilliseconds);
    validateKeyPackages(
        bundle,
        now === null ? null : Math.floor(Math.max(now, bundle.createdAt) / 1_000),
    );
}

function encodedBundle(bundle: DiscoveryBundle): Uint8Array {
    return canonicalJsonBytes({
        ...unsignedJson(bundle),
        signature: encodeBase64Url(bundle.signature),
    });
}

function validationTime(options: DiscoveryBundleValidationOptions): {
    readonly now: number;
    readonly maximumFutureSkewMilliseconds: number;
} {
    return {
        now: options.now ?? Date.now(),
        maximumFutureSkewMilliseconds:
            options.maximumFutureSkewMilliseconds ?? DEFAULT_MAXIMUM_FUTURE_SKEW_MILLISECONDS,
    };
}

/** Create one signed discovery bundle from current public KeyPackages. */
export function createDiscoveryBundle(
    identity: IdentityKeyPair,
    keyPackages: readonly MlsKeyPackage[],
    options: DiscoveryBundleOptions = {},
): DiscoveryBundle {
    const createdAt = options.createdAt ?? Date.now();
    const unsigned: DiscoveryBundle = {
        version: 1,
        identityKey: identity.publicKey.slice(),
        createdAt,
        expiresAt: options.expiresAt ?? createdAt + DEFAULT_LIFETIME_MILLISECONDS,
        keyPackages: keyPackages.map((value) => decodeMlsKeyPackage(encodeMlsKeyPackage(value))),
        signature: new Uint8Array(64),
    };
    validate(unsigned, createdAt, 0);
    const bundle = { ...unsigned, signature: signBytes(identity, signingBytes(unsigned)) };
    if (encodedBundle(bundle).length > MAXIMUM_BUNDLE_BYTES) {
        throw new Error("Discovery bundle exceeds maximum encoded size");
    }
    return bundle;
}

/** Verify identity binding, outer signature, KeyPackages, lifetime, and uniqueness. */
export function verifyDiscoveryBundle(
    bundle: DiscoveryBundle,
    options: DiscoveryBundleValidationOptions = {},
): boolean {
    try {
        const time = validationTime(options);
        validate(bundle, time.now, time.maximumFutureSkewMilliseconds);
        return verifyBytes(
            { publicKey: bundle.identityKey },
            signingBytes(bundle),
            bundle.signature,
        );
    } catch {
        return false;
    }
}

/** Serialize a discovery bundle as strict canonical JSON bytes. */
export function serializeDiscoveryBundle(bundle: DiscoveryBundle): Uint8Array {
    validate(bundle, null, 0);
    if (!verifyBytes({ publicKey: bundle.identityKey }, signingBytes(bundle), bundle.signature)) {
        throw new Error("Invalid discovery bundle signature");
    }
    const bytes = encodedBundle(bundle);
    if (bytes.length > MAXIMUM_BUNDLE_BYTES) {
        throw new Error("Discovery bundle exceeds maximum encoded size");
    }
    return bytes;
}

/** Parse and verify strict discovery-bundle bytes. */
export function parseDiscoveryBundle(
    bytes: Uint8Array,
    options: DiscoveryBundleValidationOptions = {},
): DiscoveryBundle {
    if (bytes.length < 1 || bytes.length > MAXIMUM_BUNDLE_BYTES) {
        throw new Error("Invalid discovery bundle length");
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid discovery bundle JSON");
    }
    const input = object(parsed);
    exact(input);
    if (
        input.version !== 1 ||
        typeof input.identityKey !== "string" ||
        typeof input.createdAt !== "number" ||
        typeof input.expiresAt !== "number" ||
        !Array.isArray(input.keyPackages) ||
        input.keyPackages.some((value) => typeof value !== "string") ||
        typeof input.signature !== "string"
    ) {
        throw new Error("Invalid discovery bundle");
    }
    if (
        input.keyPackages.length < 1 ||
        input.keyPackages.length > MAXIMUM_KEY_PACKAGES ||
        input.keyPackages.some(
            (value) => (value as string).length > Math.ceil((MAXIMUM_KEY_PACKAGE_BYTES * 4) / 3),
        )
    ) {
        throw new Error("Invalid discovery KeyPackage count or size");
    }
    const identityKey = decodeBase64Url(input.identityKey);
    const signature = decodeBase64Url(input.signature);
    if (
        encodeBase64Url(identityKey) !== input.identityKey ||
        encodeBase64Url(signature) !== input.signature
    ) {
        throw new Error("Non-canonical discovery bundle encoding");
    }
    const time = validationTime(options);
    const header: DiscoveryBundle = {
        version: 1,
        identityKey,
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        keyPackages: [],
        signature,
    };
    validateHeader(header, time.now, time.maximumFutureSkewMilliseconds);
    if (
        !verifyBytes(
            { publicKey: identityKey },
            signingJsonBytes({
                version: 1,
                identityKey: input.identityKey,
                createdAt: input.createdAt,
                expiresAt: input.expiresAt,
                keyPackages: input.keyPackages as string[],
            }),
            signature,
        )
    ) {
        throw new Error("Invalid discovery bundle authentication");
    }
    const bundle: DiscoveryBundle = {
        version: 1,
        identityKey,
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        keyPackages: input.keyPackages.map((value) =>
            decodeMlsKeyPackage(decodeBase64Url(value as string)),
        ),
        signature,
    };
    validateKeyPackages(bundle, Math.floor(Math.max(time.now, bundle.createdAt) / 1_000));
    const canonical = encodedBundle(bundle);
    if (!equalBytes(canonical, bytes)) {
        throw new Error("Non-canonical discovery bundle");
    }
    return bundle;
}
