import {
    concatBytes,
    equalBytes,
    randomBytes,
    type IdentityKeyPair,
    zeroBytes,
} from "../internal.js";
import {
    canonicalizeHpkePublicKey,
    deriveHpkeKeyPair,
    isHpkeKeyPair,
    mlsReferenceHash,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import { encodeUint32 } from "../encoding/index.js";
import {
    decodeMlsKeyPackage,
    encodeKeyPackageTbs,
    encodeLeafNodeTbs,
    encodeMlsKeyPackage,
} from "./impl/codec.js";
import type { MlsKeyPackage, MlsKeyPackageBundle, MlsKeyPackageLeafNode } from "./types.js";

export type {
    MlsBasicCredential,
    MlsKeyPackage,
    MlsKeyPackageBundle,
    MlsKeyPackageLeafNode,
} from "./types.js";
export { decodeMlsKeyPackage, encodeMlsKeyPackage } from "./impl/codec.js";

const DEFAULT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const KEY_PACKAGE_BUNDLE_HEADER = new Uint8Array([0x4d, 0x4b, 0x42, 1]);
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;

/** Create an authenticated one-use RFC 9420 KeyPackage bundle. */
export function createMlsKeyPackage(
    identity: IdentityKeyPair,
    nowSeconds: number = Math.floor(Date.now() / 1_000),
    lifetimeSeconds: number = DEFAULT_LIFETIME_SECONDS,
    credentialIdentity: Uint8Array = identity.publicKey,
): MlsKeyPackageBundle {
    if (
        !Number.isSafeInteger(nowSeconds) ||
        nowSeconds < 0 ||
        !Number.isSafeInteger(lifetimeSeconds) ||
        lifetimeSeconds < 1
    ) {
        throw new Error("Invalid KeyPackage lifetime");
    }
    let initKeyPair: ReturnType<typeof deriveHpkeKeyPair> | undefined;
    let leafKeyPair: ReturnType<typeof deriveHpkeKeyPair> | undefined;
    try {
        initKeyPair = deriveHpkeKeyPair(randomBytes(32));
        leafKeyPair = deriveHpkeKeyPair(randomBytes(32));
        const notBefore = BigInt(nowSeconds);
        const notAfter = notBefore + BigInt(lifetimeSeconds);
        if (notAfter > 0xffff_ffff_ffff_ffffn) {
            throw new Error("KeyPackage lifetime exceeds uint64");
        }
        if (credentialIdentity.length < 1 || credentialIdentity.length > 1024) {
            throw new Error("Invalid MLS credential identity");
        }
        const unsignedLeaf = {
            encryptionKey: leafKeyPair.publicKey,
            signatureKey: identity.publicKey.slice(),
            credential: { identity: credentialIdentity.slice() },
            notBefore,
            notAfter,
        };
        const leafNode: MlsKeyPackageLeafNode = {
            ...unsignedLeaf,
            signature: mlsSignWithLabel(
                identity.secretKey,
                "LeafNodeTBS",
                encodeLeafNodeTbs(unsignedLeaf),
            ),
        };
        const unsignedKeyPackage = {
            version: 1 as const,
            cipherSuite: 0x0001 as const,
            initKey: initKeyPair.publicKey,
            leafNode,
        };
        const keyPackage: MlsKeyPackage = {
            ...unsignedKeyPackage,
            signature: mlsSignWithLabel(
                identity.secretKey,
                "KeyPackageTBS",
                encodeKeyPackageTbs(unsignedKeyPackage),
            ),
        };
        return { keyPackage, initKeyPair, leafKeyPair };
    } catch (error: unknown) {
        if (initKeyPair !== undefined) {
            zeroBytes(initKeyPair.secretKey);
        }
        if (leafKeyPair !== undefined) {
            zeroBytes(leafKeyPair.secretKey);
        }
        throw error;
    }
}

/** Verify signatures, key separation, and lifetime of a KeyPackage. */
export function verifyMlsKeyPackage(
    keyPackage: MlsKeyPackage,
    nowSeconds: number | null = Math.floor(Date.now() / 1_000),
): boolean {
    try {
        const canonicalInitKey = canonicalizeHpkePublicKey(keyPackage.initKey);
        const canonicalLeafKey = canonicalizeHpkePublicKey(keyPackage.leafNode.encryptionKey);
        const credentialMatches = keyPackage.leafNode.credential.identity.length === 32;
        return (
            keyPackage.version === 1 &&
            keyPackage.cipherSuite === 0x0001 &&
            keyPackage.initKey.length === 32 &&
            keyPackage.leafNode.encryptionKey.length === 32 &&
            keyPackage.leafNode.signatureKey.length === 32 &&
            keyPackage.leafNode.credential.identity.length <= 1024 &&
            credentialMatches &&
            !equalBytes(canonicalInitKey, canonicalLeafKey) &&
            (nowSeconds === null ||
                (Number.isSafeInteger(nowSeconds) &&
                    nowSeconds >= 0 &&
                    BigInt(nowSeconds) >= keyPackage.leafNode.notBefore &&
                    BigInt(nowSeconds) <= keyPackage.leafNode.notAfter)) &&
            mlsVerifyWithLabel(
                keyPackage.leafNode.signatureKey,
                "LeafNodeTBS",
                encodeLeafNodeTbs(keyPackage.leafNode),
                keyPackage.leafNode.signature,
            ) &&
            mlsVerifyWithLabel(
                keyPackage.leafNode.signatureKey,
                "KeyPackageTBS",
                encodeKeyPackageTbs(keyPackage),
                keyPackage.signature,
            )
        );
    } catch {
        return false;
    }
}

/** RFC 9420 KeyPackageRef. */
export function mlsKeyPackageReference(keyPackage: MlsKeyPackage): Uint8Array {
    return mlsReferenceHash("KeyPackage Reference", encodeMlsKeyPackage(keyPackage));
}

/** Destroy one-use local HPKE secrets after join or expiry. */
export function destroyMlsKeyPackageBundle(bundle: MlsKeyPackageBundle): void {
    zeroBytes(bundle.initKeyPair.secretKey);
    zeroBytes(bundle.leafKeyPair.secretKey);
}

/**
 * Serialize a one-use KeyPackage bundle for private durable application state.
 *
 * The returned bytes contain both HPKE private keys and must never be shared.
 */
export function serializeMlsKeyPackageBundle(bundle: MlsKeyPackageBundle): Uint8Array {
    if (
        !verifyMlsKeyPackage(bundle.keyPackage, null) ||
        !isHpkeKeyPair(bundle.initKeyPair) ||
        !isHpkeKeyPair(bundle.leafKeyPair) ||
        !equalBytes(bundle.initKeyPair.publicKey, bundle.keyPackage.initKey) ||
        !equalBytes(bundle.leafKeyPair.publicKey, bundle.keyPackage.leafNode.encryptionKey)
    ) {
        throw new Error("Invalid MLS KeyPackage bundle");
    }
    const keyPackage = encodeMlsKeyPackage(bundle.keyPackage);
    if (keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES) {
        throw new Error("MLS KeyPackage is too large");
    }
    return concatBytes(
        KEY_PACKAGE_BUNDLE_HEADER,
        encodeUint32(keyPackage.length),
        keyPackage,
        bundle.initKeyPair.secretKey,
        bundle.leafKeyPair.secretKey,
    );
}

/**
 * Restore and validate a one-use KeyPackage bundle from private durable state.
 *
 * The returned bundle owns independent secret-key copies.
 */
export function deserializeMlsKeyPackageBundle(bytes: Uint8Array): MlsKeyPackageBundle {
    if (
        bytes.length < KEY_PACKAGE_BUNDLE_HEADER.length + 4 + 64 ||
        !equalBytes(bytes.subarray(0, KEY_PACKAGE_BUNDLE_HEADER.length), KEY_PACKAGE_BUNDLE_HEADER)
    ) {
        throw new Error("Invalid durable MLS KeyPackage bundle");
    }
    const offset = KEY_PACKAGE_BUNDLE_HEADER.length;
    const keyPackageLength =
        (bytes[offset] ?? 0) * 0x1_00_00_00 +
        ((bytes[offset + 1] ?? 0) << 16) +
        ((bytes[offset + 2] ?? 0) << 8) +
        (bytes[offset + 3] ?? 0);
    const keyPackageStart = offset + 4;
    const secretsStart = keyPackageStart + keyPackageLength;
    if (
        keyPackageLength < 1 ||
        keyPackageLength > MAXIMUM_KEY_PACKAGE_BYTES ||
        secretsStart + 64 !== bytes.length
    ) {
        throw new Error("Invalid durable MLS KeyPackage bundle length");
    }
    const keyPackage = decodeMlsKeyPackage(bytes.slice(keyPackageStart, secretsStart));
    let initSecretKey: Uint8Array | undefined;
    let leafSecretKey: Uint8Array | undefined;
    try {
        initSecretKey = bytes.slice(secretsStart, secretsStart + 32);
        leafSecretKey = bytes.slice(secretsStart + 32);
        const bundle: MlsKeyPackageBundle = {
            keyPackage,
            initKeyPair: {
                secretKey: initSecretKey,
                publicKey: keyPackage.initKey.slice(),
            },
            leafKeyPair: {
                secretKey: leafSecretKey,
                publicKey: keyPackage.leafNode.encryptionKey.slice(),
            },
        };
        if (
            !verifyMlsKeyPackage(keyPackage, null) ||
            !isHpkeKeyPair(bundle.initKeyPair) ||
            !isHpkeKeyPair(bundle.leafKeyPair)
        ) {
            throw new Error("Invalid durable MLS KeyPackage key binding");
        }
        return bundle;
    } catch (error: unknown) {
        if (initSecretKey !== undefined) {
            zeroBytes(initSecretKey);
        }
        if (leafSecretKey !== undefined) {
            zeroBytes(leafSecretKey);
        }
        throw error;
    }
}
