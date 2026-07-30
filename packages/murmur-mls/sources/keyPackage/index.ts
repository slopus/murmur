import { equalBytes, randomBytes, type IdentityKeyPair, zeroBytes } from "@murmur/core";
import {
    canonicalizeHpkePublicKey,
    deriveHpkeKeyPair,
    mlsReferenceHash,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import { encodeKeyPackageTbs, encodeLeafNodeTbs, encodeMlsKeyPackage } from "./impl/codec.js";
import type { MlsKeyPackage, MlsKeyPackageBundle, MlsKeyPackageLeafNode } from "./types.js";

export type {
    MlsBasicCredential,
    MlsKeyPackage,
    MlsKeyPackageBundle,
    MlsKeyPackageLeafNode,
} from "./types.js";
export { decodeMlsKeyPackage, encodeMlsKeyPackage } from "./impl/codec.js";

const DEFAULT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

/** Create an authenticated one-use RFC 9420 KeyPackage bundle. */
export function createMlsKeyPackage(
    identity: IdentityKeyPair,
    nowSeconds: number = Math.floor(Date.now() / 1_000),
    lifetimeSeconds: number = DEFAULT_LIFETIME_SECONDS,
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
        const unsignedLeaf = {
            encryptionKey: leafKeyPair.publicKey,
            signatureKey: identity.signingKey.slice(),
            credential: { identity: identity.signingKey.slice() },
            notBefore,
            notAfter,
        };
        const leafNode: MlsKeyPackageLeafNode = {
            ...unsignedLeaf,
            signature: mlsSignWithLabel(
                identity.signingSecretKey,
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
                identity.signingSecretKey,
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
    nowSeconds: number = Math.floor(Date.now() / 1_000),
): boolean {
    try {
        const canonicalInitKey = canonicalizeHpkePublicKey(keyPackage.initKey);
        const canonicalLeafKey = canonicalizeHpkePublicKey(keyPackage.leafNode.encryptionKey);
        return (
            keyPackage.version === 1 &&
            keyPackage.cipherSuite === 0x0001 &&
            keyPackage.initKey.length === 32 &&
            keyPackage.leafNode.encryptionKey.length === 32 &&
            keyPackage.leafNode.signatureKey.length === 32 &&
            keyPackage.leafNode.credential.identity.length === 32 &&
            equalBytes(keyPackage.leafNode.credential.identity, keyPackage.leafNode.signatureKey) &&
            !equalBytes(canonicalInitKey, canonicalLeafKey) &&
            BigInt(nowSeconds) >= keyPackage.leafNode.notBefore &&
            BigInt(nowSeconds) <= keyPackage.leafNode.notAfter &&
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
