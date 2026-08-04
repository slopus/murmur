import type { HpkeKeyPair } from "../cipherSuite/index.js";

/** RFC 9420 BasicCredential. */
export interface MlsBasicCredential {
    readonly identity: Uint8Array;
}

/** RFC 9420 key-package LeafNode profile. */
export interface MlsKeyPackageLeafNode {
    readonly encryptionKey: Uint8Array;
    readonly signatureKey: Uint8Array;
    readonly credential: MlsBasicCredential;
    readonly notBefore: bigint;
    readonly notAfter: bigint;
    readonly signature: Uint8Array;
}

/** Public RFC 9420 KeyPackage. */
export interface MlsKeyPackage {
    readonly version: 1;
    readonly cipherSuite: 0x0001;
    readonly initKey: Uint8Array;
    readonly leafNode: MlsKeyPackageLeafNode;
    readonly signature: Uint8Array;
}

/** Public KeyPackage plus its one-use local HPKE private keys. */
export interface MlsKeyPackageBundle {
    readonly keyPackage: MlsKeyPackage;
    readonly initKeyPair: HpkeKeyPair;
    readonly leafKeyPair: HpkeKeyPair;
}
