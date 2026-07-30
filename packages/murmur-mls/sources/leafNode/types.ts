import type { MlsBasicCredential } from "../keyPackage/types.js";

/** RFC 9420 LeafNode capabilities. Unknown non-default values are retained. */
export interface MlsLeafCapabilities {
    readonly versions: readonly number[];
    readonly cipherSuites: readonly number[];
    readonly extensions: readonly number[];
    readonly proposals: readonly number[];
    readonly credentials: readonly number[];
}

/** RFC extension carried by a LeafNode. */
export interface MlsLeafExtension {
    readonly type: number;
    readonly data: Uint8Array;
}

/** Parsed RFC 9420 LeafNode for the Murmur BasicCredential profile. */
export interface MlsLeafNode {
    readonly encryptionKey: Uint8Array;
    readonly signatureKey: Uint8Array;
    readonly credential: MlsBasicCredential;
    readonly capabilities: MlsLeafCapabilities;
    readonly source: "key_package" | "update" | "commit";
    readonly notBefore?: bigint;
    readonly notAfter?: bigint;
    readonly parentHash?: Uint8Array;
    readonly extensions: readonly MlsLeafExtension[];
    readonly signature: Uint8Array;
}

/** Group context appended to Update/Commit LeafNodeTBS signatures. */
export interface MlsLeafNodeSignatureContext {
    readonly groupId: Uint8Array;
    readonly leafIndex: number;
}
