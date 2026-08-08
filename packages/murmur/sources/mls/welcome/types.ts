import type { HpkeCiphertext } from "../cipherSuite/index.js";
import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsKeyPackage, MlsKeyPackageBundle } from "../keyPackage/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";

/** One KeyPackage-targeted GroupSecrets ciphertext in a Welcome. */
export interface MlsEncryptedGroupSecrets {
    readonly newMember: Uint8Array;
    readonly encryptedGroupSecrets: HpkeCiphertext;
}

/** Parsed RFC 9420 Welcome for cipher suite 0x0001. */
export interface MlsWelcome {
    readonly secrets: readonly MlsEncryptedGroupSecrets[];
    readonly encryptedGroupInfo: Uint8Array;
}

/** Decrypted extension-free GroupInfo. The ratchet tree is supplied externally. */
export interface MlsGroupInfo {
    readonly context: MlsGroupContext;
    readonly confirmationTag: Uint8Array;
    readonly signer: number;
    readonly signature: Uint8Array;
}

/** Inputs for an RFC Welcome with optional per-member TreeKEM path secrets. */
export interface CreateMlsWelcomeOptions {
    readonly context: MlsGroupContext;
    readonly joinerSecret: Uint8Array;
    readonly confirmationKey: Uint8Array;
    readonly signer: number;
    readonly signerSecretKey: Uint8Array;
    readonly newMembers: readonly MlsKeyPackage[];
    /** Parallel to `newMembers`; omitted entries encode a null path secret. */
    readonly pathSecrets?: readonly (Uint8Array | undefined)[];
}

/** Inputs for opening a Welcome using one unconsumed KeyPackage. */
export interface OpenMlsWelcomeOptions {
    readonly welcome: Uint8Array;
    readonly keyPackageBundle: MlsKeyPackageBundle;
    /**
     * Validate the external ratchet tree against GroupInfo.tree_hash, including
     * parent hashes and the joining KeyPackage leaf, then return the signer's
     * signature key. Returning undefined rejects the join.
     */
    readonly validateExternalTree: (
        groupInfo: MlsGroupInfo,
        joiningKeyPackage: MlsKeyPackage,
    ) => Uint8Array | undefined;
    readonly expectedGroupId?: Uint8Array;
    /** Exact retained Commit confirmation tag which this Welcome must authenticate. */
    readonly expectedCommitConfirmationTag?: Uint8Array;
}

/** Verified epoch state recovered from a Welcome. */
export interface OpenedMlsWelcome {
    readonly groupInfo: MlsGroupInfo;
    readonly epochSecrets: MlsEpochSecrets;
    /** Common-ancestor TreeKEM path secret, when the creating Commit had a path. */
    readonly pathSecret?: Uint8Array;
}
