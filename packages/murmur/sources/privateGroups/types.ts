import type {
    AlgebraicMac,
    AlgebraicMacParameters,
    AlgebraicMacSecretKey,
    ElGamalCiphertext,
    ElGamalKeyPair,
} from "../math/index.js";

/** Member-only parameters for deterministic group-specific UID encryption. */
export interface IdentifierEncryptionParameters {
    readonly keyPair: ElGamalKeyPair;
    readonly deterministicNonceKey: Uint8Array;
    readonly messageGenerator: Uint8Array;
}

/** Symmetric keys derived for encrypted canonical group metadata. */
export interface PrivateGroupMetadataKeys {
    readonly encryptionKey: Uint8Array;
    readonly authenticationKey: Uint8Array;
}

/** Public group parameters used by encrypted-UID presentation proofs. */
export interface PrivateGroupProofParameters {
    readonly encryptionPublicKey: Uint8Array;
    readonly messageGenerator: Uint8Array;
}

/** All outputs derived from one 32-byte private-group master secret. */
export interface PrivateGroupParameters {
    readonly opaqueGroupId: Uint8Array;
    readonly encryptionParams: IdentifierEncryptionParameters;
    readonly metadataKeys: PrivateGroupMetadataKeys;
    readonly publicProofParams: PrivateGroupProofParameters;
}

/** Public subset of group parameters provided to the state service. */
export interface PrivateGroupPublicParameters {
    readonly opaqueGroupId: Uint8Array;
    readonly publicProofParams: PrivateGroupProofParameters;
}

/** Deterministic, group-specific encrypted account identifier. */
export type EncryptedUid = ElGamalCiphertext;

/** Public algebraic-MAC and proof parameters for one credential issuer. */
export interface CredentialIssuerPublicParameters {
    readonly issuerId: Uint8Array;
    readonly macParameters: AlgebraicMacParameters;
    readonly identifierGenerator: Uint8Array;
    readonly expiryGenerator: Uint8Array;
    readonly blindGenerator: Uint8Array;
    readonly unblindingKey: Uint8Array;
    readonly keyProofGenerators: {
        readonly w: Uint8Array;
        readonly x0: Uint8Array;
        readonly x1: Uint8Array;
        readonly identifier: Uint8Array;
        readonly expiry: Uint8Array;
    };
    readonly keyCommitments: {
        readonly w: Uint8Array;
        readonly x0: Uint8Array;
        readonly x1: Uint8Array;
        readonly identifier: Uint8Array;
        readonly expiry: Uint8Array;
    };
    readonly randomizationGenerators: {
        readonly v: Uint8Array;
        readonly x0: Uint8Array;
        readonly x1: Uint8Array;
        readonly identifier: Uint8Array;
        readonly expiry: Uint8Array;
    };
    readonly verificationGenerator: Uint8Array;
}

/** Secret and public configuration for the keyed credential service. */
export interface CredentialIssuer {
    readonly secretKey: AlgebraicMacSecretKey;
    readonly publicParameters: CredentialIssuerPublicParameters;
}

/** Blind request sent by an authenticated account to the issuer. */
export interface CredentialIssuanceRequest {
    readonly blindedIdentifier: Uint8Array;
    readonly proof: Uint8Array;
}

/** Client-only state retained until a blind response is finalized. */
export interface CredentialIssuanceState {
    readonly request: CredentialIssuanceRequest;
    readonly blinding: Uint8Array;
}

/** Issuer response containing a blinded MAC and proof of correct issuance. */
export interface CredentialIssuanceResponse {
    readonly expiresAt: number;
    readonly mac: AlgebraicMac;
    readonly proof: Uint8Array;
}

/** Unblinded anonymous credential retained by the account. */
export interface AccountCredential {
    readonly expiresAt: number;
    readonly mac: AlgebraicMac;
}

/** Randomized proof tying a credential to one encrypted group UID. */
export interface UidPresentation {
    readonly expiresAt: number;
    readonly replayNonce: Uint8Array;
    readonly cX0: Uint8Array;
    readonly cX1: Uint8Array;
    readonly cIdentifier: Uint8Array;
    readonly cExpiry: Uint8Array;
    readonly cV: Uint8Array;
    readonly verificationTag: Uint8Array;
    readonly proof: Uint8Array;
}
