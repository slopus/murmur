/** A canonical ElGamal key pair over Ristretto255. */
export interface ElGamalKeyPair {
    readonly secretKey: Uint8Array;
    readonly publicKey: Uint8Array;
}

/** Correct additive ElGamal encryption of one Ristretto255 point. */
export interface ElGamalCiphertext {
    readonly ephemeralPublicKey: Uint8Array;
    readonly encryptedPoint: Uint8Array;
}

/** One generator/witness term in a generalized Schnorr relation. */
export interface SchnorrTerm {
    readonly generator: Uint8Array;
    readonly witnessIndex: number;
}

/** A relation `target = sum(generator[i] * witness[index[i]])`. */
export interface SchnorrRelation {
    readonly target: Uint8Array;
    readonly terms: readonly SchnorrTerm[];
}

/** Inputs for a generalized Schnorr proof. */
export interface SchnorrProveOptions {
    readonly domain: string;
    readonly statement: Uint8Array;
    readonly relations: readonly SchnorrRelation[];
    readonly witnesses: readonly Uint8Array[];
    readonly context: Uint8Array;
    readonly randomness?: readonly Uint8Array[];
}

/** Inputs for generalized Schnorr verification. */
export interface SchnorrVerifyOptions {
    readonly domain: string;
    readonly statement: Uint8Array;
    readonly relations: readonly SchnorrRelation[];
    readonly witnessCount: number;
    readonly context: Uint8Array;
    readonly proof: Uint8Array;
}

/** Secret keyed-verification algebraic-MAC parameters. */
export interface AlgebraicMacSecretKey {
    readonly w: Uint8Array;
    readonly x0: Uint8Array;
    readonly x1: Uint8Array;
    readonly identifier: Uint8Array;
    readonly expiry: Uint8Array;
}

/** Public generator needed to issue the algebraic MAC. */
export interface AlgebraicMacParameters {
    readonly wGenerator: Uint8Array;
}

/** CPZ-style algebraic MAC over identifier and expiry group elements. */
export interface AlgebraicMac {
    readonly t: Uint8Array;
    readonly u: Uint8Array;
    readonly v: Uint8Array;
}
