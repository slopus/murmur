import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import {
    hashToPoint,
    hashToScalar,
    encodeUint64,
    multiplyBase,
    multiplyPoint,
    subtractPoints,
} from "../../math/index.js";
import { utf8Encode, zeroBytes } from "../../utils/index.js";
import type {
    CredentialIssuer,
    CredentialIssuerPublicParameters,
    PrivateGroupParameters,
    PrivateGroupPublicParameters,
} from "../types.js";

const GROUP_KDF_SALT = sha256(utf8Encode("Murmur private-group master KDF v1"));
const ISSUER_KDF_SALT = sha256(utf8Encode("Murmur credential issuer KDF v1"));

function requireMasterSecret(value: Uint8Array, name: string): void {
    if (value.length !== 32) {
        throw new Error(`${name} must be exactly 32 bytes`);
    }
}

function deriveBytes(
    secret: Uint8Array,
    salt: Uint8Array,
    domain: string,
    length = 32,
): Uint8Array {
    return hkdf(sha256, secret, salt, utf8Encode(domain), length);
}

function deriveSecretScalar(secret: Uint8Array, salt: Uint8Array, label: string): Uint8Array {
    const material = deriveBytes(secret, salt, `scalar/${label}`, 64);
    try {
        return hashToScalar(
            "murmur.private-groups.secret-scalar.v1",
            [utf8Encode(label), material],
            true,
        );
    } finally {
        zeroBytes(material);
    }
}

function issuerPoint(issuerId: Uint8Array, label: string): Uint8Array {
    return hashToPoint("murmur.private-groups.issuer-point.v1", [issuerId, utf8Encode(label)]);
}

/** Map a stable 32-byte account identifier to its hidden credential scalar. */
export function accountIdentifierScalar(accountIdentifier: Uint8Array): Uint8Array {
    if (accountIdentifier.length !== 32) {
        throw new Error("Account identifier must be exactly 32 bytes");
    }
    return hashToScalar("murmur.private-groups.account-identifier.v1", [accountIdentifier], true);
}

/** Encode a safe millisecond expiry as a scalar. */
export function credentialExpiryScalar(expiresAt: number): Uint8Array {
    return hashToScalar(
        "murmur.private-groups.credential-expiry.v1",
        [encodeUint64(expiresAt)],
        true,
    );
}

/** Derive the issuer's identifier attribute point for an account. */
export function credentialIdentifierPoint(
    accountIdentifier: Uint8Array,
    parameters: CredentialIssuerPublicParameters,
): Uint8Array {
    const scalar = accountIdentifierScalar(accountIdentifier);
    try {
        return multiplyPoint(parameters.identifierGenerator, scalar);
    } finally {
        zeroBytes(scalar);
    }
}

/** Derive the issuer's revealed expiry attribute point. */
export function credentialExpiryPoint(
    expiresAt: number,
    parameters: CredentialIssuerPublicParameters,
): Uint8Array {
    const scalar = credentialExpiryScalar(expiresAt);
    try {
        return multiplyPoint(parameters.expiryGenerator, scalar);
    } finally {
        zeroBytes(scalar);
    }
}

/** Derive all private and public group parameters from one random master secret. */
export function derivePrivateGroupParameters(masterSecret: Uint8Array): PrivateGroupParameters {
    requireMasterSecret(masterSecret, "Private-group master secret");
    const opaqueGroupId = deriveBytes(masterSecret, GROUP_KDF_SALT, "opaque-group-id");
    const encryptionSecretKey = deriveSecretScalar(
        masterSecret,
        GROUP_KDF_SALT,
        "identifier-encryption",
    );
    const encryptionPublicKey = multiplyBase(encryptionSecretKey);
    const messageGenerator = hashToPoint("murmur.private-groups.uid-generator.v1", [opaqueGroupId]);
    return {
        opaqueGroupId,
        encryptionParams: {
            keyPair: {
                secretKey: encryptionSecretKey,
                publicKey: encryptionPublicKey,
            },
            deterministicNonceKey: deriveBytes(
                masterSecret,
                GROUP_KDF_SALT,
                "identifier-deterministic-nonce",
            ),
            messageGenerator,
        },
        metadataKeys: {
            encryptionKey: deriveBytes(masterSecret, GROUP_KDF_SALT, "metadata-encryption"),
            authenticationKey: deriveBytes(masterSecret, GROUP_KDF_SALT, "metadata-authentication"),
        },
        publicProofParams: {
            encryptionPublicKey: encryptionPublicKey.slice(),
            messageGenerator: messageGenerator.slice(),
        },
    };
}

/** Copy the service-visible subset of derived group parameters. */
export function privateGroupPublicParameters(
    parameters: PrivateGroupParameters,
): PrivateGroupPublicParameters {
    return {
        opaqueGroupId: parameters.opaqueGroupId.slice(),
        publicProofParams: {
            encryptionPublicKey: parameters.publicProofParams.encryptionPublicKey.slice(),
            messageGenerator: parameters.publicProofParams.messageGenerator.slice(),
        },
    };
}

/** Derive a credential issuer and its public proof parameters from one secret. */
export function deriveCredentialIssuer(masterSecret: Uint8Array): CredentialIssuer {
    requireMasterSecret(masterSecret, "Credential issuer master secret");
    const issuerId = deriveBytes(masterSecret, ISSUER_KDF_SALT, "issuer-id");
    const secretKey = {
        w: deriveSecretScalar(masterSecret, ISSUER_KDF_SALT, "mac-w"),
        x0: deriveSecretScalar(masterSecret, ISSUER_KDF_SALT, "mac-x0"),
        x1: deriveSecretScalar(masterSecret, ISSUER_KDF_SALT, "mac-x1"),
        identifier: deriveSecretScalar(masterSecret, ISSUER_KDF_SALT, "mac-identifier"),
        expiry: deriveSecretScalar(masterSecret, ISSUER_KDF_SALT, "mac-expiry"),
    };
    const macParameters = { wGenerator: issuerPoint(issuerId, "mac/w") };
    const identifierGenerator = issuerPoint(issuerId, "attribute/identifier");
    const expiryGenerator = issuerPoint(issuerId, "attribute/expiry");
    const blindGenerator = issuerPoint(issuerId, "issuance/blind");
    const keyProofGenerators = {
        w: issuerPoint(issuerId, "key-proof/w"),
        x0: issuerPoint(issuerId, "key-proof/x0"),
        x1: issuerPoint(issuerId, "key-proof/x1"),
        identifier: issuerPoint(issuerId, "key-proof/identifier"),
        expiry: issuerPoint(issuerId, "key-proof/expiry"),
    };
    const keyCommitments = {
        w: multiplyPoint(keyProofGenerators.w, secretKey.w),
        x0: multiplyPoint(keyProofGenerators.x0, secretKey.x0),
        x1: multiplyPoint(keyProofGenerators.x1, secretKey.x1),
        identifier: multiplyPoint(keyProofGenerators.identifier, secretKey.identifier),
        expiry: multiplyPoint(keyProofGenerators.expiry, secretKey.expiry),
    };
    const randomizationGenerators = {
        v: issuerPoint(issuerId, "presentation/v"),
        x0: issuerPoint(issuerId, "presentation/x0"),
        x1: issuerPoint(issuerId, "presentation/x1"),
        identifier: issuerPoint(issuerId, "presentation/identifier"),
        expiry: issuerPoint(issuerId, "presentation/expiry"),
    };
    let verificationGenerator = randomizationGenerators.v;
    verificationGenerator = subtractPoints(
        verificationGenerator,
        multiplyPoint(randomizationGenerators.x0, secretKey.x0),
    );
    verificationGenerator = subtractPoints(
        verificationGenerator,
        multiplyPoint(randomizationGenerators.x1, secretKey.x1),
    );
    verificationGenerator = subtractPoints(
        verificationGenerator,
        multiplyPoint(randomizationGenerators.identifier, secretKey.identifier),
    );
    verificationGenerator = subtractPoints(
        verificationGenerator,
        multiplyPoint(randomizationGenerators.expiry, secretKey.expiry),
    );
    return {
        secretKey,
        publicParameters: {
            issuerId,
            macParameters,
            identifierGenerator,
            expiryGenerator,
            blindGenerator,
            unblindingKey: multiplyPoint(blindGenerator, secretKey.identifier),
            keyProofGenerators,
            keyCommitments,
            randomizationGenerators,
            verificationGenerator,
        },
    };
}

/** Zero member-only group parameters in place. */
export function destroyPrivateGroupParameters(parameters: PrivateGroupParameters): void {
    zeroBytes(parameters.encryptionParams.keyPair.secretKey);
    zeroBytes(parameters.encryptionParams.deterministicNonceKey);
    zeroBytes(parameters.metadataKeys.encryptionKey);
    zeroBytes(parameters.metadataKeys.authenticationKey);
}

/** Zero the credential issuer's keyed-verification secret. */
export function destroyCredentialIssuer(issuer: CredentialIssuer): void {
    for (const scalar of Object.values(issuer.secretKey)) zeroBytes(scalar);
}
