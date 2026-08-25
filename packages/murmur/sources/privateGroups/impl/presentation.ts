import {
    addPoints,
    basePoint,
    encodeTranscript,
    encodeUint64,
    multiplyPoint,
    multiplyScalars,
    negateScalar,
    proveGeneralizedSchnorr,
    randomScalar,
    subtractPoints,
    verifyGeneralizedSchnorr,
    type SchnorrRelation,
} from "../../math/index.js";
import { equalBytes, utf8Encode, zeroBytes } from "../../utils/index.js";
import type {
    AccountCredential,
    CredentialIssuer,
    CredentialIssuerPublicParameters,
    EncryptedUid,
    PrivateGroupParameters,
    PrivateGroupPublicParameters,
    UidPresentation,
} from "../types.js";
import { accountIdentifierScalar, credentialExpiryPoint } from "./parameters.js";
import {
    createEncryptedUid,
    deterministicUidRandomness,
    encodeEncryptedUid,
    validatePrivateGroupPublicParameters,
} from "./uid.js";

const PRESENTATION_STATEMENT = utf8Encode(
    "valid algebraic MAC and encrypted UID contain the same hidden identifier",
);
const PRESENTATION_WITNESS_COUNT = 5;

function validatePresentationContext(context: Uint8Array): void {
    if (context.length > 4096) {
        throw new Error("Presentation context exceeds 4096 bytes");
    }
}

function presentationRelations(
    presentation: UidPresentation,
    encryptedUid: EncryptedUid,
    group: PrivateGroupPublicParameters,
    issuer: CredentialIssuerPublicParameters,
): readonly SchnorrRelation[] {
    const generators = issuer.randomizationGenerators;
    return [
        {
            target: presentation.cX1,
            terms: [
                { generator: presentation.cX0, witnessIndex: 3 },
                { generator: generators.x0, witnessIndex: 4 },
                { generator: generators.x1, witnessIndex: 2 },
            ],
        },
        {
            target: presentation.cIdentifier,
            terms: [
                { generator: issuer.identifierGenerator, witnessIndex: 0 },
                { generator: generators.identifier, witnessIndex: 2 },
            ],
        },
        {
            target: presentation.cExpiry,
            terms: [{ generator: generators.expiry, witnessIndex: 2 }],
        },
        {
            target: presentation.verificationTag,
            terms: [{ generator: issuer.verificationGenerator, witnessIndex: 2 }],
        },
        {
            target: encryptedUid.ephemeralPublicKey,
            terms: [{ generator: basePoint(), witnessIndex: 1 }],
        },
        {
            target: encryptedUid.encryptedPoint,
            terms: [
                { generator: group.publicProofParams.messageGenerator, witnessIndex: 0 },
                { generator: group.publicProofParams.encryptionPublicKey, witnessIndex: 1 },
            ],
        },
    ];
}

function presentationProofContext(
    presentation: UidPresentation,
    encryptedUid: EncryptedUid,
    group: PrivateGroupPublicParameters,
    issuer: CredentialIssuerPublicParameters,
    context: Uint8Array,
): Uint8Array {
    validatePresentationContext(context);
    return encodeTranscript("murmur.private-groups.uid-presentation.context.v1", [
        { label: "issuer-id", value: issuer.issuerId },
        { label: "opaque-group-id", value: group.opaqueGroupId },
        { label: "encrypted-uid", value: encodeEncryptedUid(encryptedUid) },
        { label: "expires-at", value: encodeUint64(presentation.expiresAt) },
        { label: "replay-nonce", value: presentation.replayNonce },
        { label: "external-context", value: context },
    ]);
}

/** Create a fresh randomized proof that a credential matches one encrypted UID. */
export function createUidPresentation(options: {
    readonly credential: AccountCredential;
    readonly accountIdentifier: Uint8Array;
    readonly encryptedUid: EncryptedUid;
    readonly group: PrivateGroupParameters;
    readonly issuer: CredentialIssuerPublicParameters;
    readonly replayNonce: Uint8Array;
    readonly context: Uint8Array;
    readonly now: number;
}): UidPresentation {
    if (
        !Number.isSafeInteger(options.now) ||
        options.now < 0 ||
        options.credential.expiresAt <= options.now
    ) {
        throw new Error("Cannot present an expired credential");
    }
    if (options.replayNonce.length !== 32) {
        throw new Error("Presentation replay nonce must be exactly 32 bytes");
    }
    const expectedUid = createEncryptedUid(options.accountIdentifier, options.group);
    if (!equalBytes(encodeEncryptedUid(expectedUid), encodeEncryptedUid(options.encryptedUid))) {
        throw new Error("Encrypted UID is not the canonical entry for this account and group");
    }
    const groupPublic: PrivateGroupPublicParameters = {
        opaqueGroupId: options.group.opaqueGroupId,
        publicProofParams: options.group.publicProofParams,
    };
    const identifier = accountIdentifierScalar(options.accountIdentifier);
    const uidRandomness = deterministicUidRandomness(options.accountIdentifier, options.group);
    const randomizer = randomScalar();
    const z0 = negateScalar(multiplyScalars(options.credential.mac.t, randomizer));
    try {
        const generators = options.issuer.randomizationGenerators;
        const presentationWithoutProof: UidPresentation = {
            expiresAt: options.credential.expiresAt,
            replayNonce: options.replayNonce.slice(),
            cX0: addPoints(options.credential.mac.u, multiplyPoint(generators.x0, randomizer)),
            cX1: addPoints(
                multiplyPoint(options.credential.mac.u, options.credential.mac.t),
                multiplyPoint(generators.x1, randomizer),
            ),
            cIdentifier: addPoints(
                multiplyPoint(options.issuer.identifierGenerator, identifier),
                multiplyPoint(generators.identifier, randomizer),
            ),
            cExpiry: multiplyPoint(generators.expiry, randomizer),
            cV: addPoints(options.credential.mac.v, multiplyPoint(generators.v, randomizer)),
            verificationTag: multiplyPoint(options.issuer.verificationGenerator, randomizer),
            proof: new Uint8Array(),
        };
        const proof = proveGeneralizedSchnorr({
            domain: "murmur.private-groups.uid-presentation.v1",
            statement: PRESENTATION_STATEMENT,
            relations: presentationRelations(
                presentationWithoutProof,
                options.encryptedUid,
                groupPublic,
                options.issuer,
            ),
            witnesses: [identifier, uidRandomness, randomizer, options.credential.mac.t, z0],
            context: presentationProofContext(
                presentationWithoutProof,
                options.encryptedUid,
                groupPublic,
                options.issuer,
                options.context,
            ),
        });
        return { ...presentationWithoutProof, proof };
    } finally {
        zeroBytes(identifier);
        zeroBytes(uidRandomness);
        zeroBytes(randomizer);
        zeroBytes(z0);
    }
}

function keyedPresentationTag(presentation: UidPresentation, issuer: CredentialIssuer): Uint8Array {
    const parameters = issuer.publicParameters;
    const expiryPoint = credentialExpiryPoint(presentation.expiresAt, parameters);
    let tag = presentation.cV;
    tag = subtractPoints(
        tag,
        multiplyPoint(parameters.macParameters.wGenerator, issuer.secretKey.w),
    );
    tag = subtractPoints(tag, multiplyPoint(presentation.cX0, issuer.secretKey.x0));
    tag = subtractPoints(tag, multiplyPoint(presentation.cX1, issuer.secretKey.x1));
    tag = subtractPoints(tag, multiplyPoint(presentation.cIdentifier, issuer.secretKey.identifier));
    tag = subtractPoints(
        tag,
        multiplyPoint(addPoints(presentation.cExpiry, expiryPoint), issuer.secretKey.expiry),
    );
    return tag;
}

/**
 * Verify expiry, replay/context binding, keyed credential validity, and the
 * same-identifier encrypted-UID proof without learning the identifier.
 */
export function verifyUidPresentation(options: {
    readonly presentation: UidPresentation;
    readonly encryptedUid: EncryptedUid;
    readonly group: PrivateGroupPublicParameters;
    readonly issuer: CredentialIssuer;
    readonly expectedReplayNonce: Uint8Array;
    readonly context: Uint8Array;
    readonly now: number;
}): boolean {
    try {
        if (
            !Number.isSafeInteger(options.now) ||
            options.now < 0 ||
            !Number.isSafeInteger(options.presentation.expiresAt) ||
            options.presentation.expiresAt <= options.now ||
            options.expectedReplayNonce.length !== 32 ||
            options.presentation.replayNonce.length !== 32 ||
            !equalBytes(options.presentation.replayNonce, options.expectedReplayNonce)
        ) {
            return false;
        }
        validatePrivateGroupPublicParameters(options.group);
        const expectedTag = keyedPresentationTag(options.presentation, options.issuer);
        if (!equalBytes(expectedTag, options.presentation.verificationTag)) {
            return false;
        }
        return verifyGeneralizedSchnorr({
            domain: "murmur.private-groups.uid-presentation.v1",
            statement: PRESENTATION_STATEMENT,
            relations: presentationRelations(
                options.presentation,
                options.encryptedUid,
                options.group,
                options.issuer.publicParameters,
            ),
            witnessCount: PRESENTATION_WITNESS_COUNT,
            context: presentationProofContext(
                options.presentation,
                options.encryptedUid,
                options.group,
                options.issuer.publicParameters,
                options.context,
            ),
            proof: options.presentation.proof,
        });
    } catch {
        return false;
    }
}
