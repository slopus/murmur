import {
    addPoints,
    encodeTranscript,
    encodeUint64,
    hashToPoint,
    issueAlgebraicMac,
    multiplyPoint,
    proveGeneralizedSchnorr,
    randomScalar,
    subtractPoints,
    unblindAlgebraicMac,
    verifyAlgebraicMac,
    verifyGeneralizedSchnorr,
    type SchnorrRelation,
} from "../../math/index.js";
import { equalBytes, utf8Encode, zeroBytes } from "../../utils/index.js";
import type {
    AccountCredential,
    CredentialIssuanceRequest,
    CredentialIssuanceResponse,
    CredentialIssuanceState,
    CredentialIssuer,
    CredentialIssuerPublicParameters,
} from "../types.js";
import { credentialExpiryPoint, credentialIdentifierPoint } from "./parameters.js";

const REQUEST_STATEMENT = utf8Encode("blindedIdentifier = identifier + blindGenerator * blinding");
const ISSUANCE_STATEMENT = utf8Encode("issuer keys certify blinded identifier and expiry");

function validateContext(context: Uint8Array): void {
    if (context.length > 4096) {
        throw new Error("Credential context exceeds 4096 bytes");
    }
}

function requestRelation(
    blindedIdentifier: Uint8Array,
    identifierPoint: Uint8Array,
    parameters: CredentialIssuerPublicParameters,
): SchnorrRelation {
    return {
        target: subtractPoints(blindedIdentifier, identifierPoint),
        terms: [{ generator: parameters.blindGenerator, witnessIndex: 0 }],
    };
}

function requestProofContext(
    blindedIdentifier: Uint8Array,
    identifierPoint: Uint8Array,
    parameters: CredentialIssuerPublicParameters,
    context: Uint8Array,
): Uint8Array {
    validateContext(context);
    return encodeTranscript("murmur.private-groups.credential-request.context.v1", [
        { label: "issuer-id", value: parameters.issuerId },
        { label: "identifier-point", value: identifierPoint },
        { label: "blinded-identifier", value: blindedIdentifier },
        { label: "external-context", value: context },
    ]);
}

function verifyCredentialRequest(
    request: CredentialIssuanceRequest,
    identifierPoint: Uint8Array,
    parameters: CredentialIssuerPublicParameters,
    context: Uint8Array,
): boolean {
    return verifyGeneralizedSchnorr({
        domain: "murmur.private-groups.credential-request.v1",
        statement: REQUEST_STATEMENT,
        relations: [requestRelation(request.blindedIdentifier, identifierPoint, parameters)],
        witnessCount: 1,
        context: requestProofContext(
            request.blindedIdentifier,
            identifierPoint,
            parameters,
            context,
        ),
        proof: request.proof,
    });
}

/** Create a blind credential request and client-only unblinding state. */
export function createCredentialIssuanceRequest(
    accountIdentifier: Uint8Array,
    parameters: CredentialIssuerPublicParameters,
    context: Uint8Array,
): CredentialIssuanceState {
    const identifierPoint = credentialIdentifierPoint(accountIdentifier, parameters);
    const blinding = randomScalar();
    const blindedIdentifier = addPoints(
        identifierPoint,
        multiplyPoint(parameters.blindGenerator, blinding),
    );
    const relation = requestRelation(blindedIdentifier, identifierPoint, parameters);
    const proof = proveGeneralizedSchnorr({
        domain: "murmur.private-groups.credential-request.v1",
        statement: REQUEST_STATEMENT,
        relations: [relation],
        witnesses: [blinding],
        context: requestProofContext(blindedIdentifier, identifierPoint, parameters, context),
    });
    return { request: { blindedIdentifier, proof }, blinding };
}

function issuanceRelations(
    request: CredentialIssuanceRequest,
    response: CredentialIssuanceResponse,
    parameters: CredentialIssuerPublicParameters,
): readonly SchnorrRelation[] {
    const generators = parameters.keyProofGenerators;
    const commitments = parameters.keyCommitments;
    const expiryPoint = credentialExpiryPoint(response.expiresAt, parameters);
    return [
        { target: commitments.w, terms: [{ generator: generators.w, witnessIndex: 0 }] },
        { target: commitments.x0, terms: [{ generator: generators.x0, witnessIndex: 1 }] },
        { target: commitments.x1, terms: [{ generator: generators.x1, witnessIndex: 2 }] },
        {
            target: commitments.identifier,
            terms: [{ generator: generators.identifier, witnessIndex: 3 }],
        },
        {
            target: commitments.expiry,
            terms: [{ generator: generators.expiry, witnessIndex: 4 }],
        },
        {
            target: parameters.unblindingKey,
            terms: [{ generator: parameters.blindGenerator, witnessIndex: 3 }],
        },
        {
            target: subtractPoints(
                parameters.randomizationGenerators.v,
                parameters.verificationGenerator,
            ),
            terms: [
                { generator: parameters.randomizationGenerators.x0, witnessIndex: 1 },
                { generator: parameters.randomizationGenerators.x1, witnessIndex: 2 },
                {
                    generator: parameters.randomizationGenerators.identifier,
                    witnessIndex: 3,
                },
                { generator: parameters.randomizationGenerators.expiry, witnessIndex: 4 },
            ],
        },
        {
            target: response.mac.v,
            terms: [
                { generator: parameters.macParameters.wGenerator, witnessIndex: 0 },
                { generator: response.mac.u, witnessIndex: 1 },
                { generator: multiplyPoint(response.mac.u, response.mac.t), witnessIndex: 2 },
                { generator: request.blindedIdentifier, witnessIndex: 3 },
                { generator: expiryPoint, witnessIndex: 4 },
            ],
        },
    ];
}

function issuanceProofContext(
    request: CredentialIssuanceRequest,
    response: CredentialIssuanceResponse,
    parameters: CredentialIssuerPublicParameters,
    context: Uint8Array,
): Uint8Array {
    validateContext(context);
    return encodeTranscript("murmur.private-groups.credential-issuance.context.v1", [
        { label: "issuer-id", value: parameters.issuerId },
        { label: "blinded-identifier", value: request.blindedIdentifier },
        { label: "expires-at", value: encodeUint64(response.expiresAt) },
        { label: "mac-t", value: response.mac.t },
        { label: "mac-u", value: response.mac.u },
        { label: "mac-v", value: response.mac.v },
        { label: "external-context", value: context },
    ]);
}

/**
 * Verify a blind request for the authenticated account and issue a blinded MAC.
 *
 * The authenticated account identifier is used only to verify the request; the
 * issued MAC is evaluated over the blinded group element.
 */
export function issueCredential(options: {
    readonly issuer: CredentialIssuer;
    readonly accountIdentifier: Uint8Array;
    readonly request: CredentialIssuanceRequest;
    readonly expiresAt: number;
    readonly now: number;
    readonly context: Uint8Array;
}): CredentialIssuanceResponse {
    if (
        !Number.isSafeInteger(options.now) ||
        !Number.isSafeInteger(options.expiresAt) ||
        options.now < 0 ||
        options.expiresAt <= options.now
    ) {
        throw new Error("Credential expiry must be a future safe millisecond timestamp");
    }
    const parameters = options.issuer.publicParameters;
    const identifierPoint = credentialIdentifierPoint(options.accountIdentifier, parameters);
    if (!verifyCredentialRequest(options.request, identifierPoint, parameters, options.context)) {
        throw new Error("Invalid blind credential request");
    }
    const expiryPoint = credentialExpiryPoint(options.expiresAt, parameters);
    const mac = issueAlgebraicMac(
        parameters.macParameters,
        options.issuer.secretKey,
        options.request.blindedIdentifier,
        expiryPoint,
    );
    const incomplete: CredentialIssuanceResponse = {
        expiresAt: options.expiresAt,
        mac,
        proof: new Uint8Array(),
    };
    const proof = proveGeneralizedSchnorr({
        domain: "murmur.private-groups.credential-issuance.v1",
        statement: ISSUANCE_STATEMENT,
        relations: issuanceRelations(options.request, incomplete, parameters),
        witnesses: [
            options.issuer.secretKey.w,
            options.issuer.secretKey.x0,
            options.issuer.secretKey.x1,
            options.issuer.secretKey.identifier,
            options.issuer.secretKey.expiry,
        ],
        context: issuanceProofContext(options.request, incomplete, parameters, options.context),
    });
    return { expiresAt: options.expiresAt, mac, proof };
}

/** Verify the issuer proof, remove the request blind, and return a credential. */
export function finalizeCredentialIssuance(options: {
    readonly state: CredentialIssuanceState;
    readonly response: CredentialIssuanceResponse;
    readonly accountIdentifier: Uint8Array;
    readonly parameters: CredentialIssuerPublicParameters;
    readonly context: Uint8Array;
}): AccountCredential {
    const expectedU = hashToPoint("murmur.math.algebraic-mac.u.v1", [options.response.mac.t]);
    if (!equalBytes(expectedU, options.response.mac.u)) {
        throw new Error("Credential MAC base is invalid");
    }
    const identifierPoint = credentialIdentifierPoint(
        options.accountIdentifier,
        options.parameters,
    );
    if (
        !verifyCredentialRequest(
            options.state.request,
            identifierPoint,
            options.parameters,
            options.context,
        )
    ) {
        throw new Error("Credential request state is invalid");
    }
    if (
        !verifyGeneralizedSchnorr({
            domain: "murmur.private-groups.credential-issuance.v1",
            statement: ISSUANCE_STATEMENT,
            relations: issuanceRelations(
                options.state.request,
                options.response,
                options.parameters,
            ),
            witnessCount: 5,
            context: issuanceProofContext(
                options.state.request,
                options.response,
                options.parameters,
                options.context,
            ),
            proof: options.response.proof,
        })
    ) {
        throw new Error("Credential issuer proof is invalid");
    }
    return {
        expiresAt: options.response.expiresAt,
        mac: unblindAlgebraicMac(
            options.response.mac,
            options.state.blinding,
            options.parameters.unblindingKey,
        ),
    };
}

/** Keyed verification of a finalized credential for tests and issuer policy. */
export function verifyAccountCredential(
    credential: AccountCredential,
    accountIdentifier: Uint8Array,
    issuer: CredentialIssuer,
): boolean {
    return verifyAlgebraicMac(
        issuer.publicParameters.macParameters,
        issuer.secretKey,
        credentialIdentifierPoint(accountIdentifier, issuer.publicParameters),
        credentialExpiryPoint(credential.expiresAt, issuer.publicParameters),
        credential.mac,
    );
}

/** Zero client-only blind issuance state after finalization or cancellation. */
export function destroyCredentialIssuanceState(state: CredentialIssuanceState): void {
    zeroBytes(state.blinding);
}
