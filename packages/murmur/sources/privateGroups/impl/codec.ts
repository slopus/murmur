import {
    canonicalizePoint,
    decodeAlgebraicMac,
    decodeSchnorrProof,
    decodeUint64,
    encodeAlgebraicMac,
    encodeUint64,
} from "../../math/index.js";
import { concatBytes, equalBytes } from "../../utils/index.js";
import type {
    AccountCredential,
    CredentialIssuanceRequest,
    CredentialIssuanceResponse,
    CredentialIssuerPublicParameters,
    PrivateGroupPublicParameters,
    UidPresentation,
} from "../types.js";

const REQUEST_HEADER = new Uint8Array([0x50, 0x47, 0x52, 0x01]);
const RESPONSE_HEADER = new Uint8Array([0x50, 0x47, 0x42, 0x01]);
const CREDENTIAL_HEADER = new Uint8Array([0x50, 0x47, 0x43, 0x01]);
const PRESENTATION_HEADER = new Uint8Array([0x50, 0x47, 0x50, 0x01]);
const GROUP_PARAMETERS_HEADER = new Uint8Array([0x50, 0x47, 0x47, 0x01]);
const ISSUER_PARAMETERS_HEADER = new Uint8Array([0x50, 0x47, 0x49, 0x01]);
const REQUEST_PROOF_LENGTH = 72;
const ISSUANCE_PROOF_LENGTH = 424;
const PRESENTATION_PROOF_LENGTH = 360;

/** Canonically serialize a blind credential request. */
export function encodeCredentialIssuanceRequest(request: CredentialIssuanceRequest): Uint8Array {
    decodeSchnorrProof(request.proof, 1, 1);
    return concatBytes(REQUEST_HEADER, canonicalizePoint(request.blindedIdentifier), request.proof);
}

/** Strictly decode a blind credential request. */
export function decodeCredentialIssuanceRequest(value: Uint8Array): CredentialIssuanceRequest {
    if (
        value.length !== 4 + 32 + REQUEST_PROOF_LENGTH ||
        !equalBytes(value.subarray(0, 4), REQUEST_HEADER)
    ) {
        throw new Error("Invalid credential issuance request encoding");
    }
    const proof = value.slice(36);
    decodeSchnorrProof(proof, 1, 1);
    return {
        blindedIdentifier: canonicalizePoint(value.subarray(4, 36)),
        proof,
    };
}

/** Canonically serialize a blind credential response. */
export function encodeCredentialIssuanceResponse(response: CredentialIssuanceResponse): Uint8Array {
    decodeSchnorrProof(response.proof, 8, 5);
    return concatBytes(
        RESPONSE_HEADER,
        encodeUint64(response.expiresAt),
        encodeAlgebraicMac(response.mac),
        response.proof,
    );
}

/** Strictly decode a blind credential response. */
export function decodeCredentialIssuanceResponse(value: Uint8Array): CredentialIssuanceResponse {
    if (
        value.length !== 4 + 8 + 100 + ISSUANCE_PROOF_LENGTH ||
        !equalBytes(value.subarray(0, 4), RESPONSE_HEADER)
    ) {
        throw new Error("Invalid credential issuance response encoding");
    }
    const proof = value.slice(112);
    decodeSchnorrProof(proof, 8, 5);
    return {
        expiresAt: decodeUint64(value, 4),
        mac: decodeAlgebraicMac(value.subarray(12, 112)),
        proof,
    };
}

/** Canonically serialize a finalized account credential. */
export function encodeAccountCredential(credential: AccountCredential): Uint8Array {
    return concatBytes(
        CREDENTIAL_HEADER,
        encodeUint64(credential.expiresAt),
        encodeAlgebraicMac(credential.mac),
    );
}

/** Strictly decode a finalized account credential. */
export function decodeAccountCredential(value: Uint8Array): AccountCredential {
    if (value.length !== 112 || !equalBytes(value.subarray(0, 4), CREDENTIAL_HEADER)) {
        throw new Error("Invalid account credential encoding");
    }
    return {
        expiresAt: decodeUint64(value, 4),
        mac: decodeAlgebraicMac(value.subarray(12, 112)),
    };
}

/** Canonically serialize a randomized encrypted-UID presentation. */
export function encodeUidPresentation(presentation: UidPresentation): Uint8Array {
    if (presentation.replayNonce.length !== 32) {
        throw new Error("Presentation replay nonce must be 32 bytes");
    }
    decodeSchnorrProof(presentation.proof, 6, 5);
    return concatBytes(
        PRESENTATION_HEADER,
        encodeUint64(presentation.expiresAt),
        presentation.replayNonce,
        canonicalizePoint(presentation.cX0),
        canonicalizePoint(presentation.cX1),
        canonicalizePoint(presentation.cIdentifier),
        canonicalizePoint(presentation.cExpiry),
        canonicalizePoint(presentation.cV),
        canonicalizePoint(presentation.verificationTag),
        presentation.proof,
    );
}

/** Strictly decode a randomized encrypted-UID presentation. */
export function decodeUidPresentation(value: Uint8Array): UidPresentation {
    if (
        value.length !== 4 + 8 + 32 + 6 * 32 + PRESENTATION_PROOF_LENGTH ||
        !equalBytes(value.subarray(0, 4), PRESENTATION_HEADER)
    ) {
        throw new Error("Invalid UID presentation encoding");
    }
    let offset = 4;
    const expiresAt = decodeUint64(value, offset);
    offset += 8;
    const replayNonce = value.slice(offset, offset + 32);
    offset += 32;
    const points: Uint8Array[] = [];
    for (let index = 0; index < 6; index += 1) {
        points.push(canonicalizePoint(value.subarray(offset, offset + 32)));
        offset += 32;
    }
    const proof = value.slice(offset);
    decodeSchnorrProof(proof, 6, 5);
    const cX0 = points[0];
    const cX1 = points[1];
    const cIdentifier = points[2];
    const cExpiry = points[3];
    const cV = points[4];
    const verificationTag = points[5];
    if (
        cX0 === undefined ||
        cX1 === undefined ||
        cIdentifier === undefined ||
        cExpiry === undefined ||
        cV === undefined ||
        verificationTag === undefined
    ) {
        throw new Error("Truncated UID presentation points");
    }
    return {
        expiresAt,
        replayNonce,
        cX0,
        cX1,
        cIdentifier,
        cExpiry,
        cV,
        verificationTag,
        proof,
    };
}

/** Canonically serialize service-visible group proof parameters. */
export function encodePrivateGroupPublicParameters(
    parameters: PrivateGroupPublicParameters,
): Uint8Array {
    if (parameters.opaqueGroupId.length !== 32) {
        throw new Error("Opaque group identifier must be 32 bytes");
    }
    return concatBytes(
        GROUP_PARAMETERS_HEADER,
        parameters.opaqueGroupId,
        canonicalizePoint(parameters.publicProofParams.encryptionPublicKey),
        canonicalizePoint(parameters.publicProofParams.messageGenerator),
    );
}

/** Strictly decode service-visible group proof parameters. */
export function decodePrivateGroupPublicParameters(
    value: Uint8Array,
): PrivateGroupPublicParameters {
    if (value.length !== 100 || !equalBytes(value.subarray(0, 4), GROUP_PARAMETERS_HEADER)) {
        throw new Error("Invalid private-group public parameter encoding");
    }
    return {
        opaqueGroupId: value.slice(4, 36),
        publicProofParams: {
            encryptionPublicKey: canonicalizePoint(value.subarray(36, 68)),
            messageGenerator: canonicalizePoint(value.subarray(68, 100)),
        },
    };
}

function issuerParameterPoints(
    parameters: CredentialIssuerPublicParameters,
): readonly Uint8Array[] {
    return [
        parameters.macParameters.wGenerator,
        parameters.identifierGenerator,
        parameters.expiryGenerator,
        parameters.blindGenerator,
        parameters.unblindingKey,
        parameters.keyProofGenerators.w,
        parameters.keyProofGenerators.x0,
        parameters.keyProofGenerators.x1,
        parameters.keyProofGenerators.identifier,
        parameters.keyProofGenerators.expiry,
        parameters.keyCommitments.w,
        parameters.keyCommitments.x0,
        parameters.keyCommitments.x1,
        parameters.keyCommitments.identifier,
        parameters.keyCommitments.expiry,
        parameters.randomizationGenerators.v,
        parameters.randomizationGenerators.x0,
        parameters.randomizationGenerators.x1,
        parameters.randomizationGenerators.identifier,
        parameters.randomizationGenerators.expiry,
        parameters.verificationGenerator,
    ];
}

/** Canonically serialize credential issuer public parameters. */
export function encodeCredentialIssuerPublicParameters(
    parameters: CredentialIssuerPublicParameters,
): Uint8Array {
    if (parameters.issuerId.length !== 32) {
        throw new Error("Credential issuer identifier must be 32 bytes");
    }
    return concatBytes(
        ISSUER_PARAMETERS_HEADER,
        parameters.issuerId,
        ...issuerParameterPoints(parameters).map(canonicalizePoint),
    );
}

/** Strictly decode credential issuer public parameters. */
export function decodeCredentialIssuerPublicParameters(
    value: Uint8Array,
): CredentialIssuerPublicParameters {
    if (
        value.length !== 4 + 32 + 21 * 32 ||
        !equalBytes(value.subarray(0, 4), ISSUER_PARAMETERS_HEADER)
    ) {
        throw new Error("Invalid credential issuer public parameter encoding");
    }
    const issuerId = value.slice(4, 36);
    const points: Uint8Array[] = [];
    let offset = 36;
    for (let index = 0; index < 21; index += 1) {
        points.push(canonicalizePoint(value.subarray(offset, offset + 32)));
        offset += 32;
    }
    const point = (index: number): Uint8Array => {
        const result = points[index];
        if (result === undefined) throw new Error("Truncated issuer parameters");
        return result;
    };
    return {
        issuerId,
        macParameters: { wGenerator: point(0) },
        identifierGenerator: point(1),
        expiryGenerator: point(2),
        blindGenerator: point(3),
        unblindingKey: point(4),
        keyProofGenerators: {
            w: point(5),
            x0: point(6),
            x1: point(7),
            identifier: point(8),
            expiry: point(9),
        },
        keyCommitments: {
            w: point(10),
            x0: point(11),
            x1: point(12),
            identifier: point(13),
            expiry: point(14),
        },
        randomizationGenerators: {
            v: point(15),
            x0: point(16),
            x1: point(17),
            identifier: point(18),
            expiry: point(19),
        },
        verificationGenerator: point(20),
    };
}
