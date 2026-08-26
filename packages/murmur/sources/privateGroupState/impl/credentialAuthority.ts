import { equalBytes } from "../../utils/index.js";
import {
    decodeCredentialIssuanceRequest,
    decodeEncryptedUid,
    decodePrivateGroupPublicParameters,
    decodeUidPresentation,
    deriveCredentialIssuer,
    encodeCredentialIssuanceResponse,
    encodeCredentialIssuerPublicParameters,
    issueCredential,
    verifyUidPresentation,
    type CredentialIssuer,
} from "../../privateGroups/index.js";

/** Byte-only authority shape consumed by the private-group state service. */
export interface PrivateGroupCredentialAuthorityAdapter {
    readonly publicParameters: Uint8Array;
    issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly expiresAt: number;
        readonly now: number;
        readonly context: Uint8Array;
    }): Uint8Array;
    validateGroupPublicParameters(
        publicParameters: Uint8Array,
        expectedOpaqueGroupId: Uint8Array,
    ): boolean;
    verifyPresentation(options: {
        readonly presentation: Uint8Array;
        readonly encryptedEntry: Uint8Array;
        readonly groupPublicParameters: Uint8Array;
        readonly expectedReplayNonce: Uint8Array;
        readonly context: Uint8Array;
        readonly now: number;
    }): number | null;
}

/**
 * Adapt the existing keyed credential issuer to the byte-only state-service boundary.
 *
 * The returned object retains the issuer secret and belongs only in trusted
 * service configuration. It stores no authenticated account identifiers.
 */
export function createPrivateGroupCredentialAuthority(
    issuer: CredentialIssuer,
): PrivateGroupCredentialAuthorityAdapter {
    return {
        publicParameters: encodeCredentialIssuerPublicParameters(issuer.publicParameters),
        issueCredential: (options): Uint8Array =>
            encodeCredentialIssuanceResponse(
                issueCredential({
                    issuer,
                    accountIdentifier: options.authenticatedAccountIdentifier,
                    request: decodeCredentialIssuanceRequest(options.request),
                    expiresAt: options.expiresAt,
                    now: options.now,
                    context: options.context,
                }),
            ),
        validateGroupPublicParameters: (publicParameters, expectedOpaqueGroupId): boolean => {
            try {
                return equalBytes(
                    decodePrivateGroupPublicParameters(publicParameters).opaqueGroupId,
                    expectedOpaqueGroupId,
                );
            } catch {
                return false;
            }
        },
        verifyPresentation: (options): number | null => {
            try {
                const presentation = decodeUidPresentation(options.presentation);
                return verifyUidPresentation({
                    presentation,
                    encryptedUid: decodeEncryptedUid(options.encryptedEntry),
                    group: decodePrivateGroupPublicParameters(options.groupPublicParameters),
                    issuer,
                    expectedReplayNonce: options.expectedReplayNonce,
                    context: options.context,
                    now: options.now,
                })
                    ? presentation.expiresAt
                    : null;
            } catch {
                return null;
            }
        },
    };
}

/**
 * EXPERIMENTAL: construct a private-group credential authority from a 32-byte secret.
 *
 * This is intended for trusted relay hosts. Applications must never receive
 * this secret; operators should derive it in a private-group-specific domain
 * from their deployment root secret.
 */
export function createPrivateGroupCredentialAuthorityFromSecret(
    secret: Uint8Array,
): PrivateGroupCredentialAuthorityAdapter {
    return createPrivateGroupCredentialAuthority(deriveCredentialIssuer(secret));
}
