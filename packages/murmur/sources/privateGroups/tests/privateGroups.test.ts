import { describe, expect, it } from "vitest";
import { addPoints, basePoint, multiplyPoint } from "../../math/index.js";
import { equalBytes, utf8Encode } from "../../utils/index.js";
import {
    accountIdentifierScalar,
    createCredentialIssuanceRequest,
    createEncryptedUid,
    createUidPresentation,
    decodeAccountCredential,
    decodeCredentialIssuanceRequest,
    decodeCredentialIssuanceResponse,
    decodeCredentialIssuerPublicParameters,
    decodeEncryptedUid,
    decodePrivateGroupPublicParameters,
    decodeUidPresentation,
    decryptEncryptedUid,
    deriveCredentialIssuer,
    derivePrivateGroupParameters,
    encodeAccountCredential,
    encodeCredentialIssuanceRequest,
    encodeCredentialIssuanceResponse,
    encodeCredentialIssuerPublicParameters,
    encodeEncryptedUid,
    encodePrivateGroupPublicParameters,
    encodeUidPresentation,
    equalEncryptedUids,
    finalizeCredentialIssuance,
    isEncryptedUidForAccount,
    issueCredential,
    privateGroupPublicParameters,
    verifyAccountCredential,
    verifyUidPresentation,
    type AccountCredential,
    type CredentialIssuanceState,
    type CredentialIssuer,
    type EncryptedUid,
    type PrivateGroupParameters,
} from "../index.js";

const NOW = 1_800_000_000_000;
const EXPIRES_AT = NOW + 5 * 60_000;
const ISSUANCE_CONTEXT = utf8Encode("authenticated session 72 / credential issue");
const PRESENTATION_CONTEXT = utf8Encode("PATCH revision 18 / entry member");

interface Fixture {
    readonly accountIdentifier: Uint8Array;
    readonly otherAccountIdentifier: Uint8Array;
    readonly issuer: CredentialIssuer;
    readonly groupA: PrivateGroupParameters;
    readonly groupB: PrivateGroupParameters;
    readonly state: CredentialIssuanceState;
    readonly credential: AccountCredential;
    readonly encryptedUid: EncryptedUid;
}

function bytes(seed: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 17) & 0xff);
}

function fixture(): Fixture {
    const accountIdentifier = bytes(11);
    const issuer = deriveCredentialIssuer(bytes(91));
    const groupA = derivePrivateGroupParameters(bytes(101));
    const groupB = derivePrivateGroupParameters(bytes(102));
    const state = createCredentialIssuanceRequest(
        accountIdentifier,
        issuer.publicParameters,
        ISSUANCE_CONTEXT,
    );
    const request = decodeCredentialIssuanceRequest(encodeCredentialIssuanceRequest(state.request));
    const response = issueCredential({
        issuer,
        accountIdentifier,
        request,
        expiresAt: EXPIRES_AT,
        now: NOW,
        context: ISSUANCE_CONTEXT,
    });
    const decodedResponse = decodeCredentialIssuanceResponse(
        encodeCredentialIssuanceResponse(response),
    );
    const credential = finalizeCredentialIssuance({
        state,
        response: decodedResponse,
        accountIdentifier,
        parameters: issuer.publicParameters,
        context: ISSUANCE_CONTEXT,
    });
    return {
        accountIdentifier,
        otherAccountIdentifier: bytes(12),
        issuer,
        groupA,
        groupB,
        state,
        credential,
        encryptedUid: createEncryptedUid(accountIdentifier, groupA),
    };
}

describe("private-group encrypted UIDs and credentials", () => {
    it("blind-issues, validates, serializes, and unblinds an account credential", () => {
        const value = fixture();
        expect(
            verifyAccountCredential(value.credential, value.accountIdentifier, value.issuer),
        ).toBe(true);
        expect(
            verifyAccountCredential(value.credential, value.otherAccountIdentifier, value.issuer),
        ).toBe(false);
        expect(decodeAccountCredential(encodeAccountCredential(value.credential))).toEqual(
            value.credential,
        );
        expect(
            decodeCredentialIssuerPublicParameters(
                encodeCredentialIssuerPublicParameters(value.issuer.publicParameters),
            ),
        ).toEqual(value.issuer.publicParameters);
    });

    it("constructs one deterministic UID per account/group and decrypts its message", () => {
        const value = fixture();
        const duplicate = createEncryptedUid(value.accountIdentifier, value.groupA);
        const otherGroup = createEncryptedUid(value.accountIdentifier, value.groupB);
        expect(equalEncryptedUids(value.encryptedUid, duplicate)).toBe(true);
        expect(equalEncryptedUids(value.encryptedUid, otherGroup)).toBe(false);
        expect(
            isEncryptedUidForAccount(value.encryptedUid, value.accountIdentifier, value.groupA),
        ).toBe(true);
        expect(
            isEncryptedUidForAccount(
                value.encryptedUid,
                value.otherAccountIdentifier,
                value.groupA,
            ),
        ).toBe(false);
        const expectedPoint = multiplyPoint(
            value.groupA.publicProofParams.messageGenerator,
            accountIdentifierScalar(value.accountIdentifier),
        );
        expect(decryptEncryptedUid(value.encryptedUid, value.groupA)).toEqual(expectedPoint);
        expect(decodeEncryptedUid(encodeEncryptedUid(value.encryptedUid))).toEqual(
            value.encryptedUid,
        );
    });

    it("creates unlinkable randomized presentations for the same credential and entry", () => {
        const value = fixture();
        const replayNonce = bytes(201);
        const first = createUidPresentation({
            credential: value.credential,
            accountIdentifier: value.accountIdentifier,
            encryptedUid: value.encryptedUid,
            group: value.groupA,
            issuer: value.issuer.publicParameters,
            replayNonce,
            context: PRESENTATION_CONTEXT,
            now: NOW,
        });
        const second = createUidPresentation({
            credential: value.credential,
            accountIdentifier: value.accountIdentifier,
            encryptedUid: value.encryptedUid,
            group: value.groupA,
            issuer: value.issuer.publicParameters,
            replayNonce,
            context: PRESENTATION_CONTEXT,
            now: NOW,
        });
        const publicGroup = privateGroupPublicParameters(value.groupA);
        expect(equalBytes(encodeUidPresentation(first), encodeUidPresentation(second))).toBe(false);
        expect(
            verifyUidPresentation({
                presentation: first,
                encryptedUid: value.encryptedUid,
                group: publicGroup,
                issuer: value.issuer,
                expectedReplayNonce: replayNonce,
                context: PRESENTATION_CONTEXT,
                now: NOW,
            }),
        ).toBe(true);
        expect(
            verifyUidPresentation({
                presentation: second,
                encryptedUid: value.encryptedUid,
                group: publicGroup,
                issuer: value.issuer,
                expectedReplayNonce: replayNonce,
                context: PRESENTATION_CONTEXT,
                now: NOW,
            }),
        ).toBe(true);
        expect(decodeUidPresentation(encodeUidPresentation(first))).toEqual(first);
        expect(
            decodePrivateGroupPublicParameters(encodePrivateGroupPublicParameters(publicGroup)),
        ).toEqual(publicGroup);
    });

    it("rejects wrong-group, cross-group UID, expiry, replay, and context attacks", () => {
        const value = fixture();
        const replayNonce = bytes(210);
        const presentation = createUidPresentation({
            credential: value.credential,
            accountIdentifier: value.accountIdentifier,
            encryptedUid: value.encryptedUid,
            group: value.groupA,
            issuer: value.issuer.publicParameters,
            replayNonce,
            context: PRESENTATION_CONTEXT,
            now: NOW,
        });
        const verify = (overrides: {
            readonly group?: ReturnType<typeof privateGroupPublicParameters>;
            readonly encryptedUid?: EncryptedUid;
            readonly expectedReplayNonce?: Uint8Array;
            readonly context?: Uint8Array;
            readonly now?: number;
        }): boolean =>
            verifyUidPresentation({
                presentation,
                encryptedUid: overrides.encryptedUid ?? value.encryptedUid,
                group: overrides.group ?? privateGroupPublicParameters(value.groupA),
                issuer: value.issuer,
                expectedReplayNonce: overrides.expectedReplayNonce ?? replayNonce,
                context: overrides.context ?? PRESENTATION_CONTEXT,
                now: overrides.now ?? NOW,
            });

        expect(verify({ group: privateGroupPublicParameters(value.groupB) })).toBe(false);
        expect(
            verify({
                encryptedUid: createEncryptedUid(value.accountIdentifier, value.groupB),
            }),
        ).toBe(false);
        expect(verify({ now: EXPIRES_AT })).toBe(false);
        expect(verify({ expectedReplayNonce: bytes(211) })).toBe(false);
        expect(verify({ context: utf8Encode("GET revision 18") })).toBe(false);
    });

    it("rejects blind-request substitution and tampered issuance proofs", () => {
        const value = fixture();
        expect(() =>
            issueCredential({
                issuer: value.issuer,
                accountIdentifier: value.otherAccountIdentifier,
                request: value.state.request,
                expiresAt: EXPIRES_AT,
                now: NOW,
                context: ISSUANCE_CONTEXT,
            }),
        ).toThrow("Invalid blind credential request");

        const response = issueCredential({
            issuer: value.issuer,
            accountIdentifier: value.accountIdentifier,
            request: value.state.request,
            expiresAt: EXPIRES_AT,
            now: NOW,
            context: ISSUANCE_CONTEXT,
        });
        const proof = response.proof.slice();
        proof[8] = (proof[8] ?? 0) ^ 4;
        expect(() =>
            finalizeCredentialIssuance({
                state: value.state,
                response: { ...response, proof },
                accountIdentifier: value.accountIdentifier,
                parameters: value.issuer.publicParameters,
                context: ISSUANCE_CONTEXT,
            }),
        ).toThrow("Credential issuer proof is invalid");
    });

    it("rejects forged MACs, tampered presentation commitments, and expired credentials", () => {
        const value = fixture();
        const replayNonce = bytes(220);
        const forgedCredential: AccountCredential = {
            ...value.credential,
            mac: {
                ...value.credential.mac,
                v: addPoints(value.credential.mac.v, basePoint()),
            },
        };
        const forgedPresentation = createUidPresentation({
            credential: forgedCredential,
            accountIdentifier: value.accountIdentifier,
            encryptedUid: value.encryptedUid,
            group: value.groupA,
            issuer: value.issuer.publicParameters,
            replayNonce,
            context: PRESENTATION_CONTEXT,
            now: NOW,
        });
        expect(
            verifyUidPresentation({
                presentation: forgedPresentation,
                encryptedUid: value.encryptedUid,
                group: privateGroupPublicParameters(value.groupA),
                issuer: value.issuer,
                expectedReplayNonce: replayNonce,
                context: PRESENTATION_CONTEXT,
                now: NOW,
            }),
        ).toBe(false);

        const valid = createUidPresentation({
            credential: value.credential,
            accountIdentifier: value.accountIdentifier,
            encryptedUid: value.encryptedUid,
            group: value.groupA,
            issuer: value.issuer.publicParameters,
            replayNonce,
            context: PRESENTATION_CONTEXT,
            now: NOW,
        });
        const tamperedProof = valid.proof.slice();
        tamperedProof[8] = (tamperedProof[8] ?? 0) ^ 8;
        expect(
            verifyUidPresentation({
                presentation: { ...valid, proof: tamperedProof },
                encryptedUid: value.encryptedUid,
                group: privateGroupPublicParameters(value.groupA),
                issuer: value.issuer,
                expectedReplayNonce: replayNonce,
                context: PRESENTATION_CONTEXT,
                now: NOW,
            }),
        ).toBe(false);
        expect(() =>
            createUidPresentation({
                credential: value.credential,
                accountIdentifier: value.accountIdentifier,
                encryptedUid: value.encryptedUid,
                group: value.groupA,
                issuer: value.issuer.publicParameters,
                replayNonce,
                context: PRESENTATION_CONTEXT,
                now: EXPIRES_AT,
            }),
        ).toThrow("expired credential");
    });
});
