import { describe, expect, it } from "vitest";
import {
    createCredentialIssuanceRequest,
    decodeCredentialIssuanceRequest,
    decodePrivateGroupPublicParameters,
    deriveCredentialIssuer,
    derivePrivateGroupParameters,
    encodeCredentialIssuanceRequest,
    encodePrivateGroupPublicParameters,
    privateGroupPublicParameters,
} from "../../index.js";
import { utf8Encode } from "../../../utils/index.js";

function bytes(seed: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 9) & 0xff);
}

describe("private-group canonical codecs", () => {
    it("rejects trailing data and non-canonical point encodings", () => {
        const issuer = deriveCredentialIssuer(bytes(1));
        const state = createCredentialIssuanceRequest(
            bytes(2),
            issuer.publicParameters,
            utf8Encode("codec test"),
        );
        const request = encodeCredentialIssuanceRequest(state.request);
        const trailing = new Uint8Array(request.length + 1);
        trailing.set(request);
        expect(() => decodeCredentialIssuanceRequest(trailing)).toThrow();

        const malformed = request.slice();
        malformed.fill(0xff, 4, 36);
        expect(() => decodeCredentialIssuanceRequest(malformed)).toThrow();
    });

    it("round-trips only the service-visible group parameter subset", () => {
        const privateParameters = derivePrivateGroupParameters(bytes(3));
        const publicParameters = privateGroupPublicParameters(privateParameters);
        const encoded = encodePrivateGroupPublicParameters(publicParameters);
        expect(decodePrivateGroupPublicParameters(encoded)).toEqual(publicParameters);
        expect(
            containsSequence(encoded, privateParameters.encryptionParams.keyPair.secretKey),
        ).toBe(false);
        expect(containsSequence(encoded, privateParameters.metadataKeys.encryptionKey)).toBe(false);
    });
});

function containsSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
    for (let offset = 0; offset + needle.length <= haystack.length; offset += 1) {
        let matches = true;
        for (let index = 0; index < needle.length; index += 1) {
            matches &&= haystack[offset + index] === needle[index];
        }
        if (matches) return true;
    }
    return false;
}
