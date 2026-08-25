import { describe, expect, it } from "vitest";
import {
    addPoints,
    addScalars,
    basePoint,
    decodeSchnorrProof,
    encodeSchnorrProof,
    hashToPoint,
    hashToScalar,
    multiplyBase,
    proveGeneralizedSchnorr,
    verifyGeneralizedSchnorr,
    RISTRETTO_ORDER,
    type SchnorrRelation,
} from "../../index.js";
import { utf8Encode } from "../../../utils/index.js";

function fixture(): {
    readonly relation: SchnorrRelation;
    readonly context: Uint8Array;
    readonly proof: Uint8Array;
} {
    const witness = hashToScalar("murmur.math.schnorr.test", [utf8Encode("witness")], true);
    const context = hashToPoint("murmur.math.schnorr.test", [utf8Encode("context")]);
    const relation: SchnorrRelation = {
        target: multiplyBase(witness),
        terms: [{ generator: basePoint(), witnessIndex: 0 }],
    };
    const proof = proveGeneralizedSchnorr({
        domain: "murmur.math.schnorr.test-proof.v1",
        statement: utf8Encode("T = G * x"),
        relations: [relation],
        witnesses: [witness],
        context,
    });
    return { relation, context, proof };
}

describe("generalized Schnorr transcript", () => {
    it("proves knowledge and binds domain, statement, generators, and context", () => {
        const { relation, context, proof } = fixture();
        const verify = (
            domain: string,
            selectedContext: Uint8Array,
            selected = relation,
        ): boolean =>
            verifyGeneralizedSchnorr({
                domain,
                statement: utf8Encode("T = G * x"),
                relations: [selected],
                witnessCount: 1,
                context: selectedContext,
                proof,
            });
        expect(verify("murmur.math.schnorr.test-proof.v1", context)).toBe(true);
        expect(verify("murmur.math.schnorr.other-domain.v1", context)).toBe(false);
        expect(verify("murmur.math.schnorr.test-proof.v1", new Uint8Array(32))).toBe(false);
        expect(
            verify("murmur.math.schnorr.test-proof.v1", context, {
                ...relation,
                terms: [{ generator: context, witnessIndex: 0 }],
            }),
        ).toBe(false);
    });

    it("rejects the malleation that succeeds when Fiat-Shamir omits commitments", () => {
        const { relation, context, proof } = fixture();
        const decoded = decodeSchnorrProof(proof, 1, 1);
        const delta = hashToScalar("murmur.math.schnorr.test", [utf8Encode("delta")], true);
        const commitment = decoded.commitments[0];
        const response = decoded.responses[0];
        expect(commitment).toBeDefined();
        expect(response).toBeDefined();
        const malleated = encodeSchnorrProof(
            [addPoints(commitment!, multiplyBase(delta))],
            [addScalars(response!, delta)],
        );
        expect(
            verifyGeneralizedSchnorr({
                domain: "murmur.math.schnorr.test-proof.v1",
                statement: utf8Encode("T = G * x"),
                relations: [relation],
                witnessCount: 1,
                context,
                proof: malleated,
            }),
        ).toBe(false);
    });

    it("rejects tampered commitments, forgeries, and non-canonical responses", () => {
        const { relation, context, proof } = fixture();
        const tampered = proof.slice();
        tampered[8] = (tampered[8] ?? 0) ^ 2;
        const verify = (candidate: Uint8Array): boolean =>
            verifyGeneralizedSchnorr({
                domain: "murmur.math.schnorr.test-proof.v1",
                statement: utf8Encode("T = G * x"),
                relations: [relation],
                witnessCount: 1,
                context,
                proof: candidate,
            });
        expect(verify(tampered)).toBe(false);
        expect(
            verify(
                encodeSchnorrProof(
                    [multiplyBase(hashToScalar("murmur.math.forgery", [context], true))],
                    [new Uint8Array(32)],
                ),
            ),
        ).toBe(false);

        const nonCanonical = proof.slice();
        nonCanonical.set(littleEndian(RISTRETTO_ORDER), 40);
        expect(verify(nonCanonical)).toBe(false);
    });
});

function littleEndian(value: bigint): Uint8Array {
    const result = new Uint8Array(32);
    let remaining = value;
    for (let index = 0; index < result.length; index += 1) {
        result[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return result;
}
