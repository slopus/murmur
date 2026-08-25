import { concatBytes, equalBytes, zeroBytes } from "../../utils/index.js";
import type { SchnorrProveOptions, SchnorrRelation, SchnorrVerifyOptions } from "../types.js";
import { decodeUint16, encodeUint16 } from "./codec.js";
import {
    addPoints,
    canonicalizeNonIdentityPoint,
    canonicalizePoint,
    identityPoint,
    multiplyPoint,
    subtractPoints,
} from "./point.js";
import {
    addScalars,
    decodeScalar,
    encodeScalar,
    hashToScalar,
    multiplyScalars,
    randomScalar,
} from "./scalar.js";
import { encodeTranscript } from "./transcript.js";

const PROOF_HEADER = new Uint8Array([0x4d, 0x53, 0x50, 0x01]);

interface DecodedProof {
    readonly commitments: readonly Uint8Array[];
    readonly responses: readonly Uint8Array[];
}

function validateRelation(relation: SchnorrRelation, witnessCount: number): void {
    canonicalizePoint(relation.target);
    if (relation.terms.length === 0 || relation.terms.length > 0xffff) {
        throw new Error("Schnorr relations require 1-65535 terms");
    }
    for (const term of relation.terms) {
        canonicalizeNonIdentityPoint(term.generator);
        if (
            !Number.isSafeInteger(term.witnessIndex) ||
            term.witnessIndex < 0 ||
            term.witnessIndex >= witnessCount
        ) {
            throw new Error("Schnorr witness index is out of range");
        }
    }
}

function evaluateRelation(relation: SchnorrRelation, scalars: readonly Uint8Array[]): Uint8Array {
    let result = identityPoint();
    for (const term of relation.terms) {
        const scalar = scalars[term.witnessIndex];
        if (scalar === undefined) {
            throw new Error("Missing Schnorr scalar");
        }
        result = addPoints(result, multiplyPoint(term.generator, scalar));
    }
    return result;
}

function encodeRelations(relations: readonly SchnorrRelation[], witnessCount: number): Uint8Array {
    const encoded: Uint8Array[] = [encodeUint16(witnessCount), encodeUint16(relations.length)];
    for (const relation of relations) {
        validateRelation(relation, witnessCount);
        encoded.push(canonicalizePoint(relation.target), encodeUint16(relation.terms.length));
        for (const term of relation.terms) {
            encoded.push(encodeUint16(term.witnessIndex), canonicalizePoint(term.generator));
        }
    }
    return concatBytes(...encoded);
}

function challengeFor(
    domain: string,
    statement: Uint8Array,
    relations: readonly SchnorrRelation[],
    witnessCount: number,
    commitments: readonly Uint8Array[],
    context: Uint8Array,
): Uint8Array {
    const transcript = encodeTranscript("murmur.math.generalized-schnorr.v1", [
        { label: "proof-domain", value: new TextEncoder().encode(domain) },
        { label: "statement", value: statement },
        { label: "relations", value: encodeRelations(relations, witnessCount) },
        { label: "commitments", value: concatBytes(...commitments.map(canonicalizePoint)) },
        { label: "external-context", value: context },
    ]);
    return hashToScalar("murmur.math.generalized-schnorr.challenge.v1", [transcript]);
}

/** Canonically serialize a generalized Schnorr proof. */
export function encodeSchnorrProof(
    commitments: readonly Uint8Array[],
    responses: readonly Uint8Array[],
): Uint8Array {
    if (commitments.length === 0 || commitments.length > 0xffff || responses.length > 0xffff) {
        throw new Error("Invalid Schnorr proof dimensions");
    }
    return concatBytes(
        PROOF_HEADER,
        encodeUint16(commitments.length),
        encodeUint16(responses.length),
        ...commitments.map(canonicalizePoint),
        ...responses.map((response) => encodeScalar(decodeScalar(response))),
    );
}

/** Strictly decode a generalized Schnorr proof. */
export function decodeSchnorrProof(
    proof: Uint8Array,
    expectedCommitments: number,
    expectedResponses: number,
): DecodedProof {
    if (proof.length < 8 || !equalBytes(proof.subarray(0, 4), PROOF_HEADER)) {
        throw new Error("Invalid Schnorr proof header");
    }
    const commitmentCount = decodeUint16(proof, 4);
    const responseCount = decodeUint16(proof, 6);
    if (commitmentCount !== expectedCommitments || responseCount !== expectedResponses) {
        throw new Error("Unexpected Schnorr proof dimensions");
    }
    const expectedLength = 8 + commitmentCount * 32 + responseCount * 32;
    if (proof.length !== expectedLength) {
        throw new Error("Invalid Schnorr proof length");
    }
    let offset = 8;
    const commitments: Uint8Array[] = [];
    for (let index = 0; index < commitmentCount; index += 1) {
        commitments.push(canonicalizePoint(proof.subarray(offset, offset + 32)));
        offset += 32;
    }
    const responses: Uint8Array[] = [];
    for (let index = 0; index < responseCount; index += 1) {
        const response = proof.subarray(offset, offset + 32);
        responses.push(encodeScalar(decodeScalar(response)));
        offset += 32;
    }
    return { commitments, responses };
}

/** Create a non-interactive generalized Schnorr proof. */
export function proveGeneralizedSchnorr(options: SchnorrProveOptions): Uint8Array {
    const witnessCount = options.witnesses.length;
    if (witnessCount === 0 || witnessCount > 0xffff || options.relations.length > 0xffff) {
        throw new Error("Invalid Schnorr proof dimensions");
    }
    const witnesses = options.witnesses.map((value) => encodeScalar(decodeScalar(value)));
    for (const relation of options.relations) {
        validateRelation(relation, witnessCount);
        if (
            !equalBytes(evaluateRelation(relation, witnesses), canonicalizePoint(relation.target))
        ) {
            throw new Error("Schnorr witness does not satisfy the statement");
        }
    }
    if (
        options.randomness !== undefined &&
        options.randomness.length !== options.witnesses.length
    ) {
        throw new Error("Schnorr randomness count must equal the witness count");
    }
    const randomness =
        options.randomness?.map((value) => encodeScalar(decodeScalar(value))) ??
        witnesses.map(() => randomScalar());
    try {
        const commitments = options.relations.map((relation) =>
            evaluateRelation(relation, randomness),
        );
        const challenge = challengeFor(
            options.domain,
            options.statement,
            options.relations,
            witnessCount,
            commitments,
            options.context,
        );
        const responses = witnesses.map((witness, index) => {
            const nonce = randomness[index];
            if (nonce === undefined) throw new Error("Missing Schnorr randomness");
            return addScalars(nonce, multiplyScalars(challenge, witness));
        });
        return encodeSchnorrProof(commitments, responses);
    } finally {
        for (const value of randomness) zeroBytes(value);
        for (const value of witnesses) zeroBytes(value);
    }
}

/** Verify a generalized Schnorr proof using constant-time encoded-point comparisons. */
export function verifyGeneralizedSchnorr(options: SchnorrVerifyOptions): boolean {
    try {
        if (
            !Number.isSafeInteger(options.witnessCount) ||
            options.witnessCount <= 0 ||
            options.witnessCount > 0xffff
        ) {
            return false;
        }
        for (const relation of options.relations) {
            validateRelation(relation, options.witnessCount);
        }
        const decoded = decodeSchnorrProof(
            options.proof,
            options.relations.length,
            options.witnessCount,
        );
        const challenge = challengeFor(
            options.domain,
            options.statement,
            options.relations,
            options.witnessCount,
            decoded.commitments,
            options.context,
        );
        for (let index = 0; index < options.relations.length; index += 1) {
            const relation = options.relations[index];
            const commitment = decoded.commitments[index];
            if (relation === undefined || commitment === undefined) return false;
            const left = evaluateRelation(relation, decoded.responses);
            const right = addPoints(commitment, multiplyPoint(relation.target, challenge));
            if (!equalBytes(left, right)) return false;
        }
        return true;
    } catch {
        return false;
    }
}

/** Reconstruct the first-round commitment implied by a response and challenge. */
export function reconstructSchnorrCommitment(
    relation: SchnorrRelation,
    responses: readonly Uint8Array[],
    challenge: Uint8Array,
): Uint8Array {
    return subtractPoints(
        evaluateRelation(relation, responses),
        multiplyPoint(relation.target, challenge),
    );
}
