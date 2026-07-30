import { hashBytes, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import {
    createMlsConfirmationTag,
    decodeMlsGroupContext,
    encodeMlsGroupContext,
    equalMlsGroupContext,
    initializeConfirmedTranscriptHash,
    updateConfirmedTranscriptHash,
    updateInterimTranscriptHash,
    verifyMlsConfirmationTag,
    type MlsGroupContext,
} from "../index.js";

describe("MLS GroupContext and transcripts", () => {
    it("round trips the extension-free RFC structure", () => {
        const context: MlsGroupContext = {
            groupId: utf8Encode("group"),
            epoch: 42n,
            treeHash: hashBytes(utf8Encode("tree")),
            confirmedTranscriptHash: hashBytes(utf8Encode("transcript")),
        };

        const encoded = encodeMlsGroupContext(context);
        const decoded = decodeMlsGroupContext(encoded);

        expect(encoded.slice(0, 4)).toEqual(Uint8Array.of(0, 1, 0, 1));
        expect(equalMlsGroupContext(decoded, context)).toBe(true);
        const unsupportedVersion = encoded.slice();
        unsupportedVersion[1] = 2;
        expect(() => decodeMlsGroupContext(unsupportedVersion)).toThrow("profile");
    });

    it("updates transcript hashes and authenticates confirmation", () => {
        const interim = hashBytes(utf8Encode("interim"));
        const commitInput = utf8Encode("commit input");
        const confirmed = updateConfirmedTranscriptHash(interim, commitInput);
        const key = hashBytes(utf8Encode("confirmation key"));
        const tag = createMlsConfirmationTag(key, confirmed);

        expect(verifyMlsConfirmationTag(key, confirmed, tag)).toBe(true);
        expect(verifyMlsConfirmationTag(key, hashBytes(confirmed), tag)).toBe(false);
        expect(updateInterimTranscriptHash(confirmed, tag)).toHaveLength(32);
        expect(initializeConfirmedTranscriptHash(commitInput)).toEqual(hashBytes(commitInput));
    });

    it("encodes the RFC epoch-zero empty transcript", () => {
        const initial: MlsGroupContext = {
            groupId: utf8Encode("new group"),
            epoch: 0n,
            treeHash: hashBytes(utf8Encode("initial tree")),
            confirmedTranscriptHash: new Uint8Array(),
        };
        const confirmationKey = hashBytes(utf8Encode("initial confirmation"));
        const tag = createMlsConfirmationTag(confirmationKey, initial.confirmedTranscriptHash);

        expect(decodeMlsGroupContext(encodeMlsGroupContext(initial))).toEqual(initial);
        expect(updateInterimTranscriptHash(initial.confirmedTranscriptHash, tag)).toHaveLength(32);
        expect(
            verifyMlsConfirmationTag(confirmationKey, initial.confirmedTranscriptHash, tag),
        ).toBe(true);
        expect(() =>
            encodeMlsGroupContext({
                ...initial,
                confirmedTranscriptHash: new Uint8Array(1),
            }),
        ).toThrow("GroupContext");
        expect(() =>
            decodeMlsGroupContext(
                encodeMlsGroupContext({
                    ...initial,
                    epoch: 1n,
                }),
            ),
        ).toThrow("final");
    });
});
