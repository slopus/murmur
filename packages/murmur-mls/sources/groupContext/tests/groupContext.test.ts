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
});
