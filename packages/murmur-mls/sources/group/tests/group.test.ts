import { equalBytes, generateIdentityKeyPair, utf8Decode, utf8Encode } from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import { createMlsTreeEpochFromWelcome, MlsEpochState } from "../../epoch/index.js";
import { authenticateMurmurMlsCredential, createMlsGroup } from "../index.js";
import { createMlsKeyPackage, destroyMlsKeyPackageBundle } from "../../keyPackage/index.js";
import { openMlsWelcome } from "../../welcome/index.js";

describe("RFC 9420 group creation", () => {
    it("creates epoch zero and adds the first remote member", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const groupId = utf8Encode("deterministic initial group");
        const epochSecret = new Uint8Array(32).fill(7);
        const aliceEpoch = createMlsGroup(alice, {
            groupId,
            epochSecret,
        });
        const initialState = aliceEpoch.serialize();

        expect(aliceEpoch.context.groupId).toEqual(groupId);
        expect(aliceEpoch.context.epoch).toBe(0n);
        expect(aliceEpoch.context.confirmedTranscriptHash).toHaveLength(0);
        expect(epochSecret).toEqual(new Uint8Array(32).fill(7));
        const restoredInitial = MlsEpochState.deserialize(initialState, {
            localSigningSecretKey: alice.signingSecretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            minimumPersistenceGeneration: 0n,
        });
        restoredInitial.destroy();

        const bobBundle = createMlsKeyPackage(bob);
        const prepared = aliceEpoch.prepareCommit([
            { type: "add", keyPackage: bobBundle.keyPackage },
        ]);
        const opened = openMlsWelcome({
            welcome: prepared.welcome!,
            keyPackageBundle: bobBundle,
            expectedGroupId: groupId,
            validateExternalTree: (groupInfo) =>
                equalBytes(groupInfo.context.treeHash, prepared.tree.treeHash())
                    ? alice.signingKey
                    : undefined,
        });
        const bobEpoch = createMlsTreeEpochFromWelcome({
            opened,
            tree: prepared.tree,
            localLeaf: prepared.addedLeaves[0]!,
            leafKeyPair: bobBundle.leafKeyPair,
            localSigningSecretKey: bob.signingSecretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
        });
        const aliceNext = prepared.transition.commit();

        expect(aliceNext.context.epoch).toBe(1n);
        expect(aliceNext.context.confirmedTranscriptHash).toHaveLength(32);
        expect(
            utf8Decode(
                bobEpoch.open(aliceNext.seal(utf8Encode("hello from the first Commit")))
                    .applicationData,
            ),
        ).toBe("hello from the first Commit");

        aliceNext.destroy();
        bobEpoch.destroy();
        destroyMlsKeyPackageBundle(bobBundle);
    });
});
