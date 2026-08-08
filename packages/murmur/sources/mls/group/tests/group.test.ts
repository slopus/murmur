import { equalBytes, generateIdentityKeyPair, utf8Decode, utf8Encode } from "../../internal.js";
import { describe, expect, it } from "vitest";
import { decodeMlsTreeCommit } from "../../commit/index.js";
import { createMlsTreeEpochFromWelcome, MlsEpochState } from "../../epoch/index.js";
import {
    authenticateMurmurMlsCredential,
    createMlsGroup,
    joinMlsGroupFromWelcome,
} from "../index.js";
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
            localSigningSecretKey: alice.secretKey,
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
                    ? alice.publicKey
                    : undefined,
        });
        const bobEpoch = createMlsTreeEpochFromWelcome({
            opened,
            tree: prepared.tree,
            localLeaf: prepared.addedLeaves[0]!,
            leafKeyPair: bobBundle.leafKeyPair,
            localSigningSecretKey: bob.secretKey,
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

    it("rejects a Welcome from a competing Add before adopting the retained branch", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const initial = createMlsGroup(alice);
        const checkpoint = initial.serialize();
        const restore = (): MlsEpochState =>
            MlsEpochState.deserialize(checkpoint, {
                localSigningSecretKey: alice.secretKey,
                authenticateCredential: authenticateMurmurMlsCredential,
                minimumPersistenceGeneration: initial.persistenceGeneration,
            });
        const branchA = restore();
        const branchB = restore();
        const bobBundle = createMlsKeyPackage(bob);
        const addA = branchA.prepareCommit([{ type: "add", keyPackage: bobBundle.keyPackage }]);
        const addB = branchB.prepareCommit([{ type: "add", keyPackage: bobBundle.keyPackage }]);
        const commitA = decodeMlsTreeCommit(addA.commit);
        const commitB = decodeMlsTreeCommit(addB.commit);

        expect(() =>
            joinMlsGroupFromWelcome({
                identity: bob,
                inviter: { publicKey: alice.publicKey },
                groupId: initial.context.groupId,
                welcome: addA.welcome!,
                tree: addA.tree,
                keyPackageBundle: bobBundle,
                expectedCommitConfirmationTag: commitB.confirmationTag,
            }),
        ).toThrow("does not match the retained Commit");

        const joinedB = joinMlsGroupFromWelcome({
            identity: bob,
            inviter: { publicKey: alice.publicKey },
            groupId: initial.context.groupId,
            welcome: addB.welcome!,
            tree: addB.tree,
            keyPackageBundle: bobBundle,
            expectedCommitConfirmationTag: commitB.confirmationTag,
        });
        const winningB = addB.transition.commit();
        expect(
            utf8Decode(joinedB.open(winningB.seal(utf8Encode("retained branch"))).applicationData),
        ).toBe("retained branch");

        addA.transition.cancel();
        initial.destroy();
        branchA.destroy();
        branchB.destroy();
        winningB.destroy();
        joinedB.destroy();
        destroyMlsKeyPackageBundle(bobBundle);
        expect(commitA.confirmationTag).not.toEqual(commitB.confirmationTag);
    });

    it("adds, serializes, and contracts one group through 4, 5, 6, and 8 members", () => {
        const identities = Array.from({ length: 8 }, generateIdentityKeyPair);
        const bundles = identities.map((identity) => createMlsKeyPackage(identity));
        let current = createMlsGroup(identities[0]!);

        for (let memberCount = 2; memberCount <= 8; memberCount += 1) {
            const prepared = current.prepareCommit([
                { type: "add", keyPackage: bundles[memberCount - 1]!.keyPackage },
            ]);
            expect(Object.keys(prepared.tree.nodes)).toHaveLength(prepared.tree.nodes.length);
            const next = prepared.transition.commit();
            if ([4, 5, 6, 8].includes(memberCount)) {
                const checkpoint = next.serialize();
                const restored = MlsEpochState.deserialize(checkpoint, {
                    localSigningSecretKey: identities[0]!.secretKey,
                    authenticateCredential: authenticateMurmurMlsCredential,
                    minimumPersistenceGeneration: next.persistenceGeneration,
                });
                expect(restored.memberSignatureKeys.filter(Boolean)).toHaveLength(memberCount);
                restored.destroy();
            }
            current = next;
        }

        for (let removed = 7; removed >= 4; removed -= 1) {
            const prepared = current.prepareCommit([{ type: "remove", removed }]);
            const next = prepared.transition.commit();
            const checkpoint = next.serialize();
            const restored = MlsEpochState.deserialize(checkpoint, {
                localSigningSecretKey: identities[0]!.secretKey,
                authenticateCredential: authenticateMurmurMlsCredential,
                minimumPersistenceGeneration: next.persistenceGeneration,
            });
            restored.destroy();
            current = next;
        }
        expect(current.memberSignatureKeys.filter(Boolean)).toHaveLength(4);

        current.destroy();
        for (const bundle of bundles) {
            destroyMlsKeyPackageBundle(bundle);
        }
    }, 30_000);
});
