import {
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
} from "../../internal.js";
import { describe, expect, it } from "vitest";
import { createMlsTreeEpochFromWelcome, MlsEpochState } from "../index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    type MlsKeyPackageBundle,
} from "../../keyPackage/index.js";
import { deriveMlsEpochSecretsFromJoiner } from "../../keySchedule/index.js";
import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import { MlsRatchetTree, type MlsRatchetTreeLeaf } from "../../ratchetTree/index.js";
import { openMlsWelcome } from "../../welcome/index.js";

function treeLeaf(bundle: MlsKeyPackageBundle): MlsRatchetTreeLeaf {
    const keyPackageLeaf = bundle.keyPackage.leafNode;
    const leaf: MlsLeafNode = {
        encryptionKey: keyPackageLeaf.encryptionKey,
        signatureKey: keyPackageLeaf.signatureKey,
        credential: keyPackageLeaf.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: keyPackageLeaf.notBefore,
        notAfter: keyPackageLeaf.notAfter,
        extensions: [],
        signature: keyPackageLeaf.signature,
    };
    return {
        type: "leaf",
        encoded: encodeMlsLeafNode(leaf),
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
    };
}

function authenticateCredential(leaf: MlsLeafNode): boolean {
    return equalBytes(leaf.credential.identity, leaf.signatureKey);
}

function copyLeafPrivateKey(leaf: number, bundle: MlsKeyPackageBundle) {
    return {
        node: leaf * 2,
        keyPair: {
            secretKey: bundle.leafKeyPair.secretKey.slice(),
            publicKey: bundle.leafKeyPair.publicKey.slice(),
        },
    };
}

describe("MLS TreeKEM epoch application state", () => {
    it("owns durable state across Remove, Add, Welcome, and application ratchets", () => {
        const identities = Array.from({ length: 4 }, generateIdentityKeyPair);
        const bundles = identities.map((identity) => createMlsKeyPackage(identity));
        const tree = new MlsRatchetTree([
            treeLeaf(bundles[0]!),
            undefined,
            treeLeaf(bundles[1]!),
            undefined,
            treeLeaf(bundles[2]!),
            undefined,
            undefined,
        ]);
        const currentContext: MlsGroupContext = {
            groupId: utf8Encode("integrated TreeKEM epoch"),
            epoch: 7n,
            treeHash: tree.treeHash(),
            confirmedTranscriptHash: hashBytes(utf8Encode("confirmed")),
        };
        const interimTranscriptHash = hashBytes(utf8Encode("interim"));
        const joinerSecret = hashBytes(utf8Encode("shared current joiner"));
        const createCurrent = (localLeaf: number): MlsEpochState =>
            new MlsEpochState({
                context: currentContext,
                secrets: deriveMlsEpochSecretsFromJoiner(
                    joinerSecret,
                    encodeMlsGroupContext(currentContext),
                ),
                tree,
                privateKeys: [copyLeafPrivateKey(localLeaf, bundles[localLeaf]!)],
                localLeaf,
                localSigningSecretKey: identities[localLeaf]!.secretKey,
                authenticateCredential,
                interimTranscriptHash,
            });
        const aliceCurrent = createCurrent(0);
        const bobCurrent = createCurrent(1);
        const carolCurrent = createCurrent(2);

        const prepared = aliceCurrent.prepareCommit([
            { type: "remove", removed: 1 },
            { type: "add", keyPackage: bundles[3]!.keyPackage },
        ]);
        expect(() => aliceCurrent.serialize()).toThrow("pending transition");
        expect(() => aliceCurrent.open(new Uint8Array())).toThrow("pending transition");
        const stagedCheckpoint = prepared.transition.serialize();
        const restoredStaged = MlsEpochState.deserialize(stagedCheckpoint, {
            localSigningSecretKey: identities[0]!.secretKey,
            authenticateCredential,
            minimumPersistenceGeneration: prepared.transition.persistenceGeneration,
        });
        expect(restoredStaged.context.epoch).toBe(currentContext.epoch + 1n);
        const stagedGeneration = restoredStaged.persistenceGeneration;
        restoredStaged.rebasePersistenceGeneration(stagedGeneration + 7n);
        expect(restoredStaged.persistenceGeneration).toBe(stagedGeneration + 7n);
        expect(() => restoredStaged.rebasePersistenceGeneration(stagedGeneration)).toThrow(
            "generation rebase",
        );
        const rebasedCheckpoint = restoredStaged.serialize();
        const rebasedStaged = MlsEpochState.deserialize(rebasedCheckpoint, {
            localSigningSecretKey: identities[0]!.secretKey,
            authenticateCredential,
            minimumPersistenceGeneration: stagedGeneration + 7n,
        });
        expect(rebasedStaged.context.epoch).toBe(currentContext.epoch + 1n);
        expect(rebasedStaged.persistenceGeneration).toBe(stagedGeneration + 7n);
        rebasedStaged.destroy();
        rebasedCheckpoint.fill(0);
        restoredStaged.destroy();
        expect(prepared.removedLeaves).toEqual([1]);
        expect(prepared.addedLeaves).toEqual([1]);
        expect(prepared.welcome).toBeDefined();
        const carolTransition = carolCurrent.applyCommit(prepared.commit);
        expect(() => bobCurrent.applyCommit(prepared.commit)).toThrow("removed");

        const joined = openMlsWelcome({
            welcome: prepared.welcome!,
            keyPackageBundle: bundles[3]!,
            expectedGroupId: currentContext.groupId,
            validateExternalTree: (groupInfo) =>
                equalBytes(groupInfo.context.treeHash, prepared.tree.treeHash())
                    ? identities[0]!.publicKey
                    : undefined,
        });
        const daveNext = createMlsTreeEpochFromWelcome({
            opened: joined,
            tree: prepared.tree,
            localLeaf: prepared.addedLeaves[0]!,
            leafKeyPair: bundles[3]!.leafKeyPair,
            localSigningSecretKey: identities[3]!.secretKey,
            authenticateCredential,
        });
        const aliceNext = prepared.transition.commit();
        const carolNext = carolTransition.commit();

        expect(
            utf8Decode(carolNext.open(aliceNext.seal(utf8Encode("retained"))).applicationData),
        ).toBe("retained");
        expect(
            utf8Decode(daveNext.open(carolNext.seal(utf8Encode("welcomed"))).applicationData),
        ).toBe("welcomed");
        expect(
            utf8Decode(aliceNext.open(daveNext.seal(utf8Encode("joined"))).applicationData),
        ).toBe("joined");

        const persistedAlice = aliceNext.serialize();
        const restoredAlice = MlsEpochState.deserialize(persistedAlice, {
            localSigningSecretKey: identities[0]!.secretKey,
            authenticateCredential,
            minimumPersistenceGeneration: aliceNext.persistenceGeneration,
        });
        aliceNext.destroy();
        expect(
            utf8Decode(
                carolNext.open(restoredAlice.seal(utf8Encode("persisted TreeKEM"))).applicationData,
            ),
        ).toBe("persisted TreeKEM");
        const stagedRemoval = restoredAlice.prepareCommit([
            { type: "remove", removed: prepared.addedLeaves[0]! },
        ]);
        stagedRemoval.transition.cancel();

        bobCurrent.destroy();
        restoredAlice.destroy();
        carolNext.destroy();
        daveNext.destroy();
        for (const bundle of bundles) {
            destroyMlsKeyPackageBundle(bundle);
        }
    });
});
