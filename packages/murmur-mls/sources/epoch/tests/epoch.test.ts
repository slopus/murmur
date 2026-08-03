import {
    encodeBase64Url,
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
} from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import {
    createMlsEpochFromWelcome,
    createMlsTreeEpochFromWelcome,
    MlsEpochState,
    type MlsEpochTransition,
} from "../index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    type MlsKeyPackageBundle,
} from "../../keyPackage/index.js";
import {
    deriveMlsEpochSecretsFromJoiner,
    destroyMlsEpochSecrets,
} from "../../keySchedule/index.js";
import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import { MlsRatchetTree, type MlsRatchetTreeLeaf } from "../../ratchetTree/index.js";
import { createMlsWelcome, openMlsWelcome } from "../../welcome/index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 1n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("commit")),
    };
}

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

describe("MLS epoch application state", () => {
    it("exchanges bidirectional messages after a Welcome join", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const bobKeyPackage = createMlsKeyPackage(bob);
        const joinerSecret = hashBytes(utf8Encode("joiner"));
        const aliceSecrets = deriveMlsEpochSecretsFromJoiner(
            joinerSecret,
            encodeMlsGroupContext(context()),
        );
        const welcome = createMlsWelcome({
            context: context(),
            joinerSecret,
            confirmationKey: aliceSecrets.confirmationKey,
            signer: 0,
            signerSecretKey: alice.signingSecretKey,
            newMembers: [bobKeyPackage.keyPackage],
        });
        const joined = openMlsWelcome({
            welcome,
            keyPackageBundle: bobKeyPackage,
            validateExternalTree: (groupInfo, joiningKeyPackage) =>
                equalBytes(groupInfo.context.treeHash, context().treeHash) &&
                joiningKeyPackage === bobKeyPackage.keyPackage
                    ? alice.signingKey
                    : undefined,
        });
        const members = [{ signatureKey: alice.signingKey }, { signatureKey: bob.signingKey }];
        const aliceEpoch = new MlsEpochState({
            context: context(),
            secrets: aliceSecrets,
            members,
            localLeaf: 0,
            localSigningSecretKey: alice.signingSecretKey,
        });
        expect(aliceSecrets.encryptionSecret.every((byte) => byte === 0)).toBe(true);
        const bobEpoch = new MlsEpochState({
            context: joined.groupInfo.context,
            secrets: joined.epochSecrets,
            members,
            localLeaf: 1,
            localSigningSecretKey: bob.signingSecretKey,
        });
        expect(joined.epochSecrets.senderDataSecret.every((byte) => byte === 0)).toBe(true);

        expect(
            utf8Decode(bobEpoch.open(aliceEpoch.seal(utf8Encode("hello"))).applicationData),
        ).toBe("hello");
        expect(utf8Decode(aliceEpoch.open(bobEpoch.seal(utf8Encode("hi"))).applicationData)).toBe(
            "hi",
        );
        aliceEpoch.destroy();
        bobEpoch.destroy();
        expect(() => aliceEpoch.seal(utf8Encode("after"))).toThrow("destroyed");
    });

    it("exports matching, ratchet-free secrets on both sides of one epoch", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const secrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("exporter-joiner")),
            encodeMlsGroupContext(context()),
        );
        const shared = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("exporter-joiner")),
            encodeMlsGroupContext(context()),
        );
        const members = [{ signatureKey: alice.signingKey }, { signatureKey: bob.signingKey }];
        const aliceEpoch = new MlsEpochState({
            context: context(),
            secrets,
            members,
            localLeaf: 0,
            localSigningSecretKey: alice.signingSecretKey,
        });
        const bobEpoch = new MlsEpochState({
            context: context(),
            secrets: shared,
            members,
            localLeaf: 1,
            localSigningSecretKey: bob.signingSecretKey,
        });

        const generationBefore = aliceEpoch.persistenceGeneration;
        const checkpointBefore = aliceEpoch.serialize();
        const aliceExport = aliceEpoch.exportSecret("murmur test", utf8Encode("ctx"), 32);
        const bobExport = bobEpoch.exportSecret("murmur test", utf8Encode("ctx"), 32);

        expect(encodeBase64Url(aliceExport)).toBe(encodeBase64Url(bobExport));
        expect(aliceEpoch.localLeaf).toBe(0);
        expect(bobEpoch.localLeaf).toBe(1);
        // The exporter must not advance the ratchet or oblige a checkpoint.
        expect(aliceEpoch.persistenceGeneration).toBe(generationBefore);
        expect(encodeBase64Url(aliceEpoch.serialize())).toBe(encodeBase64Url(checkpointBefore));

        const otherLabel = aliceEpoch.exportSecret("murmur other", utf8Encode("ctx"), 32);
        const otherContext = aliceEpoch.exportSecret("murmur test", utf8Encode("ctx2"), 32);
        expect(encodeBase64Url(otherLabel)).not.toBe(encodeBase64Url(aliceExport));
        expect(encodeBase64Url(otherContext)).not.toBe(encodeBase64Url(aliceExport));

        aliceEpoch.destroy();
        bobEpoch.destroy();
        expect(() => aliceEpoch.exportSecret("murmur test", utf8Encode("ctx"), 32)).toThrow(
            "destroyed",
        );
    });

    it("rejects a local signing key which does not own the configured leaf", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const secrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("joiner")),
            encodeMlsGroupContext(context()),
        );

        expect(
            () =>
                new MlsEpochState({
                    context: context(),
                    secrets,
                    members: [{ signatureKey: alice.signingKey }],
                    localLeaf: 0,
                    localSigningSecretKey: bob.signingSecretKey,
                }),
        ).toThrow("does not match");
        destroyMlsEpochSecrets(secrets);
    });

    it("persists sender ratchets and skipped generations without the signing key", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [{ signatureKey: alice.signingKey }, { signatureKey: bob.signingKey }];
        const joinerSecret = hashBytes(utf8Encode("durable legacy epoch"));
        const aliceSecrets = deriveMlsEpochSecretsFromJoiner(
            joinerSecret,
            encodeMlsGroupContext(context()),
        );
        const originalRoot = encodeBase64Url(aliceSecrets.encryptionSecret);
        const originalEpochSecret = encodeBase64Url(aliceSecrets.epochSecret);
        const aliceEpoch = new MlsEpochState({
            context: context(),
            secrets: aliceSecrets,
            members,
            localLeaf: 0,
            localSigningSecretKey: alice.signingSecretKey,
        });
        const bobEpoch = new MlsEpochState({
            context: context(),
            secrets: deriveMlsEpochSecretsFromJoiner(
                joinerSecret,
                encodeMlsGroupContext(context()),
            ),
            members,
            localLeaf: 1,
            localSigningSecretKey: bob.signingSecretKey,
        });
        const first = aliceEpoch.seal(utf8Encode("first"));
        const second = aliceEpoch.seal(utf8Encode("second"));
        expect(utf8Decode(bobEpoch.open(second).applicationData)).toBe("second");

        const aliceState = aliceEpoch.serialize();
        const bobState = bobEpoch.serialize();
        expect(utf8Decode(aliceState)).not.toContain(encodeBase64Url(alice.signingSecretKey));
        expect(utf8Decode(aliceState)).not.toContain(originalRoot);
        expect(utf8Decode(aliceState)).not.toContain(originalEpochSecret);
        expect(aliceEpoch.persistenceGeneration).toBe(2n);
        expect(() =>
            MlsEpochState.deserialize(aliceState, {
                localSigningSecretKey: alice.signingSecretKey,
                minimumPersistenceGeneration: 3n,
            }),
        ).toThrow("rolled back");
        const duplicateKeyState = utf8Encode(
            utf8Decode(aliceState).replace('{"context":', '{"context":"duplicate","context":'),
        );
        expect(() =>
            MlsEpochState.deserialize(duplicateKeyState, {
                localSigningSecretKey: alice.signingSecretKey,
                minimumPersistenceGeneration: 2n,
            }),
        ).toThrow("canonical JSON");
        const wrongIdentity = generateIdentityKeyPair();
        expect(() =>
            MlsEpochState.deserialize(aliceState, {
                localSigningSecretKey: wrongIdentity.signingSecretKey,
                minimumPersistenceGeneration: 2n,
            }),
        ).toThrow("does not match");
        const restoredAlice = MlsEpochState.deserialize(aliceState, {
            localSigningSecretKey: alice.signingSecretKey,
            minimumPersistenceGeneration: 2n,
        });
        const restoredBob = MlsEpochState.deserialize(bobState, {
            localSigningSecretKey: bob.signingSecretKey,
            minimumPersistenceGeneration: 1n,
        });
        expect(restoredAlice.persistenceGeneration).toBe(2n);
        aliceEpoch.destroy();
        bobEpoch.destroy();

        const beforeInvalid = restoredBob.serialize();
        const beforeInvalidGeneration = restoredBob.persistenceGeneration;
        const invalid = first.slice();
        invalid[invalid.length - 1] = (invalid[invalid.length - 1] ?? 0) ^ 1;
        expect(() => restoredBob.openWithCheckpoint(invalid)).toThrow();
        expect(restoredBob.persistenceGeneration).toBe(beforeInvalidGeneration);
        expect(restoredBob.serialize()).toEqual(beforeInvalid);
        const checkpointedFirst = restoredBob.openWithCheckpoint(first);
        expect(utf8Decode(checkpointedFirst.message.applicationData)).toBe("first");
        expect(checkpointedFirst.state).toEqual(restoredBob.serialize());
        expect(() => restoredBob.open(first)).toThrow("already consumed");
        expect(
            utf8Decode(
                restoredAlice.open(restoredBob.seal(utf8Encode("after restart"))).applicationData,
            ),
        ).toBe("after restart");
        restoredAlice.destroy();
        restoredBob.destroy();
    });

    it("prepares and applies an add-only epoch transition", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const charlie = generateIdentityKeyPair();
        const charlieKeyPackage = createMlsKeyPackage(charlie);
        const currentContext = context();
        const currentJoiner = hashBytes(utf8Encode("current epoch"));
        const interimTranscriptHash = hashBytes(utf8Encode("current interim"));
        const nextTreeHash = hashBytes(utf8Encode("three-member tree"));
        const currentMembers = [
            { signatureKey: alice.signingKey, encryptionKey: alice.encryptionKey },
            { signatureKey: bob.signingKey, encryptionKey: bob.encryptionKey },
        ];
        const createCurrentEpoch = (
            localLeaf: number,
            signingSecretKey: Uint8Array,
        ): MlsEpochState =>
            new MlsEpochState({
                context: currentContext,
                secrets: deriveMlsEpochSecretsFromJoiner(
                    currentJoiner,
                    encodeMlsGroupContext(currentContext),
                ),
                members: currentMembers,
                localLeaf,
                localSigningSecretKey: signingSecretKey,
                interimTranscriptHash,
            });
        const aliceCurrent = createCurrentEpoch(0, alice.signingSecretKey);
        const bobCurrent = createCurrentEpoch(1, bob.signingSecretKey);
        const treeTransition = () => ({
            treeHash: nextTreeHash,
            commit: (): void => undefined,
            cancel: (): void => undefined,
        });

        let preparedTransition: MlsEpochTransition | undefined;
        let rejectedReentrantCommit = false;
        const prepared = aliceCurrent.prepareAdd([charlieKeyPackage.keyPackage], (additions) => {
            expect(() => aliceCurrent.prepareAdd(additions, treeTransition)).toThrow(
                "pending transition",
            );
            return {
                treeHash: nextTreeHash,
                commit: (): void => {
                    try {
                        preparedTransition?.commit();
                    } catch {
                        rejectedReentrantCommit = true;
                    }
                },
                cancel: (): void => undefined,
            };
        });
        preparedTransition = prepared.transition;
        expect(() => aliceCurrent.seal(utf8Encode("while staged"))).toThrow("pending transition");
        const bobTransition = bobCurrent.applyAdd(prepared.commit, treeTransition);
        const joined = openMlsWelcome({
            welcome: prepared.welcome,
            keyPackageBundle: charlieKeyPackage,
            validateExternalTree: (groupInfo) =>
                equalBytes(groupInfo.context.treeHash, nextTreeHash) ? alice.signingKey : undefined,
        });
        const nextMembers = [
            ...currentMembers,
            {
                signatureKey: charlie.signingKey,
                encryptionKey: charlieKeyPackage.keyPackage.leafNode.encryptionKey,
            },
        ];
        expect(() =>
            createMlsEpochFromWelcome({
                opened: joined,
                tree: {
                    treeHash: hashBytes(utf8Encode("wrong tree")),
                    members: nextMembers,
                    localLeaf: 2,
                },
                localSigningSecretKey: charlie.signingSecretKey,
            }),
        ).toThrow("does not match");
        const charlieNext = createMlsEpochFromWelcome({
            opened: joined,
            tree: { treeHash: nextTreeHash, members: nextMembers, localLeaf: 2 },
            localSigningSecretKey: charlie.signingSecretKey,
        });
        const aliceNext = prepared.transition.commit();
        expect(rejectedReentrantCommit).toBe(true);
        const bobNext = bobTransition.commit();
        expect(() => prepared.transition.commit()).toThrow("settled");

        expect(
            utf8Decode(bobNext.open(aliceNext.seal(utf8Encode("after add"))).applicationData),
        ).toBe("after add");
        expect(
            utf8Decode(aliceNext.open(charlieNext.seal(utf8Encode("joined"))).applicationData),
        ).toBe("joined");

        expect(() => aliceCurrent.seal(utf8Encode("old epoch"))).toThrow("destroyed");
        aliceNext.destroy();
        bobNext.destroy();
        charlieNext.destroy();
    });

    it("owns full TreeKEM state across Remove, Add, and Welcome", () => {
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
                localSigningSecretKey: identities[localLeaf]!.signingSecretKey,
                authenticateCredential,
                interimTranscriptHash,
            });
        const aliceCurrent = createCurrent(0);
        const bobCurrent = createCurrent(1);
        const carolCurrent = createCurrent(2);

        expect(() =>
            aliceCurrent.prepareAdd([bundles[3]!.keyPackage], () => ({
                treeHash: new Uint8Array(32),
                commit: (): void => undefined,
                cancel: (): void => undefined,
            })),
        ).toThrow("full Commit");
        expect(() =>
            aliceCurrent.applyAdd(new Uint8Array(), () => ({
                treeHash: new Uint8Array(32),
                commit: (): void => undefined,
                cancel: (): void => undefined,
            })),
        ).toThrow("full Commit");
        const prepared = aliceCurrent.prepareCommit([
            { type: "remove", removed: 1 },
            { type: "add", keyPackage: bundles[3]!.keyPackage },
        ]);
        expect(() => aliceCurrent.serialize()).toThrow("pending transition");
        expect(() => aliceCurrent.open(new Uint8Array())).toThrow("pending transition");
        const stagedCheckpoint = prepared.transition.serialize();
        const restoredStaged = MlsEpochState.deserialize(stagedCheckpoint, {
            localSigningSecretKey: identities[0]!.signingSecretKey,
            authenticateCredential,
            minimumPersistenceGeneration: prepared.transition.persistenceGeneration,
        });
        expect(restoredStaged.context.epoch).toBe(currentContext.epoch + 1n);
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
                    ? identities[0]!.signingKey
                    : undefined,
        });
        expect(() =>
            createMlsEpochFromWelcome({
                opened: joined,
                tree: {
                    treeHash: prepared.tree.treeHash(),
                    members: [],
                    localLeaf: 0,
                },
                localSigningSecretKey: identities[3]!.signingSecretKey,
            }),
        ).toThrow("integrated TreeKEM");
        const daveNext = createMlsTreeEpochFromWelcome({
            opened: joined,
            tree: prepared.tree,
            localLeaf: prepared.addedLeaves[0]!,
            leafKeyPair: bundles[3]!.leafKeyPair,
            localSigningSecretKey: identities[3]!.signingSecretKey,
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
            localSigningSecretKey: identities[0]!.signingSecretKey,
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
