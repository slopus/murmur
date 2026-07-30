import {
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Encode,
    zeroBytes,
} from "@murmur/core";
import { describe, expect, it } from "vitest";
import {
    createMlsAddCommit,
    createMlsTreeCommit,
    decodeMlsAddCommit,
    decodeMlsTreeCommit,
    destroyMlsTreeCommitResult,
    encodeMlsAddCommit,
    encodeMlsTreeCommit,
    openMlsAddCommit,
    openMlsTreeCommit,
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
import { openMlsWelcome } from "../../welcome/index.js";
import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import { MlsRatchetTree, type MlsRatchetTreeLeaf } from "../../ratchetTree/index.js";
import { deriveMlsWelcomePrivateKeys, destroyMlsTreePrivateKeys } from "../../updatePath/index.js";

function genericLeaf(bundle: MlsKeyPackageBundle): MlsLeafNode {
    const leaf = bundle.keyPackage.leafNode;
    return {
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
        credential: leaf.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: leaf.notBefore,
        notAfter: leaf.notAfter,
        extensions: [],
        signature: leaf.signature,
    };
}

function publicLeaf(bundle: MlsKeyPackageBundle): MlsRatchetTreeLeaf {
    const leaf = genericLeaf(bundle);
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

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("add-commit-group"),
        epoch: 4n,
        treeHash: hashBytes(utf8Encode("current-tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("current-confirmed")),
    };
}

describe("MLS add-only Commit", () => {
    it("advances existing members and welcomes the added member", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const charlie = generateIdentityKeyPair();
        const charlieKeyPackage = createMlsKeyPackage(charlie);
        const current = context();
        const currentSecrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("current-joiner")),
            encodeMlsGroupContext(current),
        );
        const interimTranscriptHash = hashBytes(utf8Encode("current-interim"));
        const nextTreeHash = hashBytes(utf8Encode("next-tree"));
        const members = [
            { signatureKey: alice.signingKey, encryptionKey: alice.encryptionKey },
            { signatureKey: bob.signingKey, encryptionKey: bob.encryptionKey },
        ];

        const created = createMlsAddCommit({
            context: current,
            interimTranscriptHash,
            nextInitSecret: currentSecrets.nextInitSecret,
            membershipKey: currentSecrets.membershipKey,
            members,
            sender: 0,
            signingSecretKey: alice.signingSecretKey,
            additions: [charlieKeyPackage.keyPackage],
            validateExternalTree: () => nextTreeHash,
            authenticatedData: utf8Encode("add Charlie"),
        });
        expect(Array.from(created.commit.slice(0, 4))).toEqual([0, 1, 0, 1]);
        expect(encodeMlsAddCommit(decodeMlsAddCommit(created.commit))).toEqual(created.commit);

        const opened = openMlsAddCommit({
            message: created.commit,
            context: current,
            interimTranscriptHash,
            nextInitSecret: currentSecrets.nextInitSecret,
            membershipKey: currentSecrets.membershipKey,
            members,
            validateExternalTree: (additions, nextMembers) => {
                expect(additions).toHaveLength(1);
                expect(nextMembers).toHaveLength(3);
                return nextTreeHash;
            },
        });
        expect(equalBytes(opened.secrets.encryptionSecret, created.secrets.encryptionSecret)).toBe(
            true,
        );
        expect(opened.context).toEqual(created.context);
        expect(opened.interimTranscriptHash).toEqual(created.interimTranscriptHash);

        const joined = openMlsWelcome({
            welcome: created.welcome,
            keyPackageBundle: charlieKeyPackage,
            expectedGroupId: current.groupId,
            validateExternalTree: (groupInfo, joiningKeyPackage) =>
                joiningKeyPackage === charlieKeyPackage.keyPackage &&
                equalBytes(groupInfo.context.treeHash, nextTreeHash) &&
                groupInfo.signer === 0
                    ? alice.signingKey
                    : undefined,
        });
        expect(
            equalBytes(joined.epochSecrets.encryptionSecret, created.secrets.encryptionSecret),
        ).toBe(true);

        destroyMlsEpochSecrets(currentSecrets);
        destroyMlsEpochSecrets(created.secrets);
        destroyMlsEpochSecrets(opened.secrets);
        destroyMlsEpochSecrets(joined.epochSecrets);
    });

    it("rejects tampering and an inconsistent external tree", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const bobKeyPackage = createMlsKeyPackage(bob);
        const current = context();
        const currentSecrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("current-joiner")),
            encodeMlsGroupContext(current),
        );
        const interimTranscriptHash = hashBytes(utf8Encode("current-interim"));
        const nextTreeHash = hashBytes(utf8Encode("next-tree"));
        const members = [{ signatureKey: alice.signingKey, encryptionKey: alice.encryptionKey }];
        expect(() =>
            createMlsAddCommit({
                context: current,
                interimTranscriptHash,
                nextInitSecret: currentSecrets.nextInitSecret,
                membershipKey: currentSecrets.membershipKey,
                members: [
                    {
                        signatureKey: alice.signingKey,
                        encryptionKey: bobKeyPackage.keyPackage.leafNode.encryptionKey,
                    },
                ],
                sender: 0,
                signingSecretKey: alice.signingSecretKey,
                additions: [bobKeyPackage.keyPackage],
                validateExternalTree: () => nextTreeHash,
            }),
        ).toThrow("encryption key is already present");
        const created = createMlsAddCommit({
            context: current,
            interimTranscriptHash,
            nextInitSecret: currentSecrets.nextInitSecret,
            membershipKey: currentSecrets.membershipKey,
            members,
            sender: 0,
            signingSecretKey: alice.signingSecretKey,
            additions: [bobKeyPackage.keyPackage],
            validateExternalTree: () => nextTreeHash,
        });
        const tampered = created.commit.slice();
        tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;

        expect(() =>
            openMlsAddCommit({
                message: tampered,
                context: current,
                interimTranscriptHash,
                nextInitSecret: currentSecrets.nextInitSecret,
                membershipKey: currentSecrets.membershipKey,
                members,
                validateExternalTree: () => nextTreeHash,
            }),
        ).toThrow("membership tag");
        expect(() =>
            openMlsAddCommit({
                message: created.commit,
                context: current,
                interimTranscriptHash,
                nextInitSecret: currentSecrets.nextInitSecret,
                membershipKey: currentSecrets.membershipKey,
                members,
                validateExternalTree: () => hashBytes(utf8Encode("wrong-tree")),
            }),
        ).toThrow("confirmation tag");

        destroyMlsEpochSecrets(currentSecrets);
        destroyMlsEpochSecrets(created.secrets);
    });
});

describe("MLS full TreeKEM Commit", () => {
    it("cryptographically removes one member while adding another", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const carol = generateIdentityKeyPair();
        const dave = generateIdentityKeyPair();
        const bundles = [alice, bob, carol, dave].map((identity) => createMlsKeyPackage(identity));
        const tree = new MlsRatchetTree([
            publicLeaf(bundles[0]!),
            undefined,
            publicLeaf(bundles[1]!),
            undefined,
            publicLeaf(bundles[2]!),
            undefined,
            undefined,
        ]);
        const current: MlsGroupContext = {
            groupId: utf8Encode("full-commit-group"),
            epoch: 9n,
            treeHash: tree.treeHash(),
            confirmedTranscriptHash: hashBytes(utf8Encode("confirmed")),
        };
        const currentSecrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("current full epoch")),
            encodeMlsGroupContext(current),
        );
        const interimTranscriptHash = hashBytes(utf8Encode("interim"));
        const created = createMlsTreeCommit({
            context: current,
            interimTranscriptHash,
            nextInitSecret: currentSecrets.nextInitSecret,
            membershipKey: currentSecrets.membershipKey,
            tree,
            sender: 0,
            signingSecretKey: alice.signingSecretKey,
            proposals: [
                { type: "remove", removed: 1 },
                { type: "add", keyPackage: bundles[3]!.keyPackage },
            ],
            authenticateCredential,
            authenticatedData: utf8Encode("replace Bob with Dave"),
        });
        expect(encodeMlsTreeCommit(decodeMlsTreeCommit(created.commit))).toEqual(created.commit);
        expect(created.removedLeaves).toEqual([1]);
        expect(created.addedLeaves).toEqual([1]);
        expect(created.welcome).toBeDefined();

        const carolOpened = openMlsTreeCommit({
            message: created.commit,
            context: current,
            interimTranscriptHash,
            nextInitSecret: currentSecrets.nextInitSecret,
            membershipKey: currentSecrets.membershipKey,
            tree,
            localLeaf: 2,
            privateKeys: [{ node: 4, keyPair: bundles[2]!.leafKeyPair }],
            authenticateCredential,
        });
        expect(
            equalBytes(carolOpened.secrets.encryptionSecret, created.secrets.encryptionSecret),
        ).toBe(true);

        expect(() =>
            openMlsTreeCommit({
                message: created.commit,
                context: current,
                interimTranscriptHash,
                nextInitSecret: currentSecrets.nextInitSecret,
                membershipKey: currentSecrets.membershipKey,
                tree,
                localLeaf: 1,
                privateKeys: [{ node: 2, keyPair: bundles[1]!.leafKeyPair }],
                authenticateCredential,
            }),
        ).toThrow("removed");

        const joined = openMlsWelcome({
            welcome: created.welcome!,
            keyPackageBundle: bundles[3]!,
            expectedGroupId: current.groupId,
            validateExternalTree: (groupInfo) =>
                equalBytes(groupInfo.context.treeHash, created.tree.treeHash())
                    ? alice.signingKey
                    : undefined,
        });
        expect(
            equalBytes(joined.epochSecrets.encryptionSecret, created.secrets.encryptionSecret),
        ).toBe(true);
        expect(joined.pathSecret).toBeDefined();
        expect(() =>
            deriveMlsWelcomePrivateKeys({
                tree: created.tree,
                groupId: created.context.groupId,
                sender: 0,
                localLeaf: created.addedLeaves[0]!,
                leafKeyPair: bundles[3]!.leafKeyPair,
                authenticateCredential,
            }),
        ).toThrow("required");
        expect(() =>
            deriveMlsWelcomePrivateKeys({
                tree: created.tree,
                groupId: created.context.groupId,
                sender: 3,
                localLeaf: created.addedLeaves[0]!,
                leafKeyPair: bundles[3]!.leafKeyPair,
                pathSecret: joined.pathSecret!,
                authenticateCredential,
            }),
        ).toThrow("sender");
        const davePrivateKeys = deriveMlsWelcomePrivateKeys({
            tree: created.tree,
            groupId: created.context.groupId,
            sender: 0,
            localLeaf: created.addedLeaves[0]!,
            leafKeyPair: bundles[3]!.leafKeyPair,
            pathSecret: joined.pathSecret!,
            authenticateCredential,
        });

        const nextCreated = createMlsTreeCommit({
            context: created.context,
            interimTranscriptHash: created.interimTranscriptHash,
            nextInitSecret: created.secrets.nextInitSecret,
            membershipKey: created.secrets.membershipKey,
            tree: created.tree,
            sender: 2,
            signingSecretKey: carol.signingSecretKey,
            proposals: [],
            authenticateCredential,
            authenticatedData: utf8Encode("Carol updates the path"),
        });
        const daveOpened = openMlsTreeCommit({
            message: nextCreated.commit,
            context: created.context,
            interimTranscriptHash: created.interimTranscriptHash,
            nextInitSecret: created.secrets.nextInitSecret,
            membershipKey: created.secrets.membershipKey,
            tree: created.tree,
            localLeaf: 1,
            privateKeys: davePrivateKeys,
            authenticateCredential,
        });
        expect(
            equalBytes(daveOpened.secrets.encryptionSecret, nextCreated.secrets.encryptionSecret),
        ).toBe(true);

        destroyMlsEpochSecrets(currentSecrets);
        destroyMlsTreePrivateKeys(davePrivateKeys);
        destroyMlsTreeCommitResult(created);
        destroyMlsTreeCommitResult(carolOpened);
        destroyMlsTreeCommitResult(nextCreated);
        destroyMlsTreeCommitResult(daveOpened);
        destroyMlsEpochSecrets(joined.epochSecrets);
        zeroBytes(joined.pathSecret!);
        for (const bundle of bundles) {
            destroyMlsKeyPackageBundle(bundle);
        }
    });
});
