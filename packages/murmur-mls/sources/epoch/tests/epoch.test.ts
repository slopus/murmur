import {
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
} from "@murmur/core";
import { describe, expect, it } from "vitest";
import { createMlsEpochFromWelcome, MlsEpochState, type MlsEpochTransition } from "../index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import { createMlsKeyPackage } from "../../keyPackage/index.js";
import {
    deriveMlsEpochSecretsFromJoiner,
    destroyMlsEpochSecrets,
} from "../../keySchedule/index.js";
import { createMlsWelcome, openMlsWelcome } from "../../welcome/index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 1n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("commit")),
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
});
