import { equalBytes, generateIdentityKeyPair, hashBytes, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import {
    createMlsAddCommit,
    decodeMlsAddCommit,
    encodeMlsAddCommit,
    openMlsAddCommit,
} from "../index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import { createMlsKeyPackage } from "../../keyPackage/index.js";
import {
    deriveMlsEpochSecretsFromJoiner,
    destroyMlsEpochSecrets,
} from "../../keySchedule/index.js";
import { openMlsWelcome } from "../../welcome/index.js";

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
