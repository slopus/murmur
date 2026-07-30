import { equalBytes, generateIdentityKeyPair, hashBytes, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import { createMlsKeyPackage } from "../../keyPackage/index.js";
import {
    deriveMlsEpochSecretsFromJoiner,
    destroyMlsEpochSecrets,
} from "../../keySchedule/index.js";
import { createMlsWelcome, openMlsWelcome } from "../index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 1n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("commit")),
    };
}

describe("MLS Welcome", () => {
    it("delivers and authenticates an epoch to a KeyPackage holder", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const bobKeyPackage = createMlsKeyPackage(bob);
        const joinerSecret = hashBytes(utf8Encode("joiner"));
        const expected = deriveMlsEpochSecretsFromJoiner(
            joinerSecret,
            encodeMlsGroupContext(context()),
        );
        const welcome = createMlsWelcome({
            context: context(),
            joinerSecret,
            confirmationKey: expected.confirmationKey,
            signer: 0,
            signerSecretKey: alice.signingSecretKey,
            newMembers: [bobKeyPackage.keyPackage],
        });
        expect(Array.from(welcome.slice(0, 4))).toEqual([0, 1, 0, 3]);

        const opened = openMlsWelcome({
            welcome,
            keyPackageBundle: bobKeyPackage,
            validateExternalTree: (groupInfo, joiningKeyPackage) =>
                groupInfo.signer === 0 &&
                equalBytes(groupInfo.context.treeHash, context().treeHash) &&
                joiningKeyPackage === bobKeyPackage.keyPackage
                    ? alice.signingKey
                    : undefined,
            expectedGroupId: context().groupId,
        });

        expect(equalBytes(opened.epochSecrets.encryptionSecret, expected.encryptionSecret)).toBe(
            true,
        );
        expect(bobKeyPackage.initKeyPair.secretKey.every((byte) => byte === 0)).toBe(true);
        expect(bobKeyPackage.leafKeyPair.secretKey.some((byte) => byte !== 0)).toBe(true);
        destroyMlsEpochSecrets(expected);
        destroyMlsEpochSecrets(opened.epochSecrets);
    });

    it("does not consume the local init key when authentication fails", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const bobKeyPackage = createMlsKeyPackage(bob);
        const joinerSecret = hashBytes(utf8Encode("joiner"));
        const expected = deriveMlsEpochSecretsFromJoiner(
            joinerSecret,
            encodeMlsGroupContext(context()),
        );
        const welcome = createMlsWelcome({
            context: context(),
            joinerSecret,
            confirmationKey: expected.confirmationKey,
            signer: 0,
            signerSecretKey: alice.signingSecretKey,
            newMembers: [bobKeyPackage.keyPackage],
        });

        expect(() =>
            openMlsWelcome({
                welcome,
                keyPackageBundle: bobKeyPackage,
                validateExternalTree: () => new Uint8Array(32),
            }),
        ).toThrow("signature");
        expect(bobKeyPackage.initKeyPair.secretKey.some((byte) => byte !== 0)).toBe(true);
        destroyMlsEpochSecrets(expected);
    });
});
