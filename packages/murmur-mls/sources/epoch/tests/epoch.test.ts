import {
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
} from "@murmur/core";
import { describe, expect, it } from "vitest";
import { MlsEpochState } from "../index.js";
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
});
