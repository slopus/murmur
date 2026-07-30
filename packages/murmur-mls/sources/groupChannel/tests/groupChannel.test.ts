import {
    createRelayEvent,
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
    type PublishResult,
    type ReceivedEvent,
} from "@murmur/core";
import { describe, expect, it, vi } from "vitest";
import { MlsEpochState } from "../../epoch/index.js";
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
import { MlsGroupChannel, type MlsGroupMurmurClient } from "../index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 1n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("commit")),
    };
}

function publicLeaf(bundle: MlsKeyPackageBundle): MlsRatchetTreeLeaf {
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

describe("MLS group relay channel", () => {
    it("publishes opaque epoch content and preserves manual acknowledgement", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const joinerSecret = hashBytes(utf8Encode("joiner"));
        const members = [{ signatureKey: alice.signingKey }, { signatureKey: bob.signingKey }];
        const aliceChannel = new MlsGroupChannel(
            new MlsEpochState({
                context: context(),
                secrets: deriveMlsEpochSecretsFromJoiner(
                    joinerSecret,
                    encodeMlsGroupContext(context()),
                ),
                members,
                localLeaf: 0,
                localSigningSecretKey: alice.signingSecretKey,
            }),
        );
        const bobChannel = new MlsGroupChannel(
            new MlsEpochState({
                context: context(),
                secrets: deriveMlsEpochSecretsFromJoiner(
                    joinerSecret,
                    encodeMlsGroupContext(context()),
                ),
                members,
                localLeaf: 1,
                localSigningSecretKey: bob.signingSecretKey,
            }),
        );
        const subscriptions: string[] = [];
        const client: MlsGroupMurmurClient = {
            subscribe: async (topic): Promise<void> => {
                subscriptions.push(topic);
            },
            publish: async (topic, payload): Promise<PublishResult> => {
                const event = createRelayEvent(alice, topic, payload);
                return {
                    event,
                    publishedRelayIds: ["test"],
                    failedRelayIds: [],
                };
            },
        };
        await bobChannel.subscribe(client);
        const published = await aliceChannel.send(client, utf8Encode("hello"));
        const acknowledge = vi.fn(async (): Promise<void> => undefined);
        const received: ReceivedEvent = { event: published.event, acknowledge };

        const delivery = bobChannel.handle(received);

        expect(subscriptions).toEqual([bobChannel.topic]);
        expect(delivery?.status).toBe("opened");
        if (delivery?.status === "opened") {
            expect(utf8Decode(delivery.message.applicationData)).toBe("hello");
            await delivery.acknowledge();
        }
        expect(acknowledge).toHaveBeenCalledOnce();
        aliceChannel.destroy();
        bobChannel.destroy();
    });

    it("defers invalid or future-epoch payloads without acknowledging them", () => {
        const alice = generateIdentityKeyPair();
        const secrets = deriveMlsEpochSecretsFromJoiner(
            hashBytes(utf8Encode("joiner")),
            encodeMlsGroupContext(context()),
        );
        const channel = new MlsGroupChannel(
            new MlsEpochState({
                context: context(),
                secrets,
                members: [{ signatureKey: alice.signingKey }],
                localLeaf: 0,
                localSigningSecretKey: alice.signingSecretKey,
            }),
        );
        const acknowledge = vi.fn(async (): Promise<void> => undefined);
        const received: ReceivedEvent = {
            event: createRelayEvent(alice, channel.topic, utf8Encode("not an MLS message")),
            acknowledge,
        };

        expect(channel.handle(received)?.status).toBe("deferred");
        expect(acknowledge).not.toHaveBeenCalled();
        expect(
            channel.handle({
                ...received,
                event: { ...received.event, topic: "other" },
            }),
        ).toBeUndefined();
        channel.destroy();
    });

    it("stages PublicMessage Commits and explicitly adopts the next epoch", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceBundle = createMlsKeyPackage(alice);
        const bobBundle = createMlsKeyPackage(bob);
        const tree = new MlsRatchetTree([
            publicLeaf(aliceBundle),
            undefined,
            publicLeaf(bobBundle),
        ]);
        const current: MlsGroupContext = {
            groupId: utf8Encode("relay Commit group"),
            epoch: 3n,
            treeHash: tree.treeHash(),
            confirmedTranscriptHash: hashBytes(utf8Encode("confirmed")),
        };
        const joinerSecret = hashBytes(utf8Encode("current joiner"));
        const interimTranscriptHash = hashBytes(utf8Encode("interim"));
        const createChannel = (localLeaf: number, bundle: MlsKeyPackageBundle): MlsGroupChannel =>
            new MlsGroupChannel(
                new MlsEpochState({
                    context: current,
                    secrets: deriveMlsEpochSecretsFromJoiner(
                        joinerSecret,
                        encodeMlsGroupContext(current),
                    ),
                    tree,
                    privateKeys: [
                        {
                            node: localLeaf * 2,
                            keyPair: {
                                secretKey: bundle.leafKeyPair.secretKey.slice(),
                                publicKey: bundle.leafKeyPair.publicKey.slice(),
                            },
                        },
                    ],
                    localLeaf,
                    localSigningSecretKey:
                        localLeaf === 0 ? alice.signingSecretKey : bob.signingSecretKey,
                    authenticateCredential,
                    interimTranscriptHash,
                }),
            );
        const aliceChannel = createChannel(0, aliceBundle);
        const bobChannel = createChannel(1, bobBundle);
        const client: MlsGroupMurmurClient = {
            subscribe: async (): Promise<void> => undefined,
            publish: async (topic, payload): Promise<PublishResult> => ({
                event: createRelayEvent(alice, topic, payload),
                publishedRelayIds: ["test"],
                failedRelayIds: [],
            }),
        };
        const outbound = aliceChannel.prepareCommit([]);
        const originalPayload = outbound.payload.slice();
        outbound.payload.fill(0);
        const acknowledge = vi.fn(async (): Promise<void> => undefined);
        const delivery = bobChannel.handle({
            event: createRelayEvent(alice, bobChannel.topic, originalPayload),
            acknowledge,
        });
        expect(delivery?.status).toBe("commit");
        if (delivery?.status !== "commit") {
            throw new Error("Expected staged MLS Commit");
        }
        await expect(delivery.acknowledge()).rejects.toThrow("adopted");
        expect(() => outbound.adopt()).toThrow("prepared");
        expect(() => aliceChannel.destroy()).toThrow("pending outbound");
        const committed = await outbound.publish(client);
        expect(() => outbound.cancel()).toThrow("confirmed");
        outbound.adopt();
        delivery.adopt();
        await delivery.acknowledge();
        expect(acknowledge).toHaveBeenCalledOnce();
        expect(aliceChannel.appliedCommitFingerprints).toHaveLength(1);
        const echoAcknowledge = vi.fn(async (): Promise<void> => undefined);
        const echo = aliceChannel.handle({
            event: committed.event,
            acknowledge: echoAcknowledge,
        });
        expect(echo?.status).toBe("applied");
        if (echo?.status === "applied") {
            await echo.acknowledge();
            aliceChannel.forgetAppliedCommit(echo.fingerprint);
        }
        expect(echoAcknowledge).toHaveBeenCalledOnce();
        const published = await aliceChannel.send(client, utf8Encode("new epoch"));
        const opened = bobChannel.handle({
            event: published.event,
            acknowledge: async (): Promise<void> => undefined,
        });
        expect(opened?.status).toBe("opened");
        if (opened?.status === "opened") {
            expect(utf8Decode(opened.message.applicationData)).toBe("new epoch");
        }

        const ambiguous = aliceChannel.prepareCommit([]);
        await expect(
            ambiguous.publish({
                subscribe: async (): Promise<void> => undefined,
                publish: async (): Promise<PublishResult> => {
                    throw new Error("ambiguous relay failure");
                },
            }),
        ).rejects.toThrow("ambiguous");
        expect(() => ambiguous.cancel()).toThrow("ambiguous");
        expect(() => aliceChannel.destroy()).toThrow("pending outbound");
        expect(() =>
            ambiguous.confirmPublished({
                event: createRelayEvent(alice, aliceChannel.topic, utf8Encode("wrong Commit")),
                publishedRelayIds: ["test"],
                failedRelayIds: [],
            }),
        ).toThrow("does not match");
        ambiguous.confirmPublished({
            event: createRelayEvent(alice, aliceChannel.topic, ambiguous.payload),
            publishedRelayIds: ["test"],
            failedRelayIds: [],
        });
        ambiguous.adopt();

        aliceChannel.destroy();
        bobChannel.destroy();
        destroyMlsKeyPackageBundle(aliceBundle);
        destroyMlsKeyPackageBundle(bobBundle);
    });
});
