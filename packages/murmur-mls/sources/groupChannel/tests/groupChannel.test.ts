import {
    createRelayEvent,
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Decode,
    utf8Encode,
    type PublishResult,
    type ReceivedEvent,
    type SignedRelayEvent,
    type StoreTransaction,
} from "@slopus/murmur";
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

const transaction: StoreTransaction = {
    get: async (): Promise<Uint8Array | undefined> => undefined,
    set: async (): Promise<void> => undefined,
    delete: async (): Promise<void> => undefined,
    list: async (): Promise<ReadonlyMap<string, Uint8Array>> => new Map(),
};

function publishResult(event: SignedRelayEvent): PublishResult {
    return {
        event,
        publications: [
            {
                relayId: "test",
                outcome: { seq: 1n, duplicate: false },
            },
        ],
        publishedRelayIds: ["test"],
        failedRelayIds: [],
    };
}

function receivedEvent(
    event: SignedRelayEvent,
    advanceCursor: (transaction: StoreTransaction) => Promise<void>,
): ReceivedEvent {
    return {
        kind: "event",
        relayId: "test",
        seq: 1n,
        event,
        advanceCursor,
    };
}

describe("MLS group relay channel", () => {
    it("publishes opaque epoch content and preserves transactional cursor control", async () => {
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
                return publishResult(event);
            },
        };
        await bobChannel.subscribe(client);
        const prepared = aliceChannel.prepareSend(utf8Encode("hello"));
        const outboundCheckpoint = prepared.serializeEpoch();
        const restoredOutbound = MlsEpochState.deserialize(outboundCheckpoint, {
            localSigningSecretKey: alice.signingSecretKey,
            minimumPersistenceGeneration: prepared.persistenceGeneration,
        });
        restoredOutbound.destroy();
        await expect(prepared.publish(client)).rejects.toThrow("prepared");
        prepared.markPersisted();
        const published = await prepared.publish(client);
        expect(() => prepared.serializeEpoch()).toThrow("confirmed");
        const advanceCursor = vi.fn(async (): Promise<void> => undefined);
        const received = receivedEvent(published.event, advanceCursor);

        const delivery = bobChannel.handle(received);

        expect(subscriptions).toEqual([bobChannel.topic]);
        expect(delivery?.status).toBe("opened");
        let durableInboundCheckpoint: Uint8Array | undefined;
        if (delivery?.status === "opened") {
            expect(utf8Decode(delivery.message.applicationData)).toBe("hello");
            const inboundCheckpoint = delivery.serializeEpoch();
            durableInboundCheckpoint = inboundCheckpoint.slice();
            const restoredInbound = MlsEpochState.deserialize(inboundCheckpoint, {
                localSigningSecretKey: bob.signingSecretKey,
                minimumPersistenceGeneration: delivery.persistenceGeneration,
            });
            restoredInbound.destroy();
            expect(advanceCursor).not.toHaveBeenCalled();
            delivery.markPersisted();
            await delivery.advanceCursor(transaction);
        }
        expect(advanceCursor).toHaveBeenCalledOnce();
        expect(aliceChannel.appliedApplicationFingerprints).toEqual([prepared.fingerprint]);
        expect(bobChannel.appliedApplicationFingerprints).toHaveLength(1);
        if (delivery?.status !== "opened" || durableInboundCheckpoint === undefined) {
            throw new Error("Expected durable inbound MLS checkpoint");
        }
        const restoredBob = new MlsGroupChannel(
            MlsEpochState.deserialize(durableInboundCheckpoint, {
                localSigningSecretKey: bob.signingSecretKey,
                minimumPersistenceGeneration: delivery.persistenceGeneration,
            }),
            [],
            bobChannel.appliedApplicationFingerprints,
        );
        const replayAdvanceCursor = vi.fn(async (): Promise<void> => undefined);
        const replay = restoredBob.handle(receivedEvent(published.event, replayAdvanceCursor));
        expect(replay?.status).toBe("application-applied");
        if (replay?.status === "application-applied") {
            await replay.advanceCursor(transaction);
        }
        expect(replayAdvanceCursor).toHaveBeenCalledOnce();
        restoredBob.destroy();
        aliceChannel.destroy();
        bobChannel.destroy();
    });

    it("defers invalid or future-epoch payloads without consuming them", () => {
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
        const advanceCursor = vi.fn(async (): Promise<void> => undefined);
        const received = receivedEvent(
            createRelayEvent(alice, channel.topic, utf8Encode("not an MLS message")),
            advanceCursor,
        );

        expect(channel.handle(received)?.status).toBe("deferred");
        expect(advanceCursor).not.toHaveBeenCalled();
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
            publish: async (topic, payload): Promise<PublishResult> =>
                publishResult(createRelayEvent(alice, topic, payload)),
        };
        const outbound = aliceChannel.prepareCommit([]);
        const stagedCheckpoint = outbound.serializeNextEpoch();
        const restoredStaged = MlsEpochState.deserialize(stagedCheckpoint, {
            localSigningSecretKey: alice.signingSecretKey,
            authenticateCredential,
            minimumPersistenceGeneration: outbound.persistenceGeneration,
        });
        expect(restoredStaged.context.epoch).toBe(current.epoch + 1n);
        restoredStaged.destroy();
        const originalPayload = outbound.payload.slice();
        outbound.payload.fill(0);
        const advanceCursor = vi.fn(async (): Promise<void> => undefined);
        const delivery = bobChannel.handle(
            receivedEvent(
                createRelayEvent(alice, bobChannel.topic, originalPayload),
                advanceCursor,
            ),
        );
        expect(delivery?.status).toBe("commit");
        if (delivery?.status !== "commit") {
            throw new Error("Expected staged MLS Commit");
        }
        expect(advanceCursor).not.toHaveBeenCalled();
        expect(() => outbound.adopt()).toThrow("prepared");
        expect(() => aliceChannel.destroy()).toThrow("pending outbound");
        outbound.markPersisted();
        const committed = await outbound.publish(client);
        expect(() => outbound.cancel()).toThrow("confirmed");
        outbound.adopt();
        expect(() => outbound.serializeNextEpoch()).toThrow("settled");
        const inboundCommitCheckpoint = delivery.serializeNextEpoch();
        const restoredInboundCommit = MlsEpochState.deserialize(inboundCommitCheckpoint, {
            localSigningSecretKey: bob.signingSecretKey,
            authenticateCredential,
            minimumPersistenceGeneration: delivery.persistenceGeneration,
        });
        restoredInboundCommit.destroy();
        delivery.markPersisted();
        delivery.adopt();
        await delivery.advanceCursor(transaction);
        expect(advanceCursor).toHaveBeenCalledOnce();
        expect(aliceChannel.appliedCommitFingerprints).toHaveLength(1);
        const echoAdvanceCursor = vi.fn(async (): Promise<void> => undefined);
        const echo = aliceChannel.handle(receivedEvent(committed.event, echoAdvanceCursor));
        expect(echo?.status).toBe("applied");
        if (echo?.status === "applied") {
            await echo.advanceCursor(transaction);
            aliceChannel.forgetAppliedCommit(echo.fingerprint);
        }
        expect(echoAdvanceCursor).toHaveBeenCalledOnce();
        const preparedApplication = aliceChannel.prepareSend(utf8Encode("new epoch"));
        preparedApplication.serializeEpoch().fill(0);
        preparedApplication.markPersisted();
        const published = await preparedApplication.publish(client);
        const opened = bobChannel.handle(
            receivedEvent(published.event, async (): Promise<void> => undefined),
        );
        expect(opened?.status).toBe("opened");
        if (opened?.status === "opened") {
            expect(utf8Decode(opened.message.applicationData)).toBe("new epoch");
            opened.serializeEpoch().fill(0);
            opened.markPersisted();
        }

        const ambiguous = aliceChannel.prepareCommit([]);
        ambiguous.serializeNextEpoch().fill(0);
        ambiguous.markPersisted();
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
            ambiguous.confirmPublished(
                publishResult(
                    createRelayEvent(alice, aliceChannel.topic, utf8Encode("wrong Commit")),
                ),
            ),
        ).toThrow("does not match");
        ambiguous.confirmPublished(
            publishResult(createRelayEvent(alice, aliceChannel.topic, ambiguous.payload)),
        );
        ambiguous.adopt();

        aliceChannel.destroy();
        bobChannel.destroy();
        destroyMlsKeyPackageBundle(aliceBundle);
        destroyMlsKeyPackageBundle(bobBundle);
    });
});
