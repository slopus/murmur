import {
    createRelayEvent,
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
import { deriveMlsEpochSecretsFromJoiner } from "../../keySchedule/index.js";
import { MlsGroupChannel, type MlsGroupMurmurClient } from "../index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 1n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("commit")),
    };
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
});
