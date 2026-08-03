import {
    concatBytes,
    generateIdentityKeyPair,
    signBytes,
    utf8Encode,
    type IdentityKeyPair,
} from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    mlsAeadSeal,
    mlsExpandWithLabel,
} from "../../cipherSuite/index.js";
import { encodeOpaqueV, encodeUint16 } from "../../encoding/index.js";
import {
    decodeMlsEphemeralHeader,
    encodeMlsEphemeralHeader,
    MAX_MLS_EPHEMERAL_PAYLOAD_BYTES,
    MLS_EPHEMERAL_CHANNEL_SECRET_BYTES,
    MlsEphemeralCipher,
} from "../index.js";

const groupId = new Uint8Array([9, 8, 7, 6]);
const channelSecret = new Uint8Array(MLS_EPHEMERAL_CHANNEL_SECRET_BYTES).fill(23);

function cipher(options: {
    readonly identity: IdentityKeyPair;
    readonly localLeaf: number;
    readonly epoch?: bigint;
    readonly members: readonly IdentityKeyPair[];
    readonly secret?: Uint8Array;
}): MlsEphemeralCipher {
    return new MlsEphemeralCipher({
        groupId,
        epoch: options.epoch ?? 3n,
        localLeaf: options.localLeaf,
        identity: options.identity,
        channelSecret: options.secret ?? channelSecret,
        signatureKeyFor: (leaf) => options.members[leaf]?.signingKey,
    });
}

/** Forge a frame the way a malicious group insider would try to. */
function forge(options: {
    readonly claimedLeaf: number;
    readonly signer: IdentityKeyPair;
    readonly streamId: Uint8Array;
    readonly payload: Uint8Array;
}): Uint8Array {
    const header = encodeMlsEphemeralHeader({
        type: "data",
        epoch: 3n,
        senderLeaf: options.claimedLeaf,
        streamId: options.streamId,
        counter: 0n,
    });
    const context = concatBytes(encodeUint16(options.claimedLeaf), options.streamId);
    const key = mlsExpandWithLabel(
        channelSecret,
        "murmur ephemeral key",
        context,
        MLS_AEAD_KEY_LENGTH,
    );
    const nonce = mlsExpandWithLabel(
        channelSecret,
        "murmur ephemeral nonce",
        context,
        MLS_AEAD_NONCE_LENGTH,
    );
    const ciphertext = mlsAeadSeal(key, nonce, concatBytes(header, groupId), options.payload);
    const signature = signBytes(
        options.signer,
        concatBytes(
            utf8Encode("murmur/mls/ephemeral-frame/v1"),
            encodeOpaqueV(groupId),
            header,
            ciphertext,
        ),
    );
    return concatBytes(header, signature, ciphertext);
}

describe("MLS ephemeral frames", () => {
    it("round trips authenticated frames between two members of one epoch", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [alice, bob];
        const sender = cipher({ identity: alice, localLeaf: 0, members });
        const receiver = cipher({ identity: bob, localLeaf: 1, members });

        const opened = receiver.open(sender.seal(utf8Encode("keystroke")));

        expect(opened.status).toBe("opened");
        if (opened.status !== "opened") {
            return;
        }
        expect(opened.frame.senderLeaf).toBe(0);
        expect(opened.frame.epoch).toBe(3n);
        expect(opened.frame.type).toBe("data");
        expect(new TextDecoder().decode(opened.frame.bytes)).toBe("keystroke");
    });

    it("keeps the sender ordered and rejects a replayed counter", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [alice, bob];
        const sender = cipher({ identity: alice, localLeaf: 0, members });
        const receiver = cipher({ identity: bob, localLeaf: 1, members });

        const frames = ["a", "b", "c"].map((value) => sender.seal(utf8Encode(value)));
        const received = frames.map((frame) => receiver.open(frame.slice()));
        expect(
            received.map((result) =>
                result.status === "opened" ? new TextDecoder().decode(result.frame.bytes) : "?",
            ),
        ).toEqual(["a", "b", "c"]);

        expect(receiver.open(frames[1]!)).toEqual({ status: "dropped", reason: "replay" });
    });

    it("refuses a frame forged by another member holding the same exporter secret", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const mallory = generateIdentityKeyPair();
        const members = [alice, bob, mallory];
        const receiver = cipher({ identity: bob, localLeaf: 1, members });

        const forged = forge({
            claimedLeaf: 0,
            signer: mallory,
            streamId: new Uint8Array(16).fill(4),
            payload: utf8Encode("rm -rf /"),
        });

        expect(receiver.open(forged)).toEqual({ status: "dropped", reason: "authentication" });
    });

    it("reports the observed epoch of a frame from another epoch", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [alice, bob];
        const stale = cipher({ identity: alice, localLeaf: 0, epoch: 2n, members });
        const receiver = cipher({ identity: bob, localLeaf: 1, epoch: 3n, members });

        expect(receiver.open(stale.seal(utf8Encode("late")))).toEqual({
            status: "dropped",
            reason: "foreign-epoch",
            epoch: 2n,
        });
    });

    it("drops a member's own echo and an unknown leaf", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const sender = cipher({ identity: alice, localLeaf: 0, members: [alice, bob] });
        const loopback = cipher({ identity: alice, localLeaf: 0, members: [alice, bob] });
        const strangerView = cipher({ identity: bob, localLeaf: 1, members: [] });

        const frame = sender.seal(utf8Encode("echo"));
        expect(loopback.open(frame.slice())).toEqual({ status: "dropped", reason: "self" });
        expect(strangerView.open(frame)).toEqual({ status: "dropped", reason: "unknown-sender" });
    });

    it("bounds tracked streams per sender and still accepts a fresh stream", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [alice, bob];
        const receiver = cipher({ identity: bob, localLeaf: 1, members });

        // Every restarted sender instance picks a fresh random stream id.
        const streams = Array.from({ length: 9 }, () =>
            cipher({ identity: alice, localLeaf: 0, members }),
        );
        const identifiers = new Set(
            streams.map((instance) => {
                const header = decodeMlsEphemeralHeader(instance.seal(utf8Encode("x")));
                return header === undefined ? "" : header.streamId.join(",");
            }),
        );
        expect(identifiers.size).toBe(9);

        for (const instance of streams) {
            expect(receiver.open(instance.seal(utf8Encode("bounded"))).status).toBe("opened");
        }
    });

    it("refuses to seal more than one bounded payload's worth of bytes", () => {
        const alice = generateIdentityKeyPair();
        const sender = cipher({ identity: alice, localLeaf: 0, members: [alice] });

        expect(() => sender.seal(new Uint8Array(MAX_MLS_EPHEMERAL_PAYLOAD_BYTES + 1))).toThrowError(
            /exceeds/,
        );
    });

    it("drops malformed bytes instead of throwing", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const receiver = cipher({ identity: bob, localLeaf: 1, members: [alice, bob] });

        expect(receiver.open(new Uint8Array(4))).toEqual({
            status: "dropped",
            reason: "malformed",
        });
        expect(receiver.open(new Uint8Array(200))).toEqual({
            status: "dropped",
            reason: "malformed",
        });
    });

    it("produces unrelated key material for a different epoch secret", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const members = [alice, bob];
        const sender = cipher({ identity: alice, localLeaf: 0, members });
        const nextEpochReceiver = cipher({
            identity: bob,
            localLeaf: 1,
            members,
            secret: new Uint8Array(MLS_EPHEMERAL_CHANNEL_SECRET_BYTES).fill(24),
        });

        expect(nextEpochReceiver.open(sender.seal(utf8Encode("stale")))).toEqual({
            status: "dropped",
            reason: "authentication",
        });
    });
});
