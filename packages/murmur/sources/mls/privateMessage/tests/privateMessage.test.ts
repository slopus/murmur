import { generateIdentityKeyPair, hashBytes, utf8Decode, utf8Encode } from "../../internal.js";
import { describe, expect, it } from "vitest";
import { type MlsGroupContext } from "../../groupContext/index.js";
import { MlsSecretTree } from "../../secretTree/index.js";
import {
    decodeMlsPrivateMessage,
    encodeMlsPrivateMessage,
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
} from "../index.js";

function context(): MlsGroupContext {
    return {
        groupId: utf8Encode("group"),
        epoch: 7n,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("transcript")),
    };
}

describe("MLS application PrivateMessage", () => {
    it("hides sender data and round trips signed application content", () => {
        const alice = generateIdentityKeyPair();
        const epoch = hashBytes(utf8Encode("encryption"));
        const senderDataSecret = hashBytes(utf8Encode("sender data"));
        const senderTree = new MlsSecretTree(epoch, 2);
        const receiverTree = new MlsSecretTree(epoch, 2);
        const message = sealMlsApplicationMessage({
            context: context(),
            sender: 0,
            signingSecretKey: alice.secretKey,
            senderDataSecret,
            secretTree: senderTree,
            applicationData: utf8Encode("private"),
            authenticatedData: utf8Encode("aad"),
            paddingBytes: 32,
        });

        const parsed = decodeMlsPrivateMessage(message);
        expect(parsed.ciphertext).not.toEqual(utf8Encode("private"));
        const opened = openMlsApplicationMessage({
            context: context(),
            senderDataSecret,
            secretTree: receiverTree,
            message,
            signatureKeyFor: (sender) => (sender === 0 ? alice.publicKey : undefined),
        });

        expect(utf8Decode(opened.applicationData)).toBe("private");
        expect(utf8Decode(opened.authenticatedData)).toBe("aad");
        expect(opened).toMatchObject({ sender: 0, generation: 0 });
        senderTree.destroy();
        receiverTree.destroy();
    });

    it("rejects tampering without burning the legitimate generation", () => {
        const alice = generateIdentityKeyPair();
        const epoch = hashBytes(utf8Encode("encryption"));
        const senderDataSecret = hashBytes(utf8Encode("sender data"));
        const senderTree = new MlsSecretTree(epoch, 1);
        const receiverTree = new MlsSecretTree(epoch, 1);
        const message = sealMlsApplicationMessage({
            context: context(),
            sender: 0,
            signingSecretKey: alice.secretKey,
            senderDataSecret,
            secretTree: senderTree,
            applicationData: utf8Encode("private"),
        });
        const parsed = decodeMlsPrivateMessage(message);
        const tampered = parsed.ciphertext.slice();
        tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
        const encodedTampered = encodeMlsPrivateMessage({
            ...parsed,
            ciphertext: tampered,
        });

        expect(() =>
            openMlsApplicationMessage({
                context: context(),
                senderDataSecret,
                secretTree: receiverTree,
                message: encodedTampered,
                signatureKeyFor: () => alice.publicKey,
            }),
        ).toThrow();
        expect(
            utf8Decode(
                openMlsApplicationMessage({
                    context: context(),
                    senderDataSecret,
                    secretTree: receiverTree,
                    message,
                    signatureKeyFor: () => alice.publicKey,
                }).applicationData,
            ),
        ).toBe("private");
        senderTree.destroy();
        receiverTree.destroy();
    });
});
