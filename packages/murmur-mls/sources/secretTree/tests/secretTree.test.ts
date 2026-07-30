import { equalBytes, hashBytes, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import { destroyMlsGenerationKey, destroyMlsSecretTreeState, MlsSecretTree } from "../index.js";

describe("MLS Secret Tree", () => {
    it("derives matching one-time application keys for independent members", () => {
        const root = hashBytes(utf8Encode("epoch encryption secret"));
        const senderTree = new MlsSecretTree(root, 3);
        const receiverTree = new MlsSecretTree(root, 3);

        const outbound = senderTree.next(1, "application");
        const inbound = receiverTree.take(1, "application", outbound.generation);

        expect(equalBytes(outbound.key, inbound.key)).toBe(true);
        expect(equalBytes(outbound.nonce, inbound.nonce)).toBe(true);
        expect(receiverTree.take.bind(receiverTree, 1, "application", 0)).toThrow("consumed");

        destroyMlsGenerationKey(outbound);
        destroyMlsGenerationKey(inbound);
        senderTree.destroy();
        receiverTree.destroy();
    });

    it("retains bounded skipped keys and separates handshake ratchets", () => {
        const root = hashBytes(utf8Encode("epoch encryption secret"));
        const senderTree = new MlsSecretTree(root, 2);
        const receiverTree = new MlsSecretTree(root, 2, 2);
        const generation0 = senderTree.next(0, "application");
        const generation1 = senderTree.next(0, "application");
        const generation2 = senderTree.next(0, "application");

        const received2 = receiverTree.take(0, "application", 2);
        const received0 = receiverTree.take(0, "application", 0);
        const handshake = receiverTree.take(0, "handshake", 0);

        expect(equalBytes(received2.key, generation2.key)).toBe(true);
        expect(equalBytes(received0.key, generation0.key)).toBe(true);
        expect(equalBytes(received0.key, handshake.key)).toBe(false);
        expect(() => receiverTree.take(0, "application", 0)).toThrow("consumed");

        for (const key of [
            generation0,
            generation1,
            generation2,
            received2,
            received0,
            handshake,
        ]) {
            destroyMlsGenerationKey(key);
        }
        senderTree.destroy();
        receiverTree.destroy();
    });

    it("rejects generations beyond the forward-distance limit", () => {
        const tree = new MlsSecretTree(hashBytes(utf8Encode("root")), 1, 1);

        expect(() => tree.take(0, "application", 2)).toThrow("future");
        tree.destroy();
        expect(() => tree.next(0, "application")).toThrow("destroyed");
        expect(() => new MlsSecretTree(hashBytes(utf8Encode("root")), 1, 10_001)).toThrow(
            "forward-distance",
        );
    });

    it("enforces a tree-wide skipped-key budget before advancing", () => {
        const tree = new MlsSecretTree(hashBytes(utf8Encode("root")), 2, 10, 1);

        expect(() => tree.take(0, "application", 2)).toThrow("budget");
        const generation0 = tree.take(0, "application", 0);
        expect(generation0.generation).toBe(0);
        destroyMlsGenerationKey(generation0);
        tree.destroy();
    });

    it("restores a generation after authenticated opening fails", () => {
        const tree = new MlsSecretTree(hashBytes(utf8Encode("root")), 1);

        expect(() =>
            tree.use(0, "application", 0, () => {
                throw new Error("invalid ciphertext");
            }),
        ).toThrow("invalid ciphertext");
        expect(tree.use(0, "application", 0, (generationKey) => generationKey.generation)).toBe(0);
        expect(() => tree.take(0, "application", 0)).toThrow("consumed");
        tree.destroy();
    });

    it("burns a generation exposed to an async use callback", () => {
        const tree = new MlsSecretTree(hashBytes(utf8Encode("root")), 1);

        expect(() => tree.use(0, "application", 0, async () => 1)).toThrow("synchronous");
        expect(() => tree.take(0, "application", 0)).toThrow("consumed");
        tree.destroy();
    });

    it("snapshots ratchet generations, skipped keys, and the forward-secret frontier", () => {
        const tree = new MlsSecretTree(hashBytes(utf8Encode("durable root")), 4);
        destroyMlsGenerationKey(tree.next(1, "application"));
        destroyMlsGenerationKey(tree.take(2, "application", 2));
        const state = tree.snapshot();
        const restored = MlsSecretTree.fromState(state);

        const originalNext = tree.next(1, "application");
        const restoredNext = restored.next(1, "application");
        const originalSkipped = tree.take(2, "application", 0);
        const restoredSkipped = restored.take(2, "application", 0);

        expect(restoredNext.generation).toBe(1);
        expect(equalBytes(restoredNext.key, originalNext.key)).toBe(true);
        expect(equalBytes(restoredSkipped.key, originalSkipped.key)).toBe(true);
        expect(() =>
            MlsSecretTree.fromState({
                ...state,
                nodeSecrets: [...state.nodeSecrets, ...state.nodeSecrets],
            }),
        ).toThrow("snapshot");

        for (const key of [originalNext, restoredNext, originalSkipped, restoredSkipped]) {
            destroyMlsGenerationKey(key);
        }
        tree.destroy();
        restored.destroy();
        destroyMlsSecretTreeState(state);
        expect(
            state.ratchets.every(
                (ratchet) =>
                    ratchet.secret.every((byte) => byte === 0) &&
                    ratchet.skipped.every(
                        (skipped) =>
                            skipped.key.every((byte) => byte === 0) &&
                            skipped.nonce.every((byte) => byte === 0),
                    ),
            ),
        ).toBe(true);
    });
});
