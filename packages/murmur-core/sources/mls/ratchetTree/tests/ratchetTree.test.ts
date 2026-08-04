import {
    destroyIdentity,
    equalBytes,
    generateIdentityKeyPair,
    hashBytes,
    utf8Encode,
    zeroBytes,
} from "../../internal.js";
import { describe, expect, it } from "vitest";
import { deriveHpkeKeyPair, mlsSignWithLabel } from "../../cipherSuite/index.js";
import { createMlsKeyPackage, destroyMlsKeyPackageBundle } from "../../keyPackage/index.js";
import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    encodeMlsLeafNodeTbs,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import {
    decodeMlsRatchetTree,
    encodeMlsRatchetTree,
    MlsRatchetTree,
    type MlsRatchetTreeLeaf,
} from "../index.js";

const OFFICIAL_TREE_VECTOR =
    "41a5010120c699b3cad02afaee6c9a0ea2a35f078482e53c830ebba510dc349b2a945ff96b20d9c893be859ac2c6a4ee95820ab1ffc63f8ef371054ae8165225886e6898026a000105416c6963650200010e00010002000300040005000600070000020001032091b43a9ebdd181fc2a368e05627b009a64591ed7bb29d78dcd6bef620351edb7004040efb4542a4364d9ce223ddcd170e0a1889f53ef10b7399b0ccfb0b01127189aeee93ee83810425827e8231f504055a8c41e7b6a3be7b062abdc67272533c66f0a010220566e1f1bddcf6b9a3415e3022c316cb09ba33733f6a307a42c7db653ff6ead7b0000010120129388082a7660bda213aaa17e7d6cd5e2b08b37cfa46e2fa0184cceb340ee2520a0ba7c18b0faa49f7cb51d9e8e76dc18efbadec946ba1a17b946ef2b4453550a000106416c696365310200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040499a320a53322e9f9dd948128d46880d86e37b7905b963b66b22b4135412ef758a27fd31a5ef1bbad2927eda2c3b43d11b5e4ade1a8de36f4606373bddc01502";
const OFFICIAL_ROOT_HASH = "b30fe5a7fce94e0d267f3f8d3e1628c695587370833efcd11584b32978c23dd2";
const TEST_GROUP_ID = utf8Encode("ratchet-tree-tests");
const OFFICIAL_GROUP_ID = hex("99eb8e58d827942e1d519c80de6861e96e365f0c9f4c01bb12daed4a29ae31a9");

function hex(value: string): Uint8Array {
    return Uint8Array.from(Buffer.from(value, "hex"));
}

function publicKey(label: string): Uint8Array {
    const seed = hashBytes(utf8Encode(label));
    const keyPair = deriveHpkeKeyPair(seed);
    try {
        return keyPair.publicKey.slice();
    } finally {
        zeroBytes(seed);
        zeroBytes(keyPair.secretKey);
    }
}

function leaf(label: string): MlsRatchetTreeLeaf {
    const identity = generateIdentityKeyPair();
    const nowSeconds = hashBytes(utf8Encode(label))[0] ?? 0;
    const bundle = createMlsKeyPackage(identity, nowSeconds);
    try {
        const keyPackageLeaf = bundle.keyPackage.leafNode;
        const leafNode: MlsLeafNode = {
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
            encoded: encodeMlsLeafNode(leafNode),
            encryptionKey: leafNode.encryptionKey,
            signatureKey: leafNode.signatureKey,
        };
    } finally {
        destroyMlsKeyPackageBundle(bundle);
        destroyIdentity(identity);
    }
}

function commitLeaf(label: string, parentHash: Uint8Array, leafIndex: number): MlsRatchetTreeLeaf {
    const identity = generateIdentityKeyPair();
    try {
        const unsigned: Omit<MlsLeafNode, "signature"> = {
            encryptionKey: publicKey(`commit:${label}`),
            signatureKey: identity.publicKey,
            credential: { identity: identity.publicKey },
            capabilities: defaultMlsLeafCapabilities(),
            source: "commit",
            parentHash,
            extensions: [],
        };
        const context = { groupId: TEST_GROUP_ID, leafIndex };
        const leafNode: MlsLeafNode = {
            ...unsigned,
            signature: mlsSignWithLabel(
                identity.secretKey,
                "LeafNodeTBS",
                encodeMlsLeafNodeTbs(unsigned, context),
            ),
        };
        return {
            type: "leaf",
            encoded: encodeMlsLeafNode(leafNode, context),
            encryptionKey: leafNode.encryptionKey,
            signatureKey: leafNode.signatureKey,
            parentHash,
        };
    } finally {
        destroyIdentity(identity);
    }
}

describe("MLS public ratchet tree", () => {
    it("matches the official MLS working-group tree-validation vector", () => {
        const encoded = hex(OFFICIAL_TREE_VECTOR);
        const tree = decodeMlsRatchetTree(encoded, {
            groupId: OFFICIAL_GROUP_ID,
            authenticateCredential: () => true,
        });

        expect(Buffer.from(tree.treeHash()).toString("hex")).toBe(OFFICIAL_ROOT_HASH);
        expect(tree.resolution(0)).toEqual([0]);
        expect(tree.resolution(1)).toEqual([1]);
        expect(tree.resolution(2)).toEqual([2]);
        expect(encodeMlsRatchetTree(tree)).toEqual(encoded);
    });

    it("computes resolutions and filtered paths in RFC order", () => {
        const tree = new MlsRatchetTree([
            leaf("A"),
            {
                type: "parent",
                encryptionKey: publicKey("parent:X"),
                parentHash: new Uint8Array(),
                unmergedLeaves: [1],
            },
            leaf("B"),
            undefined,
            undefined,
            undefined,
            leaf("H"),
        ]);

        expect(tree.resolution(1)).toEqual([1, 2]);
        expect(tree.resolution(3)).toEqual([1, 2, 6]);
        expect(tree.filteredDirectPath(0)).toEqual([1, 3]);
    });

    it("adds leftmost, removes, truncates, and merges public paths", () => {
        const tree = new MlsRatchetTree([
            leaf("A"),
            undefined,
            leaf("B"),
            undefined,
            undefined,
            undefined,
            leaf("D"),
        ]);
        expect(tree.addLeaf(leaf("C"))).toBe(2);
        expect(tree.leafCount).toBe(4);

        tree.removeLeaf(3);
        expect(tree.leafCount).toBe(4);
        tree.removeLeaf(2);
        expect(tree.leafCount).toBe(2);

        const expectedParentHash = tree.prepareUpdatePath(0, [publicKey("path:AB")]);
        tree.setCommitLeaf(0, commitLeaf("A2", expectedParentHash, 0));
        expect(tree.nodes[1]?.type).toBe("parent");
        expect(tree.filteredDirectPath(0)).toEqual([1]);
    });

    it("produces stable, mutation-sensitive RFC tree hashes", () => {
        const tree = new MlsRatchetTree([leaf("A"), undefined, leaf("B")]);
        const before = tree.treeHash();
        expect(equalBytes(before, tree.clone().treeHash())).toBe(true);

        const expectedParentHash = tree.prepareUpdatePath(0, [publicKey("path:root")]);
        tree.setCommitLeaf(0, commitLeaf("A2", expectedParentHash, 0));
        expect(equalBytes(before, tree.treeHash())).toBe(false);
    });

    it("rejects duplicate canonical HPKE keys", () => {
        const shared = leaf("shared");
        expect(() => new MlsRatchetTree([shared, undefined, shared])).toThrow("Duplicate");
    });

    it("rejects unauthenticated leaf fields and invalid unmerged ancestry", () => {
        const authenticated = leaf("authenticated");
        expect(
            () =>
                new MlsRatchetTree([
                    {
                        ...authenticated,
                        encryptionKey: publicKey("substituted"),
                    },
                ]),
        ).toThrow("disagree");

        const invalidAncestry = new MlsRatchetTree([
            leaf("left"),
            {
                type: "parent",
                encryptionKey: publicKey("parent"),
                parentHash: new Uint8Array(),
                unmergedLeaves: [1],
            },
            undefined,
        ]);
        expect(() =>
            invalidAncestry.validate({
                groupId: TEST_GROUP_ID,
                authenticateCredential: () => true,
            }),
        ).toThrow("ancestry");

        expect(
            () =>
                new MlsRatchetTree([
                    leaf("left-root"),
                    {
                        type: "parent",
                        encryptionKey: publicKey("invalid-root"),
                        parentHash: new Uint8Array(32),
                        unmergedLeaves: [],
                    },
                    leaf("right-root"),
                ]),
        ).toThrow("root parent hash");
    });

    it("strips and restores trailing blank extension nodes", () => {
        const tree = new MlsRatchetTree([
            leaf("first"),
            undefined,
            leaf("second"),
            undefined,
            undefined,
            undefined,
            undefined,
        ]);
        const encoded = encodeMlsRatchetTree(tree);
        const decoded = decodeMlsRatchetTree(encoded, {
            groupId: TEST_GROUP_ID,
            authenticateCredential: () => true,
        });

        expect(decoded.leafCount).toBe(2);
        expect(decoded.nodes).toHaveLength(3);
        expect(decoded.nodes[1]).toBeUndefined();
        expect(decoded.nodes[2]?.type).toBe("leaf");
    });
});
