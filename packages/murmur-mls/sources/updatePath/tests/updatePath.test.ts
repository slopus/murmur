import { equalBytes, generateIdentityKeyPair, hashBytes, utf8Encode } from "@murmur/core";
import { describe, expect, it } from "vitest";
import { type IdentityKeyPair } from "@murmur/core";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    type MlsKeyPackageBundle,
} from "../../keyPackage/index.js";
import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    encodeMlsLeafNodeTbs,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import { mlsSignWithLabel } from "../../cipherSuite/index.js";
import {
    decodeMlsRatchetTree,
    MlsRatchetTree,
    type MlsRatchetTreeLeaf,
} from "../../ratchetTree/index.js";
import {
    createMlsUpdatePath,
    decodeMlsUpdatePath,
    destroyMlsUpdatePathResult,
    encodeMlsUpdatePath,
    openMlsUpdatePath,
} from "../index.js";

const OFFICIAL_TREE =
    "41da010120c929637bda524adad04ac85cf8ab7164d9cd88139aef5c9f7157902707c3fb5820c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c000100020003000400050006000004000100020320be6b0e33b576ab16727c86317eee6b8bbc20b641440f1f55ed68a4861b6746f70040404007c2a631b8a394f6cb8704b1cbbe2e149241ca32f316ffc6f8a541521b0a298dc0239d0ec0e8ab77f3c39b5810da1815d3a83dd4797d0ea5a0488718b8af0201022029eb3645264612282039eb7ddb095a780f39b1904a9613aaad568642a4b9b2040000010120d17b7296c1ac920c635574c84ee59f11c43bf534f4135225dbf1ac360e4629092018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e866138390325d0200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040405ca8f99de58c59bc29c4d7b5bbc489ca7a62a8971d5944080940cf14d6795443a20cd96c290a67b59c28a53e9e9795ac9f21cbb257ca333e75e72e5582ca8e0f";
const OFFICIAL_UPDATE_PATH =
    "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c0001000200030004000500060000040001000203204ab91adcf7be9ea795042e1fd2d3c2021d3bdc7c0a767bb13b96f4b2b75b7188004040c42e9b322d874ac6f51b40fdad15f740ff99e85fa86c0c5da28dddcb9667403eb94e55bd34fd610be9308c86b3e881b1751649f15d34ede85689f59968116202407520875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220c8d8c0ec4526045cce5979e3cb3a2435322b20cb224073c1b00ef0deb336d50b30f7b94d151d792713a4814d0bc3219d627fe44c0f82258db4804ea79bda9c18027da4c9a4ef89cc703d70049104889432";

function hex(value: string): Uint8Array {
    return Uint8Array.from(Buffer.from(value, "hex"));
}

function leafNode(bundle: MlsKeyPackageBundle): MlsLeafNode {
    const leaf = bundle.keyPackage.leafNode;
    return {
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
        credential: leaf.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: leaf.notBefore,
        notAfter: leaf.notAfter,
        extensions: [],
        signature: leaf.signature,
    };
}

function publicLeaf(bundle: MlsKeyPackageBundle): MlsRatchetTreeLeaf {
    const leaf = leafNode(bundle);
    return {
        type: "leaf",
        encoded: encodeMlsLeafNode(leaf),
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
    };
}

function provisional(groupId: Uint8Array) {
    return {
        groupId,
        epoch: 2n,
        confirmedTranscriptHash: hashBytes(utf8Encode("confirmed")),
    };
}

function privateLeaf(index: number, bundle: MlsKeyPackageBundle) {
    return {
        node: index * 2,
        keyPair: bundle.leafKeyPair,
    };
}

function authenticateCredential(leaf: MlsLeafNode): boolean {
    return equalBytes(leaf.credential.identity, leaf.signatureKey);
}

describe("MLS UpdatePath", () => {
    it("opens the official MLS working-group TreeKEM vector", () => {
        const groupId = hex("476813a66a9e9a464c40e79f4f8449d939d9235c56ea955ba7e230ec6d7f6b03");
        const tree = decodeMlsRatchetTree(hex(OFFICIAL_TREE), {
            groupId,
            authenticateCredential: () => true,
        });
        const recipient = tree.nodes[2];
        if (recipient?.type !== "leaf") {
            throw new Error("Official vector recipient leaf is missing");
        }
        const path = decodeMlsUpdatePath(hex(OFFICIAL_UPDATE_PATH));
        expect(
            Buffer.from(
                encodeMlsUpdatePath(path, {
                    groupId: hex(
                        "476813a66a9e9a464c40e79f4f8449d939d9235c56ea955ba7e230ec6d7f6b03",
                    ),
                    leafIndex: 0,
                }),
            ).toString("hex"),
        ).toBe(OFFICIAL_UPDATE_PATH);
        const candidate = tree.clone();
        candidate.mergeUpdatePath(
            0,
            {
                type: "leaf",
                encoded: encodeMlsLeafNode(path.leafNode, {
                    groupId: hex(
                        "476813a66a9e9a464c40e79f4f8449d939d9235c56ea955ba7e230ec6d7f6b03",
                    ),
                    leafIndex: 0,
                }),
                encryptionKey: path.leafNode.encryptionKey,
                signatureKey: path.leafNode.signatureKey,
                parentHash: path.leafNode.parentHash!,
            },
            path.nodes.map((node) => node.encryptionKey),
        );
        expect(Buffer.from(candidate.treeHash()).toString("hex")).toBe(
            "e90f531363f40f04a0e5207e4fcdad46fb9398ca2c208eee1c198ea3e73876c5",
        );
        const result = openMlsUpdatePath({
            tree,
            sender: 0,
            path,
            provisionalContext: {
                groupId,
                epoch: 28061n,
                confirmedTranscriptHash: hex(
                    "7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5",
                ),
            },
            localLeaf: 1,
            privateKeys: [
                {
                    node: 2,
                    keyPair: {
                        secretKey: hex(
                            "2a7ab9e8c1a8077944fa0f59303faf1d7da5ec43c7a3f345910c87478d12c202",
                        ),
                        publicKey: recipient.encryptionKey,
                    },
                },
            ],
            authenticateCredential: () => true,
        });

        expect(Buffer.from(result.commitSecret).toString("hex")).toBe(
            "5ccc25c82569cc9731283abbdb9265187c17503e6f9c4ba2484a9e210e83f5a3",
        );
        expect(Buffer.from(result.tree.treeHash()).toString("hex")).toBe(
            "e90f531363f40f04a0e5207e4fcdad46fb9398ca2c208eee1c198ea3e73876c5",
        );
        destroyMlsUpdatePathResult(result);
    });

    it("distributes the same commit secret to another member", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const aliceBundle = createMlsKeyPackage(alice);
        const bobBundle = createMlsKeyPackage(bob);
        const tree = new MlsRatchetTree([
            publicLeaf(aliceBundle),
            undefined,
            publicLeaf(bobBundle),
        ]);
        const groupId = utf8Encode("two-member-update");
        const created = createMlsUpdatePath({
            tree,
            sender: 0,
            signingSecretKey: alice.signingSecretKey,
            provisionalContext: provisional(groupId),
            authenticateCredential,
            leafSecret: hashBytes(utf8Encode("leaf secret")),
            firstPathSecret: hashBytes(utf8Encode("path secret")),
        });
        const encoded = encodeMlsUpdatePath(created.path, {
            groupId,
            leafIndex: 0,
        });
        const decoded = decodeMlsUpdatePath(encoded);
        const forgedParentHash = decoded.leafNode.parentHash;
        if (forgedParentHash === undefined) {
            throw new Error("Generated UpdatePath is missing a parent hash");
        }
        const attacker = generateIdentityKeyPair();
        const forgedUnsigned: Omit<MlsLeafNode, "signature"> = {
            encryptionKey: decoded.leafNode.encryptionKey,
            signatureKey: attacker.signingKey,
            credential: { identity: attacker.signingKey },
            capabilities: decoded.leafNode.capabilities,
            source: "commit",
            parentHash: forgedParentHash,
            extensions: decoded.leafNode.extensions,
        };
        const forged = {
            ...decoded,
            leafNode: {
                ...forgedUnsigned,
                signature: mlsSignWithLabel(
                    attacker.signingSecretKey,
                    "LeafNodeTBS",
                    encodeMlsLeafNodeTbs(forgedUnsigned, { groupId, leafIndex: 0 }),
                ),
            },
        };
        expect(() =>
            openMlsUpdatePath({
                tree,
                sender: 0,
                path: forged,
                provisionalContext: provisional(groupId),
                localLeaf: 1,
                privateKeys: [privateLeaf(1, bobBundle)],
                authenticateCredential,
            }),
        ).toThrow("LeafNode");
        const metadataUnsigned: Omit<MlsLeafNode, "signature"> = {
            encryptionKey: decoded.leafNode.encryptionKey,
            signatureKey: decoded.leafNode.signatureKey,
            credential: decoded.leafNode.credential,
            capabilities: {
                ...decoded.leafNode.capabilities,
                versions: [...decoded.leafNode.capabilities.versions, 0x0a0a],
            },
            source: "commit",
            parentHash: forgedParentHash,
            extensions: decoded.leafNode.extensions,
        };
        const metadataTamper = {
            ...decoded,
            leafNode: {
                ...metadataUnsigned,
                signature: mlsSignWithLabel(
                    alice.signingSecretKey,
                    "LeafNodeTBS",
                    encodeMlsLeafNodeTbs(metadataUnsigned, { groupId, leafIndex: 0 }),
                ),
            },
        };
        expect(() =>
            openMlsUpdatePath({
                tree,
                sender: 0,
                path: metadataTamper,
                provisionalContext: provisional(groupId),
                localLeaf: 1,
                privateKeys: [privateLeaf(1, bobBundle)],
                authenticateCredential,
            }),
        ).toThrow("LeafNode");
        const equivalentBobKey = privateLeaf(1, bobBundle);
        equivalentBobKey.keyPair.publicKey[31] =
            (equivalentBobKey.keyPair.publicKey[31] ?? 0) | 0x80;
        const opened = openMlsUpdatePath({
            tree,
            sender: 0,
            path: decoded,
            provisionalContext: provisional(groupId),
            localLeaf: 1,
            privateKeys: [equivalentBobKey],
            authenticateCredential,
        });

        expect(equalBytes(opened.commitSecret, created.commitSecret)).toBe(true);
        expect(equalBytes(opened.tree.treeHash(), created.tree.treeHash())).toBe(true);

        destroyMlsUpdatePathResult(created);
        destroyMlsUpdatePathResult(opened);
        destroyMlsKeyPackageBundle(aliceBundle);
        destroyMlsKeyPackageBundle(bobBundle);
    });

    it("creates a valid single-member empty-path update", () => {
        const alice = generateIdentityKeyPair();
        const bundle = createMlsKeyPackage(alice);
        const groupId = utf8Encode("single-member");
        const created = createMlsUpdatePath({
            tree: new MlsRatchetTree([publicLeaf(bundle)]),
            sender: 0,
            signingSecretKey: alice.signingSecretKey,
            provisionalContext: provisional(groupId),
            authenticateCredential,
        });

        expect(created.path.nodes).toEqual([]);
        expect(created.path.leafNode.parentHash).toEqual(new Uint8Array());
        destroyMlsUpdatePathResult(created);
        destroyMlsKeyPackageBundle(bundle);
    });

    it("excludes a removed member while a retained member advances", () => {
        const identities: IdentityKeyPair[] = Array.from({ length: 3 }, generateIdentityKeyPair);
        const bundles = identities.map((identity) => createMlsKeyPackage(identity));
        const tree = new MlsRatchetTree([
            publicLeaf(bundles[0]!),
            undefined,
            publicLeaf(bundles[1]!),
            undefined,
            publicLeaf(bundles[2]!),
            undefined,
            undefined,
        ]);
        const candidate = tree.clone();
        candidate.removeLeaf(1);
        const groupId = utf8Encode("remove-member");
        const created = createMlsUpdatePath({
            tree: candidate,
            sender: 0,
            signingSecretKey: identities[0]!.signingSecretKey,
            provisionalContext: provisional(groupId),
            authenticateCredential,
        });

        expect(() =>
            openMlsUpdatePath({
                tree: candidate,
                sender: 0,
                path: created.path,
                provisionalContext: provisional(groupId),
                localLeaf: 1,
                privateKeys: [privateLeaf(1, bundles[1]!)],
                authenticateCredential,
            }),
        ).toThrow("removed");
        const retained = openMlsUpdatePath({
            tree: candidate,
            sender: 0,
            path: created.path,
            provisionalContext: provisional(groupId),
            localLeaf: 2,
            privateKeys: [privateLeaf(2, bundles[2]!)],
            authenticateCredential,
        });
        expect(equalBytes(retained.commitSecret, created.commitSecret)).toBe(true);

        destroyMlsUpdatePathResult(created);
        destroyMlsUpdatePathResult(retained);
        for (const bundle of bundles) {
            destroyMlsKeyPackageBundle(bundle);
        }
    });
});
