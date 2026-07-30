import { encodeBase64Url, equalBytes, randomBytes, zeroBytes } from "@slopus/murmur";
import {
    canonicalizeHpkePublicKey,
    deriveHpkeKeyPair,
    isHpkeKeyPair,
    mlsDecryptWithLabel,
    mlsDeriveSecret,
    mlsEncryptWithLabel,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
    type HpkeKeyPair,
} from "../cipherSuite/index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../groupContext/index.js";
import {
    decodeMlsLeafNodeBytes,
    encodeMlsLeafNode,
    encodeMlsLeafNodeTbs,
    type MlsLeafNode,
} from "../leafNode/index.js";
import { type MlsRatchetTreeLeaf } from "../ratchetTree/index.js";
import { copath, directPath, leafNode } from "../tree/index.js";
import type {
    CreateMlsUpdatePathOptions,
    DeriveMlsWelcomePrivateKeysOptions,
    MlsTreePrivateKey,
    MlsUpdatePath,
    MlsUpdatePathResult,
    MlsValidatedUpdatePath,
    OpenMlsUpdatePathOptions,
    ValidateMlsUpdatePathOptions,
} from "./types.js";

export type {
    CreateMlsUpdatePathOptions,
    DeriveMlsWelcomePrivateKeysOptions,
    MlsTreePrivateKey,
    MlsUpdatePath,
    MlsUpdatePathNode,
    MlsUpdatePathResult,
    MlsValidatedUpdatePath,
    OpenMlsUpdatePathOptions,
    ValidateMlsUpdatePathOptions,
} from "./types.js";
export {
    decodeMlsUpdatePath,
    decodeMlsUpdatePathFromReader,
    encodeMlsUpdatePath,
    type MlsUpdatePathReader,
} from "./impl/codec.js";

function deriveNodeKeyPair(pathSecret: Uint8Array): HpkeKeyPair {
    const nodeSecret = mlsDeriveSecret(pathSecret, "node");
    try {
        return deriveHpkeKeyPair(nodeSecret);
    } finally {
        zeroBytes(nodeSecret);
    }
}

function copyKey(node: number, keyPair: HpkeKeyPair): MlsTreePrivateKey {
    return {
        node,
        keyPair: {
            secretKey: keyPair.secretKey.slice(),
            publicKey: keyPair.publicKey.slice(),
        },
    };
}

function publicLeaf(leaf: MlsLeafNode, sender: number, groupId: Uint8Array): MlsRatchetTreeLeaf {
    return {
        type: "leaf",
        encoded: encodeMlsLeafNode(leaf, { groupId, leafIndex: sender }),
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
        ...(leaf.parentHash === undefined ? {} : { parentHash: leaf.parentHash }),
    };
}

function provisionalContext(
    options: Pick<CreateMlsUpdatePathOptions, "provisionalContext">,
    treeHash: Uint8Array,
): MlsGroupContext {
    return {
        groupId: options.provisionalContext.groupId.slice(),
        epoch: options.provisionalContext.epoch,
        confirmedTranscriptHash: options.provisionalContext.confirmedTranscriptHash.slice(),
        treeHash,
    };
}

function pathEntries(
    tree: CreateMlsUpdatePathOptions["tree"],
    sender: number,
): readonly { readonly node: number; readonly sibling: number }[] {
    const path = directPath(sender, tree.leafCount);
    const siblings = copath(sender, tree.leafCount);
    return path.flatMap((node, index) => {
        const sibling = siblings[index];
        return sibling !== undefined && tree.resolution(sibling).length > 0
            ? [{ node, sibling }]
            : [];
    });
}

function validateFreshKeys(
    tree: CreateMlsUpdatePathOptions["tree"],
    encryptionKeys: readonly Uint8Array[],
): void {
    const existing = new Set(
        tree.nodes.flatMap((node) =>
            node === undefined
                ? []
                : [encodeBase64Url(canonicalizeHpkePublicKey(node.encryptionKey))],
        ),
    );
    const fresh = new Set<string>();
    for (const encryptionKey of encryptionKeys) {
        const identifier = encodeBase64Url(canonicalizeHpkePublicKey(encryptionKey));
        if (existing.has(identifier) || fresh.has(identifier)) {
            throw new Error("MLS UpdatePath reuses an encryption key");
        }
        fresh.add(identifier);
    }
}

function equalNumberVectors(left: readonly number[], right: readonly number[]): boolean {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}

function equalLeafMetadata(left: MlsLeafNode, right: MlsLeafNode): boolean {
    return (
        equalBytes(left.signatureKey, right.signatureKey) &&
        equalBytes(left.credential.identity, right.credential.identity) &&
        equalNumberVectors(left.capabilities.versions, right.capabilities.versions) &&
        equalNumberVectors(left.capabilities.cipherSuites, right.capabilities.cipherSuites) &&
        equalNumberVectors(left.capabilities.extensions, right.capabilities.extensions) &&
        equalNumberVectors(left.capabilities.proposals, right.capabilities.proposals) &&
        equalNumberVectors(left.capabilities.credentials, right.capabilities.credentials) &&
        left.extensions.length === right.extensions.length &&
        left.extensions.every(
            (extension, index) =>
                extension.type === right.extensions[index]?.type &&
                equalBytes(extension.data, right.extensions[index]!.data),
        )
    );
}

/** Generate, sign, merge, and encrypt one RFC 9420 UpdatePath. */
export function createMlsUpdatePath(options: CreateMlsUpdatePathOptions): MlsUpdatePathResult {
    const tree = options.tree.clone();
    const currentPublicLeaf = tree.nodes[leafNode(options.sender, tree.leafCount)];
    if (currentPublicLeaf?.type !== "leaf") {
        throw new Error("MLS UpdatePath sender leaf is blank");
    }
    const currentLeaf = decodeMlsLeafNodeBytes(currentPublicLeaf.encoded);
    const entries = pathEntries(tree, options.sender);
    const leafSecret = options.leafSecret?.slice() ?? randomBytes(32);
    let currentPathSecret = options.firstPathSecret?.slice() ?? randomBytes(32);
    if (leafSecret.length !== 32 || currentPathSecret.length !== 32) {
        zeroBytes(leafSecret);
        zeroBytes(currentPathSecret);
        throw new Error("MLS TreeKEM secrets must be 32 bytes");
    }
    const retainedKeys: MlsTreePrivateKey[] = [];
    const retainedPathSecrets: Array<{ readonly node: number; readonly secret: Uint8Array }> = [];
    const pathKeyPairs: HpkeKeyPair[] = [];
    let commitSecret: Uint8Array | undefined;
    try {
        const leafKeyPair = deriveNodeKeyPair(leafSecret);
        try {
            retainedKeys.push(copyKey(leafNode(options.sender, tree.leafCount), leafKeyPair));
        } finally {
            zeroBytes(leafKeyPair.secretKey);
        }

        for (const entry of entries) {
            const pathSecret = currentPathSecret;
            retainedPathSecrets.push({ node: entry.node, secret: pathSecret.slice() });
            const keyPair = deriveNodeKeyPair(pathSecret);
            pathKeyPairs.push(keyPair);
            retainedKeys.push(copyKey(entry.node, keyPair));
            currentPathSecret = mlsDeriveSecret(pathSecret, "path");
            zeroBytes(pathSecret);
        }
        commitSecret = currentPathSecret;
        validateFreshKeys(options.tree, [
            retainedKeys[0]!.keyPair.publicKey,
            ...pathKeyPairs.map((keyPair) => keyPair.publicKey),
        ]);
        const parentHash = tree.prepareUpdatePath(
            options.sender,
            pathKeyPairs.map((keyPair) => keyPair.publicKey),
        );
        const unsignedLeaf: Omit<MlsLeafNode, "signature"> = {
            encryptionKey: retainedKeys[0]!.keyPair.publicKey,
            signatureKey: currentLeaf.signatureKey,
            credential: currentLeaf.credential,
            capabilities: currentLeaf.capabilities,
            source: "commit",
            parentHash,
            extensions: currentLeaf.extensions,
        };
        const signatureContext = {
            groupId: options.provisionalContext.groupId,
            leafIndex: options.sender,
        };
        const leaf: MlsLeafNode = {
            ...unsignedLeaf,
            signature: mlsSignWithLabel(
                options.signingSecretKey,
                "LeafNodeTBS",
                encodeMlsLeafNodeTbs(unsignedLeaf, signatureContext),
            ),
        };
        if (
            !mlsVerifyWithLabel(
                leaf.signatureKey,
                "LeafNodeTBS",
                encodeMlsLeafNodeTbs(unsignedLeaf, signatureContext),
                leaf.signature,
            )
        ) {
            throw new Error("MLS UpdatePath signing key does not match sender");
        }
        tree.setCommitLeaf(
            options.sender,
            publicLeaf(leaf, options.sender, options.provisionalContext.groupId),
        );
        const context = provisionalContext(options, tree.treeHash());
        const encodedContext = encodeMlsGroupContext(context);
        const nodes = entries.map((entry, index) => {
            const pathSecret = retainedPathSecrets[index]?.secret;
            const keyPair = pathKeyPairs[index];
            if (pathSecret === undefined || keyPair === undefined) {
                throw new Error("MLS UpdatePath derivation mismatch");
            }
            const resolution = tree.resolution(entry.sibling, options.excludedNewLeaves);
            const snapshot = tree.nodes;
            return {
                encryptionKey: keyPair.publicKey.slice(),
                encryptedPathSecrets: resolution.map((node) => {
                    const recipient = snapshot[node];
                    if (recipient === undefined) {
                        throw new Error("MLS UpdatePath resolution contains a blank node");
                    }
                    return mlsEncryptWithLabel(
                        recipient.encryptionKey,
                        "UpdatePathNode",
                        encodedContext,
                        pathSecret,
                    );
                }),
            };
        });
        tree.validate({
            groupId: options.provisionalContext.groupId,
            authenticateCredential: options.authenticateCredential,
        });
        return {
            tree,
            path: { leafNode: leaf, nodes },
            context,
            commitSecret,
            privateKeys: retainedKeys,
            pathSecrets: retainedPathSecrets,
        };
    } catch (error: unknown) {
        if (commitSecret !== undefined) {
            zeroBytes(commitSecret);
        } else {
            zeroBytes(currentPathSecret);
        }
        for (const key of retainedKeys) {
            zeroBytes(key.keyPair.secretKey);
        }
        for (const pathSecret of retainedPathSecrets) {
            zeroBytes(pathSecret.secret);
        }
        throw error;
    } finally {
        zeroBytes(leafSecret);
        for (const keyPair of pathKeyPairs) {
            zeroBytes(keyPair.secretKey);
        }
    }
}

function authenticatePublicUpdatePath(options: ValidateMlsUpdatePathOptions): {
    readonly treeBefore: CreateMlsUpdatePathOptions["tree"];
    readonly entries: readonly { readonly node: number; readonly sibling: number }[];
    readonly tree: CreateMlsUpdatePathOptions["tree"];
    readonly context: MlsGroupContext;
} {
    const treeBefore = options.tree.clone();
    const entries = pathEntries(treeBefore, options.sender);
    if (entries.length !== options.path.nodes.length) {
        throw new Error("MLS UpdatePath length does not match filtered direct path");
    }
    const currentSender = treeBefore.nodes[leafNode(options.sender, treeBefore.leafCount)];
    if (currentSender?.type !== "leaf") {
        throw new Error("MLS UpdatePath sender leaf is blank");
    }
    const authenticatedSenderLeaf = decodeMlsLeafNodeBytes(currentSender.encoded);
    if (
        options.path.leafNode.source !== "commit" ||
        options.path.leafNode.parentHash === undefined ||
        !equalLeafMetadata(options.path.leafNode, authenticatedSenderLeaf) ||
        !mlsVerifyWithLabel(
            options.path.leafNode.signatureKey,
            "LeafNodeTBS",
            encodeMlsLeafNodeTbs(options.path.leafNode, {
                groupId: options.provisionalContext.groupId,
                leafIndex: options.sender,
            }),
            options.path.leafNode.signature,
        )
    ) {
        throw new Error("Invalid MLS UpdatePath LeafNode");
    }
    validateFreshKeys(treeBefore, [
        options.path.leafNode.encryptionKey,
        ...options.path.nodes.map((node) => node.encryptionKey),
    ]);
    for (let pathIndex = 0; pathIndex < entries.length; pathIndex += 1) {
        const entry = entries[pathIndex]!;
        if (
            treeBefore.resolution(entry.sibling, options.excludedNewLeaves).length !==
            options.path.nodes[pathIndex]!.encryptedPathSecrets.length
        ) {
            throw new Error("MLS UpdatePath ciphertext count does not match resolution");
        }
    }
    const publicLeafNode = publicLeaf(
        options.path.leafNode,
        options.sender,
        options.provisionalContext.groupId,
    );
    const tree = treeBefore.clone();
    tree.mergeUpdatePath(
        options.sender,
        publicLeafNode,
        options.path.nodes.map((node) => node.encryptionKey),
    );
    tree.validate({
        groupId: options.provisionalContext.groupId,
        authenticateCredential: options.authenticateCredential,
    });
    return {
        treeBefore,
        entries,
        tree,
        context: {
            ...options.provisionalContext,
            groupId: options.provisionalContext.groupId.slice(),
            confirmedTranscriptHash: options.provisionalContext.confirmedTranscriptHash.slice(),
            treeHash: tree.treeHash(),
        },
    };
}

/** Authenticate and merge the public portion of an RFC 9420 UpdatePath. */
export function validateMlsUpdatePath(
    options: ValidateMlsUpdatePathOptions,
): MlsValidatedUpdatePath {
    const validated = authenticatePublicUpdatePath(options);
    return {
        tree: validated.tree,
        context: validated.context,
    };
}

/** Merge, decrypt, and authenticate an RFC 9420 UpdatePath. */
export function openMlsUpdatePath(options: OpenMlsUpdatePathOptions): MlsUpdatePathResult {
    const validated = authenticatePublicUpdatePath(options);
    const { treeBefore, entries, tree, context } = validated;
    const treeSnapshot = treeBefore.nodes;
    const localLeafNode =
        Number.isSafeInteger(options.localLeaf) &&
        options.localLeaf >= 0 &&
        options.localLeaf < treeBefore.leafCount
            ? treeSnapshot[leafNode(options.localLeaf, treeBefore.leafCount)]
            : undefined;
    if (localLeafNode?.type !== "leaf") {
        throw new Error("Local member was removed by MLS Commit");
    }
    const allowedPrivateNodes = new Set([
        leafNode(options.localLeaf, treeBefore.leafCount),
        ...directPath(options.localLeaf, treeBefore.leafCount),
    ]);
    if (
        options.privateKeys.some((entry) => {
            const publicNode = treeSnapshot[entry.node];
            return (
                !allowedPrivateNodes.has(entry.node) ||
                publicNode === undefined ||
                !equalBytes(
                    canonicalizeHpkePublicKey(publicNode.encryptionKey),
                    canonicalizeHpkePublicKey(entry.keyPair.publicKey),
                )
            );
        })
    ) {
        throw new Error("Invalid local MLS TreeKEM private keys");
    }
    const privateKeys = new Map(options.privateKeys.map((entry) => [entry.node, entry.keyPair]));
    let encrypted:
        | {
              readonly pathIndex: number;
              readonly keyPair: HpkeKeyPair;
              readonly recipientPublicKey: Uint8Array;
              readonly ciphertext: MlsUpdatePath["nodes"][number]["encryptedPathSecrets"][number];
          }
        | undefined;
    for (let pathIndex = 0; pathIndex < entries.length; pathIndex += 1) {
        const entry = entries[pathIndex]!;
        const resolution = treeBefore.resolution(entry.sibling, options.excludedNewLeaves);
        const ciphertexts = options.path.nodes[pathIndex]!.encryptedPathSecrets;
        for (let index = 0; index < resolution.length; index += 1) {
            const keyPair = privateKeys.get(resolution[index]!);
            const ciphertext = ciphertexts[index];
            if (keyPair !== undefined && ciphertext !== undefined) {
                const recipient = treeSnapshot[resolution[index]!];
                if (recipient === undefined) {
                    throw new Error("MLS UpdatePath resolution contains a blank node");
                }
                encrypted = {
                    pathIndex,
                    keyPair,
                    recipientPublicKey: recipient.encryptionKey,
                    ciphertext,
                };
                break;
            }
        }
        if (encrypted !== undefined) {
            break;
        }
    }
    if (encrypted === undefined) {
        throw new Error("Local member cannot decrypt MLS UpdatePath");
    }
    const encodedContext = encodeMlsGroupContext(context);
    let currentPathSecret = mlsDecryptWithLabel(
        {
            secretKey: encrypted.keyPair.secretKey,
            publicKey: encrypted.recipientPublicKey,
        },
        "UpdatePathNode",
        encodedContext,
        encrypted.ciphertext,
    );
    const derivedKeys: MlsTreePrivateKey[] = [];
    const pathSecrets: Array<{ readonly node: number; readonly secret: Uint8Array }> = [];
    try {
        for (let index = encrypted.pathIndex; index < entries.length; index += 1) {
            const entry = entries[index]!;
            const expected = options.path.nodes[index]!.encryptionKey;
            const keyPair = deriveNodeKeyPair(currentPathSecret);
            if (!equalBytes(keyPair.publicKey, expected)) {
                zeroBytes(keyPair.secretKey);
                throw new Error("MLS UpdatePath derived public key mismatch");
            }
            derivedKeys.push(copyKey(entry.node, keyPair));
            zeroBytes(keyPair.secretKey);
            pathSecrets.push({ node: entry.node, secret: currentPathSecret.slice() });
            const next = mlsDeriveSecret(currentPathSecret, "path");
            zeroBytes(currentPathSecret);
            currentPathSecret = next;
        }
        const replaced = new Set(directPath(options.sender, tree.leafCount));
        return {
            tree,
            path: options.path,
            context,
            commitSecret: currentPathSecret,
            privateKeys: [
                ...options.privateKeys
                    .filter((entry) => !replaced.has(entry.node))
                    .map((entry) => copyKey(entry.node, entry.keyPair)),
                ...derivedKeys,
            ],
            pathSecrets,
        };
    } catch (error: unknown) {
        zeroBytes(currentPathSecret);
        for (const key of derivedKeys) {
            zeroBytes(key.keyPair.secretKey);
        }
        for (const secret of pathSecrets) {
            zeroBytes(secret.secret);
        }
        throw error;
    }
}

/** Derive the private TreeKEM path delivered to a member through Welcome. */
export function deriveMlsWelcomePrivateKeys(
    options: DeriveMlsWelcomePrivateKeysOptions,
): readonly MlsTreePrivateKey[] {
    options.tree.validate({
        groupId: options.groupId,
        authenticateCredential: options.authenticateCredential,
    });
    const nodes = options.tree.nodes;
    if (
        !Number.isSafeInteger(options.sender) ||
        options.sender < 0 ||
        options.sender >= options.tree.leafCount ||
        nodes[leafNode(options.sender, options.tree.leafCount)]?.type !== "leaf"
    ) {
        throw new Error("Invalid MLS Welcome sender");
    }
    const localNodeIndex = leafNode(options.localLeaf, options.tree.leafCount);
    const localNode = nodes[localNodeIndex];
    if (
        localNode?.type !== "leaf" ||
        !isHpkeKeyPair(options.leafKeyPair) ||
        !equalBytes(
            canonicalizeHpkePublicKey(localNode.encryptionKey),
            canonicalizeHpkePublicKey(options.leafKeyPair.publicKey),
        )
    ) {
        throw new Error("Invalid MLS Welcome leaf private key");
    }
    const privateKeys: MlsTreePrivateKey[] = [
        {
            node: localNodeIndex,
            keyPair: {
                secretKey: options.leafKeyPair.secretKey.slice(),
                publicKey: localNode.encryptionKey.slice(),
            },
        },
    ];
    const localPath = new Set(directPath(options.localLeaf, options.tree.leafCount));
    const commonAncestor = directPath(options.sender, options.tree.leafCount).find((node) =>
        localPath.has(node),
    );
    if (commonAncestor === undefined) {
        destroyMlsTreePrivateKeys(privateKeys);
        throw new Error("MLS Welcome path has no common ancestor");
    }
    if (options.pathSecret === undefined) {
        const commonParent = nodes[commonAncestor];
        if (
            commonParent?.type === "parent" &&
            !commonParent.unmergedLeaves.includes(options.localLeaf)
        ) {
            destroyMlsTreePrivateKeys(privateKeys);
            throw new Error("MLS Welcome path secret is required");
        }
        return privateKeys;
    }
    if (options.pathSecret.length !== 32) {
        destroyMlsTreePrivateKeys(privateKeys);
        throw new Error("Invalid MLS Welcome path secret");
    }
    const senderPath = options.tree.filteredDirectPath(options.sender);
    const commonIndex = senderPath.indexOf(commonAncestor);
    if (commonIndex < 0) {
        destroyMlsTreePrivateKeys(privateKeys);
        throw new Error("MLS Welcome path has no common ancestor");
    }
    let current: Uint8Array = options.pathSecret.slice();
    try {
        for (let index = commonIndex; index < senderPath.length; index += 1) {
            const nodeIndex = senderPath[index]!;
            const publicNode = nodes[nodeIndex];
            if (publicNode === undefined) {
                throw new Error("MLS Welcome private path contains a blank node");
            }
            const keyPair = deriveNodeKeyPair(current);
            if (
                !equalBytes(
                    canonicalizeHpkePublicKey(publicNode.encryptionKey),
                    canonicalizeHpkePublicKey(keyPair.publicKey),
                )
            ) {
                zeroBytes(keyPair.secretKey);
                throw new Error("MLS Welcome path secret does not match public tree");
            }
            privateKeys.push({
                node: nodeIndex,
                keyPair: {
                    secretKey: keyPair.secretKey,
                    publicKey: publicNode.encryptionKey.slice(),
                },
            });
            if (index + 1 < senderPath.length) {
                const next = mlsDeriveSecret(current, "path");
                zeroBytes(current);
                current = next;
            }
        }
        return privateKeys;
    } catch (error: unknown) {
        destroyMlsTreePrivateKeys(privateKeys);
        throw error;
    } finally {
        zeroBytes(current);
    }
}

/** Destroy TreeKEM secrets returned by create/open. */
export function destroyMlsUpdatePathResult(result: MlsUpdatePathResult): void {
    zeroBytes(result.commitSecret);
    for (const key of result.privateKeys) {
        zeroBytes(key.keyPair.secretKey);
    }
    for (const secret of result.pathSecrets) {
        zeroBytes(secret.secret);
    }
}

/** Destroy an owned collection of TreeKEM private keys. */
export function destroyMlsTreePrivateKeys(privateKeys: readonly MlsTreePrivateKey[]): void {
    for (const key of privateKeys) {
        zeroBytes(key.keyPair.secretKey);
    }
}
