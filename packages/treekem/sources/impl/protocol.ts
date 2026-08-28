import type {
    TreeKemChanges,
    TreeKemKeyPair,
    TreeKemResult,
    TreeKemUpdateResult,
} from "../types.js";
import {
    byteIdentifier,
    concatBytes,
    encodeUint32,
    encodeUint64,
    equalBytes,
    utf8Encode,
} from "./bytes.js";
import {
    decodeAdmissionPublicKey,
    decodeAdmissionSecretKey,
    decodeState,
    decodeUpdate,
    decodeWelcome,
    decodeWelcomePayload,
    destroyDecodedState,
    encodeAdmissionPublicKey,
    encodeAdmissionSecretKey,
    encodeState,
    encodeUpdate,
    encodeUpdateBody,
    encodeWelcome,
    encodeWelcomeBody,
    encodeWelcomePayload,
    type AdmissionPublicKey,
    type AdmissionSecretKey,
    type PacketAddition,
    type PacketNode,
    type UpdatePacket,
    type WelcomeMessage,
} from "./codec.js";
import {
    canonicalizePublicKey,
    deriveHpkeKeyPair,
    deriveNextPathSecret,
    deriveNodeKeyPair,
    deriveSharedSecret,
    generateSecret,
    hpkeOpen,
    hpkeSeal,
    publicKeyFromSecret,
    sign,
    signingPublicKey,
    verify,
    type HpkeKeyPair,
} from "./crypto.js";
import {
    addLeaf,
    blankDirectPath,
    cloneTree,
    directPath,
    findLeafBySignatureKey,
    getLeaf,
    leafNode,
    pathEntries,
    removeLeaf,
    resolution,
    setLeaf,
    setParent,
    treeHash,
    validateTree,
    type PathEntry,
    type PublicTree,
} from "./tree.js";

const UPDATE_CONTEXT_DOMAIN = utf8Encode("@slopus/treekem update context v1");
const INITIAL_CONTEXT_DOMAIN = utf8Encode("@slopus/treekem initial context v1");
const WELCOME_CONTEXT_DOMAIN = utf8Encode("@slopus/treekem welcome context v1");

interface AddedMember {
    readonly leaf: number;
    readonly key: AdmissionPublicKey;
    readonly encodedKey: Uint8Array;
}

interface PreparedTree {
    readonly tree: PublicTree;
    readonly removals: readonly number[];
    readonly additions: readonly AddedMember[];
    readonly excludedNewLeaves: ReadonlySet<number>;
}

function updateContext(
    groupId: Uint8Array,
    epoch: bigint,
    sender: number,
    previousTreeHash: Uint8Array,
    nextTreeHash: Uint8Array,
): Uint8Array {
    return concatBytes(
        UPDATE_CONTEXT_DOMAIN,
        groupId,
        encodeUint64(epoch),
        encodeUint32(sender),
        previousTreeHash,
        nextTreeHash,
    );
}

function initialContext(groupId: Uint8Array, publicTreeHash: Uint8Array): Uint8Array {
    return concatBytes(INITIAL_CONTEXT_DOMAIN, groupId, publicTreeHash);
}

function welcomeContext(update: Uint8Array, recipient: number): Uint8Array {
    return concatBytes(WELCOME_CONTEXT_DOMAIN, update, encodeUint32(recipient));
}

function destroyAdmissionSecret(key: AdmissionSecretKey): void {
    key.encryptionInput.fill(0);
    key.signingSecretKey.fill(0);
}

function admissionFromSecret(key: AdmissionSecretKey): {
    readonly publicKey: AdmissionPublicKey;
    readonly encryptionKeyPair: HpkeKeyPair;
} {
    const encryptionKeyPair = deriveHpkeKeyPair(key.encryptionInput);
    return {
        publicKey: {
            encryptionKey: encryptionKeyPair.publicKey,
            signatureKey: signingPublicKey(key.signingSecretKey),
        },
        encryptionKeyPair,
    };
}

function validateKeyPair(keyPair: TreeKemKeyPair): {
    readonly secret: AdmissionSecretKey;
    readonly publicKey: AdmissionPublicKey;
    readonly encryptionKeyPair: HpkeKeyPair;
} {
    const secret = decodeAdmissionSecretKey(keyPair.secretKey);
    let derived: ReturnType<typeof admissionFromSecret> | undefined;
    try {
        derived = admissionFromSecret(secret);
        const supplied = decodeAdmissionPublicKey(keyPair.publicKey);
        if (
            !equalBytes(derived.publicKey.encryptionKey, supplied.encryptionKey) ||
            !equalBytes(derived.publicKey.signatureKey, supplied.signatureKey)
        ) {
            throw new Error("TreeKEM admission public and secret keys do not match");
        }
        return {
            secret,
            publicKey: derived.publicKey,
            encryptionKeyPair: derived.encryptionKeyPair,
        };
    } catch (error: unknown) {
        destroyAdmissionSecret(secret);
        derived?.encryptionKeyPair.secretKey.fill(0);
        throw error;
    }
}

function destroyPrivateKeys(privateKeys: ReadonlyMap<number, Uint8Array>): void {
    for (const secretKey of privateKeys.values()) {
        secretKey.fill(0);
    }
}

function normalizePublicKeys(values: readonly Uint8Array[]): readonly {
    readonly decoded: AdmissionPublicKey;
    readonly encoded: Uint8Array;
}[] {
    return values.map((value) => {
        const decoded = decodeAdmissionPublicKey(value);
        return { decoded, encoded: encodeAdmissionPublicKey(decoded) };
    });
}

function prepareCommitTree(
    input: PublicTree,
    sender: number,
    change: TreeKemChanges,
): PreparedTree {
    let tree = cloneTree(input);
    const removeKeys = normalizePublicKeys(change.remove ?? []);
    const addKeys = normalizePublicKeys(change.add ?? []);
    const changeSignatures = new Set<string>();
    const removals: number[] = [];
    for (const key of removeKeys) {
        const identifier = byteIdentifier(key.decoded.signatureKey);
        if (changeSignatures.has(identifier)) {
            throw new Error("TreeKEM membership change repeats a member");
        }
        changeSignatures.add(identifier);
        const leaf = findLeafBySignatureKey(tree, key.decoded.signatureKey);
        if (leaf === undefined) {
            throw new Error("TreeKEM removal does not name a current member");
        }
        if (leaf === sender) {
            throw new Error("A TreeKEM committer cannot remove itself");
        }
        removals.push(leaf);
        tree = removeLeaf(tree, leaf);
    }
    const additions: AddedMember[] = [];
    for (const key of addKeys) {
        const identifier = byteIdentifier(key.decoded.signatureKey);
        if (
            changeSignatures.has(identifier) ||
            findLeafBySignatureKey(tree, key.decoded.signatureKey) !== undefined
        ) {
            throw new Error("TreeKEM membership change repeats a member");
        }
        changeSignatures.add(identifier);
        const added = addLeaf(tree, {
            type: "leaf",
            encryptionKey: key.decoded.encryptionKey,
            signatureKey: key.decoded.signatureKey,
        });
        tree = added.tree;
        additions.push({ leaf: added.leaf, key: key.decoded, encodedKey: key.encoded });
    }
    return {
        tree,
        removals,
        additions,
        excludedNewLeaves: new Set(additions.map((addition) => addition.leaf)),
    };
}

function applyPacketMembership(
    input: PublicTree,
    sender: number,
    removals: readonly number[],
    additions: readonly PacketAddition[],
): PreparedTree {
    let tree = cloneTree(input);
    const changedLeaves = new Set<number>();
    const changedSignatures = new Set<string>();
    for (const leaf of removals) {
        if (changedLeaves.has(leaf) || leaf === sender) {
            throw new Error("Invalid TreeKEM removal list");
        }
        const removed = getLeaf(tree, leaf);
        changedLeaves.add(leaf);
        changedSignatures.add(byteIdentifier(removed.signatureKey));
        tree = removeLeaf(tree, leaf);
    }
    const addedMembers: AddedMember[] = [];
    for (const addition of additions) {
        const decoded = decodeAdmissionPublicKey(addition.publicKey);
        const identifier = byteIdentifier(decoded.signatureKey);
        if (
            changedSignatures.has(identifier) ||
            findLeafBySignatureKey(tree, decoded.signatureKey) !== undefined
        ) {
            throw new Error("Invalid TreeKEM addition list");
        }
        changedSignatures.add(identifier);
        const added = addLeaf(tree, {
            type: "leaf",
            encryptionKey: decoded.encryptionKey,
            signatureKey: decoded.signatureKey,
        });
        if (added.leaf !== addition.leaf) {
            throw new Error("TreeKEM addition does not use the leftmost blank leaf");
        }
        tree = added.tree;
        addedMembers.push({
            leaf: added.leaf,
            key: decoded,
            encodedKey: encodeAdmissionPublicKey(decoded),
        });
    }
    return {
        tree,
        removals: [...removals],
        additions: addedMembers,
        excludedNewLeaves: new Set(addedMembers.map((addition) => addition.leaf)),
    };
}

function prepareFreshPath(
    input: PublicTree,
    sender: number,
    signatureKey: Uint8Array,
): {
    readonly tree: PublicTree;
    readonly entries: readonly PathEntry[];
    readonly leafKeyPair: HpkeKeyPair;
    readonly pathKeyPairs: ReadonlyMap<number, HpkeKeyPair>;
    readonly pathSecrets: ReadonlyMap<number, Uint8Array>;
    readonly commitSecret: Uint8Array;
} {
    let tree = blankDirectPath(input, sender);
    const entries = pathEntries(tree, sender);
    const leafSecret = generateSecret();
    const leafKeyPair = deriveNodeKeyPair(leafSecret);
    leafSecret.fill(0);
    tree = setLeaf(tree, sender, {
        type: "leaf",
        encryptionKey: leafKeyPair.publicKey,
        signatureKey,
    });
    const pathKeyPairs = new Map<number, HpkeKeyPair>();
    const pathSecrets = new Map<number, Uint8Array>();
    let currentPathSecret = generateSecret();
    try {
        for (const entry of entries) {
            pathSecrets.set(entry.node, currentPathSecret.slice());
            const keyPair = deriveNodeKeyPair(currentPathSecret);
            pathKeyPairs.set(entry.node, keyPair);
            tree = setParent(tree, entry.node, keyPair.publicKey);
            const nextPathSecret = deriveNextPathSecret(currentPathSecret);
            currentPathSecret.fill(0);
            currentPathSecret = nextPathSecret;
        }
        validateTree(tree);
        return {
            tree,
            entries,
            leafKeyPair,
            pathKeyPairs,
            pathSecrets,
            commitSecret: currentPathSecret,
        };
    } catch (error: unknown) {
        currentPathSecret.fill(0);
        leafKeyPair.secretKey.fill(0);
        for (const keyPair of pathKeyPairs.values()) {
            keyPair.secretKey.fill(0);
        }
        for (const pathSecret of pathSecrets.values()) {
            pathSecret.fill(0);
        }
        throw error;
    }
}

function destroyFreshPath(path: ReturnType<typeof prepareFreshPath>): void {
    path.leafKeyPair.secretKey.fill(0);
    for (const keyPair of path.pathKeyPairs.values()) {
        keyPair.secretKey.fill(0);
    }
    for (const pathSecret of path.pathSecrets.values()) {
        pathSecret.fill(0);
    }
    path.commitSecret.fill(0);
}

function createWelcomeForMember(
    stateSigningKey: Uint8Array,
    path: ReturnType<typeof prepareFreshPath>,
    addition: AddedMember,
    groupId: Uint8Array,
    epoch: bigint,
    sender: number,
    previousTreeHash: Uint8Array,
    nextTreeHash: Uint8Array,
    context: Uint8Array,
): Uint8Array {
    const recipientPath = new Set(directPath(addition.leaf, path.tree.leafCount));
    const privateKeys = new Map<number, Uint8Array>();
    for (const [node, keyPair] of path.pathKeyPairs) {
        if (recipientPath.has(node)) {
            privateKeys.set(node, keyPair.secretKey);
        }
    }
    const plaintext = encodeWelcomePayload({
        tree: path.tree,
        privateKeys,
        commitSecret: path.commitSecret,
    });
    try {
        const encrypted = hpkeSeal(
            addition.key.encryptionKey,
            welcomeContext(context, addition.leaf),
            plaintext,
        );
        const unsigned: Omit<WelcomeMessage, "signature"> = {
            groupId,
            epoch,
            sender,
            recipient: addition.leaf,
            previousTreeHash,
            treeHash: nextTreeHash,
            encapsulatedKey: encrypted.encapsulatedKey,
            ciphertext: encrypted.ciphertext,
        };
        const body = encodeWelcomeBody(unsigned);
        return encodeWelcome({ ...unsigned, signature: sign(stateSigningKey, body) });
    } finally {
        plaintext.fill(0);
    }
}

/** Generate a one-use public/secret admission key pair. */
export function createTreeKemKeyPair(): TreeKemKeyPair {
    const secret: AdmissionSecretKey = {
        encryptionInput: generateSecret(),
        signingSecretKey: generateSecret(),
    };
    const derived = admissionFromSecret(secret);
    try {
        return {
            publicKey: encodeAdmissionPublicKey(derived.publicKey),
            secretKey: encodeAdmissionSecretKey(secret),
        };
    } finally {
        destroyAdmissionSecret(secret);
        derived.encryptionKeyPair.secretKey.fill(0);
    }
}

/** Create initial opaque state and a one-member epoch secret. */
export function createTreeKemGroup(memberKeyPair: TreeKemKeyPair): TreeKemResult {
    const member = validateKeyPair(memberKeyPair);
    const groupId = generateSecret();
    const commitSecret = generateSecret();
    try {
        const tree = {
            leafCount: 1,
            nodes: [
                {
                    type: "leaf" as const,
                    encryptionKey: member.publicKey.encryptionKey,
                    signatureKey: member.publicKey.signatureKey,
                },
            ],
        };
        validateTree(tree);
        const publicTreeHash = treeHash(tree);
        const privateKeys = new Map([
            [leafNode(0, tree.leafCount), member.encryptionKeyPair.secretKey],
        ]);
        const state = encodeState({
            groupId,
            epoch: 0n,
            localLeaf: 0,
            signingSecretKey: member.secret.signingSecretKey,
            tree,
            privateKeys,
        });
        return {
            secretState: state,
            secretKey: deriveSharedSecret(commitSecret, initialContext(groupId, publicTreeHash)),
        };
    } finally {
        groupId.fill(0);
        commitSecret.fill(0);
        member.encryptionKeyPair.secretKey.fill(0);
        destroyAdmissionSecret(member.secret);
    }
}

/** Create one authenticated update and replacement state. */
export function createTreeKemUpdate(
    stateBytes: Uint8Array,
    change: TreeKemChanges,
): TreeKemUpdateResult {
    const state = decodeState(stateBytes);
    let path: ReturnType<typeof prepareFreshPath> | undefined;
    try {
        if (state.epoch === 0xffff_ffff_ffff_ffffn) {
            throw new Error("TreeKEM epoch is exhausted");
        }
        const previousTreeHash = treeHash(state.tree);
        const currentLeaf = getLeaf(state.tree, state.localLeaf);
        const prepared = prepareCommitTree(state.tree, state.localLeaf, change);
        const freshPath = prepareFreshPath(
            prepared.tree,
            state.localLeaf,
            currentLeaf.signatureKey,
        );
        path = freshPath;
        const nextEpoch = state.epoch + 1n;
        const nextTreeHash = treeHash(freshPath.tree);
        const context = updateContext(
            state.groupId,
            nextEpoch,
            state.localLeaf,
            previousTreeHash,
            nextTreeHash,
        );
        const packetNodes: PacketNode[] = freshPath.entries.map((entry) => {
            const pathSecret = freshPath.pathSecrets.get(entry.node);
            const keyPair = freshPath.pathKeyPairs.get(entry.node);
            if (pathSecret === undefined || keyPair === undefined) {
                throw new Error("TreeKEM path derivation mismatch");
            }
            const recipients = resolution(
                freshPath.tree,
                entry.sibling,
                prepared.excludedNewLeaves,
            );
            return {
                node: entry.node,
                encryptionKey: keyPair.publicKey,
                encryptedPathSecrets: recipients.map((node) => {
                    const recipient = freshPath.tree.nodes[node];
                    if (recipient === undefined) {
                        throw new Error("TreeKEM resolution contains a blank node");
                    }
                    return hpkeSeal(recipient.encryptionKey, context, pathSecret);
                }),
            };
        });
        const unsigned: Omit<UpdatePacket, "signature"> = {
            groupId: state.groupId,
            epoch: nextEpoch,
            sender: state.localLeaf,
            previousTreeHash,
            removals: prepared.removals,
            additions: prepared.additions.map((addition) => ({
                leaf: addition.leaf,
                publicKey: addition.encodedKey,
            })),
            leafEncryptionKey: freshPath.leafKeyPair.publicKey,
            nodes: packetNodes,
            treeHash: nextTreeHash,
        };
        const body = encodeUpdateBody(unsigned);
        const packet = encodeUpdate({ ...unsigned, signature: sign(state.signingSecretKey, body) });
        const nextPrivateKeys = new Map<number, Uint8Array>([
            [leafNode(state.localLeaf, freshPath.tree.leafCount), freshPath.leafKeyPair.secretKey],
            ...[...freshPath.pathKeyPairs].map(
                ([node, keyPair]) => [node, keyPair.secretKey] as const,
            ),
        ]);
        const nextState = encodeState({
            groupId: state.groupId,
            epoch: nextEpoch,
            localLeaf: state.localLeaf,
            signingSecretKey: state.signingSecretKey,
            tree: freshPath.tree,
            privateKeys: nextPrivateKeys,
        });
        const welcomes = prepared.additions.map((addition) =>
            createWelcomeForMember(
                state.signingSecretKey,
                freshPath,
                addition,
                state.groupId,
                nextEpoch,
                state.localLeaf,
                previousTreeHash,
                nextTreeHash,
                context,
            ),
        );
        return {
            secretState: nextState,
            publicPacket: packet,
            publicWelcomes: welcomes,
            secretKey: deriveSharedSecret(freshPath.commitSecret, context),
        };
    } finally {
        if (path !== undefined) {
            destroyFreshPath(path);
        }
        destroyDecodedState(state);
    }
}

function publicKeyMatchesPrivate(tree: PublicTree, node: number, secretKey: Uint8Array): boolean {
    const publicNode = tree.nodes[node];
    return (
        publicNode !== undefined &&
        equalBytes(
            canonicalizePublicKey(publicNode.encryptionKey),
            canonicalizePublicKey(publicKeyFromSecret(secretKey)),
        )
    );
}

/** Authenticate and apply another member's update packet. */
export function applyTreeKemPacket(stateBytes: Uint8Array, packetBytes: Uint8Array): TreeKemResult {
    const state = decodeState(stateBytes);
    const packet = decodeUpdate(packetBytes);
    const derivedPrivateKeys = new Map<number, Uint8Array>();
    let commitSecret: Uint8Array | undefined;
    try {
        const previousTreeHash = treeHash(state.tree);
        if (
            !equalBytes(packet.groupId, state.groupId) ||
            packet.epoch !== state.epoch + 1n ||
            !equalBytes(packet.previousTreeHash, previousTreeHash)
        ) {
            throw new Error("TreeKEM update does not extend the current state");
        }
        const senderLeaf = getLeaf(state.tree, packet.sender);
        if (!verify(senderLeaf.signatureKey, packet.body, packet.signature)) {
            throw new Error("Invalid TreeKEM update signature");
        }
        if (packet.sender === state.localLeaf) {
            throw new Error("TreeKEM cannot apply its own public packet");
        }
        const prepared = applyPacketMembership(
            state.tree,
            packet.sender,
            packet.removals,
            packet.additions,
        );
        const localRemoved = prepared.removals.includes(state.localLeaf);
        let provisionalTree = blankDirectPath(prepared.tree, packet.sender);
        const entries = pathEntries(provisionalTree, packet.sender);
        if (
            entries.length !== packet.nodes.length ||
            entries.some((entry, index) => entry.node !== packet.nodes[index]?.node)
        ) {
            throw new Error("TreeKEM update path does not match the public tree");
        }
        const recipientTree = provisionalTree;
        provisionalTree = setLeaf(provisionalTree, packet.sender, {
            type: "leaf",
            encryptionKey: packet.leafEncryptionKey,
            signatureKey: senderLeaf.signatureKey,
        });
        for (const node of packet.nodes) {
            provisionalTree = setParent(provisionalTree, node.node, node.encryptionKey);
        }
        validateTree(provisionalTree);
        if (!equalBytes(treeHash(provisionalTree), packet.treeHash)) {
            throw new Error("TreeKEM update tree hash does not match");
        }
        for (let index = 0; index < entries.length; index += 1) {
            const entry = entries[index]!;
            const expected = resolution(
                recipientTree,
                entry.sibling,
                prepared.excludedNewLeaves,
            ).length;
            if (packet.nodes[index]!.encryptedPathSecrets.length !== expected) {
                throw new Error("TreeKEM update ciphertext count does not match its resolution");
            }
        }
        if (localRemoved) {
            throw new Error("Local member was removed from the TreeKEM group");
        }
        const context = updateContext(
            state.groupId,
            packet.epoch,
            packet.sender,
            packet.previousTreeHash,
            packet.treeHash,
        );
        let opened: { readonly pathIndex: number; readonly pathSecret: Uint8Array } | undefined;
        for (
            let pathIndex = 0;
            pathIndex < entries.length && opened === undefined;
            pathIndex += 1
        ) {
            const entry = entries[pathIndex]!;
            const recipients = resolution(recipientTree, entry.sibling, prepared.excludedNewLeaves);
            for (let index = 0; index < recipients.length; index += 1) {
                const recipientNode = recipients[index]!;
                const secretKey = state.privateKeys.get(recipientNode);
                const publicNode = recipientTree.nodes[recipientNode];
                const encrypted = packet.nodes[pathIndex]!.encryptedPathSecrets[index];
                if (
                    secretKey !== undefined &&
                    publicNode !== undefined &&
                    encrypted !== undefined
                ) {
                    opened = {
                        pathIndex,
                        pathSecret: hpkeOpen(
                            { secretKey, publicKey: publicNode.encryptionKey },
                            context,
                            encrypted,
                        ),
                    };
                    break;
                }
            }
        }
        if (opened === undefined || opened.pathSecret.length !== 32) {
            opened?.pathSecret.fill(0);
            throw new Error("Local member cannot decrypt the TreeKEM update");
        }
        let currentPathSecret = opened.pathSecret;
        try {
            for (let index = opened.pathIndex; index < entries.length; index += 1) {
                const entry = entries[index]!;
                const expectedPublicKey = packet.nodes[index]!.encryptionKey;
                const keyPair = deriveNodeKeyPair(currentPathSecret);
                if (!equalBytes(keyPair.publicKey, expectedPublicKey)) {
                    keyPair.secretKey.fill(0);
                    throw new Error("TreeKEM update derived the wrong public key");
                }
                derivedPrivateKeys.set(entry.node, keyPair.secretKey);
                const nextPathSecret = deriveNextPathSecret(currentPathSecret);
                currentPathSecret.fill(0);
                currentPathSecret = nextPathSecret;
            }
            commitSecret = currentPathSecret;
        } catch (error: unknown) {
            currentPathSecret.fill(0);
            throw error;
        }
        const allowedNodes = new Set([
            leafNode(state.localLeaf, provisionalTree.leafCount),
            ...directPath(state.localLeaf, provisionalTree.leafCount),
        ]);
        const nextPrivateKeys = new Map<number, Uint8Array>();
        for (const [node, secretKey] of state.privateKeys) {
            if (
                allowedNodes.has(node) &&
                publicKeyMatchesPrivate(provisionalTree, node, secretKey)
            ) {
                nextPrivateKeys.set(node, secretKey.slice());
            }
        }
        for (const [node, secretKey] of derivedPrivateKeys) {
            nextPrivateKeys.get(node)?.fill(0);
            nextPrivateKeys.set(node, secretKey.slice());
        }
        try {
            return {
                secretState: encodeState({
                    groupId: state.groupId,
                    epoch: packet.epoch,
                    localLeaf: state.localLeaf,
                    signingSecretKey: state.signingSecretKey,
                    tree: provisionalTree,
                    privateKeys: nextPrivateKeys,
                }),
                secretKey: deriveSharedSecret(commitSecret, context),
            };
        } finally {
            destroyPrivateKeys(nextPrivateKeys);
        }
    } finally {
        commitSecret?.fill(0);
        destroyPrivateKeys(derivedPrivateKeys);
        destroyDecodedState(state);
    }
}

/** Decrypt and validate a Welcome into independent local state. */
export function joinTreeKemGroup(
    secretKeyBytes: Uint8Array,
    welcomeBytes: Uint8Array,
): TreeKemResult {
    const secret = decodeAdmissionSecretKey(secretKeyBytes);
    const admission = admissionFromSecret(secret);
    const welcome = decodeWelcome(welcomeBytes);
    const context = updateContext(
        welcome.groupId,
        welcome.epoch,
        welcome.sender,
        welcome.previousTreeHash,
        welcome.treeHash,
    );
    let plaintext: Uint8Array | undefined;
    let payload: ReturnType<typeof decodeWelcomePayload> | undefined;
    const privateKeys = new Map<number, Uint8Array>();
    try {
        plaintext = hpkeOpen(
            admission.encryptionKeyPair,
            welcomeContext(context, welcome.recipient),
            {
                encapsulatedKey: welcome.encapsulatedKey,
                ciphertext: welcome.ciphertext,
            },
        );
        payload = decodeWelcomePayload(plaintext);
        if (!equalBytes(treeHash(payload.tree), welcome.treeHash)) {
            throw new Error("TreeKEM Welcome tree hash does not match");
        }
        const localLeaf = getLeaf(payload.tree, welcome.recipient);
        if (
            !equalBytes(localLeaf.encryptionKey, admission.publicKey.encryptionKey) ||
            !equalBytes(localLeaf.signatureKey, admission.publicKey.signatureKey)
        ) {
            throw new Error("TreeKEM Welcome does not belong to this admission key");
        }
        const senderLeaf = getLeaf(payload.tree, welcome.sender);
        if (!verify(senderLeaf.signatureKey, welcome.body, welcome.signature)) {
            throw new Error("Invalid TreeKEM Welcome signature");
        }
        const allowedNodes = new Set(directPath(welcome.recipient, payload.tree.leafCount));
        for (const [node, privateKey] of payload.privateKeys) {
            if (
                !allowedNodes.has(node) ||
                !publicKeyMatchesPrivate(payload.tree, node, privateKey)
            ) {
                throw new Error("Invalid TreeKEM Welcome private path");
            }
            privateKeys.set(node, privateKey.slice());
        }
        privateKeys.set(
            leafNode(welcome.recipient, payload.tree.leafCount),
            admission.encryptionKeyPair.secretKey.slice(),
        );
        const state = encodeState({
            groupId: welcome.groupId,
            epoch: welcome.epoch,
            localLeaf: welcome.recipient,
            signingSecretKey: secret.signingSecretKey,
            tree: payload.tree,
            privateKeys,
        });
        return {
            secretState: state,
            secretKey: deriveSharedSecret(payload.commitSecret, context),
        };
    } finally {
        plaintext?.fill(0);
        payload?.commitSecret.fill(0);
        if (payload !== undefined) {
            destroyPrivateKeys(payload.privateKeys);
        }
        destroyPrivateKeys(privateKeys);
        admission.encryptionKeyPair.secretKey.fill(0);
        destroyAdmissionSecret(secret);
    }
}
