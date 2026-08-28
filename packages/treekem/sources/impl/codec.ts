import {
    ByteReader,
    concatBytes,
    encodeUint16,
    encodeUint32,
    encodeUint64,
    equalBytes,
    utf8Encode,
} from "./bytes.js";
import {
    canonicalizePublicKey,
    publicKeyFromSecret,
    signingPublicKey,
    type HpkeCiphertext,
} from "./crypto.js";
import {
    directPath,
    getLeaf,
    leafNode,
    MAXIMUM_LEAVES,
    nodeLevel,
    treeWidth,
    validateTree,
    type PublicNode,
    type PublicTree,
} from "./tree.js";

export interface AdmissionPublicKey {
    readonly encryptionKey: Uint8Array;
    readonly signatureKey: Uint8Array;
}

export interface AdmissionSecretKey {
    readonly encryptionInput: Uint8Array;
    readonly signingSecretKey: Uint8Array;
}

export interface DecodedState {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly localLeaf: number;
    readonly signingSecretKey: Uint8Array;
    readonly tree: PublicTree;
    readonly privateKeys: ReadonlyMap<number, Uint8Array>;
}

export interface PacketAddition {
    readonly leaf: number;
    readonly publicKey: Uint8Array;
}

export interface PacketNode {
    readonly node: number;
    readonly encryptionKey: Uint8Array;
    readonly encryptedPathSecrets: readonly HpkeCiphertext[];
}

export interface UpdatePacket {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly sender: number;
    readonly previousTreeHash: Uint8Array;
    readonly removals: readonly number[];
    readonly additions: readonly PacketAddition[];
    readonly leafEncryptionKey: Uint8Array;
    readonly nodes: readonly PacketNode[];
    readonly treeHash: Uint8Array;
    readonly signature: Uint8Array;
}

export interface DecodedUpdatePacket extends UpdatePacket {
    readonly body: Uint8Array;
}

export interface WelcomeMessage {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly sender: number;
    readonly recipient: number;
    readonly previousTreeHash: Uint8Array;
    readonly treeHash: Uint8Array;
    readonly encapsulatedKey: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly signature: Uint8Array;
}

export interface DecodedWelcomeMessage extends WelcomeMessage {
    readonly body: Uint8Array;
}

export interface WelcomePayload {
    readonly tree: PublicTree;
    readonly privateKeys: ReadonlyMap<number, Uint8Array>;
    readonly commitSecret: Uint8Array;
}

const VERSION = 1;
const STATE_MAGIC = utf8Encode("TKST");
const UPDATE_MAGIC = utf8Encode("TKUP");
const WELCOME_MAGIC = utf8Encode("TKWL");
const WELCOME_PAYLOAD_MAGIC = utf8Encode("TKWP");
const MAXIMUM_BLOB_BYTES = 8 * 1024 * 1024;
const MAXIMUM_PATH_NODES = 32;
const PATH_CIPHERTEXT_BYTES = 48;

function assertMagic(actual: Uint8Array, expected: Uint8Array, label: string): void {
    if (!equalBytes(actual, expected)) {
        throw new Error(`Invalid ${label} format`);
    }
}

function validateBlob(bytes: Uint8Array, label: string): void {
    if (bytes.length === 0 || bytes.length > MAXIMUM_BLOB_BYTES) {
        throw new Error(`Invalid ${label} size`);
    }
}

/** Decode and canonicalize a public admission key. */
export function decodeAdmissionPublicKey(bytes: Uint8Array): AdmissionPublicKey {
    if (bytes.length !== 64) {
        throw new Error("TreeKEM public admission key must be 64 bytes");
    }
    const encryptionKey = canonicalizePublicKey(bytes.slice(0, 32));
    const signatureKey = bytes.slice(32);
    return { encryptionKey, signatureKey };
}

/** Encode a canonical public admission key. */
export function encodeAdmissionPublicKey(key: AdmissionPublicKey): Uint8Array {
    if (key.signatureKey.length !== 32) {
        throw new Error("TreeKEM signature public key must be 32 bytes");
    }
    return concatBytes(canonicalizePublicKey(key.encryptionKey), key.signatureKey);
}

/** Decode an opaque admission secret into independently owned seeds. */
export function decodeAdmissionSecretKey(bytes: Uint8Array): AdmissionSecretKey {
    if (bytes.length !== 64) {
        throw new Error("TreeKEM secret admission key must be 64 bytes");
    }
    return {
        encryptionInput: bytes.slice(0, 32),
        signingSecretKey: bytes.slice(32),
    };
}

/** Encode an opaque admission secret. */
export function encodeAdmissionSecretKey(key: AdmissionSecretKey): Uint8Array {
    if (key.encryptionInput.length !== 32 || key.signingSecretKey.length !== 32) {
        throw new Error("Invalid TreeKEM admission secret");
    }
    return concatBytes(key.encryptionInput, key.signingSecretKey);
}

/** Encode a validated public tree. */
export function encodeTree(tree: PublicTree): Uint8Array {
    validateTree(tree);
    const nodes = tree.nodes.map((node) => {
        if (node === undefined) {
            return new Uint8Array([0]);
        }
        if (node.type === "leaf") {
            return concatBytes(
                new Uint8Array([1]),
                canonicalizePublicKey(node.encryptionKey),
                node.signatureKey,
            );
        }
        return concatBytes(
            new Uint8Array([2]),
            canonicalizePublicKey(node.encryptionKey),
            encodeUint32(node.unmergedLeaves.length),
            ...node.unmergedLeaves.map(encodeUint32),
        );
    });
    return concatBytes(encodeUint32(tree.leafCount), ...nodes);
}

function decodeTreeFromReader(reader: ByteReader): PublicTree {
    const leafCount = reader.readUint32();
    if (leafCount < 1 || leafCount > MAXIMUM_LEAVES || (leafCount & (leafCount - 1)) !== 0) {
        throw new Error("Invalid TreeKEM leaf capacity");
    }
    const nodes: PublicNode[] = [];
    for (let index = 0; index < treeWidth(leafCount); index += 1) {
        const type = reader.readUint8();
        if (type === 0) {
            nodes.push(undefined);
            continue;
        }
        if (type === 1) {
            if (nodeLevel(index) !== 0) {
                throw new Error("TreeKEM leaf occupies a parent position");
            }
            nodes.push({
                type: "leaf",
                encryptionKey: canonicalizePublicKey(reader.readBytes(32)),
                signatureKey: reader.readBytes(32),
            });
            continue;
        }
        if (type !== 2 || nodeLevel(index) === 0) {
            throw new Error("Invalid TreeKEM public node type");
        }
        const encryptionKey = canonicalizePublicKey(reader.readBytes(32));
        const unmergedCount = reader.readUint32();
        if (unmergedCount > leafCount) {
            throw new Error("TreeKEM unmerged-leaf list is too large");
        }
        const unmergedLeaves = Array.from({ length: unmergedCount }, () => reader.readUint32());
        nodes.push({ type: "parent", encryptionKey, unmergedLeaves });
    }
    const tree: PublicTree = { leafCount, nodes };
    validateTree(tree);
    return tree;
}

function validateState(state: DecodedState): void {
    if (
        state.groupId.length !== 32 ||
        state.epoch < 0n ||
        state.epoch > 0xffff_ffff_ffff_ffffn ||
        state.signingSecretKey.length !== 32
    ) {
        throw new Error("Invalid TreeKEM state header");
    }
    validateTree(state.tree);
    const localLeaf = getLeaf(state.tree, state.localLeaf);
    if (!equalBytes(signingPublicKey(state.signingSecretKey), localLeaf.signatureKey)) {
        throw new Error("TreeKEM state signing key does not match its leaf");
    }
    const allowedNodes = new Set([
        leafNode(state.localLeaf, state.tree.leafCount),
        ...directPath(state.localLeaf, state.tree.leafCount),
    ]);
    if (state.privateKeys.size === 0 || state.privateKeys.size > allowedNodes.size) {
        throw new Error("Invalid TreeKEM private path size");
    }
    for (const [nodeIndex, secretKey] of state.privateKeys) {
        const node = state.tree.nodes[nodeIndex];
        if (
            !allowedNodes.has(nodeIndex) ||
            node === undefined ||
            secretKey.length !== 32 ||
            !equalBytes(
                canonicalizePublicKey(publicKeyFromSecret(secretKey)),
                canonicalizePublicKey(node.encryptionKey),
            )
        ) {
            throw new Error("Invalid TreeKEM private path key");
        }
    }
    if (!state.privateKeys.has(leafNode(state.localLeaf, state.tree.leafCount))) {
        throw new Error("TreeKEM state is missing its leaf private key");
    }
    for (const nodeIndex of directPath(state.localLeaf, state.tree.leafCount)) {
        const node = state.tree.nodes[nodeIndex];
        if (
            node?.type === "parent" &&
            !node.unmergedLeaves.includes(state.localLeaf) &&
            !state.privateKeys.has(nodeIndex)
        ) {
            throw new Error("TreeKEM state is missing a merged parent private key");
        }
    }
}

/** Encode caller-owned opaque local state. */
export function encodeState(state: DecodedState): Uint8Array {
    validateState(state);
    const privateKeys = [...state.privateKeys.entries()].sort(([left], [right]) => left - right);
    return concatBytes(
        STATE_MAGIC,
        new Uint8Array([VERSION]),
        state.groupId,
        encodeUint64(state.epoch),
        encodeUint32(state.localLeaf),
        state.signingSecretKey,
        encodeTree(state.tree),
        encodeUint16(privateKeys.length),
        ...privateKeys.map(([node, secretKey]) => concatBytes(encodeUint32(node), secretKey)),
    );
}

/** Decode and fully validate opaque local state. */
export function decodeState(bytes: Uint8Array): DecodedState {
    validateBlob(bytes, "TreeKEM state");
    const reader = new ByteReader(bytes, "TreeKEM state");
    assertMagic(reader.readBytes(4), STATE_MAGIC, "TreeKEM state");
    if (reader.readUint8() !== VERSION) {
        throw new Error("Unsupported TreeKEM state version");
    }
    const groupId = reader.readBytes(32);
    const epoch = reader.readUint64();
    const localLeaf = reader.readUint32();
    const signingSecretKey = reader.readBytes(32);
    const tree = decodeTreeFromReader(reader);
    const privateCount = reader.readUint16();
    if (privateCount > MAXIMUM_PATH_NODES) {
        throw new Error("TreeKEM private path is too large");
    }
    const privateKeys = new Map<number, Uint8Array>();
    for (let index = 0; index < privateCount; index += 1) {
        const node = reader.readUint32();
        if (privateKeys.has(node)) {
            throw new Error("Duplicate TreeKEM private path key");
        }
        privateKeys.set(node, reader.readBytes(32));
    }
    reader.ensureEnd();
    const state: DecodedState = {
        groupId,
        epoch,
        localLeaf,
        signingSecretKey,
        tree,
        privateKeys,
    };
    try {
        validateState(state);
        return state;
    } catch (error: unknown) {
        destroyDecodedState(state);
        throw error;
    }
}

/** Zero private arrays allocated while decoding state. */
export function destroyDecodedState(state: DecodedState): void {
    state.signingSecretKey.fill(0);
    for (const secretKey of state.privateKeys.values()) {
        secretKey.fill(0);
    }
}

/** Canonical bytes covered by an update signature. */
export function encodeUpdateBody(packet: Omit<UpdatePacket, "signature">): Uint8Array {
    if (
        packet.groupId.length !== 32 ||
        packet.previousTreeHash.length !== 32 ||
        packet.treeHash.length !== 32 ||
        packet.leafEncryptionKey.length !== 32 ||
        packet.removals.length > MAXIMUM_LEAVES ||
        packet.additions.length > MAXIMUM_LEAVES ||
        packet.nodes.length > MAXIMUM_PATH_NODES
    ) {
        throw new Error("Invalid TreeKEM update structure");
    }
    return concatBytes(
        UPDATE_MAGIC,
        new Uint8Array([VERSION]),
        packet.groupId,
        encodeUint64(packet.epoch),
        encodeUint32(packet.sender),
        packet.previousTreeHash,
        encodeUint32(packet.removals.length),
        ...packet.removals.map(encodeUint32),
        encodeUint32(packet.additions.length),
        ...packet.additions.map((addition) => {
            if (addition.publicKey.length !== 64) {
                throw new Error("Invalid TreeKEM update admission key");
            }
            return concatBytes(encodeUint32(addition.leaf), addition.publicKey);
        }),
        canonicalizePublicKey(packet.leafEncryptionKey),
        encodeUint16(packet.nodes.length),
        ...packet.nodes.map((node) =>
            concatBytes(
                encodeUint32(node.node),
                canonicalizePublicKey(node.encryptionKey),
                encodeUint32(node.encryptedPathSecrets.length),
                ...node.encryptedPathSecrets.map((encrypted) => {
                    if (
                        encrypted.encapsulatedKey.length !== 32 ||
                        encrypted.ciphertext.length !== PATH_CIPHERTEXT_BYTES
                    ) {
                        throw new Error("Invalid TreeKEM path ciphertext");
                    }
                    return concatBytes(
                        canonicalizePublicKey(encrypted.encapsulatedKey),
                        encrypted.ciphertext,
                    );
                }),
            ),
        ),
        packet.treeHash,
    );
}

/** Encode a complete signed update packet. */
export function encodeUpdate(packet: UpdatePacket): Uint8Array {
    if (packet.signature.length !== 64) {
        throw new Error("Invalid TreeKEM update signature");
    }
    return concatBytes(encodeUpdateBody(packet), packet.signature);
}

/** Decode a signed update packet and retain its exact canonical body. */
export function decodeUpdate(bytes: Uint8Array): DecodedUpdatePacket {
    validateBlob(bytes, "TreeKEM update");
    const reader = new ByteReader(bytes, "TreeKEM update");
    assertMagic(reader.readBytes(4), UPDATE_MAGIC, "TreeKEM update");
    if (reader.readUint8() !== VERSION) {
        throw new Error("Unsupported TreeKEM update version");
    }
    const groupId = reader.readBytes(32);
    const epoch = reader.readUint64();
    const sender = reader.readUint32();
    const previousTreeHash = reader.readBytes(32);
    const removalCount = reader.readUint32();
    if (removalCount > MAXIMUM_LEAVES) {
        throw new Error("TreeKEM update has too many removals");
    }
    const removals = Array.from({ length: removalCount }, () => reader.readUint32());
    const additionCount = reader.readUint32();
    if (additionCount > MAXIMUM_LEAVES) {
        throw new Error("TreeKEM update has too many additions");
    }
    const additions = Array.from(
        { length: additionCount },
        (): PacketAddition => ({
            leaf: reader.readUint32(),
            publicKey: encodeAdmissionPublicKey({
                encryptionKey: reader.readBytes(32),
                signatureKey: reader.readBytes(32),
            }),
        }),
    );
    const leafEncryptionKey = canonicalizePublicKey(reader.readBytes(32));
    const nodeCount = reader.readUint16();
    if (nodeCount > MAXIMUM_PATH_NODES) {
        throw new Error("TreeKEM update path is too large");
    }
    const nodes = Array.from({ length: nodeCount }, (): PacketNode => {
        const node = reader.readUint32();
        const encryptionKey = canonicalizePublicKey(reader.readBytes(32));
        const ciphertextCount = reader.readUint32();
        if (ciphertextCount > MAXIMUM_LEAVES) {
            throw new Error("TreeKEM update has too many path ciphertexts");
        }
        return {
            node,
            encryptionKey,
            encryptedPathSecrets: Array.from(
                { length: ciphertextCount },
                (): HpkeCiphertext => ({
                    encapsulatedKey: canonicalizePublicKey(reader.readBytes(32)),
                    ciphertext: reader.readBytes(PATH_CIPHERTEXT_BYTES),
                }),
            ),
        };
    });
    const treeHash = reader.readBytes(32);
    const signature = reader.readBytes(64);
    reader.ensureEnd();
    const packet: UpdatePacket = {
        groupId,
        epoch,
        sender,
        previousTreeHash,
        removals,
        additions,
        leafEncryptionKey,
        nodes,
        treeHash,
        signature,
    };
    const body = encodeUpdateBody(packet);
    if (!equalBytes(body, bytes.slice(0, -64))) {
        throw new Error("Noncanonical TreeKEM update");
    }
    return { ...packet, body };
}

/** Canonical bytes covered by a Welcome signature. */
export function encodeWelcomeBody(welcome: Omit<WelcomeMessage, "signature">): Uint8Array {
    if (
        welcome.groupId.length !== 32 ||
        welcome.previousTreeHash.length !== 32 ||
        welcome.treeHash.length !== 32 ||
        welcome.encapsulatedKey.length !== 32 ||
        welcome.ciphertext.length < 16 ||
        welcome.ciphertext.length > MAXIMUM_BLOB_BYTES
    ) {
        throw new Error("Invalid TreeKEM Welcome structure");
    }
    return concatBytes(
        WELCOME_MAGIC,
        new Uint8Array([VERSION]),
        welcome.groupId,
        encodeUint64(welcome.epoch),
        encodeUint32(welcome.sender),
        encodeUint32(welcome.recipient),
        welcome.previousTreeHash,
        welcome.treeHash,
        canonicalizePublicKey(welcome.encapsulatedKey),
        encodeUint32(welcome.ciphertext.length),
        welcome.ciphertext,
    );
}

/** Encode a complete signed Welcome. */
export function encodeWelcome(welcome: WelcomeMessage): Uint8Array {
    if (welcome.signature.length !== 64) {
        throw new Error("Invalid TreeKEM Welcome signature");
    }
    return concatBytes(encodeWelcomeBody(welcome), welcome.signature);
}

/** Decode a recipient-encrypted signed Welcome. */
export function decodeWelcome(bytes: Uint8Array): DecodedWelcomeMessage {
    validateBlob(bytes, "TreeKEM Welcome");
    const reader = new ByteReader(bytes, "TreeKEM Welcome");
    assertMagic(reader.readBytes(4), WELCOME_MAGIC, "TreeKEM Welcome");
    if (reader.readUint8() !== VERSION) {
        throw new Error("Unsupported TreeKEM Welcome version");
    }
    const message: WelcomeMessage = {
        groupId: reader.readBytes(32),
        epoch: reader.readUint64(),
        sender: reader.readUint32(),
        recipient: reader.readUint32(),
        previousTreeHash: reader.readBytes(32),
        treeHash: reader.readBytes(32),
        encapsulatedKey: canonicalizePublicKey(reader.readBytes(32)),
        ciphertext: reader.readBytes(reader.readUint32()),
        signature: reader.readBytes(64),
    };
    reader.ensureEnd();
    const body = encodeWelcomeBody(message);
    if (!equalBytes(body, bytes.slice(0, -64))) {
        throw new Error("Noncanonical TreeKEM Welcome");
    }
    return { ...message, body };
}

/** Encode the recipient-only Welcome payload. */
export function encodeWelcomePayload(payload: WelcomePayload): Uint8Array {
    if (payload.commitSecret.length !== 32 || payload.privateKeys.size > MAXIMUM_PATH_NODES) {
        throw new Error("Invalid TreeKEM Welcome payload");
    }
    const privateKeys = [...payload.privateKeys.entries()].sort(([left], [right]) => left - right);
    const tree = encodeTree(payload.tree);
    return concatBytes(
        WELCOME_PAYLOAD_MAGIC,
        new Uint8Array([VERSION]),
        encodeUint32(tree.length),
        tree,
        encodeUint16(privateKeys.length),
        ...privateKeys.map(([node, secretKey]) => {
            if (secretKey.length !== 32) {
                throw new Error("Invalid TreeKEM Welcome private key");
            }
            return concatBytes(encodeUint32(node), secretKey);
        }),
        payload.commitSecret,
    );
}

/** Decode a recipient-only Welcome payload. */
export function decodeWelcomePayload(bytes: Uint8Array): WelcomePayload {
    validateBlob(bytes, "TreeKEM Welcome payload");
    const reader = new ByteReader(bytes, "TreeKEM Welcome payload");
    assertMagic(reader.readBytes(4), WELCOME_PAYLOAD_MAGIC, "TreeKEM Welcome payload");
    if (reader.readUint8() !== VERSION) {
        throw new Error("Unsupported TreeKEM Welcome payload version");
    }
    const treeBytes = reader.readBytes(reader.readUint32());
    const treeReader = new ByteReader(treeBytes, "TreeKEM Welcome tree");
    const tree = decodeTreeFromReader(treeReader);
    treeReader.ensureEnd();
    const privateCount = reader.readUint16();
    if (privateCount > MAXIMUM_PATH_NODES) {
        throw new Error("TreeKEM Welcome private path is too large");
    }
    const privateKeys = new Map<number, Uint8Array>();
    for (let index = 0; index < privateCount; index += 1) {
        const node = reader.readUint32();
        if (privateKeys.has(node)) {
            throw new Error("Duplicate TreeKEM Welcome private key");
        }
        privateKeys.set(node, reader.readBytes(32));
    }
    const commitSecret = reader.readBytes(32);
    reader.ensureEnd();
    return { tree, privateKeys, commitSecret };
}
