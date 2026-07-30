import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    zeroBytes,
    type JsonValue,
} from "@slopus/murmur";
import {
    decodeMlsGroupContext,
    encodeMlsGroupContext,
    type MlsGroupContext,
} from "../../groupContext/index.js";
import { destroyMlsEpochSecrets, type MlsEpochSecrets } from "../../keySchedule/index.js";
import type { MlsLeafNode } from "../../leafNode/index.js";
import {
    decodeMlsRatchetTree,
    encodeMlsRatchetTree,
    type MlsRatchetTree,
} from "../../ratchetTree/index.js";
import {
    destroyMlsSecretTreeState,
    type MlsGenerationKey,
    type MlsRatchetType,
    type MlsSecretTreeRatchetState,
    type MlsSecretTreeState,
} from "../../secretTree/index.js";
import { destroyMlsTreePrivateKeys, type MlsTreePrivateKey } from "../../updatePath/index.js";
import type { MlsEpochMember } from "../types.js";

const MAXIMUM_STATE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_MEMBERS = 100_000;
const MAXIMUM_PRIVATE_KEYS = 64;
const MAXIMUM_TREE_NODES = 200_000;
const MAXIMUM_RATCHETS = MAXIMUM_MEMBERS * 2;
const MAXIMUM_SKIPPED_KEYS = 100_000;
const MAXIMUM_UINT32_PLUS_ONE = 0x1_0000_0000;

const SECRET_FIELDS = [
    "senderDataSecret",
    "exporterSecret",
    "epochAuthenticator",
    "externalSecret",
    "confirmationKey",
    "membershipKey",
    "resumptionPsk",
    "nextInitSecret",
] as const satisfies readonly (keyof MlsEpochSecrets)[];

interface SerializedMember {
    readonly signing: string;
    readonly encryption: string | null;
}

interface SerializedPrivateKey {
    readonly node: number;
    readonly secret: string;
    readonly public: string;
}

interface SerializedNodeSecret {
    readonly node: number;
    readonly secret: string;
}

interface SerializedGenerationKey {
    readonly generation: number;
    readonly key: string;
    readonly nonce: string;
}

interface SerializedRatchet {
    readonly sender: number;
    readonly type: MlsRatchetType;
    readonly secret: string;
    readonly generation: number;
    readonly skipped: readonly SerializedGenerationKey[];
}

interface SerializedSecretTree {
    readonly leafCount: number;
    readonly maximumForwardDistance: number;
    readonly maximumSkippedKeys: number;
    readonly nodeSecrets: readonly SerializedNodeSecret[];
    readonly ratchets: readonly SerializedRatchet[];
}

interface SerializedEpochState {
    readonly version: 1;
    readonly mode: "legacy" | "tree";
    readonly context: string;
    readonly secrets: readonly string[];
    readonly members: readonly (SerializedMember | null)[] | null;
    readonly tree: string | null;
    readonly privateKeys: readonly SerializedPrivateKey[];
    readonly localLeaf: number;
    readonly persistenceGeneration: string;
    readonly interimTranscriptHash: string | null;
    readonly secretTree: SerializedSecretTree;
}

/** Internal, already-decoded durable state consumed by `MlsEpochState`. */
export interface DecodedMlsEpochState {
    readonly context: MlsGroupContext;
    readonly secrets: MlsEpochSecrets;
    readonly members?: readonly (MlsEpochMember | undefined)[];
    readonly tree?: MlsRatchetTree;
    readonly privateKeys: readonly MlsTreePrivateKey[];
    readonly localLeaf: number;
    readonly persistenceGeneration: bigint;
    readonly interimTranscriptHash?: Uint8Array;
    readonly secretTreeState: MlsSecretTreeState;
}

function exactOwnData(value: unknown, fields: readonly string[]): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Invalid durable MLS epoch state");
    }
    const keys = Reflect.ownKeys(value);
    if (
        keys.length !== fields.length ||
        keys.some((key) => typeof key !== "string" || !fields.includes(key))
    ) {
        throw new Error("Invalid durable MLS epoch state");
    }
    const result: Record<string, unknown> = {};
    for (const field of fields) {
        const descriptor = Object.getOwnPropertyDescriptor(value, field);
        if (descriptor === undefined || !("value" in descriptor)) {
            throw new Error("Invalid durable MLS epoch state");
        }
        result[field] = descriptor.value;
    }
    return result;
}

function safeInteger(value: unknown, minimum: number, maximum: number): number {
    if (
        typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value < minimum ||
        value > maximum
    ) {
        throw new Error("Invalid durable MLS epoch integer");
    }
    return value;
}

function decodeBytes(value: unknown, maximumBytes: number, exactBytes?: number): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximumBytes * 4) / 3)) {
        throw new Error("Invalid durable MLS epoch bytes");
    }
    const bytes = decodeBase64Url(value);
    if (
        bytes.length > maximumBytes ||
        (exactBytes !== undefined && bytes.length !== exactBytes) ||
        encodeBase64Url(bytes) !== value
    ) {
        throw new Error("Invalid durable MLS epoch bytes");
    }
    return bytes;
}

function decodeSecret(value: unknown, exactBytes: number, sensitive: Uint8Array[]): Uint8Array {
    const secret = decodeBytes(value, exactBytes, exactBytes);
    sensitive.push(secret);
    return secret;
}

function serializeSecrets(secrets: MlsEpochSecrets): readonly string[] {
    return SECRET_FIELDS.map((field) => encodeBase64Url(secrets[field]));
}

function deserializeSecrets(value: unknown, sensitive: Uint8Array[]): MlsEpochSecrets {
    if (!Array.isArray(value) || value.length !== SECRET_FIELDS.length) {
        throw new Error("Invalid durable MLS epoch secrets");
    }
    const decoded = value.map((secret) => decodeSecret(secret, 32, sensitive));
    const retained = Object.fromEntries(
        SECRET_FIELDS.map((field, index) => [field, decoded[index]]),
    ) as unknown as Omit<
        MlsEpochSecrets,
        "joinerSecret" | "memberSecret" | "epochSecret" | "encryptionSecret"
    >;
    return {
        ...retained,
        joinerSecret: new Uint8Array(32),
        memberSecret: new Uint8Array(32),
        epochSecret: new Uint8Array(32),
        encryptionSecret: new Uint8Array(32),
    };
}

function serializeMembers(
    members: readonly (MlsEpochMember | undefined)[],
): readonly (SerializedMember | null)[] {
    return members.map((member) =>
        member === undefined
            ? null
            : {
                  signing: encodeBase64Url(member.signatureKey),
                  encryption:
                      member.encryptionKey === undefined
                          ? null
                          : encodeBase64Url(member.encryptionKey),
              },
    );
}

function deserializeMembers(value: unknown): readonly (MlsEpochMember | undefined)[] {
    if (!Array.isArray(value) || value.length === 0 || value.length > MAXIMUM_MEMBERS) {
        throw new Error("Invalid durable MLS epoch members");
    }
    return value.map((entry) => {
        if (entry === null) {
            return undefined;
        }
        const member = exactOwnData(entry, ["signing", "encryption"]);
        const signatureKey = decodeBytes(member.signing, 32, 32);
        if (member.encryption === null) {
            return { signatureKey };
        }
        return {
            signatureKey,
            encryptionKey: decodeBytes(member.encryption, 32, 32),
        };
    });
}

function serializePrivateKeys(
    privateKeys: readonly MlsTreePrivateKey[],
): readonly SerializedPrivateKey[] {
    return privateKeys.map((key) => ({
        node: key.node,
        secret: encodeBase64Url(key.keyPair.secretKey),
        public: encodeBase64Url(key.keyPair.publicKey),
    }));
}

function deserializePrivateKeys(
    value: unknown,
    sensitive: Uint8Array[],
): readonly MlsTreePrivateKey[] {
    if (!Array.isArray(value) || value.length > MAXIMUM_PRIVATE_KEYS) {
        throw new Error("Invalid durable MLS private keys");
    }
    return value.map((entry) => {
        const key = exactOwnData(entry, ["node", "secret", "public"]);
        return {
            node: safeInteger(key.node, 0, MAXIMUM_TREE_NODES - 1),
            keyPair: {
                secretKey: decodeSecret(key.secret, 32, sensitive),
                publicKey: decodeBytes(key.public, 32, 32),
            },
        };
    });
}

function serializeGenerationKey(key: MlsGenerationKey): SerializedGenerationKey {
    return {
        generation: key.generation,
        key: encodeBase64Url(key.key),
        nonce: encodeBase64Url(key.nonce),
    };
}

function deserializeGenerationKey(
    value: unknown,
    sender: number,
    type: MlsRatchetType,
    sensitive: Uint8Array[],
): MlsGenerationKey {
    const key = exactOwnData(value, ["generation", "key", "nonce"]);
    return {
        sender,
        type,
        generation: safeInteger(key.generation, 0, 0xffff_ffff),
        key: decodeSecret(key.key, 16, sensitive),
        nonce: decodeSecret(key.nonce, 12, sensitive),
    };
}

function serializeSecretTree(state: MlsSecretTreeState): SerializedSecretTree {
    return {
        leafCount: state.leafCount,
        maximumForwardDistance: state.maximumForwardDistance,
        maximumSkippedKeys: state.maximumSkippedKeys,
        nodeSecrets: state.nodeSecrets.map((entry) => ({
            node: entry.node,
            secret: encodeBase64Url(entry.secret),
        })),
        ratchets: state.ratchets.map((ratchet) => ({
            sender: ratchet.sender,
            type: ratchet.type,
            secret: encodeBase64Url(ratchet.secret),
            generation: ratchet.generation,
            skipped: ratchet.skipped.map(serializeGenerationKey),
        })),
    };
}

function deserializeSecretTree(value: unknown, sensitive: Uint8Array[]): MlsSecretTreeState {
    const tree = exactOwnData(value, [
        "leafCount",
        "maximumForwardDistance",
        "maximumSkippedKeys",
        "nodeSecrets",
        "ratchets",
    ]);
    const leafCount = safeInteger(tree.leafCount, 1, MAXIMUM_MEMBERS);
    const maximumForwardDistance = safeInteger(tree.maximumForwardDistance, 0, 10_000);
    const maximumSkippedKeys = safeInteger(tree.maximumSkippedKeys, 1, MAXIMUM_SKIPPED_KEYS);
    if (!Array.isArray(tree.nodeSecrets) || tree.nodeSecrets.length > MAXIMUM_TREE_NODES) {
        throw new Error("Invalid durable MLS Secret Tree nodes");
    }
    const nodeSecrets = tree.nodeSecrets.map((value) => {
        const node = exactOwnData(value, ["node", "secret"]);
        return {
            node: safeInteger(node.node, 0, MAXIMUM_TREE_NODES - 1),
            secret: decodeSecret(node.secret, 32, sensitive),
        };
    });
    if (!Array.isArray(tree.ratchets) || tree.ratchets.length > MAXIMUM_RATCHETS) {
        throw new Error("Invalid durable MLS Secret Tree ratchets");
    }
    let skippedCount = 0;
    const ratchets: MlsSecretTreeRatchetState[] = tree.ratchets.map((value) => {
        const ratchet = exactOwnData(value, ["sender", "type", "secret", "generation", "skipped"]);
        const sender = safeInteger(ratchet.sender, 0, leafCount - 1);
        if (ratchet.type !== "handshake" && ratchet.type !== "application") {
            throw new Error("Invalid durable MLS ratchet type");
        }
        const type = ratchet.type;
        if (!Array.isArray(ratchet.skipped)) {
            throw new Error("Invalid durable MLS skipped keys");
        }
        skippedCount += ratchet.skipped.length;
        if (ratchet.skipped.length > maximumSkippedKeys || skippedCount > maximumSkippedKeys) {
            throw new Error("Durable MLS skipped keys exceed their budget");
        }
        return {
            sender,
            type,
            secret: decodeSecret(ratchet.secret, 32, sensitive),
            generation: safeInteger(ratchet.generation, 0, MAXIMUM_UINT32_PLUS_ONE),
            skipped: ratchet.skipped.map((entry) =>
                deserializeGenerationKey(entry, sender, type, sensitive),
            ),
        };
    });
    return {
        leafCount,
        maximumForwardDistance,
        maximumSkippedKeys,
        nodeSecrets,
        ratchets,
    };
}

/** Encode sensitive local epoch state for durable storage. */
export function encodeMlsEpochState(state: DecodedMlsEpochState): Uint8Array {
    const treeMode = state.tree !== undefined;
    const serialized: SerializedEpochState = {
        version: 1,
        mode: treeMode ? "tree" : "legacy",
        context: encodeBase64Url(encodeMlsGroupContext(state.context)),
        secrets: serializeSecrets(state.secrets),
        members: state.members === undefined ? null : serializeMembers(state.members),
        tree: state.tree === undefined ? null : encodeBase64Url(encodeMlsRatchetTree(state.tree)),
        privateKeys: serializePrivateKeys(state.privateKeys),
        localLeaf: state.localLeaf,
        persistenceGeneration: state.persistenceGeneration.toString(),
        interimTranscriptHash:
            state.interimTranscriptHash === undefined
                ? null
                : encodeBase64Url(state.interimTranscriptHash),
        secretTree: serializeSecretTree(state.secretTreeState),
    };
    const bytes = canonicalJsonBytes(serialized as unknown as JsonValue);
    if (bytes.length > MAXIMUM_STATE_BYTES) {
        throw new Error("Durable MLS epoch state is too large");
    }
    return bytes;
}

/** Decode and validate sensitive local epoch state. */
export function decodeMlsEpochState(
    bytes: Uint8Array,
    authenticateCredential: ((leafNode: MlsLeafNode, leafIndex: number) => boolean) | undefined,
): DecodedMlsEpochState {
    if (bytes.length === 0 || bytes.length > MAXIMUM_STATE_BYTES) {
        throw new Error("Invalid durable MLS epoch state size");
    }
    const sensitive: Uint8Array[] = [];
    try {
        const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
        const canonical = canonicalJsonBytes(parsed as JsonValue);
        if (!equalBytes(canonical, bytes)) {
            throw new Error("Durable MLS epoch state must use canonical JSON");
        }
        const value = exactOwnData(parsed, [
            "version",
            "mode",
            "context",
            "secrets",
            "members",
            "tree",
            "privateKeys",
            "localLeaf",
            "persistenceGeneration",
            "interimTranscriptHash",
            "secretTree",
        ]);
        if (value.version !== 1 || (value.mode !== "legacy" && value.mode !== "tree")) {
            throw new Error("Unsupported durable MLS epoch state");
        }
        const context = decodeMlsGroupContext(decodeBytes(value.context, 512));
        const secrets = deserializeSecrets(value.secrets, sensitive);
        const privateKeys = deserializePrivateKeys(value.privateKeys, sensitive);
        const localLeaf = safeInteger(value.localLeaf, 0, MAXIMUM_MEMBERS - 1);
        if (
            typeof value.persistenceGeneration !== "string" ||
            !/^(?:0|[1-9]\d{0,19})$/.test(value.persistenceGeneration)
        ) {
            throw new Error("Invalid durable MLS persistence generation");
        }
        const persistenceGeneration = BigInt(value.persistenceGeneration);
        if (persistenceGeneration > 0xffff_ffff_ffff_ffffn) {
            throw new Error("Invalid durable MLS persistence generation");
        }
        const interimTranscriptHash =
            value.interimTranscriptHash === null
                ? undefined
                : decodeSecret(value.interimTranscriptHash, 32, sensitive);
        const secretTreeState = deserializeSecretTree(value.secretTree, sensitive);
        if (secretTreeState.leafCount <= localLeaf) {
            throw new Error("Durable MLS local leaf is out of range");
        }
        if (value.mode === "legacy") {
            if (value.tree !== null || privateKeys.length !== 0 || value.members === null) {
                throw new Error("Invalid durable legacy MLS epoch state");
            }
            return {
                context,
                secrets,
                members: deserializeMembers(value.members),
                privateKeys,
                localLeaf,
                persistenceGeneration,
                ...(interimTranscriptHash === undefined ? {} : { interimTranscriptHash }),
                secretTreeState,
            };
        }
        if (
            typeof value.tree !== "string" ||
            value.members !== null ||
            authenticateCredential === undefined
        ) {
            throw new Error("Durable TreeKEM state requires credential authentication");
        }
        const tree = decodeMlsRatchetTree(decodeBytes(value.tree, 16 * 1024 * 1024), {
            groupId: context.groupId,
            authenticateCredential,
        });
        return {
            context,
            secrets,
            tree,
            privateKeys,
            localLeaf,
            persistenceGeneration,
            ...(interimTranscriptHash === undefined ? {} : { interimTranscriptHash }),
            secretTreeState,
        };
    } catch (error: unknown) {
        for (const secret of sensitive) {
            zeroBytes(secret);
        }
        throw error;
    }
}

/** Destroy every sensitive array owned by one decoded persistence record. */
export function destroyDecodedMlsEpochState(state: DecodedMlsEpochState): void {
    destroyMlsEpochSecrets(state.secrets);
    destroyMlsTreePrivateKeys(state.privateKeys);
    destroyMlsSecretTreeState(state.secretTreeState);
    if (state.interimTranscriptHash !== undefined) {
        zeroBytes(state.interimTranscriptHash);
    }
}
