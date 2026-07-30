import { encodeBase64Url, equalBytes, zeroBytes } from "@murmur/core";
import {
    canonicalizeHpkePublicKey,
    MLS_HASH_LENGTH,
    mlsMac,
    mlsSignWithLabel,
    mlsVerifyMac,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import {
    createMlsConfirmationTag,
    encodeMlsGroupContext,
    updateConfirmedTranscriptHash,
    updateInterimTranscriptHash,
    verifyMlsConfirmationTag,
    type MlsGroupContext,
} from "../groupContext/index.js";
import {
    mlsKeyPackageReference,
    verifyMlsKeyPackage,
    type MlsKeyPackage,
} from "../keyPackage/index.js";
import {
    deriveMlsEpochSecrets,
    destroyMlsEpochSecrets,
    type MlsEpochSecrets,
} from "../keySchedule/index.js";
import { createMlsWelcome } from "../welcome/index.js";
import {
    decodeMlsLeafNodeBytes,
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    type MlsLeafNode,
} from "../leafNode/index.js";
import { type MlsRatchetTreeLeaf } from "../ratchetTree/index.js";
import { directPath } from "../tree/index.js";
import {
    createMlsUpdatePath,
    destroyMlsUpdatePathResult,
    openMlsUpdatePath,
    validateMlsUpdatePath,
    type MlsTreePrivateKey,
    type MlsUpdatePathResult,
} from "../updatePath/index.js";
import {
    decodeMlsAddCommit,
    encodeMlsAddCommit,
    encodeMlsAddCommitConfirmedTranscriptInput,
    encodeMlsAddCommitTbm,
    encodeMlsAddCommitTbs,
} from "./impl/codec.js";
import {
    decodeMlsTreeCommit,
    encodeMlsTreeCommit,
    encodeMlsTreeCommitConfirmedTranscriptInput,
    encodeMlsTreeCommitTbm,
    encodeMlsTreeCommitTbs,
} from "./impl/treeCodec.js";
import type {
    CreateMlsAddCommitOptions,
    CreateMlsTreeCommitOptions,
    MlsAddCommitMessage,
    MlsAppliedAddCommit,
    MlsAppliedTreeCommit,
    MlsCommitMember,
    MlsCreatedAddCommit,
    MlsCreatedTreeCommit,
    MlsTreeCommitMessage,
    MlsTreeCommitProposal,
    OpenMlsAddCommitOptions,
    OpenMlsTreeCommitOptions,
} from "./types.js";

export type {
    CreateMlsAddCommitOptions,
    CreateMlsTreeCommitOptions,
    MlsAddCommitMessage,
    MlsAppliedAddCommit,
    MlsAppliedTreeCommit,
    MlsCommitMember,
    MlsCreatedAddCommit,
    MlsCreatedTreeCommit,
    MlsTreeCommitMessage,
    MlsTreeCommitProposal,
    OpenMlsAddCommitOptions,
    OpenMlsTreeCommitOptions,
} from "./types.js";

/** Authenticated Commit which removes the local member from the next epoch. */
export class MlsLocalMemberRemovedError extends Error {
    constructor() {
        super("Local member was removed by MLS Commit");
        this.name = "MlsLocalMemberRemovedError";
    }
}
export { decodeMlsAddCommit, encodeMlsAddCommit } from "./impl/codec.js";
export { decodeMlsTreeCommit, encodeMlsTreeCommit } from "./impl/treeCodec.js";

const MAXIMUM_MEMBERS = 100_000;
const ZERO_COMMIT_SECRET = new Uint8Array(MLS_HASH_LENGTH);

function validateCurrentState(
    context: MlsGroupContext,
    interimTranscriptHash: Uint8Array,
    nextInitSecret: Uint8Array,
    membershipKey: Uint8Array,
    members: readonly (MlsCommitMember | undefined)[],
): void {
    encodeMlsGroupContext(context);
    if (
        context.epoch === 0xffff_ffff_ffff_ffffn ||
        interimTranscriptHash.length !== MLS_HASH_LENGTH ||
        nextInitSecret.length !== MLS_HASH_LENGTH ||
        membershipKey.length !== MLS_HASH_LENGTH ||
        members.length === 0 ||
        members.length > MAXIMUM_MEMBERS ||
        members.some(
            (member) =>
                member !== undefined &&
                (member.signatureKey.length !== MLS_HASH_LENGTH ||
                    member.encryptionKey.length !== MLS_HASH_LENGTH),
        )
    ) {
        throw new Error("Invalid current MLS Commit state");
    }
    const encryptionKeys = new Set<string>();
    const signatureKeys = new Set<string>();
    for (const member of members) {
        if (member === undefined) {
            continue;
        }
        const encryptionKey = canonicalizeHpkePublicKey(member.encryptionKey);
        const encryptionKeyId = encodeBase64Url(encryptionKey);
        const signatureKeyId = encodeBase64Url(member.signatureKey);
        if (encryptionKeys.has(encryptionKeyId)) {
            throw new Error("Duplicate MLS leaf encryption key");
        }
        if (signatureKeys.has(signatureKeyId)) {
            throw new Error("Duplicate MLS member signature key");
        }
        encryptionKeys.add(encryptionKeyId);
        signatureKeys.add(signatureKeyId);
    }
}

function applyAdditions(
    members: readonly (MlsCommitMember | undefined)[],
    additions: readonly MlsKeyPackage[],
): readonly (MlsCommitMember | undefined)[] {
    if (additions.length === 0 || additions.length > 1_024) {
        throw new Error("MLS add Commit must contain 1 to 1024 additions");
    }
    const nextMembers = members.map((member) =>
        member === undefined
            ? undefined
            : {
                  signatureKey: member.signatureKey.slice(),
                  encryptionKey: member.encryptionKey.slice(),
              },
    );
    const references = new Set<string>();
    const identities = new Set(
        nextMembers.flatMap((member) =>
            member === undefined ? [] : [encodeBase64Url(member.signatureKey)],
        ),
    );
    const encryptionKeys = new Set(
        nextMembers.flatMap((member) =>
            member === undefined
                ? []
                : [encodeBase64Url(canonicalizeHpkePublicKey(member.encryptionKey))],
        ),
    );
    for (const keyPackage of additions) {
        if (!verifyMlsKeyPackage(keyPackage)) {
            throw new Error("Invalid MLS add KeyPackage");
        }
        const reference = mlsKeyPackageReference(keyPackage);
        const referenceId = encodeBase64Url(reference);
        if (references.has(referenceId)) {
            throw new Error("Duplicate MLS add KeyPackage");
        }
        references.add(referenceId);
        const identityId = encodeBase64Url(keyPackage.leafNode.signatureKey);
        if (identities.has(identityId)) {
            throw new Error("MLS member identity is already present");
        }
        const canonicalEncryptionKey = canonicalizeHpkePublicKey(keyPackage.leafNode.encryptionKey);
        const encryptionKeyId = encodeBase64Url(canonicalEncryptionKey);
        if (encryptionKeys.has(encryptionKeyId)) {
            throw new Error("MLS leaf encryption key is already present");
        }
        const member = {
            signatureKey: keyPackage.leafNode.signatureKey.slice(),
            encryptionKey: keyPackage.leafNode.encryptionKey.slice(),
        };
        identities.add(identityId);
        encryptionKeys.add(encryptionKeyId);
        const blank = nextMembers.findIndex((candidate) => candidate === undefined);
        if (blank >= 0) {
            nextMembers[blank] = member;
        } else {
            nextMembers.push(member);
        }
        if (nextMembers.length > MAXIMUM_MEMBERS) {
            throw new Error("MLS group has too many members");
        }
    }
    return nextMembers;
}

function unsignedMessage(
    options: Pick<
        CreateMlsAddCommitOptions,
        "additions" | "authenticatedData" | "context" | "sender"
    >,
): MlsAddCommitMessage {
    return {
        groupId: options.context.groupId.slice(),
        epoch: options.context.epoch,
        sender: options.sender,
        authenticatedData: options.authenticatedData?.slice() ?? new Uint8Array(),
        additions: options.additions,
        signature: new Uint8Array(64),
        confirmationTag: new Uint8Array(MLS_HASH_LENGTH),
        membershipTag: new Uint8Array(MLS_HASH_LENGTH),
    };
}

function nextContext(
    current: MlsGroupContext,
    treeHash: Uint8Array,
    confirmedTranscriptHash: Uint8Array,
): MlsGroupContext {
    if (treeHash.length !== MLS_HASH_LENGTH) {
        throw new Error("Invalid next MLS tree hash");
    }
    return {
        groupId: current.groupId.slice(),
        epoch: current.epoch + 1n,
        treeHash: treeHash.slice(),
        confirmedTranscriptHash,
    };
}

function deriveNextEpoch(
    currentContext: MlsGroupContext,
    interimTranscriptHash: Uint8Array,
    nextInitSecret: Uint8Array,
    signedMessage: MlsAddCommitMessage,
    treeHash: Uint8Array,
): {
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly secrets: MlsEpochSecrets;
    readonly confirmationTag: Uint8Array;
} {
    const confirmedTranscriptHash = updateConfirmedTranscriptHash(
        interimTranscriptHash,
        encodeMlsAddCommitConfirmedTranscriptInput(signedMessage),
    );
    const context = nextContext(currentContext, treeHash, confirmedTranscriptHash);
    const secrets = deriveMlsEpochSecrets(
        nextInitSecret,
        ZERO_COMMIT_SECRET,
        encodeMlsGroupContext(context),
    );
    try {
        const confirmationTag = createMlsConfirmationTag(
            secrets.confirmationKey,
            confirmedTranscriptHash,
        );
        return {
            context,
            interimTranscriptHash: updateInterimTranscriptHash(
                confirmedTranscriptHash,
                confirmationTag,
            ),
            secrets,
            confirmationTag,
        };
    } catch (error: unknown) {
        destroyMlsEpochSecrets(secrets);
        throw error;
    }
}

/** Create and authenticate an RFC 9420 add-only Commit and Welcome. */
export function createMlsAddCommit(options: CreateMlsAddCommitOptions): MlsCreatedAddCommit {
    validateCurrentState(
        options.context,
        options.interimTranscriptHash,
        options.nextInitSecret,
        options.membershipKey,
        options.members,
    );
    const sender = options.members[options.sender];
    if (
        sender === undefined ||
        !Number.isSafeInteger(options.sender) ||
        options.sender < 0 ||
        options.sender > 0xffff_ffff
    ) {
        throw new Error("Invalid MLS Commit sender");
    }
    const members = applyAdditions(options.members, options.additions);
    const nextTreeHash = options.validateExternalTree(options.additions, members);
    const draft = unsignedMessage(options);
    const signature = mlsSignWithLabel(
        options.signingSecretKey,
        "FramedContentTBS",
        encodeMlsAddCommitTbs(draft, options.context),
    );
    const signed = { ...draft, signature };
    if (
        !mlsVerifyWithLabel(
            sender.signatureKey,
            "FramedContentTBS",
            encodeMlsAddCommitTbs(signed, options.context),
            signature,
        )
    ) {
        throw new Error("MLS Commit signing key does not match sender");
    }

    const next = deriveNextEpoch(
        options.context,
        options.interimTranscriptHash,
        options.nextInitSecret,
        signed,
        nextTreeHash,
    );
    try {
        const withConfirmation = {
            ...signed,
            confirmationTag: next.confirmationTag,
        };
        const message: MlsAddCommitMessage = {
            ...withConfirmation,
            membershipTag: mlsMac(
                options.membershipKey,
                encodeMlsAddCommitTbm(withConfirmation, options.context),
            ),
        };
        const commit = encodeMlsAddCommit(message);
        const welcome = createMlsWelcome({
            context: next.context,
            joinerSecret: next.secrets.joinerSecret,
            confirmationKey: next.secrets.confirmationKey,
            signer: options.sender,
            signerSecretKey: options.signingSecretKey,
            newMembers: options.additions,
        });
        return {
            commit,
            welcome,
            message: decodeMlsAddCommit(commit),
            context: next.context,
            interimTranscriptHash: next.interimTranscriptHash,
            secrets: next.secrets,
            members,
        };
    } catch (error: unknown) {
        destroyMlsEpochSecrets(next.secrets);
        throw error;
    }
}

/** Authenticate and apply an RFC 9420 add-only Commit from a current member. */
export function openMlsAddCommit(options: OpenMlsAddCommitOptions): MlsAppliedAddCommit {
    validateCurrentState(
        options.context,
        options.interimTranscriptHash,
        options.nextInitSecret,
        options.membershipKey,
        options.members,
    );
    const message = decodeMlsAddCommit(options.message);
    if (
        message.epoch !== options.context.epoch ||
        !equalBytes(message.groupId, options.context.groupId)
    ) {
        throw new Error("MLS Commit belongs to another group or epoch");
    }
    if (
        !mlsVerifyMac(
            options.membershipKey,
            encodeMlsAddCommitTbm(message, options.context),
            message.membershipTag,
        )
    ) {
        throw new Error("Invalid MLS Commit membership tag");
    }
    const sender = options.members[message.sender];
    if (
        sender === undefined ||
        !mlsVerifyWithLabel(
            sender.signatureKey,
            "FramedContentTBS",
            encodeMlsAddCommitTbs(message, options.context),
            message.signature,
        )
    ) {
        throw new Error("Invalid MLS Commit signature");
    }
    const members = applyAdditions(options.members, message.additions);
    const treeHash = options.validateExternalTree(message.additions, members);
    const next = deriveNextEpoch(
        options.context,
        options.interimTranscriptHash,
        options.nextInitSecret,
        message,
        treeHash,
    );
    if (
        !verifyMlsConfirmationTag(
            next.secrets.confirmationKey,
            next.context.confirmedTranscriptHash,
            message.confirmationTag,
        )
    ) {
        destroyMlsEpochSecrets(next.secrets);
        zeroBytes(next.interimTranscriptHash);
        throw new Error("Invalid MLS Commit confirmation tag");
    }
    return {
        message,
        context: next.context,
        interimTranscriptHash: next.interimTranscriptHash,
        secrets: next.secrets,
        members,
    };
}

function validateTreeCommitState(
    options: Pick<
        CreateMlsTreeCommitOptions,
        | "authenticateCredential"
        | "context"
        | "interimTranscriptHash"
        | "membershipKey"
        | "nextInitSecret"
        | "tree"
    >,
): void {
    encodeMlsGroupContext(options.context);
    if (
        options.context.epoch === 0xffff_ffff_ffff_ffffn ||
        options.interimTranscriptHash.length !== MLS_HASH_LENGTH ||
        options.nextInitSecret.length !== MLS_HASH_LENGTH ||
        options.membershipKey.length !== MLS_HASH_LENGTH ||
        !equalBytes(options.context.treeHash, options.tree.treeHash())
    ) {
        throw new Error("Invalid current MLS TreeKEM Commit state");
    }
    options.tree.validate({
        groupId: options.context.groupId,
        authenticateCredential: options.authenticateCredential,
    });
}

function keyPackageLeaf(keyPackage: MlsKeyPackage): MlsLeafNode {
    return {
        encryptionKey: keyPackage.leafNode.encryptionKey,
        signatureKey: keyPackage.leafNode.signatureKey,
        credential: keyPackage.leafNode.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: keyPackage.leafNode.notBefore,
        notAfter: keyPackage.leafNode.notAfter,
        extensions: [],
        signature: keyPackage.leafNode.signature,
    };
}

function publicKeyPackageLeaf(keyPackage: MlsKeyPackage): MlsRatchetTreeLeaf {
    const leaf = keyPackageLeaf(keyPackage);
    return {
        type: "leaf",
        encoded: encodeMlsLeafNode(leaf),
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
    };
}

function applyTreeCommitProposals(
    tree: CreateMlsTreeCommitOptions["tree"],
    sender: number,
    proposals: readonly MlsTreeCommitProposal[],
): {
    readonly tree: CreateMlsTreeCommitOptions["tree"];
    readonly additions: readonly MlsKeyPackage[];
    readonly addedLeaves: readonly number[];
    readonly removedLeaves: readonly number[];
} {
    if (proposals.length > 1_024) {
        throw new Error("MLS TreeKEM Commit has too many proposals");
    }
    const candidate = tree.clone();
    const snapshot = candidate.nodes;
    const removals = proposals
        .filter(
            (proposal): proposal is Extract<MlsTreeCommitProposal, { type: "remove" }> =>
                proposal.type === "remove",
        )
        .map((proposal) => proposal.removed);
    const uniqueRemovals = new Set(removals);
    if (
        uniqueRemovals.size !== removals.length ||
        removals.some(
            (removed) =>
                !Number.isSafeInteger(removed) ||
                removed < 0 ||
                removed >= candidate.leafCount ||
                snapshot[removed * 2]?.type !== "leaf" ||
                removed === sender,
        )
    ) {
        throw new Error("Invalid MLS Remove proposal");
    }
    for (const removed of [...removals].sort((left, right) => right - left)) {
        candidate.removeLeaf(removed);
    }

    const additions = proposals.flatMap((proposal) =>
        proposal.type === "add" ? [proposal.keyPackage] : [],
    );
    const references = new Set<string>();
    const signatureKeys = new Set(
        candidate.nodes.flatMap((node) =>
            node?.type === "leaf" ? [encodeBase64Url(node.signatureKey)] : [],
        ),
    );
    const addedLeaves: number[] = [];
    for (const keyPackage of additions) {
        if (!verifyMlsKeyPackage(keyPackage)) {
            throw new Error("Invalid MLS Add KeyPackage");
        }
        const reference = encodeBase64Url(mlsKeyPackageReference(keyPackage));
        const signatureKey = encodeBase64Url(keyPackage.leafNode.signatureKey);
        if (references.has(reference) || signatureKeys.has(signatureKey)) {
            throw new Error("Duplicate MLS Add proposal identity");
        }
        references.add(reference);
        signatureKeys.add(signatureKey);
        addedLeaves.push(candidate.addLeaf(publicKeyPackageLeaf(keyPackage)));
    }
    return {
        tree: candidate,
        additions,
        addedLeaves,
        removedLeaves: [...removals].sort((left, right) => left - right),
    };
}

function treeCommitDraft(
    options: Pick<
        CreateMlsTreeCommitOptions,
        "authenticatedData" | "context" | "proposals" | "sender"
    >,
    path: MlsTreeCommitMessage["path"],
): MlsTreeCommitMessage {
    return {
        groupId: options.context.groupId.slice(),
        epoch: options.context.epoch,
        sender: options.sender,
        authenticatedData: options.authenticatedData?.slice() ?? new Uint8Array(),
        proposals: options.proposals,
        path,
        signature: new Uint8Array(64),
        confirmationTag: new Uint8Array(MLS_HASH_LENGTH),
        membershipTag: new Uint8Array(MLS_HASH_LENGTH),
    };
}

function deriveTreeCommitEpoch(
    context: MlsGroupContext,
    interimTranscriptHash: Uint8Array,
    nextInitSecret: Uint8Array,
    message: MlsTreeCommitMessage,
    treeHash: Uint8Array,
    commitSecret: Uint8Array,
): {
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly secrets: MlsEpochSecrets;
    readonly confirmationTag: Uint8Array;
} {
    const confirmedTranscriptHash = updateConfirmedTranscriptHash(
        interimTranscriptHash,
        encodeMlsTreeCommitConfirmedTranscriptInput(message),
    );
    const next = nextContext(context, treeHash, confirmedTranscriptHash);
    const secrets = deriveMlsEpochSecrets(
        nextInitSecret,
        commitSecret,
        encodeMlsGroupContext(next),
    );
    try {
        const confirmationTag = createMlsConfirmationTag(
            secrets.confirmationKey,
            confirmedTranscriptHash,
        );
        return {
            context: next,
            interimTranscriptHash: updateInterimTranscriptHash(
                confirmedTranscriptHash,
                confirmationTag,
            ),
            secrets,
            confirmationTag,
        };
    } catch (error: unknown) {
        destroyMlsEpochSecrets(secrets);
        throw error;
    }
}

function copyTreePrivateKeys(update: MlsUpdatePathResult): readonly MlsTreePrivateKey[] {
    const copies: MlsTreePrivateKey[] = [];
    try {
        for (const key of update.privateKeys) {
            copies.push({
                node: key.node,
                keyPair: {
                    secretKey: key.keyPair.secretKey.slice(),
                    publicKey: key.keyPair.publicKey.slice(),
                },
            });
        }
        return copies;
    } catch (error: unknown) {
        for (const key of copies) {
            zeroBytes(key.keyPair.secretKey);
        }
        throw error;
    }
}

function destroyTreePrivateKeys(privateKeys: readonly MlsTreePrivateKey[]): void {
    for (const key of privateKeys) {
        zeroBytes(key.keyPair.secretKey);
    }
}

function welcomePathSecrets(
    update: MlsUpdatePathResult,
    sender: number,
    addedLeaves: readonly number[],
): readonly Uint8Array[] {
    const senderPath = directPath(sender, update.tree.leafCount);
    const pathSecrets = new Map(update.pathSecrets.map((entry) => [entry.node, entry.secret]));
    return addedLeaves.map((addedLeaf) => {
        const addedPath = new Set(directPath(addedLeaf, update.tree.leafCount));
        const commonAncestor = senderPath.find((node) => addedPath.has(node));
        const pathSecret =
            commonAncestor === undefined ? undefined : pathSecrets.get(commonAncestor);
        if (pathSecret === undefined) {
            throw new Error("MLS Welcome common-ancestor path secret is missing");
        }
        return pathSecret;
    });
}

/**
 * Create a full RFC Commit whose UpdatePath provides PCS for Add and
 * cryptographic exclusion for Remove.
 */
export function createMlsTreeCommit(options: CreateMlsTreeCommitOptions): MlsCreatedTreeCommit {
    validateTreeCommitState(options);
    const sender = options.tree.nodes[options.sender * 2];
    if (!Number.isSafeInteger(options.sender) || options.sender < 0 || sender?.type !== "leaf") {
        throw new Error("Invalid MLS TreeKEM Commit sender");
    }
    const senderLeaf = decodeMlsLeafNodeBytes(sender.encoded);
    const proposals = applyTreeCommitProposals(options.tree, options.sender, options.proposals);
    const provisionalContext = {
        groupId: options.context.groupId,
        epoch: options.context.epoch + 1n,
        confirmedTranscriptHash: options.context.confirmedTranscriptHash,
    };
    const update = createMlsUpdatePath({
        tree: proposals.tree,
        sender: options.sender,
        signingSecretKey: options.signingSecretKey,
        provisionalContext,
        authenticateCredential: options.authenticateCredential,
        excludedNewLeaves: new Set(proposals.addedLeaves),
    });
    let next: ReturnType<typeof deriveTreeCommitEpoch> | undefined;
    let privateKeys: readonly MlsTreePrivateKey[] | undefined;
    try {
        const draft = treeCommitDraft(options, update.path);
        const signature = mlsSignWithLabel(
            options.signingSecretKey,
            "FramedContentTBS",
            encodeMlsTreeCommitTbs(draft, options.context),
        );
        const signed = { ...draft, signature };
        if (
            !mlsVerifyWithLabel(
                senderLeaf.signatureKey,
                "FramedContentTBS",
                encodeMlsTreeCommitTbs(signed, options.context),
                signature,
            )
        ) {
            throw new Error("MLS TreeKEM Commit signing key does not match sender");
        }
        next = deriveTreeCommitEpoch(
            options.context,
            options.interimTranscriptHash,
            options.nextInitSecret,
            signed,
            update.tree.treeHash(),
            update.commitSecret,
        );
        const withConfirmation = {
            ...signed,
            confirmationTag: next.confirmationTag,
        };
        const message: MlsTreeCommitMessage = {
            ...withConfirmation,
            membershipTag: mlsMac(
                options.membershipKey,
                encodeMlsTreeCommitTbm(withConfirmation, options.context),
            ),
        };
        const commit = encodeMlsTreeCommit(message);
        const welcome =
            proposals.additions.length === 0
                ? undefined
                : createMlsWelcome({
                      context: next.context,
                      joinerSecret: next.secrets.joinerSecret,
                      confirmationKey: next.secrets.confirmationKey,
                      signer: options.sender,
                      signerSecretKey: options.signingSecretKey,
                      newMembers: proposals.additions,
                      pathSecrets: welcomePathSecrets(
                          update,
                          options.sender,
                          proposals.addedLeaves,
                      ),
                  });
        privateKeys = copyTreePrivateKeys(update);
        return {
            commit,
            ...(welcome === undefined ? {} : { welcome }),
            message: decodeMlsTreeCommit(commit),
            context: next.context,
            interimTranscriptHash: next.interimTranscriptHash,
            secrets: next.secrets,
            tree: update.tree,
            privateKeys,
            addedLeaves: proposals.addedLeaves,
            removedLeaves: proposals.removedLeaves,
        };
    } catch (error: unknown) {
        if (privateKeys !== undefined) {
            destroyTreePrivateKeys(privateKeys);
        }
        if (next !== undefined) {
            destroyMlsEpochSecrets(next.secrets);
            zeroBytes(next.interimTranscriptHash);
        }
        throw error;
    } finally {
        destroyMlsUpdatePathResult(update);
    }
}

/** Authenticate and open a full RFC Add/Remove TreeKEM Commit. */
export function openMlsTreeCommit(options: OpenMlsTreeCommitOptions): MlsAppliedTreeCommit {
    validateTreeCommitState(options);
    const message = decodeMlsTreeCommit(options.message);
    if (
        message.epoch !== options.context.epoch ||
        !equalBytes(message.groupId, options.context.groupId)
    ) {
        throw new Error("MLS TreeKEM Commit belongs to another group or epoch");
    }
    if (
        !mlsVerifyMac(
            options.membershipKey,
            encodeMlsTreeCommitTbm(message, options.context),
            message.membershipTag,
        )
    ) {
        throw new Error("Invalid MLS TreeKEM Commit membership tag");
    }
    const sender = options.tree.nodes[message.sender * 2];
    if (sender?.type !== "leaf") {
        throw new Error("Invalid MLS TreeKEM Commit sender");
    }
    const senderLeaf = decodeMlsLeafNodeBytes(sender.encoded);
    if (
        !mlsVerifyWithLabel(
            senderLeaf.signatureKey,
            "FramedContentTBS",
            encodeMlsTreeCommitTbs(message, options.context),
            message.signature,
        )
    ) {
        throw new Error("Invalid MLS TreeKEM Commit signature");
    }
    const proposals = applyTreeCommitProposals(options.tree, message.sender, message.proposals);
    if (proposals.removedLeaves.includes(options.localLeaf)) {
        validateMlsUpdatePath({
            tree: proposals.tree,
            sender: message.sender,
            path: message.path,
            provisionalContext: {
                groupId: options.context.groupId,
                epoch: options.context.epoch + 1n,
                confirmedTranscriptHash: options.context.confirmedTranscriptHash,
            },
            excludedNewLeaves: new Set(proposals.addedLeaves),
            authenticateCredential: options.authenticateCredential,
        });
        throw new MlsLocalMemberRemovedError();
    }
    const candidateNodes = proposals.tree.nodes;
    const usablePrivateKeys = options.privateKeys.filter(
        (key) => candidateNodes[key.node] !== undefined,
    );
    const update = openMlsUpdatePath({
        tree: proposals.tree,
        sender: message.sender,
        path: message.path,
        provisionalContext: {
            groupId: options.context.groupId,
            epoch: options.context.epoch + 1n,
            confirmedTranscriptHash: options.context.confirmedTranscriptHash,
        },
        localLeaf: options.localLeaf,
        privateKeys: usablePrivateKeys,
        excludedNewLeaves: new Set(proposals.addedLeaves),
        authenticateCredential: options.authenticateCredential,
    });
    let next: ReturnType<typeof deriveTreeCommitEpoch> | undefined;
    let privateKeys: readonly MlsTreePrivateKey[] | undefined;
    try {
        next = deriveTreeCommitEpoch(
            options.context,
            options.interimTranscriptHash,
            options.nextInitSecret,
            message,
            update.tree.treeHash(),
            update.commitSecret,
        );
        if (
            !verifyMlsConfirmationTag(
                next.secrets.confirmationKey,
                next.context.confirmedTranscriptHash,
                message.confirmationTag,
            )
        ) {
            throw new Error("Invalid MLS TreeKEM Commit confirmation tag");
        }
        privateKeys = copyTreePrivateKeys(update);
        return {
            message,
            context: next.context,
            interimTranscriptHash: next.interimTranscriptHash,
            secrets: next.secrets,
            tree: update.tree,
            privateKeys,
            addedLeaves: proposals.addedLeaves,
            removedLeaves: proposals.removedLeaves,
        };
    } catch (error: unknown) {
        if (privateKeys !== undefined) {
            destroyTreePrivateKeys(privateKeys);
        }
        if (next !== undefined) {
            destroyMlsEpochSecrets(next.secrets);
            zeroBytes(next.interimTranscriptHash);
        }
        throw error;
    } finally {
        destroyMlsUpdatePathResult(update);
    }
}

/** Destroy secrets returned by a standalone full TreeKEM Commit operation. */
export function destroyMlsTreeCommitResult(result: MlsAppliedTreeCommit): void {
    destroyMlsEpochSecrets(result.secrets);
    zeroBytes(result.interimTranscriptHash);
    destroyTreePrivateKeys(result.privateKeys);
}
