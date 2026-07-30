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
    decodeMlsAddCommit,
    encodeMlsAddCommit,
    encodeMlsAddCommitConfirmedTranscriptInput,
    encodeMlsAddCommitTbm,
    encodeMlsAddCommitTbs,
} from "./impl/codec.js";
import type {
    CreateMlsAddCommitOptions,
    MlsAddCommitMessage,
    MlsAppliedAddCommit,
    MlsCommitMember,
    MlsCreatedAddCommit,
    OpenMlsAddCommitOptions,
} from "./types.js";

export type {
    CreateMlsAddCommitOptions,
    MlsAddCommitMessage,
    MlsAppliedAddCommit,
    MlsCommitMember,
    MlsCreatedAddCommit,
    OpenMlsAddCommitOptions,
} from "./types.js";
export { decodeMlsAddCommit, encodeMlsAddCommit } from "./impl/codec.js";

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
