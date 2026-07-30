import { concatBytes, equalBytes, zeroBytes } from "@murmur/core";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    MLS_HASH_LENGTH,
    mlsAeadOpen,
    mlsAeadSeal,
    mlsDecryptWithLabel,
    mlsDeriveSecret,
    mlsEncryptWithLabel,
    mlsExpandWithLabel,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import { encodeOpaqueV } from "../encoding/index.js";
import {
    createMlsConfirmationTag,
    encodeMlsGroupContext,
    verifyMlsConfirmationTag,
} from "../groupContext/index.js";
import { mlsKeyPackageReference, verifyMlsKeyPackage } from "../keyPackage/index.js";
import { deriveMlsEpochSecretsFromJoiner, destroyMlsEpochSecrets } from "../keySchedule/index.js";
import {
    decodeMlsGroupInfo,
    decodeMlsWelcome,
    encodeMlsGroupInfo,
    encodeMlsGroupInfoTbs,
    encodeMlsWelcome,
    WelcomeReader,
} from "./impl/codec.js";
import type {
    CreateMlsWelcomeOptions,
    MlsGroupInfo,
    MlsWelcome,
    OpenedMlsWelcome,
    OpenMlsWelcomeOptions,
} from "./types.js";

export type {
    CreateMlsWelcomeOptions,
    MlsEncryptedGroupSecrets,
    MlsGroupInfo,
    MlsWelcome,
    OpenedMlsWelcome,
    OpenMlsWelcomeOptions,
} from "./types.js";
export {
    decodeMlsGroupInfo,
    decodeMlsWelcome,
    encodeMlsGroupInfo,
    encodeMlsWelcome,
} from "./impl/codec.js";

const EMPTY = new Uint8Array();
const MAXIMUM_GROUP_SECRETS_BYTES = 4 * 1024;

interface GroupSecrets {
    readonly joinerSecret: Uint8Array;
    readonly pathSecret?: Uint8Array;
}

function encodeGroupSecrets(groupSecrets: GroupSecrets): Uint8Array {
    if (
        groupSecrets.joinerSecret.length !== MLS_HASH_LENGTH ||
        (groupSecrets.pathSecret !== undefined &&
            groupSecrets.pathSecret.length !== MLS_HASH_LENGTH)
    ) {
        throw new Error("Invalid MLS GroupSecrets");
    }
    return concatBytes(
        encodeOpaqueV(groupSecrets.joinerSecret),
        groupSecrets.pathSecret === undefined
            ? new Uint8Array([0])
            : concatBytes(new Uint8Array([1]), encodeOpaqueV(groupSecrets.pathSecret)),
        encodeOpaqueV(EMPTY),
    );
}

function decodeGroupSecrets(bytes: Uint8Array): GroupSecrets {
    if (bytes.length > MAXIMUM_GROUP_SECRETS_BYTES) {
        throw new Error("MLS GroupSecrets is too large");
    }
    const reader = new WelcomeReader(bytes);
    const joinerSecret = reader.readOpaqueV(MLS_HASH_LENGTH);
    let pathSecret: Uint8Array | undefined;
    try {
        const pathPresent = reader.readUint8();
        if (pathPresent === 1) {
            pathSecret = reader.readOpaqueV(MLS_HASH_LENGTH);
        } else if (pathPresent !== 0) {
            throw new Error("Invalid MLS path secret optional");
        }
        if (
            joinerSecret.length !== MLS_HASH_LENGTH ||
            (pathSecret !== undefined && pathSecret.length !== MLS_HASH_LENGTH)
        ) {
            throw new Error("Invalid MLS GroupSecrets");
        }
        if (reader.readOpaqueV(0).length !== 0) {
            throw new Error("Unsupported MLS pre-shared key");
        }
        reader.ensureEnd();
        return {
            joinerSecret,
            ...(pathSecret === undefined ? {} : { pathSecret }),
        };
    } catch (error: unknown) {
        zeroBytes(joinerSecret);
        if (pathSecret !== undefined) {
            zeroBytes(pathSecret);
        }
        throw error;
    }
}

function deriveWelcomeKeyAndNonce(joinerSecret: Uint8Array): {
    readonly welcomeSecret: Uint8Array;
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
} {
    if (joinerSecret.length !== MLS_HASH_LENGTH) {
        throw new Error("MLS joiner secret must be 32 bytes");
    }
    const welcomeSecret = mlsDeriveSecret(joinerSecret, "welcome");
    let key: Uint8Array | undefined;
    try {
        key = mlsExpandWithLabel(welcomeSecret, "key", EMPTY, MLS_AEAD_KEY_LENGTH);
        return {
            welcomeSecret,
            key,
            nonce: mlsExpandWithLabel(welcomeSecret, "nonce", EMPTY, MLS_AEAD_NONCE_LENGTH),
        };
    } catch (error: unknown) {
        zeroBytes(welcomeSecret);
        if (key !== undefined) {
            zeroBytes(key);
        }
        throw error;
    }
}

/** Create an RFC 9420 Welcome with external ratchet-tree delivery and no PSKs. */
export function createMlsWelcome(options: CreateMlsWelcomeOptions): Uint8Array {
    if (
        options.joinerSecret.length !== MLS_HASH_LENGTH ||
        options.confirmationKey.length !== MLS_HASH_LENGTH ||
        options.newMembers.length === 0 ||
        options.newMembers.length > 1_024 ||
        (options.pathSecrets !== undefined &&
            options.pathSecrets.length !== options.newMembers.length)
    ) {
        throw new Error("Invalid MLS Welcome inputs");
    }
    encodeMlsGroupContext(options.context);
    const confirmationTag = createMlsConfirmationTag(
        options.confirmationKey,
        options.context.confirmedTranscriptHash,
    );
    const unsignedGroupInfo = {
        context: options.context,
        confirmationTag,
        signer: options.signer,
    };
    const groupInfo: MlsGroupInfo = {
        ...unsignedGroupInfo,
        signature: mlsSignWithLabel(
            options.signerSecretKey,
            "GroupInfoTBS",
            encodeMlsGroupInfoTbs(unsignedGroupInfo),
        ),
    };
    const groupInfoPlaintext = encodeMlsGroupInfo(groupInfo);
    let welcomeKeys: ReturnType<typeof deriveWelcomeKeyAndNonce> | undefined;
    let encryptedGroupInfo: Uint8Array;
    try {
        welcomeKeys = deriveWelcomeKeyAndNonce(options.joinerSecret);
        encryptedGroupInfo = mlsAeadSeal(
            welcomeKeys.key,
            welcomeKeys.nonce,
            EMPTY,
            groupInfoPlaintext,
        );
    } finally {
        if (welcomeKeys !== undefined) {
            zeroBytes(welcomeKeys.welcomeSecret);
            zeroBytes(welcomeKeys.key);
            zeroBytes(welcomeKeys.nonce);
        }
        zeroBytes(groupInfoPlaintext);
    }

    const seenReferences: Uint8Array[] = [];
    const welcome: MlsWelcome = {
        secrets: options.newMembers.map((keyPackage, index) => {
            const groupSecretsPlaintext = encodeGroupSecrets({
                joinerSecret: options.joinerSecret,
                ...(options.pathSecrets?.[index] === undefined
                    ? {}
                    : { pathSecret: options.pathSecrets[index] }),
            });
            try {
                if (!verifyMlsKeyPackage(keyPackage)) {
                    throw new Error("Invalid MLS Welcome KeyPackage");
                }
                const newMember = mlsKeyPackageReference(keyPackage);
                if (seenReferences.some((reference) => equalBytes(reference, newMember))) {
                    throw new Error("Duplicate MLS Welcome KeyPackage");
                }
                seenReferences.push(newMember);
                return {
                    newMember,
                    encryptedGroupSecrets: mlsEncryptWithLabel(
                        keyPackage.initKey,
                        "Welcome",
                        encryptedGroupInfo,
                        groupSecretsPlaintext,
                    ),
                };
            } finally {
                zeroBytes(groupSecretsPlaintext);
            }
        }),
        encryptedGroupInfo,
    };
    return encodeMlsWelcome(welcome);
}

/** Open and authenticate an RFC 9420 Welcome against an externally supplied tree. */
export function openMlsWelcome(options: OpenMlsWelcomeOptions): OpenedMlsWelcome {
    if (!verifyMlsKeyPackage(options.keyPackageBundle.keyPackage)) {
        throw new Error("Invalid local MLS KeyPackage");
    }
    const welcome = decodeMlsWelcome(options.welcome);
    const reference = mlsKeyPackageReference(options.keyPackageBundle.keyPackage);
    const matches = welcome.secrets.filter((entry) => equalBytes(entry.newMember, reference));
    if (matches.length !== 1) {
        throw new Error("MLS Welcome does not contain exactly one entry for this KeyPackage");
    }
    const encryptedGroupSecrets = matches[0];
    if (encryptedGroupSecrets === undefined) {
        throw new Error("MLS Welcome entry disappeared");
    }
    const groupSecretsPlaintext = mlsDecryptWithLabel(
        options.keyPackageBundle.initKeyPair,
        "Welcome",
        welcome.encryptedGroupInfo,
        encryptedGroupSecrets.encryptedGroupSecrets,
    );
    let groupSecrets: GroupSecrets;
    try {
        groupSecrets = decodeGroupSecrets(groupSecretsPlaintext);
    } finally {
        zeroBytes(groupSecretsPlaintext);
    }
    let welcomeKeys: ReturnType<typeof deriveWelcomeKeyAndNonce> | undefined;
    let groupInfoPlaintext: Uint8Array;
    try {
        welcomeKeys = deriveWelcomeKeyAndNonce(groupSecrets.joinerSecret);
        groupInfoPlaintext = mlsAeadOpen(
            welcomeKeys.key,
            welcomeKeys.nonce,
            EMPTY,
            welcome.encryptedGroupInfo,
        );
    } catch (error: unknown) {
        zeroBytes(groupSecrets.joinerSecret);
        if (groupSecrets.pathSecret !== undefined) {
            zeroBytes(groupSecrets.pathSecret);
        }
        throw error;
    } finally {
        if (welcomeKeys !== undefined) {
            zeroBytes(welcomeKeys.welcomeSecret);
            zeroBytes(welcomeKeys.key);
            zeroBytes(welcomeKeys.nonce);
        }
    }

    let epochSecrets: ReturnType<typeof deriveMlsEpochSecretsFromJoiner> | undefined;
    try {
        const groupInfo = decodeMlsGroupInfo(groupInfoPlaintext);
        if (
            options.expectedGroupId !== undefined &&
            !equalBytes(options.expectedGroupId, groupInfo.context.groupId)
        ) {
            throw new Error("MLS Welcome belongs to another group");
        }
        epochSecrets = deriveMlsEpochSecretsFromJoiner(
            groupSecrets.joinerSecret,
            encodeMlsGroupContext(groupInfo.context),
        );
        if (
            !verifyMlsConfirmationTag(
                epochSecrets.confirmationKey,
                groupInfo.context.confirmedTranscriptHash,
                groupInfo.confirmationTag,
            )
        ) {
            throw new Error("Invalid MLS Welcome confirmation tag");
        }
        const signerKey = options.validateExternalTree(
            groupInfo,
            options.keyPackageBundle.keyPackage,
        );
        if (
            signerKey === undefined ||
            signerKey.length !== 32 ||
            !mlsVerifyWithLabel(
                signerKey,
                "GroupInfoTBS",
                encodeMlsGroupInfoTbs(groupInfo),
                groupInfo.signature,
            )
        ) {
            throw new Error("Invalid MLS GroupInfo signature");
        }
        zeroBytes(options.keyPackageBundle.initKeyPair.secretKey);
        return {
            groupInfo,
            epochSecrets,
            ...(groupSecrets.pathSecret === undefined
                ? {}
                : { pathSecret: groupSecrets.pathSecret.slice() }),
        };
    } catch (error: unknown) {
        if (epochSecrets !== undefined) {
            destroyMlsEpochSecrets(epochSecrets);
        }
        throw error;
    } finally {
        zeroBytes(groupSecrets.joinerSecret);
        if (groupSecrets.pathSecret !== undefined) {
            zeroBytes(groupSecrets.pathSecret);
        }
        zeroBytes(groupInfoPlaintext);
    }
}
