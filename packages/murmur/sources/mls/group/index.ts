import {
    decodeDeviceCredential,
    equalBytes,
    randomBytes,
    zeroBytes,
    type IdentityKeyPair,
    type IdentityPublicKey,
} from "../internal.js";
import { MlsEpochState, createMlsTreeEpochFromWelcome } from "../epoch/index.js";
import {
    createMlsConfirmationTag,
    updateInterimTranscriptHash,
    type MlsGroupContext,
} from "../groupContext/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    type MlsKeyPackageBundle,
} from "../keyPackage/index.js";
import {
    deriveMlsInitialEpochSecrets,
    destroyMlsEpochSecrets,
    type MlsEpochSecrets,
} from "../keySchedule/index.js";
import type { MlsLeafNode } from "../leafNode/index.js";
import { MlsRatchetTree } from "../ratchetTree/index.js";
import { destroyMlsTreePrivateKeys, type MlsTreePrivateKey } from "../updatePath/index.js";
import { initialMlsRatchetTreeLeaf } from "./impl/initialLeaf.js";
import { openMlsWelcome } from "../welcome/index.js";

/** Optional deterministic inputs for RFC vector and application-controlled IDs. */
export interface CreateMlsGroupOptions {
    readonly groupId?: Uint8Array;
    readonly epochSecret?: Uint8Array;
    /** Account-authorized BasicCredential identity for this device leaf. */
    readonly credentialIdentity?: Uint8Array;
}

/** Inputs for the reusable authenticated Welcome/tree adoption path. */
export interface JoinMlsGroupFromWelcomeOptions {
    readonly identity: IdentityKeyPair;
    readonly inviter: IdentityPublicKey;
    readonly groupId: Uint8Array;
    readonly welcome: Uint8Array;
    readonly tree: MlsRatchetTree;
    readonly keyPackageBundle: MlsKeyPackageBundle;
    /** Confirmation tag carried by the exact retained bootstrap Commit. */
    readonly expectedCommitConfirmationTag: Uint8Array;
}

/**
 * Authenticate and adopt a recipient-bound Welcome with an external tree.
 *
 * Stateful bootstrap codecs remain in the facade; this function owns the
 * cryptographic KeyPackage/tree/identity binding.
 */
export function joinMlsGroupFromWelcome(options: JoinMlsGroupFromWelcomeOptions): MlsEpochState {
    const localLeaves: number[] = [];
    for (let leaf = 0; leaf < options.tree.leafCount; leaf += 1) {
        const node = options.tree.nodes[leaf * 2];
        if (
            node?.type === "leaf" &&
            equalBytes(
                node.signatureKey,
                options.keyPackageBundle.keyPackage.leafNode.signatureKey,
            ) &&
            equalBytes(
                node.encryptionKey,
                options.keyPackageBundle.keyPackage.leafNode.encryptionKey,
            )
        ) {
            localLeaves.push(leaf);
        }
    }
    if (localLeaves.length !== 1) {
        throw new Error("MLS Welcome tree does not contain exactly one local leaf");
    }
    const opened = openMlsWelcome({
        welcome: options.welcome,
        keyPackageBundle: options.keyPackageBundle,
        expectedGroupId: options.groupId,
        expectedCommitConfirmationTag: options.expectedCommitConfirmationTag,
        validateExternalTree: (groupInfo) => {
            const signer = options.tree.nodes[groupInfo.signer * 2];
            return equalBytes(groupInfo.context.treeHash, options.tree.treeHash()) &&
                equalBytes(groupInfo.context.groupId, options.groupId) &&
                signer?.type === "leaf" &&
                equalBytes(signer.signatureKey, options.inviter.publicKey)
                ? signer.signatureKey
                : undefined;
        },
    });
    try {
        return createMlsTreeEpochFromWelcome({
            opened,
            tree: options.tree,
            localLeaf: localLeaves[0]!,
            leafKeyPair: options.keyPackageBundle.leafKeyPair,
            localSigningSecretKey: options.identity.secretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
        });
    } catch (error: unknown) {
        destroyMlsEpochSecrets(opened.epochSecrets);
        if (opened.pathSecret !== undefined) {
            zeroBytes(opened.pathSecret);
        }
        throw error;
    }
}

/** Authenticate Murmur's BasicCredential identity-to-signing-key binding. */
export function authenticateMurmurMlsCredential(leafNode: MlsLeafNode): boolean {
    if (
        leafNode.credential.identity.length === 32 &&
        equalBytes(leafNode.credential.identity, leafNode.signatureKey)
    ) {
        return true;
    }
    try {
        return equalBytes(
            decodeDeviceCredential(leafNode.credential.identity).deviceKey,
            leafNode.signatureKey,
        );
    } catch {
        return false;
    }
}

/** Resolve the stable account key represented by one authenticated leaf. */
export function murmurMlsAccountKey(leafNode: MlsLeafNode): Uint8Array {
    if (!authenticateMurmurMlsCredential(leafNode)) {
        throw new Error("Invalid Murmur MLS credential");
    }
    return leafNode.credential.identity.length === 32
        ? leafNode.signatureKey.slice()
        : decodeDeviceCredential(leafNode.credential.identity).accountKey;
}

/**
 * Create and take ownership of a one-member RFC 9420 epoch-zero group.
 *
 * Caller-provided group IDs and epoch secrets are copied and never mutated.
 * The returned epoch owns the creator's initial TreeKEM and key-schedule state.
 */
export function createMlsGroup(
    identity: IdentityKeyPair,
    options: CreateMlsGroupOptions = {},
): MlsEpochState {
    const groupId = options.groupId?.slice() ?? randomBytes(32);
    const epochSecret = options.epochSecret?.slice() ?? randomBytes(32);
    let bundle: MlsKeyPackageBundle | undefined;
    let secrets: MlsEpochSecrets | undefined;
    let privateSecretKey: Uint8Array | undefined;
    const privateKeys: MlsTreePrivateKey[] = [];
    try {
        if (groupId.length === 0 || groupId.length > 255 || epochSecret.length !== 32) {
            throw new Error("Invalid MLS initial group inputs");
        }
        bundle = createMlsKeyPackage(
            identity,
            Math.floor(Date.now() / 1_000),
            undefined,
            options.credentialIdentity,
        );
        const tree = new MlsRatchetTree([initialMlsRatchetTreeLeaf(bundle)]);
        const context: MlsGroupContext = {
            groupId,
            epoch: 0n,
            treeHash: tree.treeHash(),
            confirmedTranscriptHash: new Uint8Array(),
        };
        secrets = deriveMlsInitialEpochSecrets(epochSecret);
        const confirmationTag = createMlsConfirmationTag(
            secrets.confirmationKey,
            context.confirmedTranscriptHash,
        );
        privateSecretKey = bundle.leafKeyPair.secretKey.slice();
        privateKeys.push({
            node: 0,
            keyPair: {
                secretKey: privateSecretKey,
                publicKey: bundle.leafKeyPair.publicKey.slice(),
            },
        });
        return new MlsEpochState({
            context,
            secrets,
            tree,
            privateKeys,
            localLeaf: 0,
            localSigningSecretKey: identity.secretKey,
            authenticateCredential: authenticateMurmurMlsCredential,
            interimTranscriptHash: updateInterimTranscriptHash(
                context.confirmedTranscriptHash,
                confirmationTag,
            ),
        });
    } finally {
        zeroBytes(epochSecret);
        if (secrets !== undefined) {
            destroyMlsEpochSecrets(secrets);
        }
        if (privateSecretKey !== undefined) {
            zeroBytes(privateSecretKey);
        }
        destroyMlsTreePrivateKeys(privateKeys);
        if (bundle !== undefined) {
            destroyMlsKeyPackageBundle(bundle);
        }
    }
}
