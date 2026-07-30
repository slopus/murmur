import { equalBytes, randomBytes, zeroBytes, type IdentityKeyPair } from "@murmur/core";
import { MlsEpochState } from "../epoch/index.js";
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

/** Optional deterministic inputs for RFC vector and application-controlled IDs. */
export interface CreateMlsGroupOptions {
    readonly groupId?: Uint8Array;
    readonly epochSecret?: Uint8Array;
}

/** Authenticate Murmur's BasicCredential identity-to-signing-key binding. */
export function authenticateMurmurMlsCredential(leafNode: MlsLeafNode): boolean {
    return (
        leafNode.credential.identity.length === 32 &&
        equalBytes(leafNode.credential.identity, leafNode.signatureKey)
    );
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
        bundle = createMlsKeyPackage(identity);
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
            localSigningSecretKey: identity.signingSecretKey,
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
