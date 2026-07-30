import { zeroBytes } from "@murmur/core";
import { mlsSignWithLabel, mlsVerifyWithLabel } from "../cipherSuite/index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../groupContext/index.js";
import { destroyMlsEpochSecrets, type MlsEpochSecrets } from "../keySchedule/index.js";
import {
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
    type OpenedMlsApplicationMessage,
} from "../privateMessage/index.js";
import { MlsSecretTree } from "../secretTree/index.js";
import type { CreateMlsEpochOptions, MlsEpochMember } from "./types.js";

export type { CreateMlsEpochOptions, MlsEpochMember } from "./types.js";

const OWNERSHIP_LABEL = "Murmur Epoch Ownership";
const OWNERSHIP_CONTENT = new Uint8Array();
const MAXIMUM_EPOCH_MEMBERS = 100_000;

function copyContext(context: MlsGroupContext): MlsGroupContext {
    return {
        groupId: context.groupId.slice(),
        epoch: context.epoch,
        treeHash: context.treeHash.slice(),
        confirmedTranscriptHash: context.confirmedTranscriptHash.slice(),
    };
}

function snapshotEpochSecrets(secrets: MlsEpochSecrets): MlsEpochSecrets {
    return {
        joinerSecret: secrets.joinerSecret,
        memberSecret: secrets.memberSecret,
        epochSecret: secrets.epochSecret,
        senderDataSecret: secrets.senderDataSecret,
        encryptionSecret: secrets.encryptionSecret,
        exporterSecret: secrets.exporterSecret,
        epochAuthenticator: secrets.epochAuthenticator,
        externalSecret: secrets.externalSecret,
        confirmationKey: secrets.confirmationKey,
        membershipKey: secrets.membershipKey,
        resumptionPsk: secrets.resumptionPsk,
        nextInitSecret: secrets.nextInitSecret,
    };
}

function epochSecretValues(secrets: MlsEpochSecrets): readonly Uint8Array[] {
    return [
        secrets.joinerSecret,
        secrets.memberSecret,
        secrets.epochSecret,
        secrets.senderDataSecret,
        secrets.encryptionSecret,
        secrets.exporterSecret,
        secrets.epochAuthenticator,
        secrets.externalSecret,
        secrets.confirmationKey,
        secrets.membershipKey,
        secrets.resumptionPsk,
        secrets.nextInitSecret,
    ];
}

function copyEpochSecrets(secrets: MlsEpochSecrets): MlsEpochSecrets {
    const completed: Uint8Array[] = [];
    const copy = (secret: Uint8Array): Uint8Array => {
        const result = secret.slice();
        completed.push(result);
        return result;
    };
    try {
        return {
            joinerSecret: copy(secrets.joinerSecret),
            memberSecret: copy(secrets.memberSecret),
            epochSecret: copy(secrets.epochSecret),
            senderDataSecret: copy(secrets.senderDataSecret),
            encryptionSecret: copy(secrets.encryptionSecret),
            exporterSecret: copy(secrets.exporterSecret),
            epochAuthenticator: copy(secrets.epochAuthenticator),
            externalSecret: copy(secrets.externalSecret),
            confirmationKey: copy(secrets.confirmationKey),
            membershipKey: copy(secrets.membershipKey),
            resumptionPsk: copy(secrets.resumptionPsk),
            nextInitSecret: copy(secrets.nextInitSecret),
        };
    } catch (error: unknown) {
        for (const secret of completed) {
            zeroBytes(secret);
        }
        throw error;
    }
}

/**
 * Mutable application state for one authenticated RFC 9420 epoch.
 *
 * After successful construction, the instance takes ownership of
 * `options.secrets` by cloning them privately and zeroing every input array.
 * Construction failure leaves ownership with the caller. A Commit transition
 * creates a new instance only after the separate TreeKEM/Commit layer has
 * authenticated the next context and secrets.
 */
export class MlsEpochState {
    readonly #context: MlsGroupContext;
    readonly #secrets: MlsEpochSecrets;
    readonly #members: readonly (MlsEpochMember | undefined)[];
    readonly #localLeaf: number;
    readonly #localSigningSecretKey: Uint8Array;
    readonly #secretTree: MlsSecretTree;
    #destroyed = false;

    constructor(options: CreateMlsEpochOptions) {
        encodeMlsGroupContext(options.context);
        const inputSecrets = snapshotEpochSecrets(options.secrets);
        if (
            options.members.length === 0 ||
            options.members.length > MAXIMUM_EPOCH_MEMBERS ||
            !Number.isSafeInteger(options.localLeaf) ||
            options.localLeaf < 0 ||
            options.localLeaf >= options.members.length ||
            options.localSigningSecretKey.length !== 32
        ) {
            throw new Error("Invalid MLS epoch configuration");
        }
        const localMember = options.members[options.localLeaf];
        if (
            localMember === undefined ||
            localMember.signatureKey.length !== 32 ||
            options.members.some(
                (member) => member !== undefined && member.signatureKey.length !== 32,
            )
        ) {
            throw new Error("Invalid MLS epoch member");
        }
        const ownershipSignature = mlsSignWithLabel(
            options.localSigningSecretKey,
            OWNERSHIP_LABEL,
            OWNERSHIP_CONTENT,
        );
        if (
            !mlsVerifyWithLabel(
                localMember.signatureKey,
                OWNERSHIP_LABEL,
                OWNERSHIP_CONTENT,
                ownershipSignature,
            )
        ) {
            throw new Error("MLS local signing key does not match its leaf");
        }
        if (
            epochSecretValues(inputSecrets).some(
                (secret) => !(secret instanceof Uint8Array) || secret.length !== 32,
            )
        ) {
            throw new Error("Invalid MLS epoch secrets");
        }

        const ownedSecrets = copyEpochSecrets(inputSecrets);
        let localSigningSecretKey: Uint8Array | undefined;
        let secretTree: MlsSecretTree | undefined;
        try {
            localSigningSecretKey = options.localSigningSecretKey.slice();
            const members = options.members.map((member) =>
                member === undefined ? undefined : { signatureKey: member.signatureKey.slice() },
            );
            secretTree = new MlsSecretTree(ownedSecrets.encryptionSecret, members.length);
            this.#context = copyContext(options.context);
            this.#secrets = ownedSecrets;
            this.#members = members;
            this.#localLeaf = options.localLeaf;
            this.#localSigningSecretKey = localSigningSecretKey;
            this.#secretTree = secretTree;
        } catch (error: unknown) {
            secretTree?.destroy();
            destroyMlsEpochSecrets(ownedSecrets);
            if (localSigningSecretKey !== undefined) {
                zeroBytes(localSigningSecretKey);
            }
            throw error;
        }
        destroyMlsEpochSecrets(inputSecrets);
    }

    /** Immutable public context for this epoch. */
    get context(): MlsGroupContext {
        this.#ensureActive();
        return copyContext(this.#context);
    }

    /** Sign and encrypt application bytes as the local member. */
    seal(
        applicationData: Uint8Array,
        authenticatedData: Uint8Array = new Uint8Array(),
        paddingBytes: number = 0,
    ): Uint8Array {
        this.#ensureActive();
        return sealMlsApplicationMessage({
            context: this.#context,
            sender: this.#localLeaf,
            signingSecretKey: this.#localSigningSecretKey,
            senderDataSecret: this.#secrets.senderDataSecret,
            secretTree: this.#secretTree,
            applicationData,
            authenticatedData,
            paddingBytes,
        });
    }

    /** Authenticate and decrypt application bytes from another member. */
    open(message: Uint8Array): OpenedMlsApplicationMessage {
        this.#ensureActive();
        return openMlsApplicationMessage({
            context: this.#context,
            senderDataSecret: this.#secrets.senderDataSecret,
            secretTree: this.#secretTree,
            message,
            signatureKeyFor: (sender) => this.#members[sender]?.signatureKey,
        });
    }

    /** Destroy the epoch and every secret it owns. */
    destroy(): void {
        if (this.#destroyed) {
            return;
        }
        this.#destroyed = true;
        this.#secretTree.destroy();
        destroyMlsEpochSecrets(this.#secrets);
        zeroBytes(this.#localSigningSecretKey);
    }

    #ensureActive(): void {
        if (this.#destroyed) {
            throw new Error("MLS epoch was destroyed");
        }
    }
}
