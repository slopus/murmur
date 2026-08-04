import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsSecretTree } from "../secretTree/index.js";

/** Parsed RFC 9420 PrivateMessage carrying application content. */
export interface MlsPrivateMessage {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly authenticatedData: Uint8Array;
    readonly encryptedSenderData: Uint8Array;
    readonly ciphertext: Uint8Array;
}

/** Inputs needed to sign and encrypt one application message. */
export interface SealMlsApplicationMessageOptions {
    readonly context: MlsGroupContext;
    readonly sender: number;
    readonly signingSecretKey: Uint8Array;
    readonly senderDataSecret: Uint8Array;
    readonly secretTree: MlsSecretTree;
    readonly applicationData: Uint8Array;
    readonly authenticatedData?: Uint8Array;
    readonly paddingBytes?: number;
}

/** Inputs needed to authenticate and open one application message. */
export interface OpenMlsApplicationMessageOptions {
    readonly context: MlsGroupContext;
    readonly senderDataSecret: Uint8Array;
    readonly secretTree: MlsSecretTree;
    readonly message: Uint8Array;
    readonly signatureKeyFor: (sender: number) => Uint8Array | undefined;
}

/** Authenticated application content recovered from an MLS PrivateMessage. */
export interface OpenedMlsApplicationMessage {
    readonly sender: number;
    readonly generation: number;
    readonly authenticatedData: Uint8Array;
    readonly applicationData: Uint8Array;
}
