import type { IdentityPublicKeys } from "../crypto/index.js";
import type { SerializedPublicIdentity } from "../identity/index.js";
import type { RelayBlob } from "../transport/index.js";

/** Secret descriptor placed inside encrypted application data. */
export interface EncryptedFileDescriptor {
    readonly version: 1;
    readonly blobId: string;
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
    readonly name: string;
    readonly mediaType: string;
    readonly plaintextBytes: number;
}

/** Result ready for ciphertext upload and encrypted descriptor delivery. */
export interface EncryptedFile {
    readonly descriptor: EncryptedFileDescriptor;
    readonly blob: RelayBlob;
}

/** Message content encrypted by a two-member or larger MLS group. */
export interface PrivateMessage {
    readonly version: 1;
    readonly id: string;
    readonly sentAt: number;
    readonly text: string;
    readonly attachments: readonly EncryptedFileDescriptor[];
}

/** Signed private-message ciphertext addressed to one long-lived identity. */
export interface EncryptedPrivateMessage {
    readonly version: 1;
    readonly sender: SerializedPublicIdentity;
    readonly recipient: string;
    readonly ephemeralPublicKey: string;
    readonly nonce: string;
    readonly ciphertext: string;
}

/** Authenticated direct message plus the sender identity which signed it. */
export interface OpenedPrivateMessage {
    readonly identity: IdentityPublicKeys;
    readonly message: PrivateMessage;
}

/** Durable sender/message-ID replay decision for one authenticated envelope. */
export interface AcceptedPrivateMessage extends OpenedPrivateMessage {
    readonly status: "opened" | "duplicate";
}
