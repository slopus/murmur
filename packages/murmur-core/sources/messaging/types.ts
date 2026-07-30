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
