/** Wire version of the ephemeral frame header. */
export const MLS_EPHEMERAL_FRAME_VERSION = 1;
/** Fixed cleartext header bytes carried before the signature. */
export const MLS_EPHEMERAL_HEADER_BYTES = 36;
/** Ed25519 signature bytes carried between the header and the ciphertext. */
export const MLS_EPHEMERAL_SIGNATURE_BYTES = 64;
/** Random per-instance stream identifier bytes inside the header. */
export const MLS_EPHEMERAL_STREAM_ID_BYTES = 16;
/** Maximum plaintext accepted in one ephemeral frame. */
export const MAX_MLS_EPHEMERAL_PAYLOAD_BYTES = 64 * 1024;
/** Maximum encoded frame, comfortably below the relay's 1 MiB payload limit. */
export const MAX_MLS_EPHEMERAL_FRAME_BYTES =
    MLS_EPHEMERAL_HEADER_BYTES +
    MLS_EPHEMERAL_SIGNATURE_BYTES +
    MAX_MLS_EPHEMERAL_PAYLOAD_BYTES +
    16;
/** Maximum concurrently tracked inbound streams for one sending leaf. */
export const MAX_MLS_EPHEMERAL_STREAMS_PER_SENDER = 8;
/** Maximum sending leaves tracked at once, matching the MLS member bound. */
export const MAX_MLS_EPHEMERAL_SENDERS = 256;
/** Frames sent on one stream identifier before it rotates automatically. */
export const MLS_EPHEMERAL_STREAM_ROTATION_FRAMES = 0xffff_ffffn;

/** Frame classes distinguished inside the authenticated header. */
export type MlsEphemeralFrameType = "data" | "notice";

/** One authenticated ephemeral frame from another member of this epoch. */
export interface MlsEphemeralFrame {
    readonly senderLeaf: number;
    readonly epoch: bigint;
    readonly type: MlsEphemeralFrameType;
    readonly bytes: Uint8Array;
}

/** Why one inbound frame was discarded instead of surfaced. */
export type MlsEphemeralDropReason =
    | "malformed"
    | "foreign-epoch"
    | "unknown-sender"
    | "self"
    | "replay"
    | "authentication"
    | "stream-limit";

/**
 * Outcome of opening one inbound frame.
 *
 * Opening never throws for hostile input: an unauthenticated, stale, or
 * malformed frame is a routine drop on a lossy channel, and the caller counts
 * it rather than tearing anything down. `epoch` is present when a syntactically
 * valid header named an epoch other than the local one, which lets the
 * application notice that it is behind and synchronize.
 */
export type MlsEphemeralOpenResult =
    | { readonly status: "opened"; readonly frame: MlsEphemeralFrame }
    | {
          readonly status: "dropped";
          readonly reason: MlsEphemeralDropReason;
          readonly epoch?: bigint;
      };
