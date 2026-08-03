import { encodeUint16, encodeUint64 } from "../../encoding/index.js";
import type { MlsEphemeralFrameType } from "../types.js";
import {
    MLS_EPHEMERAL_FRAME_VERSION,
    MLS_EPHEMERAL_HEADER_BYTES,
    MLS_EPHEMERAL_STREAM_ID_BYTES,
} from "../types.js";

/** Cleartext routing header authenticated by both the AEAD and the signature. */
export interface MlsEphemeralHeader {
    readonly type: MlsEphemeralFrameType;
    readonly epoch: bigint;
    readonly senderLeaf: number;
    readonly streamId: Uint8Array;
    readonly counter: bigint;
}

const DATA_TYPE = 1;

/**
 * Encode the fixed 36-byte header.
 *
 * ```text
 * 0      version(1)
 * 1      type(1)
 * 2..9   epoch(8)
 * 10..11 senderLeaf(2)
 * 12..27 streamId(16)
 * 28..35 counter(8)
 * ```
 */
export function encodeMlsEphemeralHeader(header: MlsEphemeralHeader): Uint8Array {
    if (
        header.streamId.length !== MLS_EPHEMERAL_STREAM_ID_BYTES ||
        !Number.isSafeInteger(header.senderLeaf) ||
        header.senderLeaf < 0 ||
        header.senderLeaf > 0xffff ||
        header.epoch < 0n ||
        header.epoch > 0xffff_ffff_ffff_ffffn ||
        header.counter < 0n ||
        header.counter > 0xffff_ffff_ffff_ffffn
    ) {
        throw new Error("Invalid MLS ephemeral header");
    }
    const bytes = new Uint8Array(MLS_EPHEMERAL_HEADER_BYTES);
    bytes[0] = MLS_EPHEMERAL_FRAME_VERSION;
    bytes[1] = DATA_TYPE;
    bytes.set(encodeUint64(header.epoch), 2);
    bytes.set(encodeUint16(header.senderLeaf), 10);
    bytes.set(header.streamId, 12);
    bytes.set(encodeUint64(header.counter), 28);
    return bytes;
}

function decodeUint64(bytes: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let index = 0; index < 8; index += 1) {
        value = (value << 8n) | BigInt(bytes[offset + index] ?? 0);
    }
    return value;
}

/** Decode a header, or `undefined` when the bytes are not a v1 header. */
export function decodeMlsEphemeralHeader(bytes: Uint8Array): MlsEphemeralHeader | undefined {
    if (
        bytes.length < MLS_EPHEMERAL_HEADER_BYTES ||
        bytes[0] !== MLS_EPHEMERAL_FRAME_VERSION ||
        bytes[1] !== DATA_TYPE
    ) {
        return undefined;
    }
    return {
        type: "data",
        epoch: decodeUint64(bytes, 2),
        senderLeaf: ((bytes[10] ?? 0) << 8) | (bytes[11] ?? 0),
        streamId: bytes.slice(12, 12 + MLS_EPHEMERAL_STREAM_ID_BYTES),
        counter: decodeUint64(bytes, 28),
    };
}
