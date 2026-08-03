import {
    concatBytes,
    encodeBase64Url,
    randomBytes,
    signBytes,
    utf8Encode,
    verifyBytes,
    zeroBytes,
    type IdentityKeyPair,
} from "@slopus/murmur";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    mlsAeadOpen,
    mlsAeadSeal,
    mlsExpandWithLabel,
} from "../cipherSuite/index.js";
import { encodeOpaqueV, encodeUint16 } from "../encoding/index.js";
import {
    decodeMlsEphemeralHeader,
    encodeMlsEphemeralHeader,
    type MlsEphemeralHeader,
} from "./impl/frameHeaderCodec.js";
import type { MlsEphemeralOpenResult } from "./types.js";
import {
    MAX_MLS_EPHEMERAL_FRAME_BYTES,
    MAX_MLS_EPHEMERAL_PAYLOAD_BYTES,
    MAX_MLS_EPHEMERAL_SENDERS,
    MAX_MLS_EPHEMERAL_STREAMS_PER_SENDER,
    MAX_MLS_EPHEMERAL_TOMBSTONES_PER_SENDER,
    MLS_EPHEMERAL_HEADER_BYTES,
    MLS_EPHEMERAL_SIGNATURE_BYTES,
    MLS_EPHEMERAL_STREAM_ID_BYTES,
    MLS_EPHEMERAL_STREAM_ROTATION_FRAMES,
} from "./types.js";

export type {
    MlsEphemeralDropReason,
    MlsEphemeralFrame,
    MlsEphemeralFrameType,
    MlsEphemeralOpenResult,
} from "./types.js";
export {
    MAX_MLS_EPHEMERAL_FRAME_BYTES,
    MAX_MLS_EPHEMERAL_PAYLOAD_BYTES,
    MAX_MLS_EPHEMERAL_SENDERS,
    MAX_MLS_EPHEMERAL_STREAMS_PER_SENDER,
    MAX_MLS_EPHEMERAL_TOMBSTONES_PER_SENDER,
    MLS_EPHEMERAL_FRAME_VERSION,
    MLS_EPHEMERAL_HEADER_BYTES,
    MLS_EPHEMERAL_SIGNATURE_BYTES,
    MLS_EPHEMERAL_STREAM_ID_BYTES,
} from "./types.js";
export { decodeMlsEphemeralHeader, encodeMlsEphemeralHeader } from "./impl/frameHeaderCodec.js";
export type { MlsEphemeralHeader } from "./impl/frameHeaderCodec.js";

/** RFC 9420 exporter label which keys one ephemeral channel. */
export const MLS_EPHEMERAL_EXPORTER_LABEL = "murmur ephemeral channel v1";
/** Exported channel secret length. */
export const MLS_EPHEMERAL_CHANNEL_SECRET_BYTES = 32;

const SIGNATURE_CONTEXT = utf8Encode("murmur/mls/ephemeral-frame/v1");
const KEY_LABEL = "murmur ephemeral key";
const NONCE_LABEL = "murmur ephemeral nonce";

interface StreamKeys {
    readonly key: Uint8Array;
    readonly nonceBase: Uint8Array;
}

interface InboundStream extends StreamKeys {
    lastCounter: bigint;
}

interface InboundSender {
    /** Live streams with derived keys, least recently used first. */
    readonly streams: Map<string, InboundStream>;
    /** High-water counters of evicted streams, least recently used first. */
    readonly retired: Map<string, bigint>;
}

function streamContext(senderLeaf: number, streamId: Uint8Array): Uint8Array {
    return concatBytes(encodeUint16(senderLeaf), streamId);
}

function deriveStreamKeys(
    channelSecret: Uint8Array,
    senderLeaf: number,
    streamId: Uint8Array,
): StreamKeys {
    const context = streamContext(senderLeaf, streamId);
    return {
        key: mlsExpandWithLabel(channelSecret, KEY_LABEL, context, MLS_AEAD_KEY_LENGTH),
        nonceBase: mlsExpandWithLabel(channelSecret, NONCE_LABEL, context, MLS_AEAD_NONCE_LENGTH),
    };
}

function destroyStreamKeys(keys: StreamKeys): void {
    zeroBytes(keys.key);
    zeroBytes(keys.nonceBase);
}

function streamNonce(nonceBase: Uint8Array, counter: bigint): Uint8Array {
    const nonce = nonceBase.slice();
    let remaining = counter;
    for (let index = MLS_AEAD_NONCE_LENGTH - 1; index >= MLS_AEAD_NONCE_LENGTH - 8; index -= 1) {
        nonce[index] = (nonce[index] ?? 0) ^ Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return nonce;
}

function signedContent(
    groupId: Uint8Array,
    header: Uint8Array,
    ciphertext: Uint8Array,
): Uint8Array {
    return concatBytes(SIGNATURE_CONTEXT, encodeOpaqueV(groupId), header, ciphertext);
}

/** Construction inputs for one epoch-scoped ephemeral cipher. */
export interface MlsEphemeralCipherOptions {
    /** Stable MLS group identifier of the owning group. */
    readonly groupId: Uint8Array;
    /** RFC epoch the exported channel secret belongs to. */
    readonly epoch: bigint;
    /** Local MLS leaf index inside that epoch. */
    readonly localLeaf: number;
    /** Local Murmur identity, whose signing key is the local MLS leaf key. */
    readonly identity: IdentityKeyPair;
    /** Exporter output for this epoch; the cipher copies it and owns the copy. */
    readonly channelSecret: Uint8Array;
    /** Authenticated signature key of a leaf in this epoch, or `undefined`. */
    readonly signatureKeyFor: (leaf: number) => Uint8Array | undefined;
}

/**
 * Authenticated, epoch-scoped, non-durable framing for one MLS group.
 *
 * Every frame is encrypted with material exported from the current epoch, so
 * it shares the group's membership and revocation semantics exactly, and it is
 * signed with the sender's MLS leaf signature key, so one member of the group
 * cannot forge another member's frames even though they hold the same exporter
 * secret.
 *
 * ```text
 *  epoch exporter secret
 *         |
 *         +-- ExpandWithLabel(leafIndex || streamId) --> per-stream key/nonce
 *                                       |
 *  header(36) || Ed25519 signature(64) || AES-128-GCM ciphertext
 * ```
 *
 * Nothing here is written down. The random per-instance stream identifier is
 * what makes an in-memory counter safe: a restarted sender picks a new stream
 * and therefore a new key, so a nonce is never reused across restarts without
 * any durable counter.
 */
export class MlsEphemeralCipher {
    readonly #groupId: Uint8Array;
    readonly #epoch: bigint;
    readonly #localLeaf: number;
    readonly #identity: IdentityKeyPair;
    readonly #channelSecret: Uint8Array;
    readonly #signatureKeyFor: (leaf: number) => Uint8Array | undefined;
    readonly #inbound = new Map<number, InboundSender>();
    #streamId: Uint8Array;
    #outbound: StreamKeys;
    #counter = 0n;
    #destroyed = false;

    constructor(options: MlsEphemeralCipherOptions) {
        if (
            options.channelSecret.length !== MLS_EPHEMERAL_CHANNEL_SECRET_BYTES ||
            options.groupId.length === 0 ||
            !Number.isSafeInteger(options.localLeaf) ||
            options.localLeaf < 0 ||
            options.localLeaf > 0xffff ||
            options.epoch < 0n
        ) {
            throw new Error("Invalid MLS ephemeral cipher configuration");
        }
        this.#groupId = options.groupId.slice();
        this.#epoch = options.epoch;
        this.#localLeaf = options.localLeaf;
        this.#identity = options.identity;
        this.#channelSecret = options.channelSecret.slice();
        this.#signatureKeyFor = options.signatureKeyFor;
        this.#streamId = randomBytes(MLS_EPHEMERAL_STREAM_ID_BYTES);
        this.#outbound = deriveStreamKeys(this.#channelSecret, this.#localLeaf, this.#streamId);
    }

    /** RFC epoch this cipher is bound to. */
    get epoch(): bigint {
        return this.#epoch;
    }

    /** Local MLS leaf index, which receivers use to ignore their own frames. */
    get localLeaf(): number {
        return this.#localLeaf;
    }

    /** Seal one bounded payload as the local member of the current epoch. */
    seal(payload: Uint8Array): Uint8Array {
        this.#ensureActive();
        if (payload.length > MAX_MLS_EPHEMERAL_PAYLOAD_BYTES) {
            throw new Error(
                `Ephemeral payload exceeds ${MAX_MLS_EPHEMERAL_PAYLOAD_BYTES.toString()} bytes`,
            );
        }
        if (this.#counter > MLS_EPHEMERAL_STREAM_ROTATION_FRAMES) {
            this.#rotateStream();
        }
        const header = encodeMlsEphemeralHeader({
            type: "data",
            epoch: this.#epoch,
            senderLeaf: this.#localLeaf,
            streamId: this.#streamId,
            counter: this.#counter,
        });
        const nonce = streamNonce(this.#outbound.nonceBase, this.#counter);
        this.#counter += 1n;
        try {
            const ciphertext = mlsAeadSeal(
                this.#outbound.key,
                nonce,
                concatBytes(header, this.#groupId),
                payload,
            );
            const signature = signBytes(
                this.#identity,
                signedContent(this.#groupId, header, ciphertext),
            );
            return concatBytes(header, signature, ciphertext);
        } finally {
            zeroBytes(nonce);
        }
    }

    /**
     * Authenticate and decrypt one inbound frame.
     *
     * Hostile or stale input is dropped with a reason rather than thrown: this
     * channel is lossy by construction and the caller only counts drops.
     */
    open(frame: Uint8Array): MlsEphemeralOpenResult {
        this.#ensureActive();
        if (
            frame.length < MLS_EPHEMERAL_HEADER_BYTES + MLS_EPHEMERAL_SIGNATURE_BYTES ||
            frame.length > MAX_MLS_EPHEMERAL_FRAME_BYTES
        ) {
            return { status: "dropped", reason: "malformed" };
        }
        const header = decodeMlsEphemeralHeader(frame);
        if (header === undefined) {
            return { status: "dropped", reason: "malformed" };
        }
        if (header.senderLeaf === this.#localLeaf) {
            return { status: "dropped", reason: "self" };
        }
        const signatureKey = this.#signatureKeyFor(header.senderLeaf);
        if (signatureKey === undefined) {
            return { status: "dropped", reason: "unknown-sender" };
        }
        const headerBytes = frame.subarray(0, MLS_EPHEMERAL_HEADER_BYTES);
        const signature = frame.subarray(
            MLS_EPHEMERAL_HEADER_BYTES,
            MLS_EPHEMERAL_HEADER_BYTES + MLS_EPHEMERAL_SIGNATURE_BYTES,
        );
        const ciphertext = frame.subarray(
            MLS_EPHEMERAL_HEADER_BYTES + MLS_EPHEMERAL_SIGNATURE_BYTES,
        );
        if (
            !verifyBytes(
                { signingKey: signatureKey },
                signedContent(this.#groupId, headerBytes, ciphertext),
                signature,
            )
        ) {
            return { status: "dropped", reason: "authentication" };
        }
        // The epoch is checked only after the signature, because a foreign
        // epoch is reported to the application as evidence that membership
        // moved. Reporting it on an unverified header would let anyone who can
        // reach the relay name an arbitrary epoch and drive that reaction.
        if (header.epoch !== this.#epoch) {
            return { status: "dropped", reason: "foreign-epoch", epoch: header.epoch };
        }
        const stream = this.#inboundStream(header);
        if (stream === undefined) {
            return { status: "dropped", reason: "stream-limit" };
        }
        if (header.counter <= stream.lastCounter) {
            return { status: "dropped", reason: "replay" };
        }
        const nonce = streamNonce(stream.nonceBase, header.counter);
        let plaintext: Uint8Array;
        try {
            plaintext = mlsAeadOpen(
                stream.key,
                nonce,
                concatBytes(headerBytes, this.#groupId),
                ciphertext,
            );
        } catch {
            return { status: "dropped", reason: "authentication" };
        } finally {
            zeroBytes(nonce);
        }
        if (plaintext.length > MAX_MLS_EPHEMERAL_PAYLOAD_BYTES) {
            zeroBytes(plaintext);
            return { status: "dropped", reason: "malformed" };
        }
        stream.lastCounter = header.counter;
        return {
            status: "opened",
            frame: {
                senderLeaf: header.senderLeaf,
                epoch: header.epoch,
                type: header.type,
                bytes: plaintext,
            },
        };
    }

    /** Zero every derived key and the exported channel secret. */
    destroy(): void {
        if (this.#destroyed) {
            return;
        }
        this.#destroyed = true;
        destroyStreamKeys(this.#outbound);
        for (const sender of this.#inbound.values()) {
            for (const stream of sender.streams.values()) {
                destroyStreamKeys(stream);
            }
            sender.streams.clear();
            sender.retired.clear();
        }
        this.#inbound.clear();
        zeroBytes(this.#channelSecret);
        zeroBytes(this.#streamId);
    }

    #inboundStream(header: MlsEphemeralHeader): InboundStream | undefined {
        let sender = this.#inbound.get(header.senderLeaf);
        if (sender === undefined) {
            if (this.#inbound.size >= MAX_MLS_EPHEMERAL_SENDERS) {
                return undefined;
            }
            sender = {
                streams: new Map<string, InboundStream>(),
                retired: new Map<string, bigint>(),
            };
            this.#inbound.set(header.senderLeaf, sender);
        }
        const identifier = encodeBase64Url(header.streamId);
        const existing = sender.streams.get(identifier);
        if (existing !== undefined) {
            // Refresh least-recently-used order without changing the state.
            sender.streams.delete(identifier);
            sender.streams.set(identifier, existing);
            return existing;
        }
        while (sender.streams.size >= MAX_MLS_EPHEMERAL_STREAMS_PER_SENDER) {
            const oldest = sender.streams.keys().next();
            if (oldest.done === true) {
                break;
            }
            const evicted = sender.streams.get(oldest.value);
            sender.streams.delete(oldest.value);
            if (evicted !== undefined) {
                this.#retire(sender, oldest.value, evicted.lastCounter);
                destroyStreamKeys(evicted);
            }
        }
        // A stream reappearing after eviction resumes from its remembered
        // high-water mark, so replaying its old frames stays a replay.
        const resumed = sender.retired.get(identifier);
        sender.retired.delete(identifier);
        const created: InboundStream = {
            ...deriveStreamKeys(this.#channelSecret, header.senderLeaf, header.streamId),
            lastCounter: resumed ?? -1n,
        };
        sender.streams.set(identifier, created);
        return created;
    }

    #retire(sender: InboundSender, identifier: string, lastCounter: bigint): void {
        const previous = sender.retired.get(identifier);
        sender.retired.delete(identifier);
        sender.retired.set(
            identifier,
            previous !== undefined && previous > lastCounter ? previous : lastCounter,
        );
        while (sender.retired.size > MAX_MLS_EPHEMERAL_TOMBSTONES_PER_SENDER) {
            const oldest = sender.retired.keys().next();
            if (oldest.done === true) {
                break;
            }
            sender.retired.delete(oldest.value);
        }
    }

    #rotateStream(): void {
        const previous = this.#outbound;
        const previousStreamId = this.#streamId;
        this.#streamId = randomBytes(MLS_EPHEMERAL_STREAM_ID_BYTES);
        this.#outbound = deriveStreamKeys(this.#channelSecret, this.#localLeaf, this.#streamId);
        this.#counter = 0n;
        destroyStreamKeys(previous);
        zeroBytes(previousStreamId);
    }

    #ensureActive(): void {
        if (this.#destroyed) {
            throw new Error("MLS ephemeral cipher was destroyed");
        }
    }
}
