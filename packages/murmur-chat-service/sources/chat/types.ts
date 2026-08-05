import type { Murmur, MurmurStore } from "@slopus/murmur";

/** Exact metadata returned for one immutable ciphertext blob. */
export interface BlobHead {
    /** Exact ciphertext length in bytes. */
    readonly byteLength: number;
}

/** Hostile-by-default content-addressed ciphertext storage. */
export interface BlobStore {
    /**
     * Idempotently store exactly `byteLength` bytes under their 32-byte
     * SHA-256 content identifier. Buffers yielded to `put` are borrowed for
     * one iteration; copy retained bytes and never mutate yielded arrays.
     */
    put(
        blobId: Uint8Array,
        byteLength: number,
        bytes: AsyncIterable<Uint8Array>,
        signal: AbortSignal,
    ): Promise<void>;
    /** Return exact immutable blob metadata, or undefined when absent. */
    head(blobId: Uint8Array, signal: AbortSignal): Promise<BlobHead | undefined>;
    /** Read exactly one bounded byte range or throw. */
    get(
        blobId: Uint8Array,
        offset: number,
        byteLength: number,
        signal: AbortSignal,
    ): Promise<Uint8Array>;
    /** Optionally delete a blob as backend policy; chat never calls this automatically. */
    delete?(blobId: Uint8Array, signal: AbortSignal): Promise<void>;
}

/** Restart-safe plaintext source reopened by its stable application identifier. */
export interface AttachmentSource {
    /**
     * Stable resolver identifier persisted before upload. A reopened source
     * must remain immutable for the duration of each read/upload operation.
     */
    readonly sourceId: string;
    /** Exact plaintext length, at most 100 MiB. */
    readonly byteLength: number;
    /**
     * Return exactly the requested bounded plaintext range. Ownership remains
     * with the source; the service defensively copies and never mutates it.
     */
    read(offset: number, byteLength: number, signal: AbortSignal): Promise<Uint8Array>;
}

/** One attachment supplied to `send`. */
export interface ChatAttachmentInput<TAttachmentMetadata> {
    /** Stable source identifier understood by `resolveAttachmentSource`. */
    readonly sourceId: string;
    /** Caller-defined strictly encoded metadata. */
    readonly metadata: TAttachmentMetadata;
}

/** Authenticated attachment capability carried only inside the MLS frame. */
export interface ChatAttachment<TAttachmentMetadata> {
    readonly metadata: TAttachmentMetadata;
    readonly fileId: Uint8Array;
    readonly blobId: Uint8Array;
    readonly plaintextLength: number;
    readonly chunkSize: number;
    readonly chunkCount: number;
    /** Internal decryption capability; treat this value as secret. */
    readonly fileKey: Uint8Array;
    /** Commitment binding the secret capability to this manifest and sender context. */
    readonly keyCommitment: Uint8Array;
    /** Conversation binding needed to verify chunk AAD. */
    readonly conversationId: Uint8Array;
    /** MLS-authenticated sender binding needed to verify chunk AAD. */
    readonly sender: Uint8Array;
}

/** One exactly-once projected logical chat message. */
export interface ChatMessage<TMessage, TAttachmentMetadata> {
    readonly kind: "message";
    /** Stable canonical identity scoped to conversation relay sequence. */
    readonly eventId: string;
    readonly conversationId: Uint8Array;
    readonly sequence: bigint;
    readonly sender: Uint8Array;
    readonly messageId: Uint8Array;
    /** Advisory sender clock; relay sequence remains canonical order. */
    readonly claimedAt: number;
    readonly message: TMessage;
    readonly attachments: readonly ChatAttachment<TAttachmentMetadata>[];
}

/** A projected event whose application codec is no longer understood. */
export interface ChatUnknownMessage {
    readonly kind: "unknown";
    readonly eventId: string;
    readonly conversationId: Uint8Array;
    readonly sequence: bigint;
    /** Exact stored authenticated frame or corrupt cache bytes. */
    readonly rawFrame: Uint8Array;
    /** Stable bounded reason string; it contains no secret key material. */
    readonly reason: string;
}

/** One sequence-ordered known or unknown projected event. */
export type ChatHistoryItem<TMessage, TAttachmentMetadata> =
    | ChatMessage<TMessage, TAttachmentMetadata>
    | ChatUnknownMessage;

/** Durable chat group summary. */
export interface ChatConversation {
    readonly id: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly epoch: bigint;
    readonly status: "active" | "removed";
}

/** Bounded relay-sequence history page. */
export interface ChatHistoryPage<TMessage, TAttachmentMetadata> {
    readonly messages: readonly ChatHistoryItem<TMessage, TAttachmentMetadata>[];
    readonly nextAfter?: bigint;
}

/** Durable send lifecycle. */
export interface ChatOutboxEntry {
    readonly enqueueSequence: bigint;
    readonly conversationId: Uint8Array;
    readonly messageId: Uint8Array;
    readonly status: "preparing" | "ready" | "handed-off" | "failed";
    readonly attachmentCount: number;
    readonly lastError?: {
        readonly code: string;
        readonly message: string;
    };
}

/** One bounded durable outbox page in local enqueue order. */
export interface ChatOutboxPage {
    readonly entries: readonly ChatOutboxEntry[];
    /** Opaque key to pass as `after` for the next page. */
    readonly nextAfter?: string;
}

/** Result of dropping local tracking for an outbox intent. */
export interface ChatCancelResult {
    /**
     * `may-have-delivered` means Murmur handoff happened or local tracking was
     * already absent, so cancellation cannot revoke a relay event.
     */
    readonly status: "cancelled" | "may-have-delivered";
}

/** Observable service mutation. */
export interface ChatChange {
    readonly kind: "conversation" | "message" | "outbox" | "error";
    readonly conversationId?: Uint8Array;
}

/** Options used to open a generic chat layer over an existing Murmur instance. */
export interface ChatServiceOptions<TMessage, TAttachmentMetadata> {
    /** Existing open Murmur instance; chat does not own or close it. */
    readonly murmur: Murmur;
    /** Same application store supplied to Murmur, under disjoint `chat/v1/` keys. */
    readonly store: MurmurStore;
    /** Ciphertext-only backend. */
    readonly blobStore: BlobStore;
    /** Strict application message encoder. */
    readonly encodeMessage: (message: TMessage) => Uint8Array;
    /** Strict application message decoder. */
    readonly decodeMessage: (bytes: Uint8Array) => TMessage;
    /** Strict attachment metadata encoder. */
    readonly encodeAttachmentMetadata: (metadata: TAttachmentMetadata) => Uint8Array;
    /** Strict attachment metadata decoder. */
    readonly decodeAttachmentMetadata: (bytes: Uint8Array) => TAttachmentMetadata;
    /** Reopen one stable plaintext source after a crash. */
    readonly resolveAttachmentSource: (
        sourceId: string,
        signal: AbortSignal,
    ) => Promise<AttachmentSource>;
    /** Background idle polling floor, default 250 ms. */
    readonly idlePollMilliseconds?: number;
    /**
     * Legacy shared operation deadline. Prefer the separate source and network
     * settings; the applicable maximum is still enforced.
     */
    readonly operationTimeoutMilliseconds?: number;
    /** Source read/hash/encryption deadline, default and maximum 30 seconds. */
    readonly sourceTimeoutMilliseconds?: number;
    /** Blob PUT/readback deadline, default 30 seconds and maximum 30 minutes. */
    readonly networkTimeoutMilliseconds?: number;
}

/** Explicit convergence options. */
export interface ChatSyncOptions {
    readonly signal?: AbortSignal;
}

/** Bounded whole-file convenience options. */
export interface ChatDownloadOptions {
    readonly signal?: AbortSignal;
    /** Explicit allocation cap; defaults to 16 MiB and may not exceed 100 MiB. */
    readonly maximumBytes?: number;
}
