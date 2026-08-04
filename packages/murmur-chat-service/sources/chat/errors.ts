/** A strict chat frame, manifest, or caller codec rejected bytes. */
export class ChatCodecError extends Error {
    override readonly name = "ChatCodecError";
}

/** Durable data under `chat/v1/` was malformed and cannot safely be used. */
export class ChatStoreCorruptionError extends Error {
    override readonly name = "ChatStoreCorruptionError";
}

/** The attachment source no longer has the bytes bound to its durable intent. */
export class ChatAttachmentSourceChangedError extends Error {
    override readonly name = "ChatAttachmentSourceChangedError";
}

/** An attachment chunk, manifest, or blob failed authenticated verification. */
export class ChatAttachmentAuthenticationError extends Error {
    override readonly name = "ChatAttachmentAuthenticationError";
}

/** The encoded application frame cannot fit in Murmur's application bound. */
export class ChatFrameTooLargeError extends Error {
    override readonly name = "ChatFrameTooLargeError";
}

/** An operation was attempted after close began. */
export class ChatClosedError extends Error {
    override readonly name = "ChatClosedError";
}
