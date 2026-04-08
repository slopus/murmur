export interface FeedState {
    feedId: string
    epoch: number
    keys: Map<number, Uint8Array>
}

export interface FeedMetadata {
    name: string
    description?: string
}

export interface FeedAttachmentReference {
    hash: string
    iv: string
    key: string
    ciphertext: string
}

export interface FeedItemContent {
    text: string
    attachments?: Record<string, FeedAttachmentReference>
}
