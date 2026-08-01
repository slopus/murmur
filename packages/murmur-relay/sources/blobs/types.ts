/** A time-bounded direct transfer link issued by a blob backend. */
export interface BlobLink {
    readonly url: string;
    readonly method: "PUT" | "GET";
    readonly expiresAt: number;
    readonly headers?: Readonly<Record<string, string>>;
}

/**
 * Blob storage boundary.
 *
 * Backends issue transfer links without becoming part of topic persistence.
 * A backend which returns relay-local URLs also handles their signed transfer
 * requests through `handleTransfer`.
 */
export interface BlobBackend {
    createUploadLink(id: string, now: number): Promise<BlobLink>;
    createDownloadLink(id: string, now: number): Promise<BlobLink | undefined>;
    handleTransfer?(
        request: Request,
        id: string,
        now: number,
        maximumBytes: number,
    ): Promise<Response>;
    close(): Promise<void>;
}
