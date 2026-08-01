import { decodeBase64Url } from "../../utils/base64Url.js";
import { isBlobId } from "../blobId.js";
import type { BlobBackend, BlobLink } from "../types.js";
import { createS3PresignedRequest } from "./s3SigV4.js";

const DEFAULT_LINK_LIFETIME_SECONDS = 5 * 60;

/** Construction options for direct S3-compatible blob transfers. */
export interface S3BlobBackendOptions {
    readonly endpoint: string;
    readonly region: string;
    readonly bucket: string;
    readonly accessKeyId: string;
    readonly secretAccessKey: string;
    /** Put the bucket in the URL path, as required by many MinIO deployments. */
    readonly pathStyle?: boolean;
    /** Signed-link lifetime in whole seconds. Defaults to five minutes. */
    readonly linkLifetimeSeconds?: number;
    /** Fetch implementation used only for existence-checking HEAD requests. */
    readonly fetchImplementation?: typeof globalThis.fetch;
}

function required(value: string, name: string): string {
    if (value.length === 0) {
        throw new Error(`${name} cannot be empty`);
    }
    return value;
}

function standardBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64");
}

/**
 * S3-compatible backend which issues SigV4 presigned links.
 *
 * Upload links bind an `x-amz-checksum-sha256` header derived from the blob ID,
 * allowing S3 to reject bytes which do not match the content address.
 */
export class S3BlobBackend implements BlobBackend {
    readonly #endpoint: URL;
    readonly #region: string;
    readonly #bucket: string;
    readonly #accessKeyId: string;
    readonly #secretAccessKey: Uint8Array;
    readonly #pathStyle: boolean;
    readonly #linkLifetimeSeconds: number;
    readonly #fetch: typeof globalThis.fetch;
    #closed = false;

    constructor(options: S3BlobBackendOptions) {
        this.#endpoint = new URL(required(options.endpoint, "S3 endpoint"));
        if (
            (this.#endpoint.protocol !== "https:" && this.#endpoint.protocol !== "http:") ||
            this.#endpoint.username.length > 0 ||
            this.#endpoint.password.length > 0 ||
            this.#endpoint.search.length > 0 ||
            this.#endpoint.hash.length > 0
        ) {
            throw new Error("S3 endpoint must be an HTTP(S) URL without credentials or a query");
        }
        this.#region = required(options.region, "S3 region");
        this.#bucket = required(options.bucket, "S3 bucket");
        this.#accessKeyId = required(options.accessKeyId, "S3 access key ID");
        this.#secretAccessKey = new TextEncoder().encode(
            required(options.secretAccessKey, "S3 secret access key"),
        );
        this.#pathStyle = options.pathStyle ?? false;
        this.#linkLifetimeSeconds = options.linkLifetimeSeconds ?? DEFAULT_LINK_LIFETIME_SECONDS;
        if (
            !Number.isSafeInteger(this.#linkLifetimeSeconds) ||
            this.#linkLifetimeSeconds < 1 ||
            this.#linkLifetimeSeconds > 604_800
        ) {
            throw new Error("S3 link lifetime must be from 1 through 604800 seconds");
        }
        this.#fetch = options.fetchImplementation ?? globalThis.fetch;
    }

    /** Issue one direct S3 PUT link with a signed SHA-256 checksum header. */
    async createUploadLink(id: string, now: number): Promise<BlobLink> {
        this.#assertOpen();
        this.#validateInput(id, now);
        const headers = {
            "x-amz-checksum-sha256": standardBase64(decodeBase64Url(id, 32)),
        };
        const signed = this.#presign("PUT", id, now, headers);
        return {
            url: signed.url,
            method: "PUT",
            expiresAt: signed.expiresAt,
            headers,
        };
    }

    /** Issue one direct S3 GET link after a signed HEAD confirms the object exists. */
    async createDownloadLink(id: string, now: number): Promise<BlobLink | undefined> {
        this.#assertOpen();
        this.#validateInput(id, now);
        const head = this.#presign("HEAD", id, now);
        const response = await this.#fetch(head.url, { method: "HEAD" });
        if (response.status === 404) {
            return undefined;
        }
        if (!response.ok) {
            throw new Error(`S3 existence check returned HTTP ${response.status.toString()}`);
        }
        const signed = this.#presign("GET", id, now);
        return {
            url: signed.url,
            method: "GET",
            expiresAt: signed.expiresAt,
        };
    }

    /** Clear the owned credential copy and reject subsequent link requests. */
    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        this.#secretAccessKey.fill(0);
    }

    #presign(
        method: "PUT" | "GET" | "HEAD",
        id: string,
        now: number,
        headers?: Readonly<Record<string, string>>,
    ): { readonly url: string; readonly expiresAt: number } {
        const issueTime = Math.floor(now / 1_000) * 1_000;
        const expiresAt = issueTime + this.#linkLifetimeSeconds * 1_000;
        const input = {
            method,
            url: this.#objectUrl(id),
            region: this.#region,
            accessKeyId: this.#accessKeyId,
            secretAccessKey: this.#secretAccessKey,
            now,
            expiresInSeconds: this.#linkLifetimeSeconds,
            ...(headers === undefined ? {} : { headers }),
        };
        return {
            url: createS3PresignedRequest(input).url,
            expiresAt,
        };
    }

    #objectUrl(id: string): URL {
        const url = new URL(this.#endpoint);
        const prefix = url.pathname.replace(/\/+$/, "");
        if (this.#pathStyle) {
            url.pathname = `${prefix}/${encodeURIComponent(this.#bucket)}/${encodeURIComponent(id)}`;
        } else {
            url.hostname = `${this.#bucket}.${url.hostname}`;
            url.pathname = `${prefix}/${encodeURIComponent(id)}`;
        }
        return url;
    }

    #validateInput(id: string, now: number): void {
        if (!isBlobId(id)) {
            throw new Error("Invalid blob identifier");
        }
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Blob link time must be a non-negative safe integer");
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("S3 blob backend is closed");
        }
    }
}
