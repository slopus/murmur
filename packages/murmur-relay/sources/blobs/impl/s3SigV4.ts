import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";

const encoder = new TextEncoder();

/** Inputs needed to construct one AWS SigV4 presigned request. */
export interface S3PresignInput {
    readonly method: "PUT" | "GET" | "HEAD";
    readonly url: URL;
    readonly region: string;
    readonly accessKeyId: string;
    readonly secretAccessKey: string | Uint8Array;
    readonly now: number;
    readonly expiresInSeconds: number;
    readonly headers?: Readonly<Record<string, string>>;
}

/** Observable SigV4 construction details used by deterministic vector tests. */
export interface S3PresignResult {
    readonly url: string;
    readonly canonicalRequest: string;
    readonly stringToSign: string;
    readonly signature: string;
}

function hex(bytes: Uint8Array): string {
    let result = "";
    for (const byte of bytes) {
        result += byte.toString(16).padStart(2, "0");
    }
    return result;
}

function awsEncode(value: string): string {
    return encodeURIComponent(value).replace(
        /[!'()*]/g,
        (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
    );
}

function canonicalQuery(parameters: readonly (readonly [string, string])[]): string {
    return parameters
        .map(([name, value]) => [awsEncode(name), awsEncode(value)] as const)
        .sort(([leftName, leftValue], [rightName, rightValue]) =>
            leftName === rightName
                ? leftValue < rightValue
                    ? -1
                    : leftValue > rightValue
                      ? 1
                      : 0
                : leftName < rightName
                  ? -1
                  : 1,
        )
        .map(([name, value]) => `${name}=${value}`)
        .join("&");
}

function normalizedHeaderValue(value: string): string {
    return value.trim().replace(/\s+/g, " ");
}

function signingKey(secret: string | Uint8Array, date: string, region: string): Uint8Array {
    const secretBytes = typeof secret === "string" ? encoder.encode(secret) : secret;
    const prefixedSecret = new Uint8Array(4 + secretBytes.length);
    prefixedSecret.set(encoder.encode("AWS4"));
    prefixedSecret.set(secretBytes, 4);
    const dateKey = hmac(sha256, prefixedSecret, encoder.encode(date));
    const regionKey = hmac(sha256, dateKey, encoder.encode(region));
    const serviceKey = hmac(sha256, regionKey, encoder.encode("s3"));
    try {
        return hmac(sha256, serviceKey, encoder.encode("aws4_request"));
    } finally {
        prefixedSecret.fill(0);
        dateKey.fill(0);
        regionKey.fill(0);
        serviceKey.fill(0);
        if (typeof secret === "string") {
            secretBytes.fill(0);
        }
    }
}

/**
 * Construct an AWS Signature Version 4 presigned S3 request.
 *
 * The returned canonical request and string-to-sign intentionally remain
 * observable so correctness can be checked without an S3 connection.
 */
export function createS3PresignedRequest(input: S3PresignInput): S3PresignResult {
    if (
        !Number.isSafeInteger(input.now) ||
        input.now < 0 ||
        !Number.isSafeInteger(input.expiresInSeconds) ||
        input.expiresInSeconds < 1 ||
        input.expiresInSeconds > 604_800
    ) {
        throw new Error("Invalid S3 presign time or lifetime");
    }
    const issueDate = new Date(Math.floor(input.now / 1_000) * 1_000);
    const isoDate = issueDate.toISOString();
    const shortDate = isoDate.slice(0, 10).replaceAll("-", "");
    const amzDate = `${shortDate}T${isoDate.slice(11, 19).replaceAll(":", "")}Z`;
    const scope = `${shortDate}/${input.region}/s3/aws4_request`;
    const headers = new Map<string, string>([["host", input.url.host]]);
    for (const [name, value] of Object.entries(input.headers ?? {})) {
        const normalizedName = name.toLowerCase();
        if (normalizedName === "host") {
            throw new Error("S3 presign headers must not override Host");
        }
        headers.set(normalizedName, normalizedHeaderValue(value));
    }
    const sortedHeaders = [...headers].sort(([left], [right]) => left.localeCompare(right));
    const signedHeaders = sortedHeaders.map(([name]) => name).join(";");
    const canonicalHeaders = `${sortedHeaders
        .map(([name, value]) => `${name}:${normalizedHeaderValue(value)}`)
        .join("\n")}\n`;
    const query = canonicalQuery([
        ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
        ["X-Amz-Credential", `${input.accessKeyId}/${scope}`],
        ["X-Amz-Date", amzDate],
        ["X-Amz-Expires", input.expiresInSeconds.toString()],
        ["X-Amz-SignedHeaders", signedHeaders],
    ]);
    const canonicalRequest = [
        input.method,
        input.url.pathname,
        query,
        canonicalHeaders,
        signedHeaders,
        "UNSIGNED-PAYLOAD",
    ].join("\n");
    const stringToSign = [
        "AWS4-HMAC-SHA256",
        amzDate,
        scope,
        hex(sha256(encoder.encode(canonicalRequest))),
    ].join("\n");
    const key = signingKey(input.secretAccessKey, shortDate, input.region);
    let signature: string;
    try {
        signature = hex(hmac(sha256, key, encoder.encode(stringToSign)));
    } finally {
        key.fill(0);
    }
    return {
        url: `${input.url.toString()}?${query}&X-Amz-Signature=${signature}`,
        canonicalRequest,
        stringToSign,
        signature,
    };
}
