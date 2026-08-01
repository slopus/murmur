import { describe, expect, it } from "vitest";
import { createS3PresignedRequest } from "../s3SigV4.js";

describe("AWS SigV4 S3 presigning", () => {
    it("matches the published AWS S3 presigned GET example", () => {
        const result = createS3PresignedRequest({
            method: "GET",
            url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
            region: "us-east-1",
            accessKeyId: "AKIAIOSFODNN7EXAMPLE",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            now: Date.UTC(2013, 4, 24),
            expiresInSeconds: 86_400,
        });

        expect(result.canonicalRequest).toBe(
            [
                "GET",
                "/test.txt",
                "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host",
                "host:examplebucket.s3.amazonaws.com\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ].join("\n"),
        );
        expect(result.stringToSign).toBe(
            [
                "AWS4-HMAC-SHA256",
                "20130524T000000Z",
                "20130524/us-east-1/s3/aws4_request",
                "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04",
            ].join("\n"),
        );
        expect(result.signature).toBe(
            "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        );
    });
});
