import { RelayError } from "../../protocol/index.js";

/** Incrementally read a request body while maintaining a hard allocation bound. */
export async function readBoundedRequestBody(
    request: Request,
    maximumBytes: number,
): Promise<Uint8Array> {
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null) {
        if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
            throw new RelayError(400, "Invalid Content-Length", {
                error: "malformed",
            });
        }
        if (BigInt(contentLength) > BigInt(maximumBytes)) {
            throw new RelayError(413, "Request body exceeds relay limit", {
                error: "limit",
            });
        }
    }
    if (request.body === null) {
        return new Uint8Array();
    }
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    while (true) {
        const result = await reader.read();
        if (result.done) {
            break;
        }
        length += result.value.length;
        if (length > maximumBytes) {
            await reader.cancel().catch(() => undefined);
            throw new RelayError(413, "Request body exceeds relay limit", {
                error: "limit",
            });
        }
        chunks.push(result.value);
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.length;
    }
    return body;
}
