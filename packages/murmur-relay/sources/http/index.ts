import {
    decodeBase64Url,
    decodeQueueRequestWire,
    decodeRelayEventWire,
    decodeTopicSubscriptionWire,
    encodeBase64Url,
    encodeRelayDeliveriesWire,
    type QueueAcknowledgeRequest,
    type QueueReadRequest,
} from "@murmur/core";
import { RelayProtocolError, type RelayService } from "../relay/index.js";

const MAXIMUM_JSON_BODY_BYTES = 4 * 1024 * 1024;
const MAXIMUM_BLOB_BODY_BYTES = 64 * 1024 * 1024;
const MAXIMUM_DELIVERY_RESPONSE_BYTES = 32 * 1024 * 1024;

class HttpError extends Error {
    constructor(
        readonly status: number,
        message: string,
    ) {
        super(message);
    }
}

async function readBody(request: Request, maximumBytes: number): Promise<Uint8Array> {
    const declaredLength = request.headers.get("content-length");
    if (
        declaredLength !== null &&
        (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes)
    ) {
        throw new HttpError(413, "Request body is too large");
    }
    if (request.body === null) {
        return new Uint8Array();
    }
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const result = await reader.read();
        if (result.done) {
            break;
        }
        total += result.value.length;
        if (total > maximumBytes) {
            await reader.cancel("Request body is too large");
            throw new HttpError(413, "Request body is too large");
        }
        chunks.push(result.value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    return bytes;
}

function jsonResponse(bytes: Uint8Array, status: number = 200): Response {
    return new Response(bytes.slice().buffer as ArrayBuffer, {
        status,
        headers: { "content-type": "application/json" },
    });
}

function decodeRequest<T>(bytes: Uint8Array, decoder: (body: Uint8Array) => T): T {
    try {
        return decoder(bytes);
    } catch {
        throw new HttpError(400, "Invalid request body");
    }
}

function encodeBoundedDeliveries(
    deliveries: Parameters<typeof encodeRelayDeliveriesWire>[0],
): Uint8Array {
    let count = deliveries.length;
    while (count > 0) {
        const bytes = encodeRelayDeliveriesWire(deliveries.slice(0, count));
        if (bytes.length <= MAXIMUM_DELIVERY_RESPONSE_BYTES) {
            return bytes;
        }
        count -= 1;
    }
    const empty = encodeRelayDeliveriesWire([]);
    if (deliveries.length > 0) {
        throw new Error("One relay delivery exceeds the HTTP response limit");
    }
    return empty;
}

function isCanonicalBlobId(id: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(id)) {
        return false;
    }
    try {
        const bytes = decodeBase64Url(id);
        return bytes.length === 32 && encodeBase64Url(bytes) === id;
    } catch {
        return false;
    }
}

/** Create a runtime-neutral HTTP handler over one dumb relay service. */
export function createRelayFetchHandler(
    relay: RelayService,
): (request: Request) => Promise<Response> {
    return async (request: Request): Promise<Response> => {
        try {
            const url = new URL(request.url);
            if (request.method === "POST" && url.pathname === "/v1/subscriptions") {
                await relay.subscribe(
                    decodeRequest(
                        await readBody(request, MAXIMUM_JSON_BODY_BYTES),
                        decodeTopicSubscriptionWire,
                    ),
                );
                return new Response(null, { status: 204 });
            }
            if (request.method === "POST" && url.pathname === "/v1/events") {
                await relay.publish(
                    decodeRequest(
                        await readBody(request, MAXIMUM_JSON_BODY_BYTES),
                        decodeRelayEventWire,
                    ),
                );
                return new Response(null, { status: 204 });
            }
            if (request.method === "POST" && url.pathname === "/v1/queue/pull") {
                const requestBody = decodeRequest(
                    await readBody(request, MAXIMUM_JSON_BODY_BYTES),
                    decodeQueueRequestWire,
                );
                if (requestBody.action !== "read") {
                    throw new HttpError(400, "Expected a queue-read request");
                }
                const waitValue = url.searchParams.get("wait") ?? "0";
                if (!/^\d+$/.test(waitValue)) {
                    throw new HttpError(400, "Invalid long-poll duration");
                }
                const deliveries = await relay.pull(
                    requestBody as QueueReadRequest,
                    Number(waitValue),
                    request.signal,
                );
                return jsonResponse(encodeBoundedDeliveries(deliveries));
            }
            if (request.method === "POST" && url.pathname === "/v1/queue/acknowledge") {
                const requestBody = decodeRequest(
                    await readBody(request, MAXIMUM_JSON_BODY_BYTES),
                    decodeQueueRequestWire,
                );
                if (requestBody.action !== "acknowledge") {
                    throw new HttpError(400, "Expected a queue-acknowledgement request");
                }
                await relay.acknowledge(requestBody as QueueAcknowledgeRequest);
                return new Response(null, { status: 204 });
            }

            const blobMatch = /^\/v1\/blobs\/([A-Za-z0-9_-]{43})$/.exec(url.pathname);
            if (blobMatch !== null && isCanonicalBlobId(blobMatch[1] ?? "")) {
                const id = blobMatch[1] ?? "";
                if (request.method === "PUT") {
                    await relay.putBlob({
                        id,
                        bytes: await readBody(request, MAXIMUM_BLOB_BODY_BYTES),
                    });
                    return new Response(null, { status: 204 });
                }
                if (request.method === "GET") {
                    const blob = await relay.getBlob(id);
                    if (blob === undefined) {
                        return new Response("Not found", { status: 404 });
                    }
                    return new Response(blob.bytes.slice().buffer as ArrayBuffer, {
                        headers: {
                            "content-type": "application/octet-stream",
                        },
                    });
                }
            }

            return new Response("Not found", { status: 404 });
        } catch (error: unknown) {
            if (error instanceof HttpError) {
                return new Response(error.message, { status: error.status });
            }
            if (error instanceof RelayProtocolError) {
                return new Response(error.message, { status: error.status });
            }
            if (request.signal.aborted) {
                return new Response("Request cancelled", { status: 408 });
            }
            return new Response("Internal relay error", { status: 500 });
        }
    };
}
