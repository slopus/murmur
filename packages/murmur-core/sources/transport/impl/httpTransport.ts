import type {
    QueueAcknowledgeRequest,
    QueueReadRequest,
    RelayBlob,
    RelayDelivery,
    RelayEvent,
    RelayTransport,
    TopicSubscription,
} from "../types.js";
import { hashBytes } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode } from "../../utils/index.js";
import {
    decodeRelayDeliveriesWire,
    encodeQueueRequestWire,
    encodeRelayEventWire,
    encodeTopicSubscriptionWire,
} from "./wireCodec.js";

type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

function requestBody(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer as ArrayBuffer;
}

async function readBoundedResponse(response: Response, maximumBytes: number): Promise<Uint8Array> {
    const declaredLength = response.headers.get("content-length");
    if (
        declaredLength !== null &&
        (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes)
    ) {
        throw new Error("Relay response is too large");
    }
    if (response.body === null) {
        return new Uint8Array();
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const result = await reader.read();
        if (result.done) {
            break;
        }
        total += result.value.length;
        if (total > maximumBytes) {
            await reader.cancel("Relay response is too large");
            throw new Error("Relay response is too large");
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

const MAXIMUM_DELIVERY_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_BLOB_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES = 1_024;

/** Browser-safe HTTP long-poll transport for the default rendezvous relay. */
export class HttpRelayTransport implements RelayTransport {
    readonly #baseUrl: string;
    readonly #fetch: Fetch;

    constructor(
        readonly id: string,
        baseUrl: string,
        fetchImplementation: Fetch = globalThis.fetch,
    ) {
        this.#baseUrl = baseUrl.replace(/\/+$/, "");
        this.#fetch = fetchImplementation;
    }

    async publish(event: RelayEvent): Promise<void> {
        await this.#post("/v1/events", encodeRelayEventWire(event));
    }

    async subscribe(subscription: TopicSubscription): Promise<void> {
        await this.#post("/v1/subscriptions", encodeTopicSubscriptionWire(subscription));
    }

    async pull(
        request: QueueReadRequest,
        waitMilliseconds: number = 0,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]> {
        const response = await this.#fetch(
            `${this.#baseUrl}/v1/queue/pull?wait=${waitMilliseconds}`,
            {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: requestBody(encodeQueueRequestWire(request)),
                ...(signal === undefined ? {} : { signal }),
            },
        );
        await this.#requireOk(response);
        return decodeRelayDeliveriesWire(
            await readBoundedResponse(response, MAXIMUM_DELIVERY_RESPONSE_BYTES),
        );
    }

    async acknowledge(request: QueueAcknowledgeRequest): Promise<void> {
        await this.#post("/v1/queue/acknowledge", encodeQueueRequestWire(request));
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        const response = await this.#fetch(
            `${this.#baseUrl}/v1/blobs/${encodeURIComponent(blob.id)}`,
            {
                method: "PUT",
                headers: { "content-type": "application/octet-stream" },
                body: requestBody(blob.bytes),
            },
        );
        await this.#requireOk(response);
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        let decodedId: Uint8Array;
        try {
            decodedId = decodeBase64Url(id);
        } catch {
            throw new Error("Invalid relay blob identifier");
        }
        if (
            decodedId.length !== 32 ||
            encodeBase64Url(decodedId) !== id ||
            !/^[A-Za-z0-9_-]{43}$/.test(id)
        ) {
            throw new Error("Invalid relay blob identifier");
        }
        const response = await this.#fetch(`${this.#baseUrl}/v1/blobs/${encodeURIComponent(id)}`);
        if (response.status === 404) {
            return undefined;
        }
        await this.#requireOk(response);
        const blob = {
            id,
            bytes: await readBoundedResponse(response, MAXIMUM_BLOB_RESPONSE_BYTES),
        };
        if (encodeBase64Url(hashBytes(blob.bytes)) !== id) {
            throw new Error("Relay blob failed content-address validation");
        }
        return blob;
    }

    async #post(path: string, body: Uint8Array): Promise<void> {
        const response = await this.#fetch(`${this.#baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: requestBody(body),
        });
        await this.#requireOk(response);
    }

    async #requireOk(response: Response): Promise<void> {
        if (response.ok) {
            return;
        }
        const details = utf8Decode(
            await readBoundedResponse(response, MAXIMUM_ERROR_RESPONSE_BYTES),
        );
        throw new Error(
            `Relay ${this.id} returned HTTP ${response.status}${details.length === 0 ? "" : `: ${details}`}`,
        );
    }
}
