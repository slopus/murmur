import { hashBytes } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode } from "../../utils/index.js";
import type {
    EventPage,
    ListPage,
    PublishOutcome,
    RelayBlob,
    RelayFetch,
    RelayTransport,
    SignedRelayEvent,
    TopicState,
} from "../types.js";
import {
    decodeEventPageWire,
    decodeListPageWire,
    decodePublishOutcomeWire,
    decodeTopicStateWire,
    encodeSignedRelayEventWire,
} from "./wireCodec.js";

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

const MAXIMUM_PAGE_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_BLOB_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES = 1_024;

function query(
    path: string,
    values: Readonly<Record<string, string | number | undefined>>,
): string {
    const parameters = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
        if (value !== undefined) {
            parameters.set(key, String(value));
        }
    }
    const encoded = parameters.toString();
    return encoded.length === 0 ? path : `${path}?${encoded}`;
}

/** Browser-safe HTTP transport for the fixed topic-state relay protocol. */
export class HttpRelayTransport implements RelayTransport {
    readonly #baseUrl: string;
    readonly #fetch: RelayFetch;

    constructor(
        readonly id: string,
        baseUrl: string,
        fetchImplementation: RelayFetch = globalThis.fetch,
    ) {
        this.#baseUrl = baseUrl.replace(/\/+$/, "");
        this.#fetch = fetchImplementation;
    }

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        const response = await this.#fetch(
            `${this.#baseUrl}/v1/topics/${encodeURIComponent(event.topic)}/events`,
            {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: requestBody(encodeSignedRelayEventWire(event)),
            },
        );
        await this.#requireOk(response);
        return decodePublishOutcomeWire(
            await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES),
        );
    }

    async readState(topic: string, limit?: number): Promise<TopicState | undefined> {
        const response = await this.#get(query(this.#topicPath(topic, "state"), { limit }));
        return response === undefined
            ? undefined
            : decodeTopicStateWire(
                  await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES),
              );
    }

    async readList(topic: string, cursor?: string, limit?: number): Promise<ListPage | undefined> {
        const response = await this.#get(query(this.#topicPath(topic, "list"), { cursor, limit }));
        return response === undefined
            ? undefined
            : decodeListPageWire(await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES));
    }

    async readEvents(
        topic: string,
        since: bigint,
        limit?: number,
        wait?: number,
        signal?: AbortSignal,
    ): Promise<EventPage | undefined> {
        const response = await this.#get(
            query(this.#topicPath(topic, "events"), {
                since: since.toString(),
                limit,
                wait,
            }),
            signal,
        );
        return response === undefined
            ? undefined
            : decodeEventPageWire(await readBoundedResponse(response, MAXIMUM_PAGE_RESPONSE_BYTES));
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
        const response = await this.#get(`/v1/blobs/${encodeURIComponent(id)}`);
        if (response === undefined) {
            return undefined;
        }
        const blob = {
            id,
            bytes: await readBoundedResponse(response, MAXIMUM_BLOB_RESPONSE_BYTES),
        };
        if (encodeBase64Url(hashBytes(blob.bytes)) !== id) {
            throw new Error("Relay blob failed content-address validation");
        }
        return blob;
    }

    #topicPath(topic: string, resource: "events" | "list" | "state"): string {
        return `/v1/topics/${encodeURIComponent(topic)}/${resource}`;
    }

    async #get(path: string, signal?: AbortSignal): Promise<Response | undefined> {
        const response = await this.#fetch(`${this.#baseUrl}${path}`, {
            method: "GET",
            ...(signal === undefined ? {} : { signal }),
        });
        if (response.status === 404) {
            return undefined;
        }
        await this.#requireOk(response);
        return response;
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
