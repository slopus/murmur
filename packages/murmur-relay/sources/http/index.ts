import { RelayError, parseSignedRelayEvent, signedRelayEventToJson } from "../protocol/index.js";
import type { RelayService } from "../relay/index.js";
import type {
    EventPage,
    ListElement,
    ListPage,
    PublishOutcome,
    TopicState,
} from "../storage/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { encodeListCursor } from "../utils/cursor.js";
import { readBoundedRequestBody } from "./impl/requestReadBody.js";

const decoder = new TextDecoder("utf-8", { fatal: true });
const DEFAULT_MAXIMUM_PAGE_RESPONSE_BYTES = 8 * 1024 * 1024;

/** CORS policy for the Fetch-compatible relay handler. */
export interface RelayHttpOptions {
    /** `*` or an explicit browser origin allowlist. Defaults to `*`. */
    readonly origins?: "*" | readonly string[];
    /** Aggregate encoded event/list page budget. Defaults to 8 MiB. */
    readonly maximumPageResponseBytes?: number;
}

type RelayFetchHandler = (request: Request) => Promise<Response>;

interface ResolvedRelayHttpOptions {
    readonly origins: "*" | readonly string[];
    readonly maximumPageResponseBytes: number;
}

function jsonStringify(value: unknown): string {
    return JSON.stringify(value, (_key: string, member: unknown): unknown =>
        typeof member === "bigint" ? member.toString() : member,
    );
}

function jsonTextResponse(value: string, status: number = 200): Response {
    return new Response(value, {
        status,
        headers: { "content-type": "application/json; charset=utf-8" },
    });
}

function jsonResponse(value: unknown, status: number = 200): Response {
    return jsonTextResponse(jsonStringify(value), status);
}

function decodePathSegment(value: string): string {
    try {
        return decodeURIComponent(value);
    } catch {
        throw new RelayError(400, "Invalid route encoding", { error: "malformed" });
    }
}

function queryValue(url: URL, name: string): string | undefined {
    const values = url.searchParams.getAll(name);
    if (values.length > 1) {
        throw new RelayError(400, `Repeated ${name} query parameter`, {
            error: "malformed",
        });
    }
    return values[0];
}

function integerQuery(url: URL, name: string): number | undefined {
    const value = queryValue(url, name);
    if (value === undefined) {
        return undefined;
    }
    if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new RelayError(400, `Invalid ${name} query parameter`, {
            error: "malformed",
        });
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
        throw new RelayError(400, `Invalid ${name} query parameter`, {
            error: "malformed",
        });
    }
    return parsed;
}

function bigintQuery(url: URL, name: string, fallback: bigint): bigint {
    const value = queryValue(url, name);
    if (value === undefined) {
        return fallback;
    }
    if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new RelayError(400, `Invalid ${name} query parameter`, {
            error: "malformed",
        });
    }
    return BigInt(value);
}

async function jsonBody(request: Request, maximumBytes: number): Promise<unknown> {
    const bytes = await readBoundedRequestBody(request, maximumBytes);
    try {
        return JSON.parse(decoder.decode(bytes)) as unknown;
    } catch {
        throw new RelayError(400, "Malformed JSON body", { error: "malformed" });
    }
}

function elementJson(element: ListElement): {
    readonly id: string;
    readonly version: string;
    readonly bytes: string;
} {
    return {
        id: element.id,
        version: element.version.toString(),
        bytes: encodeBase64Url(element.bytes),
    };
}

function byteLength(value: string): number {
    return Buffer.byteLength(value, "utf8");
}

function listPageText(page: ListPage, maximumBytes: number): string {
    const prefix = '{"elements":[';
    const itemTexts: string[] = [];
    let itemBytes = 0;
    let nextCursor = page.nextCursor;
    for (const [index, element] of page.elements.entries()) {
        const itemText = jsonStringify(elementJson(element));
        const hasMore = index < page.elements.length - 1 || page.nextCursor !== null;
        const candidateCursor = hasMore ? encodeListCursor(element.position) : null;
        const candidateItemBytes =
            itemBytes + byteLength(itemText) + (itemTexts.length === 0 ? 0 : 1);
        const suffix = `],"nextCursor":${jsonStringify(candidateCursor)}}`;
        const candidateBytes = byteLength(prefix) + candidateItemBytes + byteLength(suffix);
        if (candidateBytes > maximumBytes && itemTexts.length > 0) {
            nextCursor = encodeListCursor(page.elements[index - 1]?.position ?? 0n);
            break;
        }
        itemTexts.push(itemText);
        itemBytes = candidateItemBytes;
        nextCursor = candidateCursor;
    }
    return `${prefix}${itemTexts.join(",")}],"nextCursor":${jsonStringify(nextCursor)}}`;
}

function stateText(state: TopicState, maximumBytes: number): string {
    const snapshot = jsonStringify(
        state.snapshot === null
            ? null
            : {
                  version: state.snapshot.version.toString(),
                  bytes: encodeBase64Url(state.snapshot.bytes),
              },
    );
    const prefix = `{"seq":"${state.seq.toString()}","snapshot":${snapshot},"list":`;
    const suffix = "}";
    const listBudget = Math.max(1, maximumBytes - byteLength(prefix) - byteLength(suffix));
    return `${prefix}${listPageText(state.list, listBudget)}${suffix}`;
}

function eventPageText(page: EventPage, maximumBytes: number): string {
    const prefix = '{"events":[';
    const suffix = `],"reset":${String(page.reset)},"seq":"${page.seq.toString()}"}`;
    const itemTexts: string[] = [];
    let itemBytes = 0;
    for (const retained of page.events) {
        const itemText = jsonStringify({
            seq: retained.seq.toString(),
            ...signedRelayEventToJson(retained.event),
        });
        const candidateItemBytes =
            itemBytes + byteLength(itemText) + (itemTexts.length === 0 ? 0 : 1);
        const candidateBytes = byteLength(prefix) + candidateItemBytes + byteLength(suffix);
        if (candidateBytes > maximumBytes && itemTexts.length > 0) {
            break;
        }
        itemTexts.push(itemText);
        itemBytes = candidateItemBytes;
    }
    return `${prefix}${itemTexts.join(",")}${suffix}`;
}

function publishJson(outcome: PublishOutcome): unknown {
    if (outcome.snapshotVersion === undefined) {
        return {
            seq: outcome.seq.toString(),
            duplicate: outcome.duplicate,
        };
    }
    return {
        seq: outcome.seq.toString(),
        duplicate: outcome.duplicate,
        snapshotVersion: outcome.snapshotVersion.toString(),
    };
}

function corsHeaders(request: Request, options: ResolvedRelayHttpOptions): Headers {
    const headers = new Headers();
    const origins = options.origins ?? "*";
    const origin = request.headers.get("origin");
    if (origins === "*") {
        headers.set("access-control-allow-origin", "*");
    } else if (origin !== null && origins.includes(origin)) {
        headers.set("access-control-allow-origin", origin);
        headers.set("vary", "Origin");
    }
    headers.set("access-control-allow-methods", "GET, POST, PUT, OPTIONS");
    headers.set("access-control-allow-headers", "Content-Type, Content-Length");
    headers.set("access-control-max-age", "86400");
    return headers;
}

function withCors(
    response: Response,
    request: Request,
    options: ResolvedRelayHttpOptions,
): Response {
    const headers = new Headers(response.headers);
    for (const [name, value] of corsHeaders(request, options)) {
        headers.set(name, value);
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
    });
}

async function routeRequest(
    service: RelayService,
    request: Request,
    options: ResolvedRelayHttpOptions,
): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname
        .split("/")
        .filter((segment) => segment.length > 0)
        .map(decodePathSegment);

    if (request.method === "OPTIONS") {
        return new Response(null, { status: 204 });
    }
    if (request.method === "GET" && segments.length === 1 && segments[0] === "health") {
        await service.health();
        return jsonResponse({ ok: true });
    }
    if (
        segments.length === 4 &&
        segments[0] === "v1" &&
        segments[1] === "topics" &&
        segments[3] === "events"
    ) {
        const topic = segments[2];
        if (topic === undefined) {
            throw new RelayError(400, "Missing topic", { error: "malformed" });
        }
        if (request.method === "POST") {
            const event = parseSignedRelayEvent(
                await jsonBody(request, service.options.maximumJsonBodyBytes),
            );
            if (event.topic !== topic) {
                throw new RelayError(400, "Route topic does not match signed event", {
                    error: "malformed",
                });
            }
            return jsonResponse(publishJson(await service.publish(event)));
        }
        if (request.method === "GET") {
            const page = await service.readEvents(
                topic,
                bigintQuery(url, "since", 0n),
                integerQuery(url, "limit"),
                integerQuery(url, "wait") ?? 0,
                request.signal,
                options.maximumPageResponseBytes,
            );
            return page === undefined
                ? jsonResponse({ error: "not_found" }, 404)
                : jsonTextResponse(eventPageText(page, options.maximumPageResponseBytes));
        }
    }
    if (
        request.method === "GET" &&
        segments.length === 4 &&
        segments[0] === "v1" &&
        segments[1] === "topics" &&
        segments[3] === "state"
    ) {
        const topic = segments[2];
        if (topic === undefined) {
            throw new RelayError(400, "Missing topic", { error: "malformed" });
        }
        const state = await service.readState(
            topic,
            integerQuery(url, "limit"),
            options.maximumPageResponseBytes,
        );
        return state === undefined
            ? jsonResponse({ error: "not_found" }, 404)
            : jsonTextResponse(stateText(state, options.maximumPageResponseBytes));
    }
    if (
        request.method === "GET" &&
        segments.length === 4 &&
        segments[0] === "v1" &&
        segments[1] === "topics" &&
        segments[3] === "list"
    ) {
        const topic = segments[2];
        if (topic === undefined) {
            throw new RelayError(400, "Missing topic", { error: "malformed" });
        }
        const page = await service.readList(
            topic,
            queryValue(url, "cursor"),
            integerQuery(url, "limit"),
            options.maximumPageResponseBytes,
        );
        return page === undefined
            ? jsonResponse({ error: "not_found" }, 404)
            : jsonTextResponse(listPageText(page, options.maximumPageResponseBytes));
    }
    if (segments.length === 3 && segments[0] === "v1" && segments[1] === "blobs") {
        const id = segments[2];
        if (id === undefined) {
            throw new RelayError(400, "Missing blob identifier", {
                error: "malformed",
            });
        }
        if (request.method === "PUT") {
            const bytes = await readBoundedRequestBody(request, service.options.maximumBlobBytes);
            await service.putBlob({ id, bytes });
            return new Response(null, { status: 204 });
        }
        if (request.method === "GET") {
            const blob = await service.getBlob(id);
            return blob === undefined
                ? jsonResponse({ error: "not_found" }, 404)
                : new Response(blob.bytes, {
                      status: 200,
                      headers: { "content-type": "application/octet-stream" },
                  });
        }
    }
    return jsonResponse({ error: "not_found" }, 404);
}

function resolveHttpOptions(options: RelayHttpOptions): ResolvedRelayHttpOptions {
    const maximumPageResponseBytes =
        options.maximumPageResponseBytes ?? DEFAULT_MAXIMUM_PAGE_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maximumPageResponseBytes) || maximumPageResponseBytes < 1) {
        throw new Error("Maximum page response bytes must be a positive safe integer");
    }
    return {
        origins: options.origins ?? "*",
        maximumPageResponseBytes,
    };
}

/** Create the complete Fetch-compatible Murmur relay handler. */
export function createRelayFetchHandler(
    service: RelayService,
    options: RelayHttpOptions = {},
): RelayFetchHandler {
    const resolvedOptions = resolveHttpOptions(options);
    return async (request): Promise<Response> => {
        try {
            return withCors(
                await routeRequest(service, request, resolvedOptions),
                request,
                resolvedOptions,
            );
        } catch (error) {
            if (error instanceof RelayError) {
                return withCors(jsonResponse(error.body, error.status), request, resolvedOptions);
            }
            return withCors(jsonResponse({ error: "internal" }, 500), request, resolvedOptions);
        }
    };
}
