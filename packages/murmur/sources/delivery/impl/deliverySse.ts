import type { InboxStreamEvent } from "../types.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/index.js";
import { parseInboxContinuity, parseInboxDelivery } from "./deliveryCodec.js";

interface TimedReadOptions {
    readonly controller: AbortController;
    readonly timeoutMilliseconds: number;
}

function timedRead(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    options: TimedReadOptions,
): Promise<ReadableStreamReadResult<Uint8Array>> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            const error = new Error("Delivery event stream heartbeat timed out");
            options.controller.abort(error);
            void reader.cancel(error).catch(() => undefined);
            reject(error);
        }, options.timeoutMilliseconds);
        void reader.read().then(
            (result) => {
                clearTimeout(timeout);
                resolve(result);
            },
            (error: unknown) => {
                clearTimeout(timeout);
                reject(error);
            },
        );
    });
}

function fieldValue(line: string, separator: number): string {
    const value = line.slice(separator + 1);
    return value.startsWith(" ") ? value.slice(1) : value;
}

/** Strictly decode a bounded sequence of exact Murmur delivery SSE events. */
export async function* decodeDeliveryEventStream(
    response: Response,
    controller: AbortController,
    maximumEventBytes: number,
    heartbeatTimeoutMilliseconds: number,
    onDeviceRosterChanged?: (accountKey: Uint8Array) => void,
): AsyncGenerator<InboxStreamEvent> {
    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("Delivery event stream has no body");
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let buffered = "";
    let eventName = "";
    let eventId = "";
    let data: string[] = [];
    let eventCharacters = 0;
    const dispatch = (): InboxStreamEvent | undefined => {
        if (data.length === 0) {
            eventName = "";
            eventId = "";
            eventCharacters = 0;
            return undefined;
        }
        if (
            (eventName !== "delivery" &&
                eventName !== "continuity" &&
                eventName !== "device_roster_changed") ||
            (eventName === "delivery" && eventId.length === 0) ||
            (eventName !== "delivery" && eventId.length !== 0)
        ) {
            throw new Error("Invalid delivery event stream record");
        }
        let parsed: unknown;
        try {
            parsed = JSON.parse(data.join("\n")) as unknown;
        } catch {
            throw new Error("Invalid delivery event stream JSON");
        }
        if (eventName === "device_roster_changed") {
            if (
                parsed === null ||
                typeof parsed !== "object" ||
                Array.isArray(parsed) ||
                Object.keys(parsed).length !== 1 ||
                typeof (parsed as { readonly accountKey?: unknown }).accountKey !== "string"
            ) {
                throw new Error("Invalid device roster change event");
            }
            const encoded = (parsed as { readonly accountKey: string }).accountKey;
            const accountKey = decodeBase64Url(encoded);
            if (accountKey.length !== 32 || encodeBase64Url(accountKey) !== encoded) {
                throw new Error("Invalid device roster change event");
            }
            onDeviceRosterChanged?.(accountKey);
            eventName = "";
            eventId = "";
            data = [];
            eventCharacters = 0;
            return undefined;
        }
        const queued =
            eventName === "continuity" ? parseInboxContinuity(parsed) : parseInboxDelivery(parsed);
        if (!("type" in queued) && queued.eventId !== eventId) {
            throw new Error("Delivery event ID does not match its SSE identifier");
        }
        eventName = "";
        eventId = "";
        data = [];
        eventCharacters = 0;
        return queued;
    };
    try {
        for (;;) {
            const result = await timedRead(reader, {
                controller,
                timeoutMilliseconds: heartbeatTimeoutMilliseconds,
            });
            if (result.done) {
                buffered += decoder.decode();
                if (buffered.length > 0 || data.length > 0 || eventName.length > 0) {
                    throw new Error("Truncated delivery event stream");
                }
                return;
            }
            buffered += decoder.decode(result.value, { stream: true });
            for (;;) {
                const newline = buffered.indexOf("\n");
                if (newline < 0) {
                    if (buffered.length > maximumEventBytes) {
                        throw new Error("Delivery event exceeds client limit");
                    }
                    break;
                }
                let line = buffered.slice(0, newline);
                buffered = buffered.slice(newline + 1);
                if (line.endsWith("\r")) line = line.slice(0, -1);
                eventCharacters += line.length + 1;
                if (eventCharacters > maximumEventBytes) {
                    throw new Error("Delivery event exceeds client limit");
                }
                if (line.length === 0) {
                    const queued = dispatch();
                    if (queued !== undefined) yield queued;
                    continue;
                }
                if (line.startsWith(":")) continue;
                const separator = line.indexOf(":");
                const field = separator < 0 ? line : line.slice(0, separator);
                const value = separator < 0 ? "" : fieldValue(line, separator);
                if (field === "event") {
                    eventName = value;
                } else if (field === "id") {
                    eventId = value;
                } else if (field === "data") {
                    data.push(value);
                } else if (field !== "retry") {
                    throw new Error("Invalid delivery event stream field");
                }
            }
        }
    } finally {
        void reader.cancel().catch(() => undefined);
        reader.releaseLock();
    }
}
