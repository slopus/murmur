import { RelayError } from "../../protocol/index.js";
import type { EphemeralStreamMessage, EphemeralSubscription } from "../../relay/index.js";
import type { RelayService } from "../../relay/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";

const encoder = new TextEncoder();
const KEEPALIVE_CHUNK = encoder.encode(": keepalive\n\n");

/** Encode one named SSE event with a single-line UTF-8 data payload. */
function sseEvent(event: string, data: string): Uint8Array {
    return encoder.encode(`event: ${event}\ndata: ${data}\n\n`);
}

/** Encode one drained stream message as its named SSE event. */
function encodeMessage(message: EphemeralStreamMessage): Uint8Array {
    if (message.kind === "frame") {
        return sseEvent("frame", encodeBase64Url(message.bytes));
    }
    if (message.kind === "wake") {
        return sseEvent("wake", "{}");
    }
    return sseEvent("drop", `{"frames":${message.frames.toString()}}`);
}

/**
 * Build the `text/event-stream` body for one topic subscription.
 *
 * The stream is strictly pull-driven so runtime backpressure is honoured: one
 * `pull` drains the subscriber's queue and enqueues each drained message, so a
 * stalled reader holds at most one drained queue plus the bounded, drop-oldest
 * queue the producer can refill behind it — roughly twice
 * `maximumStreamQueueBytes`, and bounded either way. A
 * `ready` event is emitted at construction, `: keepalive` comments are written
 * whenever the keepalive interval elapses without traffic, and the stream ends
 * when the request aborts or the service closes the subscription.
 */
function buildStreamBody(
    subscription: EphemeralSubscription,
    topic: string,
    keepAliveMilliseconds: number,
    signal: AbortSignal,
): ReadableStream<Uint8Array> {
    let onAbort: (() => void) | undefined;
    const detachAbort = (): void => {
        if (onAbort !== undefined) {
            signal.removeEventListener("abort", onAbort);
            onAbort = undefined;
        }
    };
    return new ReadableStream<Uint8Array>({
        start(controller): void {
            controller.enqueue(sseEvent("ready", `{"topic":${JSON.stringify(topic)}}`));
            if (signal.aborted) {
                subscription.close();
                return;
            }
            onAbort = (): void => {
                subscription.close();
            };
            signal.addEventListener("abort", onAbort, { once: true });
        },
        async pull(controller): Promise<void> {
            const flush = (): boolean => {
                const messages = subscription.take();
                for (const message of messages) {
                    controller.enqueue(encodeMessage(message));
                }
                return messages.length > 0;
            };
            if (flush()) {
                return;
            }
            if (subscription.closed) {
                detachAbort();
                controller.close();
                return;
            }
            await subscription.waitForActivity(keepAliveMilliseconds);
            if (flush()) {
                return;
            }
            if (subscription.closed) {
                detachAbort();
                controller.close();
                return;
            }
            controller.enqueue(KEEPALIVE_CHUNK);
        },
        cancel(): void {
            detachAbort();
            subscription.close();
        },
    });
}

/**
 * Create the `GET /v1/topics/:topic/stream` SSE response, or throw a 503 when
 * the per-process or the per-topic concurrent-stream cap is reached.
 */
export function createEphemeralStreamResponse(
    service: RelayService,
    topic: string,
    signal: AbortSignal,
): Response {
    const subscription = service.openStream(topic);
    if (subscription === undefined) {
        throw new RelayError(503, "Too many concurrent ephemeral streams", {
            error: "overloaded",
        });
    }
    const body = buildStreamBody(
        subscription,
        topic,
        service.options.streamKeepAliveMilliseconds,
        signal,
    );
    return new Response(body, {
        status: 200,
        headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
            "x-accel-buffering": "no",
        },
    });
}
