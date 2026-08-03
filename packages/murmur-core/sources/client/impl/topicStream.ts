import type { RelayStreamHandlers, RelayTransport } from "../../transport/index.js";
import type { TopicStream, TopicStreamHandlers } from "../types.js";

/** Lowest reconnect delay; the first backoff step never dips below this. */
const BACKOFF_FLOOR_MILLISECONDS = 250;
/** Highest reconnect delay; exponential growth saturates here. */
const BACKOFF_CEILING_MILLISECONDS = 15_000;
/** Guards `2 ** attempt` against overflowing to a non-finite delay. */
const MAXIMUM_BACKOFF_EXPONENT = 40;

/** Per-relay reconnect state owned by one {@link TopicStreamController}. */
interface RelayConnection {
    connected: boolean;
    abort: AbortController | undefined;
    timer: ReturnType<typeof setTimeout> | undefined;
    wake: (() => void) | undefined;
}

/**
 * Runs one live stream per capable relay and reconnects with bounded backoff.
 *
 * Each relay owns an independent loop: it opens a stream, forwards every event
 * tagged with the relay id, and on any end reconnects after an exponential,
 * jittered delay between {@link BACKOFF_FLOOR_MILLISECONDS} and
 * {@link BACKOFF_CEILING_MILLISECONDS}. `close()` aborts the active stream,
 * resolves any pending backoff, and stops the loop so no further timer is
 * scheduled. Nothing is buffered: frames pass straight through to the caller.
 */
export class TopicStreamController implements TopicStream {
    readonly #topic: string;
    readonly #handlers: TopicStreamHandlers;
    readonly #connections = new Map<string, RelayConnection>();
    #closed = false;

    constructor(
        topic: string,
        handlers: TopicStreamHandlers,
        transports: readonly RelayTransport[],
    ) {
        this.#topic = topic;
        this.#handlers = handlers;
        for (const transport of transports) {
            if (typeof transport.openStream !== "function") {
                continue;
            }
            const connection: RelayConnection = {
                connected: false,
                abort: undefined,
                timer: undefined,
                wake: undefined,
            };
            this.#connections.set(transport.id, connection);
            void this.#runRelay(transport, connection);
        }
    }

    get connected(): boolean {
        for (const connection of this.#connections.values()) {
            if (connection.connected) {
                return true;
            }
        }
        return false;
    }

    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        for (const connection of this.#connections.values()) {
            connection.abort?.abort();
            if (connection.timer !== undefined) {
                clearTimeout(connection.timer);
                connection.timer = undefined;
            }
            connection.wake?.();
        }
    }

    async #runRelay(transport: RelayTransport, connection: RelayConnection): Promise<void> {
        let attempt = 0;
        while (!this.#closed) {
            const controller = new AbortController();
            connection.abort = controller;
            let failure: Error | undefined;
            try {
                await transport.openStream?.(
                    this.#topic,
                    this.#relayHandlers(transport.id, connection, () => {
                        attempt = 0;
                    }),
                    controller.signal,
                );
            } catch (error) {
                failure = error instanceof Error ? error : new Error(String(error));
            } finally {
                connection.abort = undefined;
            }
            if (connection.connected) {
                connection.connected = false;
            }
            this.#emitStatus(transport.id, false, failure);
            if (this.#closed) {
                return;
            }
            const delay = backoffDelay(attempt);
            attempt += 1;
            await this.#waitBeforeReconnect(connection, delay);
        }
    }

    #relayHandlers(
        relayId: string,
        connection: RelayConnection,
        onReady: () => void,
    ): RelayStreamHandlers {
        return {
            onReady: (): void => {
                onReady();
                if (!connection.connected) {
                    connection.connected = true;
                    this.#emitStatus(relayId, true, undefined);
                }
            },
            onFrame: (bytes: Uint8Array): void => {
                if (!this.#closed) {
                    this.#handlers.onFrame?.({ relayId, bytes });
                }
            },
            onWake: (): void => {
                if (!this.#closed) {
                    this.#handlers.onWake?.(relayId);
                }
            },
            onDrop: (frames: number): void => {
                if (!this.#closed) {
                    this.#handlers.onDrop?.({ relayId, frames });
                }
            },
        };
    }

    #emitStatus(relayId: string, connected: boolean, error: Error | undefined): void {
        this.#handlers.onStatus?.({
            relayId,
            connected,
            ...(error === undefined ? {} : { error }),
        });
    }

    #waitBeforeReconnect(connection: RelayConnection, milliseconds: number): Promise<void> {
        return new Promise<void>((resolve) => {
            if (this.#closed) {
                resolve();
                return;
            }
            const finish = (): void => {
                if (connection.timer !== undefined) {
                    clearTimeout(connection.timer);
                    connection.timer = undefined;
                }
                connection.wake = undefined;
                resolve();
            };
            connection.wake = finish;
            connection.timer = setTimeout(finish, milliseconds);
        });
    }
}

/** Exponential reconnect delay with full jitter, clamped to the fixed bounds. */
export function backoffDelay(attempt: number): number {
    const exponent = Math.min(Math.max(attempt, 0), MAXIMUM_BACKOFF_EXPONENT);
    const ceiling = Math.min(
        BACKOFF_CEILING_MILLISECONDS,
        BACKOFF_FLOOR_MILLISECONDS * 2 ** exponent,
    );
    const jittered = ceiling / 2 + Math.random() * (ceiling / 2);
    return Math.max(BACKOFF_FLOOR_MILLISECONDS, Math.min(BACKOFF_CEILING_MILLISECONDS, jittered));
}
