import Redis from "ioredis";
import { log } from "@/log";
import { forever } from "@/utils/timing";
import { getShutdownSignal } from "@/shutdown";
import {
    EventEnvelope,
    EventEnvelopeSchema,
    GlobalEvent,
    GlobalEnvelope,
    UserEvent,
    MessageEnvelope,
    isGlobalEnvelope,
    isMessageEnvelope,
} from "./types";

/**
 * Event handler type definitions
 */
export type GlobalEventHandler = (event: GlobalEvent) => void | Promise<void>;
export type MessageEventHandler = (envelope: MessageEnvelope) => void | Promise<void>;

/**
 * EventBus provides a broadcast event distribution system using Redis Streams.
 *
 * Key differences from pub/sub:
 * - Redis Streams provide persistence with replay ability
 * - Each node independently reads the stream (fan-out)
 * - No consumer groups; all nodes see all events
 * - Supports channel-based subscriptions for future sharding
 */
export class EventBus {
    private client: Redis;
    private readonly STREAM_KEY = "murmur:events";
    private readonly STREAM_MAXLEN =
        Number.parseInt(process.env.EVENT_STREAM_MAXLEN ?? "", 10) || 10000;
    private lastStreamId: string = "$";

    private globalEventHandlers: Set<GlobalEventHandler> = new Set();
    private messageEventHandlers: Set<MessageEventHandler> = new Set();

    private isRunning = false;
    private readLoopPromise: Promise<void> | null = null;

    constructor(redisUrl?: string) {
        const url = redisUrl || process.env.REDIS_URL || "redis://localhost:6379";

        this.client = new Redis(url, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        this.client.on("error", (err) => {
            log(`EventBus Redis error: ${err.message}`);
        });
    }

    /**
     * Initialize the EventBus and start listening for events.
     */
    async start(): Promise<void> {
        if (this.isRunning) {
            log("EventBus already started");
            return;
        }

        try {
            const streamInfo = (await this.client.xinfo(
                "STREAM",
                this.STREAM_KEY,
            )) as Array<string>;
            const lastIdIndex = streamInfo.indexOf("last-generated-id");
            if (lastIdIndex >= 0 && streamInfo[lastIdIndex + 1]) {
                this.lastStreamId = streamInfo[lastIdIndex + 1];
            }
        } catch (error) {
            log(`EventBus stream info unavailable: ${error}`);
            this.lastStreamId = "$";
        }

        this.isRunning = true;

        const shutdownSignal = getShutdownSignal();
        this.readLoopPromise = this.readLoop(shutdownSignal);

        log("EventBus started with Redis Streams (broadcast)");
    }

    /**
     * Publish a global event to the global channel.
     */
    async publishGlobal(event: GlobalEvent): Promise<string> {
        const envelope: GlobalEnvelope = {
            type: "global",
            timestamp: Date.now(),
            channel: "global",
            event,
        };

        return this.publishEnvelope(envelope);
    }

    /**
     * Publish a user-scoped event to a user channel.
     * The channel allows future sharding (e.g., route "user:alice" to server A).
     */
    async publishUser(userId: string, event: UserEvent): Promise<string> {
        const envelope: MessageEnvelope = {
            type: "message",
            timestamp: Date.now(),
            channel: `user:${userId}`,
            event,
        };

        return this.publishEnvelope(envelope);
    }

    /**
     * Acknowledge a message (mark as processed and delete from stream).
     * This is called after the message has been successfully delivered to the client.
     */
    async acknowledgeMessage(messageId: string): Promise<void> {
        // No-op in broadcast mode (each node reads independently).
        log(`Ignoring acknowledgeMessage(${messageId}) in broadcast mode`);
    }

    /**
     * Register a handler for global events.
     */
    onGlobalEvent(handler: GlobalEventHandler): void {
        this.globalEventHandlers.add(handler);
    }

    /**
     * Register a handler for message events.
     */
    onMessageEvent(handler: MessageEventHandler): void {
        this.messageEventHandlers.add(handler);
    }

    /**
     * Unregister a global event handler.
     */
    offGlobalEvent(handler: GlobalEventHandler): void {
        this.globalEventHandlers.delete(handler);
    }

    /**
     * Unregister a message event handler.
     */
    offMessageEvent(handler: MessageEventHandler): void {
        this.messageEventHandlers.delete(handler);
    }

    /**
     * Shutdown the EventBus gracefully.
     */
    async shutdown(): Promise<void> {
        log("Shutting down EventBus...");

        this.isRunning = false;

        // Wait for read loop to finish
        if (this.readLoopPromise) {
            await this.readLoopPromise;
        }

        // Close Redis connection
        await this.client.quit();

        // Clear handlers
        this.globalEventHandlers.clear();
        this.messageEventHandlers.clear();

        log("EventBus shutdown complete");
    }

    /**
     * Publish an event envelope to Redis Streams.
     * @returns The Redis Stream message ID
     */
    private async publishEnvelope(envelope: EventEnvelope): Promise<string> {
        try {
            const messageData = JSON.stringify(envelope);
            // XADD stream-key * field value
            // The '*' means auto-generate stream ID (different from our message IDs)
            const streamId = await this.client.xadd(
                this.STREAM_KEY,
                "MAXLEN",
                "~",
                this.STREAM_MAXLEN,
                "*",
                "data",
                messageData,
            );
            return streamId as string;
        } catch (error) {
            log(`Error publishing event: ${error}`);
            throw error;
        }
    }

    /**
     * Read loop that consumes messages from Redis Streams.
     * Uses XREADGROUP for consumer group coordination.
     * Uses forever helper to loop until shutdown.
     */
    private async readLoop(signal: AbortSignal): Promise<void> {
        await forever(
            async () => {
                try {
                    // XREAD BLOCK ms COUNT n STREAMS stream last-id
                    const results = (await this.client.xread(
                        "COUNT",
                        10, // Read up to 10 messages at a time
                        "BLOCK",
                        5000, // Block for 5 seconds
                        "STREAMS",
                        this.STREAM_KEY,
                        this.lastStreamId,
                    )) as any; // Type assertion needed due to ioredis typing limitations

                    if (!results || results.length === 0) {
                        return;
                    }

                    // Process messages
                    for (const [_streamKey, messages] of results) {
                        for (const [streamId, fields] of messages) {
                            this.lastStreamId = streamId;
                            await this.handleStreamMessage(streamId, fields as string[]);
                        }
                    }
                } catch (error: any) {
                    if (this.isRunning) {
                        log(`Error in read loop: ${error.message}`);
                        throw error; // Re-throw to let forever handle it
                    }
                }
            },
            0,
            signal,
        ); // No delay between iterations since XREAD has its own blocking
    }

    /**
     * Handle a message from Redis Streams.
     */
    private async handleStreamMessage(streamId: string, fields: string[]): Promise<void> {
        try {
            // Fields are [key1, value1, key2, value2, ...]
            const dataIndex = fields.indexOf("data");
            if (dataIndex === -1 || dataIndex + 1 >= fields.length) {
                log(`Invalid message format in stream ${streamId}`);
                return;
            }

            const messageData = fields[dataIndex + 1];
            const parsed = JSON.parse(messageData);

            // Validate with Zod
            const result = EventEnvelopeSchema.safeParse(parsed);

            if (!result.success) {
                log(`Invalid event envelope in stream ${streamId}: ${result.error.message}`);
                return;
            }

            const envelope = result.data;

            // Route to appropriate handlers
            if (isGlobalEnvelope(envelope)) {
                this.dispatchGlobalEvent(envelope.event);
            } else if (isMessageEnvelope(envelope)) {
                this.dispatchMessageEvent(envelope);
            }

            // No acknowledgments in broadcast mode.
        } catch (error) {
            log(`Error handling stream message ${streamId}: ${error}`);
        }
    }

    /**
     * Dispatch a global event to all registered handlers.
     */
    private dispatchGlobalEvent(event: GlobalEvent): void {
        for (const handler of this.globalEventHandlers) {
            try {
                const result = handler(event);
                if (result instanceof Promise) {
                    result.catch((err) => {
                        log(`Global event handler error: ${err.message}`);
                    });
                }
            } catch (error) {
                log(`Global event handler error: ${error}`);
            }
        }
    }

    /**
     * Dispatch a message event to all registered handlers.
     */
    private dispatchMessageEvent(envelope: MessageEnvelope): void {
        for (const handler of this.messageEventHandlers) {
            try {
                const result = handler(envelope);
                if (result instanceof Promise) {
                    result.catch((err) => {
                        log(`Message event handler error: ${err.message}`);
                    });
                }
            } catch (error) {
                log(`Message event handler error: ${error}`);
            }
        }
    }
}
