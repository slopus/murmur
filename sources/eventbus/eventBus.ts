import Redis from 'ioredis';
import { log } from '@/log';
import { SequenceCounter } from './sequenceCounter';
import {
    EventEnvelope,
    EventEnvelopeSchema,
    GlobalEvent,
    GlobalEnvelope,
    UserEvent,
    UserEnvelope,
    isGlobalEnvelope,
    isUserEnvelope,
} from './types';

/**
 * Event handler type definitions
 */
export type GlobalEventHandler = (event: GlobalEvent) => void | Promise<void>;
export type UserEventHandler = (envelope: UserEnvelope) => void | Promise<void>;

/**
 * EventBus provides a high-performance, scalable event distribution system
 * using Redis pub/sub with at-most-once delivery guarantee.
 *
 * Features:
 * - Single Redis connection per process for pub/sub
 * - Strict type checking with Zod validation
 * - Automatic sequence number management for user events
 * - Atomic DB operations for Redis recovery (prevents race conditions)
 * - Support for both global and user-scoped events
 * - At-most-once delivery guarantee
 * - Survives Redis restarts without losing event ordering
 */
export class EventBus {
    private publisher: Redis;
    private subscriber: Redis;
    private sequenceCounter: SequenceCounter;
    private readonly CHANNEL = 'eventbus:events';

    private globalEventHandlers: Set<GlobalEventHandler> = new Set();
    private userEventHandlers: Set<UserEventHandler> = new Set();

    private isSubscribed = false;

    constructor(redisUrl?: string) {
        const url = redisUrl || process.env.REDIS_URL || 'redis://localhost:6379';

        // Create separate connections for pub and sub
        // Redis requires separate connections for pub/sub operations
        this.publisher = new Redis(url, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        this.subscriber = new Redis(url, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        this.sequenceCounter = new SequenceCounter(this.publisher);

        // Set up error handlers
        this.publisher.on('error', (err) => {
            log(`EventBus publisher error: ${err.message}`);
        });

        this.subscriber.on('error', (err) => {
            log(`EventBus subscriber error: ${err.message}`);
        });
    }

    /**
     * Initialize the EventBus and start listening for events.
     */
    async start(): Promise<void> {
        if (this.isSubscribed) {
            log('EventBus already started');
            return;
        }

        // Subscribe to the events channel
        await this.subscriber.subscribe(this.CHANNEL);
        this.isSubscribed = true;

        // Set up message handler
        this.subscriber.on('message', (channel, message) => {
            if (channel === this.CHANNEL) {
                this.handleIncomingMessage(message);
            }
        });

        // Start periodic sequence number flushing
        this.sequenceCounter.start();

        log('EventBus started and listening for events');
    }

    /**
     * Publish a global event (no user scope, no sequence number).
     */
    async publishGlobal(event: GlobalEvent): Promise<void> {
        const envelope: GlobalEnvelope = {
            type: 'global',
            timestamp: Date.now(),
            event,
        };

        await this.publishEnvelope(envelope);
    }

    /**
     * Publish a user-scoped event (automatically assigns sequence number).
     *
     * The sequence counter handles:
     * 1. Atomic seqno increment in Redis
     * 2. Automatic DB checkpoint writes every BATCH_SIZE events
     * 3. Redis recovery via atomic DB checkpoint increment
     */
    async publishUser(userId: string, event: UserEvent): Promise<number> {
        // Get next sequence number (handles checkpointing internally)
        const seqno = await this.sequenceCounter.getNextSeqno(userId);

        // Create envelope with the assigned seqno
        const envelope: UserEnvelope = {
            type: 'user',
            timestamp: Date.now(),
            userId,
            seqno,
            event,
        };

        // Publish to all subscribers
        await this.publishEnvelope(envelope);

        return seqno;
    }

    /**
     * Register a handler for global events.
     */
    onGlobalEvent(handler: GlobalEventHandler): void {
        this.globalEventHandlers.add(handler);
    }

    /**
     * Register a handler for user-scoped events.
     * Handler receives the full envelope (userId, seqno, event).
     */
    onUserEvent(handler: UserEventHandler): void {
        this.userEventHandlers.add(handler);
    }

    /**
     * Unregister a global event handler.
     */
    offGlobalEvent(handler: GlobalEventHandler): void {
        this.globalEventHandlers.delete(handler);
    }

    /**
     * Unregister a user event handler.
     */
    offUserEvent(handler: UserEventHandler): void {
        this.userEventHandlers.delete(handler);
    }

    /**
     * Shutdown the EventBus gracefully.
     */
    async shutdown(): Promise<void> {
        log('Shutting down EventBus...');

        // Stop periodic flushing and flush any pending data
        await this.sequenceCounter.stop();

        // Unsubscribe from channels
        if (this.isSubscribed) {
            await this.subscriber.unsubscribe(this.CHANNEL);
            this.isSubscribed = false;
        }

        // Close Redis connections
        await this.subscriber.quit();
        await this.publisher.quit();

        // Clear handlers
        this.globalEventHandlers.clear();
        this.userEventHandlers.clear();

        log('EventBus shutdown complete');
    }

    /**
     * Publish an event envelope to Redis.
     */
    private async publishEnvelope(envelope: EventEnvelope): Promise<void> {
        try {
            const message = JSON.stringify(envelope);
            await this.publisher.publish(this.CHANNEL, message);
        } catch (error) {
            log(`Error publishing event: ${error}`);
            throw error;
        }
    }

    /**
     * Handle incoming message from Redis pub/sub.
     * Validates the message and routes to appropriate handlers.
     */
    private handleIncomingMessage(message: string): void {
        try {
            // Parse JSON
            const parsed = JSON.parse(message);

            // Validate with Zod
            const result = EventEnvelopeSchema.safeParse(parsed);

            if (!result.success) {
                log(`Invalid event envelope received: ${result.error.message}`);
                // Discard incompatible updates as per requirements
                return;
            }

            const envelope = result.data;

            // Route to appropriate handlers based on envelope type
            if (isGlobalEnvelope(envelope)) {
                this.dispatchGlobalEvent(envelope.event);
            } else if (isUserEnvelope(envelope)) {
                this.dispatchUserEvent(envelope);
            } else {
                log(`Unknown envelope type received: ${JSON.stringify(envelope)}`);
            }
        } catch (error) {
            log(`Error handling incoming message: ${error}`);
            // At-most-once guarantee - we don't retry, just log and move on
        }
    }

    /**
     * Dispatch a global event to all registered handlers.
     */
    private dispatchGlobalEvent(event: GlobalEvent): void {
        for (const handler of this.globalEventHandlers) {
            try {
                const result = handler(event);
                // Handle async handlers
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
     * Dispatch a user event to all registered handlers.
     * Passes the full envelope (userId, seqno, event) to handlers.
     */
    private dispatchUserEvent(envelope: UserEnvelope): void {
        for (const handler of this.userEventHandlers) {
            try {
                const result = handler(envelope);
                // Handle async handlers
                if (result instanceof Promise) {
                    result.catch((err) => {
                        log(`User event handler error: ${err.message}`);
                    });
                }
            } catch (error) {
                log(`User event handler error: ${error}`);
            }
        }
    }

    /**
     * Get the sequence counter (useful for testing and utilities).
     */
    getSequenceCounter(): SequenceCounter {
        return this.sequenceCounter;
    }
}
