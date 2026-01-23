import Redis from 'ioredis';
import { db } from '@/db';
import { log } from '@/log';
import { trimIdent } from '@/utils/trimIndent';
import { InvalidateSync } from '@/utils/sync';

/**
 * SequenceCounter manages user event sequence numbers with high performance.
 *
 * Strategy:
 * - Each user has a monotonically increasing sequence number (seqno)
 * - Redis stores the current counter value (fast, volatile)
 * - Local Map tracks latest seqno per user for bulk flushing
 * - DB checkpoints are written every 10 seconds in bulk (slow, persistent)
 * - When Redis is lost, we atomically increment DB checkpoint by 1000 and resume from there
 * - This creates gaps (acceptable) but ensures uniqueness
 *
 * Race Condition Prevention (Three Critical Issues):
 *
 * 1. DB Checkpoint Recovery (on Redis loss):
 *    - Multiple processes simultaneously incrementing DB checkpoint
 *    - Solution: Atomic DB UPDATE...RETURNING (row-level lock)
 *    - Each process gets unique starting point (1000, 2000, 3000, etc.)
 *
 * 2. Redis Write-Back (after DB recovery):
 *    - Process A gets checkpoint 1000, Process B gets checkpoint 2000
 *    - Process B writes 2000 to Redis, then Process A writes 1000 (OVERWRITE!)
 *    - Solution: Lua script to SET MAX(current, new) atomically
 *    - Ensures Redis always has the highest value
 *
 * 3. DB Checkpoint Writes (periodic bulk writes):
 *    - Process A uses seqno 101, Process B uses seqno 200
 *    - Process B writes checkpoint (200), then Process A writes (101) (OVERWRITE!)
 *    - Solution: SQL GREATEST(current, new) to only update if higher
 *    - Ensures DB always has the highest checkpoint value
 */
export class SequenceCounter {
    private redis: Redis;
    private readonly DB_INCREMENT = 1000;
    private readonly REDIS_KEY_PREFIX = 'seqno:';
    private readonly FLUSH_INTERVAL_MS = 10000; // 10 seconds

    // Local map tracking latest seqno for each user (for bulk flushing)
    private latestSeqnos = new Map<string, number>();

    // Periodic flush using InvalidateSync
    private flushSync: InvalidateSync;
    private flushTimer?: NodeJS.Timeout;

    // Lua script to atomically set the maximum value
    // This prevents race conditions where a later process overwrites with a smaller value
    private readonly SET_MAX_SCRIPT = trimIdent(`
        local key = KEYS[1]
        local new_value = tonumber(ARGV[1])
        local current = redis.call('GET', key)

        if current == false or tonumber(current) < new_value then
            redis.call('SET', key, new_value)
            return new_value
        else
            return tonumber(current)
        end
    `);

    // Lua script to atomically check existence and increment
    // Returns 0 if key doesn't exist (needs initialization), otherwise returns incremented value
    private readonly INCR_IF_EXISTS_SCRIPT = trimIdent(`
        local key = KEYS[1]
        local current = redis.call('GET', key)

        if current == false then
            return 0
        else
            return redis.call('INCR', key)
        end
    `);

    constructor(redis: Redis) {
        this.redis = redis;

        // Initialize flush sync - will flush all active users to DB
        this.flushSync = new InvalidateSync(async () => {
            await this.flushAllToDB();
        });
    }

    /**
     * Start the periodic flush timer.
     * This invalidates the sync every 10 seconds, triggering a flush.
     */
    start(): void {
        if (this.flushTimer) {
            return; // Already started
        }

        this.flushTimer = setInterval(() => {
            this.flushSync.invalidate();
        }, this.FLUSH_INTERVAL_MS);

        log(`SequenceCounter periodic flush started (every ${this.FLUSH_INTERVAL_MS}ms)`);
    }

    /**
     * Stop the periodic flush timer and flush any pending data.
     */
    async stop(): Promise<void> {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = undefined;
        }

        // Final flush before stopping
        await this.flushSync.invalidateAndAwait();
        this.flushSync.stop();

        log('SequenceCounter periodic flush stopped');
    }

    /**
     * Get the next sequence number for a user.
     * This is optimized for high throughput with minimal DB writes.
     *
     * Handles Redis loss gracefully by reading last checkpoint from DB.
     * Tracks latest seqno locally for bulk flushing every 10 seconds.
     */
    async getNextSeqno(userId: string): Promise<number> {
        const key = this.getRedisKey(userId);

        // Try to increment atomically (returns 0 if key doesn't exist)
        const result = await this.redis.eval(
            this.INCR_IF_EXISTS_SCRIPT,
            1, // number of keys
            key
        ) as number;

        if (result > 0) {
            // Fast path: key existed, got incremented value

            // Track latest seqno for this user (for bulk flushing)
            this.latestSeqnos.set(userId, result);

            return result;
        }

        // Slow path: key doesn't exist, need to initialize from DB
        // Multiple threads might call incrementDBCheckpoint simultaneously, that's OK
        // Each gets a unique checkpoint (1000, 2000, 3000, etc.) and SET_MAX ensures
        // Redis gets the highest value
        const checkpointSeqno = await this.incrementDBCheckpoint(userId);

        // CRITICAL: Use Lua script to set the MAXIMUM value
        // This prevents race conditions:
        //   Thread A: gets checkpoint 999, Thread B: gets checkpoint 1999
        //   Thread B: sets Redis to 1999
        //   Thread A: tries to set Redis to 999 (BLOCKED by script!)
        await this.redis.eval(
            this.SET_MAX_SCRIPT,
            1, // number of keys
            key,
            checkpointSeqno
        );

        // Call self recursively to get the next seqno
        // This handles the case where Redis restarts between SET_MAX and INCR
        // If Redis restarted, the recursive call will reinitialize properly
        return await this.getNextSeqno(userId);
    }

    /**
     * Atomically increment the DB checkpoint and return the new value.
     *
     * This uses PostgreSQL's atomic UPDATE...RETURNING to ensure that
     * multiple processes get unique checkpoint values simultaneously.
     *
     * Example:
     * - Process A calls this: DB checkpoint 0 → 1000, returns 1000
     * - Process B calls this: DB checkpoint 1000 → 2000, returns 2000
     * - Each process starts from their checkpoint, creating gaps but ensuring uniqueness
     *
     * For new users, starts at DB_INCREMENT (1000).
     */
    private async incrementDBCheckpoint(userId: string): Promise<number> {
        try {
            // Use raw SQL for atomic upsert with increment
            // This is atomic across all processes/servers
            const rows = await db.$queryRaw<Array<{ seqno: number }>>`
                INSERT INTO "UserSequence" ("userId", "seqno", "updatedAt")
                VALUES (${userId}, ${this.DB_INCREMENT}, NOW())
                ON CONFLICT ("userId")
                DO UPDATE SET
                    "seqno" = "UserSequence"."seqno" + ${this.DB_INCREMENT},
                    "updatedAt" = NOW()
                RETURNING "seqno"
            `;

            const newCheckpoint = rows[0].seqno;

            // Start from 1 less than checkpoint (will INCR to checkpoint value)
            // If DB checkpoint is 1000, we start Redis at 999, next INCR gives 1000
            const startFrom = newCheckpoint - 1;

            log(`DB checkpoint incremented for user ${userId}: ${newCheckpoint}, starting Redis at ${startFrom}`);

            return startFrom;
        } catch (error) {
            log(`Error incrementing DB checkpoint for user ${userId}: ${error}`);
            throw error;
        }
    }

    /**
     * Flush all tracked users' sequence numbers to the database in bulk.
     * Called periodically by InvalidateSync (every 10 seconds).
     *
     * Uses a single non-interactive Prisma transaction for all writes.
     * After successful flush, removes entries from map only if they haven't changed.
     */
    private async flushAllToDB(): Promise<void> {
        if (this.latestSeqnos.size === 0) {
            return; // Nothing to flush
        }

        // Create a snapshot of current seqnos to flush
        const toFlush = Array.from(this.latestSeqnos.entries());
        log(`Flushing ${toFlush.length} users to DB`);

        try {
            // Flush all users in a single non-interactive transaction
            const operations = toFlush.map(([userId, seqno]) =>
                db.$executeRaw`
                    INSERT INTO "UserSequence" ("userId", "seqno", "updatedAt")
                    VALUES (${userId}, ${seqno}, NOW())
                    ON CONFLICT ("userId")
                    DO UPDATE SET
                        "seqno" = GREATEST("UserSequence"."seqno", ${seqno}),
                        "updatedAt" = NOW()
                `
            );

            await db.$transaction(operations);

            // Remove from map only if values haven't changed since we read them
            for (const [userId, seqno] of toFlush) {
                const current = this.latestSeqnos.get(userId);
                if (current === seqno) {
                    this.latestSeqnos.delete(userId);
                }
            }

            log(`Flushed ${toFlush.length} users to DB`);
        } catch (err) {
            log(`Failed to flush users to DB: ${err}`);
            throw err;
        }
    }

    /**
     * Get the Redis key for a user's sequence counter.
     */
    getRedisKey(userId: string): string {
        return `${this.REDIS_KEY_PREFIX}${userId}`;
    }

    /**
     * Get current sequence number without incrementing.
     */
    async getCurrentSeqno(userId: string): Promise<number> {
        const key = this.getRedisKey(userId);
        const current = await this.redis.get(key);

        if (current) {
            return parseInt(current, 10);
        }

        // Not in Redis, initialize from DB
        const sequence = await db.userSequence.findUnique({
            where: { userId },
            select: { seqno: true },
        });

        const seqno = sequence?.seqno ?? 0;

        if (seqno > 0) {
            await this.redis.set(key, seqno);
        }

        return seqno;
    }
}
