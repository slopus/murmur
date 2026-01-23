import { db } from '@/db';
import { log } from '@/log';

/**
 * Cleanup worker that deletes expired messages
 * Runs periodically to remove messages older than 30 days
 */
export class CleanupWorker {
    private interval?: NodeJS.Timeout;
    private readonly CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

    async start(): Promise<void> {
        log('Starting cleanup worker...');

        // Run immediately on start
        await this.cleanup();

        // Run periodically
        this.interval = setInterval(() => {
            this.cleanup().catch(err => {
                log(`Cleanup worker error: ${err}`);
            });
        }, this.CHECK_INTERVAL_MS);

        log(`Cleanup worker started (runs every ${this.CHECK_INTERVAL_MS / 1000}s)`);
    }

    async stop(): Promise<void> {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = undefined;
        }

        log('Cleanup worker stopped');
    }

    private async cleanup(): Promise<void> {
        const now = new Date();

        try {
            // Delete expired messages
            const result = await db.message.deleteMany({
                where: {
                    expiresAt: {
                        lt: now,
                    },
                },
            });

            if (result.count > 0) {
                log(`Cleanup: Deleted ${result.count} expired messages`);
            }
        } catch (error) {
            log(`Error during cleanup: ${error}`);
            throw error;
        }
    }
}

export function createCleanupWorker(): CleanupWorker {
    return new CleanupWorker();
}
