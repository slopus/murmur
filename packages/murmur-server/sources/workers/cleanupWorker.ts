import { db } from "@/db";
import { log } from "@/log";
import { forever } from "@/utils/timing";
import { getShutdownSignal } from "@/shutdown";
import { cleanupRunsTotal, messagesExpiredTotal } from "@/metrics/prometheus";

/**
 * Cleanup function that deletes expired messages
 */
async function cleanup(): Promise<void> {
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
            messagesExpiredTotal.inc(result.count);
        }

        cleanupRunsTotal.inc({ status: "success" });
    } catch (error) {
        log(`Error during cleanup: ${error}`);
        cleanupRunsTotal.inc({ status: "error" });
        throw error;
    }
}

/**
 * Start the cleanup worker that deletes expired messages
 * Runs periodically (every hour) until shutdown
 */
export async function startCleanupWorker(): Promise<void> {
    const CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
    const shutdownSignal = getShutdownSignal();

    log("Starting cleanup worker...");

    await forever(cleanup, CHECK_INTERVAL_MS, shutdownSignal, {
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        multiplier: 2,
    });

    log("Cleanup worker stopped");
}
