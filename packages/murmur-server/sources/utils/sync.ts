/**
 * InvalidateSync is a utility class that ensures only one async operation runs at a time,
 * and collapses multiple invalidation requests into a single execution.
 *
 * Use case: Periodic batch operations where multiple triggers should result in a single execution.
 */
export class InvalidateSync {
    private handler: () => Promise<void>;
    private executing = false;
    private invalidated = false;
    private stopped = false;

    constructor(handler: () => Promise<void>) {
        this.handler = handler;
    }

    /**
     * Mark as invalidated. If not currently executing, starts execution.
     * If already executing, queues another execution after current one completes.
     */
    invalidate(): void {
        if (this.stopped) {
            return;
        }

        this.invalidated = true;

        if (!this.executing) {
            this.execute();
        }
    }

    /**
     * Invalidate and wait for the execution to complete.
     */
    async invalidateAndAwait(): Promise<void> {
        if (this.stopped) {
            return;
        }

        this.invalidated = true;

        if (this.executing) {
            // Wait for current execution to complete
            await this.waitForExecution();
        } else {
            // Start execution and wait
            await this.execute();
        }
    }

    /**
     * Stop accepting new invalidations and wait for any pending execution.
     */
    stop(): void {
        this.stopped = true;
    }

    private async execute(): Promise<void> {
        this.executing = true;
        this.invalidated = false;

        try {
            await this.handler();
        } catch (error) {
            // Handler errors are logged by the handler itself
        }

        this.executing = false;

        // If invalidated again during execution, run again
        if (this.invalidated && !this.stopped) {
            this.execute();
        }
    }

    private async waitForExecution(): Promise<void> {
        while (this.executing) {
            await new Promise(resolve => setTimeout(resolve, 10));
        }
    }
}
