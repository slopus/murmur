import type { WakeSource } from "../types.js";

/** In-process wake fan-out used by the SQLite deployment. */
export class InProcessWakeSource implements WakeSource {
    readonly #listeners = new Set<(topic: string) => void>();
    #closed = false;

    /** Deliver a committed topic wake to every local service listener. */
    async notify(topic: string): Promise<void> {
        if (this.#closed) {
            return;
        }
        for (const listener of this.#listeners) {
            listener(topic);
        }
    }

    /** Subscribe one local long-poll dispatcher. */
    async subscribe(listener: (topic: string) => void): Promise<void> {
        if (this.#closed) {
            throw new Error("Wake source is closed");
        }
        this.#listeners.add(listener);
    }

    /** Stop dispatch and forget every listener. */
    async close(): Promise<void> {
        this.#closed = true;
        this.#listeners.clear();
    }
}
