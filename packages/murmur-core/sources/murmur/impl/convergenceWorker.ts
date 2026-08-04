const IDLE_MILLISECONDS = 1_000;
const MUTATION_DELAY_MILLISECONDS = 25;
const INITIAL_BACKOFF_MILLISECONDS = 100;
const MAXIMUM_BACKOFF_MILLISECONDS = 30_000;

function unrefTimer(timer: ReturnType<typeof setTimeout>): void {
    if ((typeof timer !== "object" || timer === null) && typeof timer !== "function") {
        return;
    }
    const unref = Reflect.get(timer, "unref");
    if (typeof unref === "function") {
        Reflect.apply(unref, timer, []);
    }
}

/** Retry/backoff scheduler around one serialized durable convergence pass. */
export class ConvergenceWorker {
    readonly #run: (signal: AbortSignal) => Promise<void>;
    #timer: ReturnType<typeof setTimeout> | undefined;
    #abort: AbortController | undefined;
    #running = false;
    #stopped = false;
    #backoff = INITIAL_BACKOFF_MILLISECONDS;
    #error: Error | undefined;

    constructor(run: (signal: AbortSignal) => Promise<void>) {
        this.#run = run;
    }

    /** Defensive view of the latest retained background error. */
    get error(): Error | undefined {
        if (this.#error === undefined) {
            return undefined;
        }
        const copy = new Error(this.#error.message);
        copy.name = this.#error.name;
        return copy;
    }

    /** Schedule the initial convergence pass. */
    start(): void {
        this.#schedule(0);
    }

    /** Debounce and schedule convergence after a durable mutation. */
    wake(): void {
        if (this.#stopped) {
            return;
        }
        this.pause();
        this.#schedule(MUTATION_DELAY_MILLISECONDS);
    }

    /** Cancel a scheduled pass without interrupting a pass already running. */
    pause(): void {
        if (this.#timer !== undefined) {
            clearTimeout(this.#timer);
            this.#timer = undefined;
        }
    }

    /** Resume low-frequency polling after an explicit convergence boundary. */
    resumeIdle(): void {
        this.#schedule(IDLE_MILLISECONDS);
    }

    /** Consume the retained background error. */
    takeError(): Error | undefined {
        const error = this.#error;
        this.#error = undefined;
        return error;
    }

    /** Cancel scheduled and active work permanently. */
    stop(): void {
        this.#stopped = true;
        this.pause();
        this.#abort?.abort(new Error("Murmur is closing"));
    }

    #schedule(delayMilliseconds: number): void {
        if (this.#stopped || this.#timer !== undefined) {
            return;
        }
        const timer = setTimeout(() => {
            this.#timer = undefined;
            void this.#runPass();
        }, delayMilliseconds);
        this.#timer = timer;
        unrefTimer(timer);
    }

    async #runPass(): Promise<void> {
        if (this.#stopped || this.#running) {
            return;
        }
        this.#running = true;
        const abort = new AbortController();
        this.#abort = abort;
        let failed = false;
        try {
            await this.#run(abort.signal);
            this.#backoff = INITIAL_BACKOFF_MILLISECONDS;
        } catch (error: unknown) {
            if (!this.#stopped && !abort.signal.aborted) {
                this.#error =
                    error instanceof Error
                        ? error
                        : new Error("Background Murmur convergence failed");
                failed = true;
            }
        } finally {
            this.#abort = undefined;
            this.#running = false;
        }
        if (this.#stopped) {
            return;
        }
        if (failed) {
            const delay = this.#backoff;
            this.#backoff = Math.min(this.#backoff * 2, MAXIMUM_BACKOFF_MILLISECONDS);
            this.#schedule(delay);
        } else {
            this.#schedule(IDLE_MILLISECONDS);
        }
    }
}
