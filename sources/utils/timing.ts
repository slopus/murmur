/**
 * Timing utilities for async operations with AbortSignal support
 */

/**
 * Delay for a specified duration, can be interrupted by AbortSignal
 * @param ms - Duration in milliseconds
 * @param signal - Optional AbortSignal to interrupt the delay
 * @returns Promise that resolves after delay or when aborted
 */
export async function delay(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(new DOMException('Delay aborted', 'AbortError'));
            return;
        }

        const timeout = setTimeout(() => {
            cleanup();
            resolve();
        }, ms);

        const abortHandler = () => {
            clearTimeout(timeout);
            cleanup();
            reject(new DOMException('Delay aborted', 'AbortError'));
        };

        signal?.addEventListener('abort', abortHandler);

        function cleanup() {
            signal?.removeEventListener('abort', abortHandler);
        }
    });
}

/**
 * Run a function repeatedly until aborted, with exponential backoff on errors
 * @param fn - Function to run repeatedly
 * @param intervalMs - Delay between successful iterations in milliseconds
 * @param signal - AbortSignal to stop the loop
 * @param backoffOptions - Optional backoff configuration for error retries
 */
export async function forever(
    fn: () => Promise<void>,
    intervalMs: number,
    signal: AbortSignal,
    backoffOptions?: {
        initialDelayMs?: number;
        maxDelayMs?: number;
        multiplier?: number;
    }
): Promise<void> {
    const {
        initialDelayMs = 100,
        maxDelayMs = 30000,
        multiplier = 2,
    } = backoffOptions || {};

    let currentBackoffDelay = initialDelayMs;

    while (!signal.aborted) {
        try {
            // Wrap function execution in backoff retry logic
            await retryWithBackoff(fn, {
                signal,
                initialDelayMs,
                maxDelayMs,
                multiplier,
                maxAttempts: 1, // Single attempt per iteration, backoff happens in the loop
            });

            // Reset backoff delay after successful execution
            currentBackoffDelay = initialDelayMs;

            // Wait before next iteration
            if (intervalMs > 0) {
                try {
                    await delay(intervalMs, signal);
                } catch (error) {
                    // Delay was aborted, exit the loop
                    if (error instanceof DOMException && error.name === 'AbortError') {
                        break;
                    }
                    throw error;
                }
            }
        } catch (error) {
            // If aborted, exit the loop
            if (error instanceof DOMException && (error as DOMException).name === 'AbortError') {
                break;
            }

            // On error, apply backoff before retrying
            try {
                await delay(currentBackoffDelay, signal);
                currentBackoffDelay = Math.min(currentBackoffDelay * multiplier, maxDelayMs);
            } catch (abortError) {
                // Backoff delay was aborted, exit the loop
                if (abortError instanceof DOMException && (abortError as DOMException).name === 'AbortError') {
                    break;
                }
            }
        }
    }
}

/**
 * Retry a function with exponential backoff until it succeeds or is aborted
 * @param fn - Function to retry
 * @param options - Retry options
 */
export async function retryWithBackoff<T>(
    fn: () => Promise<T>,
    options: {
        signal: AbortSignal;
        initialDelayMs?: number;
        maxDelayMs?: number;
        multiplier?: number;
        maxAttempts?: number;
    }
): Promise<T> {
    const {
        signal,
        initialDelayMs = 100,
        maxDelayMs = 30000,
        multiplier = 2,
        maxAttempts = Infinity,
    } = options;

    let attempt = 0;
    let currentDelay = initialDelayMs;

    while (!signal.aborted && attempt < maxAttempts) {
        attempt++;

        try {
            return await fn();
        } catch (error) {
            if (signal.aborted) {
                throw new DOMException('Operation aborted', 'AbortError');
            }

            // If we've hit max attempts, throw the error
            if (attempt >= maxAttempts) {
                throw error;
            }

            // Wait before retrying with exponential backoff
            try {
                await delay(currentDelay, signal);
                currentDelay = Math.min(currentDelay * multiplier, maxDelayMs);
            } catch (abortError) {
                // Delay was aborted
                throw new DOMException('Operation aborted', 'AbortError');
            }
        }
    }

    throw new DOMException('Operation aborted', 'AbortError');
}
