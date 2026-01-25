import { describe, it, expect } from 'vitest';
import { delay, forever, retryWithBackoff } from './timing';

describe('Timing utilities with AbortSignal', () => {
    describe('delay', () => {
        it('should delay for specified duration', async () => {
            const start = Date.now();
            await delay(100);
            const elapsed = Date.now() - start;

            expect(elapsed).toBeGreaterThanOrEqual(90);
            expect(elapsed).toBeLessThan(150);
        });

        it('should be interrupted by AbortSignal', async () => {
            const controller = new AbortController();
            const start = Date.now();

            // Abort after 50ms
            setTimeout(() => {
                controller.abort();
            }, 50);

            try {
                await delay(1000, controller.signal);
                throw new Error('Should have been aborted');
            } catch (error) {
                expect(error).toBeInstanceOf(DOMException);
                expect((error as DOMException).name).toBe('AbortError');
            }

            const elapsed = Date.now() - start;
            expect(elapsed).toBeLessThan(200);
        });

        it('should reject immediately if already aborted', async () => {
            const controller = new AbortController();
            controller.abort();

            const start = Date.now();
            try {
                await delay(1000, controller.signal);
                throw new Error('Should have been aborted');
            } catch (error) {
                expect(error).toBeInstanceOf(DOMException);
                expect((error as DOMException).name).toBe('AbortError');
            }

            const elapsed = Date.now() - start;
            expect(elapsed).toBeLessThan(50);
        });

        it('should work without AbortSignal', async () => {
            const start = Date.now();
            await delay(50);
            const elapsed = Date.now() - start;

            expect(elapsed).toBeGreaterThanOrEqual(40);
        });
    });

    describe('forever', () => {
        it('should run function repeatedly until aborted', async () => {
            const controller = new AbortController();
            let count = 0;

            const foreverPromise = forever(async () => {
                count++;
                if (count === 3) {
                    controller.abort();
                }
            }, 10, controller.signal);

            await foreverPromise;
            expect(count).toBe(3);
        });

        it('should handle errors without stopping', async () => {
            const controller = new AbortController();
            let count = 0;

            const foreverPromise = forever(async () => {
                count++;
                if (count === 2) {
                    throw new Error('Test error');
                }
                if (count === 4) {
                    controller.abort();
                }
            }, 10, controller.signal);

            await foreverPromise;
            expect(count).toBe(4);
        });

        it('should stop immediately if already aborted', async () => {
            const controller = new AbortController();
            controller.abort();

            let count = 0;
            await forever(async () => {
                count++;
            }, 10, controller.signal);

            expect(count).toBe(0);
        });

        it('should respect the interval between iterations', async () => {
            const controller = new AbortController();
            let count = 0;
            const start = Date.now();

            const foreverPromise = forever(async () => {
                count++;
                if (count === 3) {
                    controller.abort();
                }
            }, 100, controller.signal);

            await foreverPromise;
            const elapsed = Date.now() - start;

            expect(count).toBe(3);
            // Should have waited ~200ms (2 intervals between 3 runs)
            expect(elapsed).toBeGreaterThanOrEqual(180);
        });

        it('should work with zero interval', async () => {
            const controller = new AbortController();
            let count = 0;

            const foreverPromise = forever(async () => {
                count++;
                if (count === 5) {
                    controller.abort();
                }
            }, 0, controller.signal);

            await foreverPromise;
            expect(count).toBe(5);
        });
    });

    describe('retryWithBackoff', () => {
        it('should succeed on first attempt', async () => {
            const controller = new AbortController();
            let attempts = 0;

            const result = await retryWithBackoff(async () => {
                attempts++;
                return 'success';
            }, { signal: controller.signal });

            expect(result).toBe('success');
            expect(attempts).toBe(1);
        });

        it('should retry with exponential backoff', async () => {
            const controller = new AbortController();
            let attempts = 0;
            const start = Date.now();

            const result = await retryWithBackoff(async () => {
                attempts++;
                if (attempts < 3) {
                    throw new Error('Not yet');
                }
                return 'success';
            }, {
                signal: controller.signal,
                initialDelayMs: 50,
                multiplier: 2,
            });

            const elapsed = Date.now() - start;

            expect(result).toBe('success');
            expect(attempts).toBe(3);
            // Should have waited 50ms + 100ms = 150ms
            expect(elapsed).toBeGreaterThanOrEqual(140);
        });

        it('should respect maxAttempts', async () => {
            const controller = new AbortController();
            let attempts = 0;

            try {
                await retryWithBackoff(async () => {
                    attempts++;
                    throw new Error('Always fails');
                }, {
                    signal: controller.signal,
                    maxAttempts: 3,
                    initialDelayMs: 10,
                });
                throw new Error('Should have thrown');
            } catch (error) {
                expect((error as Error).message).toBe('Always fails');
                expect(attempts).toBe(3);
            }
        });

        it('should respect maxDelayMs', async () => {
            const controller = new AbortController();
            let attempts = 0;

            const result = await retryWithBackoff(async () => {
                attempts++;
                if (attempts < 5) {
                    throw new Error('Not yet');
                }
                return 'success';
            }, {
                signal: controller.signal,
                initialDelayMs: 10,
                maxDelayMs: 50,
                multiplier: 10,
            });

            expect(result).toBe('success');
            expect(attempts).toBe(5);
        });

        it('should abort when signal is triggered', async () => {
            const controller = new AbortController();
            let attempts = 0;

            setTimeout(() => controller.abort(), 100);

            try {
                await retryWithBackoff(async () => {
                    attempts++;
                    throw new Error('Always fails');
                }, {
                    signal: controller.signal,
                    initialDelayMs: 50,
                });
                throw new Error('Should have been aborted');
            } catch (error) {
                expect(error).toBeInstanceOf(DOMException);
                expect((error as DOMException).name).toBe('AbortError');
                expect(attempts).toBeGreaterThan(0);
            }
        });

        it('should throw AbortError if already aborted', async () => {
            const controller = new AbortController();
            controller.abort();

            try {
                await retryWithBackoff(async () => {
                    return 'success';
                }, { signal: controller.signal });
                throw new Error('Should have been aborted');
            } catch (error) {
                expect(error).toBeInstanceOf(DOMException);
                expect((error as DOMException).name).toBe('AbortError');
            }
        });
    });
});
