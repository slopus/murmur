import { log } from './log';

type ShutdownHandler = () => Promise<void>;

const shutdownHandlers = new Map<string, ShutdownHandler>();
let isShuttingDown = false;

export function onShutdown(name: string, handler: ShutdownHandler) {
    if (shutdownHandlers.has(name)) {
        throw new Error(`Shutdown handler "${name}" already registered`);
    }
    shutdownHandlers.set(name, handler);
}

async function performShutdown() {
    if (isShuttingDown) {
        log('Shutdown already in progress...');
        return;
    }
    isShuttingDown = true;
    log('Shutdown initiated...');

    // Execute shutdown handlers in reverse order (LIFO)
    const handlers = Array.from(shutdownHandlers.entries()).reverse();
    for (const [name, handler] of handlers) {
        try {
            log(`Shutting down: ${name}`);
            await handler();
        } catch (error) {
            log(`Error during shutdown of ${name}: ${error}`);
        }
    }
}

let shutdownResolver: (() => void) | null = null;

export function awaitShutdown(): Promise<void> {
    return new Promise((resolve) => {
        shutdownResolver = resolve;
    });
}

// Handle shutdown signals
process.on('SIGINT', async () => {
    log('Received SIGINT');
    await performShutdown();
    if (shutdownResolver) {
        shutdownResolver();
    }
});

process.on('SIGTERM', async () => {
    log('Received SIGTERM');
    await performShutdown();
    if (shutdownResolver) {
        shutdownResolver();
    }
});
