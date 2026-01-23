import { startApi } from './api/startApi';
import { db } from './db';
import { events } from './events';
import { log } from './log';
import { awaitShutdown, onShutdown } from './shutdown';
import { startCleanupWorker } from './workers/cleanupWorker';
import { initializeJWT } from './utils/jwt';

export async function main() {
    log('Starting Murmur Server...');

    log('Initializing JWT...');
    await initializeJWT();

    log('Connecting to database...');
    await db.$connect();
    onShutdown('db', async () => {
        await db.$disconnect();
    });

    log('Starting EventBus...');
    await events.start();
    onShutdown('events', async () => {
        await events.shutdown();
    });

    log('Starting cleanup worker...');
    // Start cleanup worker in background (runs until shutdown)
    startCleanupWorker().catch(err => {
        log(`Cleanup worker error: ${err}`);
    });

    log('Starting API...');
    await startApi();

    log('Murmur Server ready');
    await awaitShutdown();
    log('Murmur Server shutdown complete');
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
}).then(() => {
    process.exit(0);
});
