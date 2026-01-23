import { startApi } from './api/startApi';
import { db } from './db';
import { events } from './events';
import { log } from './log';
import { awaitShutdown, onShutdown } from './shutdown';
import { createCleanupWorker } from './workers/cleanupWorker';

export async function main() {
    log('Starting Murmur Server...');

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
    const cleanupWorker = createCleanupWorker();
    await cleanupWorker.start();
    onShutdown('cleanup', async () => {
        await cleanupWorker.stop();
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
