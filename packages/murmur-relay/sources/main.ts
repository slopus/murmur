import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Pool } from "pg";
import { createRelayFetchHandler, parseRelayAllowedOrigins } from "./http/index.js";
import {
    InProcessWakeSource,
    PostgresWakeSource,
    RelayService,
    type WakeSource,
} from "./relay/index.js";
import {
    closeNodeRelayServer,
    createNodeRelayServer,
    listenNodeRelayServer,
} from "./server/index.js";
import {
    PgPoolDatabase,
    parseRelayStoreBackend,
    PostgresRelayStore,
    SqliteRelayStore,
    type RelayStore,
} from "./storage/index.js";
import { createHumanLogger, safeErrorSummary } from "./utils/logger.js";

const PRUNE_INTERVAL_MILLISECONDS = 60 * 60 * 1_000;
const logger = createHumanLogger("RELAY");

function port(value: string | undefined): number {
    const parsed = value === undefined ? 8787 : Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
        throw new Error("PORT must be an integer from 1 through 65535");
    }
    return parsed;
}

async function createStore(): Promise<{ store: RelayStore; wakeSource: WakeSource }> {
    const backend = parseRelayStoreBackend(process.env.MURMUR_RELAY_STORE);
    if (backend === "sqlite") {
        const path = process.env.MURMUR_RELAY_DB ?? "./data/murmur-relay.sqlite";
        if (path !== ":memory:") await mkdir(dirname(resolve(path)), { recursive: true });
        return { store: new SqliteRelayStore(path), wakeSource: new InProcessWakeSource() };
    }
    const connectionString = process.env.MURMUR_RELAY_DB;
    if (connectionString === undefined) throw new Error("MURMUR_RELAY_DB is required");
    const database = new PgPoolDatabase(new Pool({ connectionString }));
    return {
        store: await PostgresRelayStore.create(database),
        wakeSource: new PostgresWakeSource({ connectionString }),
    };
}

/** Start the standalone ordered-event relay. */
export async function main(): Promise<void> {
    const allowedOrigins = parseRelayAllowedOrigins(process.env.MURMUR_RELAY_ORIGINS);
    const { store, wakeSource } = await createStore();
    const service = new RelayService(store, {}, wakeSource);
    const server = createNodeRelayServer(
        createRelayFetchHandler(service, {
            allowedOrigins,
        }),
    );
    await listenNodeRelayServer(server, {
        host: process.env.HOST ?? "0.0.0.0",
        port: port(process.env.PORT),
    });
    const prune = (): void => {
        void service
            .pruneExpired()
            .catch((error: unknown) =>
                logger.error(`relay:prune-failed ${safeErrorSummary(error)}`),
            );
    };
    prune();
    const pruneTimer = setInterval(prune, PRUNE_INTERVAL_MILLISECONDS);
    pruneTimer.unref();
    const stop = (): void => {
        clearInterval(pruneTimer);
        void closeNodeRelayServer(server).then(() => service.close());
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
}

void main().catch((error: unknown) => {
    logger.error(`relay:start-failed ${safeErrorSummary(error)}`);
    process.exitCode = 1;
});
