import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Pool } from "pg";
import { createRelayFetchHandler } from "./http/index.js";
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
    PostgresRelayStore,
    SqliteRelayStore,
    type RelayStore,
} from "./storage/index.js";

const PRUNE_INTERVAL_MILLISECONDS = 60 * 60 * 1_000;

function portFromEnvironment(value: string | undefined): number {
    const port = value === undefined ? 8787 : Number(value);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
        throw new Error("PORT must be an integer from 1 through 65535");
    }
    return port;
}

function originsFromEnvironment(value: string | undefined): "*" | readonly string[] {
    if (value === undefined || value === "*") {
        return "*";
    }
    const origins = value
        .split(",")
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0);
    if (origins.length === 0) {
        throw new Error("MURMUR_RELAY_ORIGINS cannot be empty");
    }
    return origins;
}

async function createStore(): Promise<{
    readonly store: RelayStore;
    readonly wakeSource: WakeSource;
}> {
    const kind = process.env.MURMUR_RELAY_STORE ?? "sqlite";
    if (kind === "sqlite") {
        const path = process.env.MURMUR_RELAY_DB ?? "./data/murmur-relay.sqlite";
        if (path !== ":memory:") {
            await mkdir(dirname(resolve(path)), { recursive: true });
        }
        return {
            store: new SqliteRelayStore(path),
            wakeSource: new InProcessWakeSource(),
        };
    }
    if (kind === "postgres") {
        const connectionString = process.env.MURMUR_RELAY_DB;
        if (connectionString === undefined || connectionString.length === 0) {
            throw new Error("MURMUR_RELAY_DB is required for Postgres");
        }
        const pool = new Pool({ connectionString });
        const database = new PgPoolDatabase(pool);
        try {
            return {
                store: await PostgresRelayStore.create(database),
                wakeSource: new PostgresWakeSource({ connectionString }),
            };
        } catch (error) {
            await database.close();
            throw error;
        }
    }
    throw new Error("MURMUR_RELAY_STORE must be sqlite or postgres");
}

/** Start the configured standalone relay and shut it down on process signals. */
export async function main(): Promise<void> {
    const origins = originsFromEnvironment(process.env.MURMUR_RELAY_ORIGINS);
    const serverOptions = {
        host: process.env.HOST ?? "0.0.0.0",
        port: portFromEnvironment(process.env.PORT),
    };
    const { store, wakeSource } = await createStore();
    const service = new RelayService(store, {}, wakeSource);
    const handler = createRelayFetchHandler(service, { origins });
    const server = createNodeRelayServer(handler);
    try {
        await listenNodeRelayServer(server, serverOptions);
    } catch (error) {
        await service.close();
        throw error;
    }

    const prune = (): void => {
        void service.prune().catch(() => {
            console.error("Murmur relay retention sweep failed");
        });
    };
    prune();
    const pruneTimer = setInterval(prune, PRUNE_INTERVAL_MILLISECONDS);
    pruneTimer.unref();

    let stopping = false;
    const stop = (): void => {
        if (stopping) {
            return;
        }
        stopping = true;
        clearInterval(pruneTimer);
        void closeNodeRelayServer(server)
            .then(() => service.close())
            .then(
                () => {
                    process.exitCode = 0;
                },
                () => {
                    process.exitCode = 1;
                },
            );
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
}

void main().catch(() => {
    console.error("Murmur relay failed to start");
    process.exitCode = 1;
});
