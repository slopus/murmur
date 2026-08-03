import { randomBytes } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { Pool } from "pg";
import { LocalBlobBackend, S3BlobBackend, type BlobBackend } from "./blobs/index.js";
import { createRelayFetchHandler } from "./http/index.js";
import type { TrustedProxyPolicy } from "./http/impl/clientIp.js";
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
import { createHumanLogger, safeErrorSummary } from "./utils/logger.js";

const PRUNE_INTERVAL_MILLISECONDS = 60 * 60 * 1_000;
const STOP_GRACE_MILLISECONDS = 10_000;
const logger = createHumanLogger("RELAY");

function oneLine(value: string): string {
    return value.replace(/\s+/g, " ").trim();
}

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

function requiredEnvironment(name: string): string {
    const value = process.env[name];
    if (value === undefined || value.length === 0) {
        throw new Error(`${name} is required for the S3 blob backend`);
    }
    return value;
}

function pathStyleFromEnvironment(value: string | undefined): boolean {
    if (value === undefined || value === "false") {
        return false;
    }
    if (value === "true") {
        return true;
    }
    throw new Error("MURMUR_RELAY_S3_PATH_STYLE must be true or false");
}

function trustedProxiesFromEnvironment(value: string | undefined): TrustedProxyPolicy | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (/^[1-9][0-9]*$/.test(value)) {
        const hops = Number(value);
        if (Number.isSafeInteger(hops)) {
            return hops;
        }
    }
    const addresses = value
        .split(",")
        .map((address) => address.trim())
        .filter((address) => address.length > 0);
    if (addresses.length === 0 || addresses.some((address) => isIP(address) === 0)) {
        throw new Error(
            "MURMUR_RELAY_TRUSTED_PROXIES must be a positive hop count or IP address list",
        );
    }
    return addresses;
}

function createBlobBackend(): BlobBackend {
    const kind = process.env.MURMUR_RELAY_BLOB_BACKEND ?? "local";
    if (kind === "local") {
        const configuredSecret = process.env.MURMUR_RELAY_BLOB_SECRET;
        let secret: Uint8Array;
        if (configuredSecret === undefined) {
            secret = randomBytes(32);
            logger.warn(
                "blob:secret-missing MURMUR_RELAY_BLOB_SECRET is unset; links will not survive restart or work across instances",
            );
        } else {
            secret = new TextEncoder().encode(configuredSecret);
        }
        try {
            return new LocalBlobBackend({
                rootDirectory: resolve(process.env.MURMUR_RELAY_BLOB_DIR ?? "./data/blobs"),
                secret,
            });
        } finally {
            secret.fill(0);
        }
    }
    if (kind === "s3") {
        return new S3BlobBackend({
            endpoint: requiredEnvironment("MURMUR_RELAY_S3_ENDPOINT"),
            region: requiredEnvironment("MURMUR_RELAY_S3_REGION"),
            bucket: requiredEnvironment("MURMUR_RELAY_S3_BUCKET"),
            accessKeyId: requiredEnvironment("MURMUR_RELAY_S3_ACCESS_KEY_ID"),
            secretAccessKey: requiredEnvironment("MURMUR_RELAY_S3_SECRET_ACCESS_KEY"),
            pathStyle: pathStyleFromEnvironment(process.env.MURMUR_RELAY_S3_PATH_STYLE),
        });
    }
    throw new Error("MURMUR_RELAY_BLOB_BACKEND must be local or s3");
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
    const trustedProxies = trustedProxiesFromEnvironment(process.env.MURMUR_RELAY_TRUSTED_PROXIES);
    const serverOptions = {
        host: process.env.HOST ?? "0.0.0.0",
        port: portFromEnvironment(process.env.PORT),
    };
    const blobBackend = createBlobBackend();
    let relayDependencies: Awaited<ReturnType<typeof createStore>>;
    try {
        relayDependencies = await createStore();
    } catch (error) {
        await blobBackend.close();
        throw error;
    }
    const { store, wakeSource } = relayDependencies;
    const service = new RelayService(store, {}, wakeSource);
    const handler = createRelayFetchHandler(service, {
        origins,
        blobBackend,
        logger,
        ...(trustedProxies === undefined ? {} : { trustedProxies }),
    });
    const server = createNodeRelayServer(handler);
    try {
        await listenNodeRelayServer(server, serverOptions);
    } catch (error) {
        await Promise.allSettled([blobBackend.close(), service.close()]);
        throw error;
    }
    logger.info(
        `relay:listen host=${oneLine(serverOptions.host)} port=${serverOptions.port.toString()} ` +
            `store=${oneLine(process.env.MURMUR_RELAY_STORE ?? "sqlite")} ` +
            `blobs=${oneLine(process.env.MURMUR_RELAY_BLOB_BACKEND ?? "local")}`,
    );

    const prune = (): void => {
        void service.prune().then(
            (outcome) => {
                logger.info(
                    `retention:complete events=${outcome.events.toString()} topics=${outcome.topics.toString()}`,
                );
            },
            (error: unknown) => {
                logger.error(`retention:failed ${safeErrorSummary(error)}`);
            },
        );
    };
    prune();
    const pruneTimer = setInterval(prune, PRUNE_INTERVAL_MILLISECONDS);
    pruneTimer.unref();

    let stopping = false;
    const stop = (signal: "SIGINT" | "SIGTERM"): void => {
        if (stopping) {
            return;
        }
        stopping = true;
        logger.info(`relay:stop signal=${signal}`);
        clearInterval(pruneTimer);
        // Stop accepting first, then end every open SSE body. Draining before
        // closing the streams would hang: an ephemeral stream only ends when its
        // subscription closes, and that used to happen after the drain.
        const drained = closeNodeRelayServer(server, {
            graceMilliseconds: STOP_GRACE_MILLISECONDS,
        });
        service.closeStreams();
        void drained
            .then(() => Promise.all([blobBackend.close(), service.close()]))
            .then(
                () => {
                    logger.info(`relay:stopped signal=${signal}`);
                    process.exitCode = 0;
                },
                (error: unknown) => {
                    logger.error(`relay:stop-failed signal=${signal} ${safeErrorSummary(error)}`);
                    process.exitCode = 1;
                },
            );
    };
    process.once("SIGINT", () => stop("SIGINT"));
    process.once("SIGTERM", () => stop("SIGTERM"));
}

void main().catch((error: unknown) => {
    logger.error(`relay:start-failed ${safeErrorSummary(error)}`);
    process.exitCode = 1;
});
