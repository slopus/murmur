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
    RELAY_EXPIRATION_BATCH_ITEMS,
    SqliteRelayStore,
    type RelayStoreBackend,
    type RelayStore,
} from "./storage/index.js";
import { createHumanLogger, safeErrorSummary } from "./utils/logger.js";

const PRUNE_INTERVAL_MILLISECONDS = 10_000;
const PRUNE_DRAIN_BUDGET_MILLISECONDS = 1_000;
const logger = createHumanLogger("RELAY");

function port(value: string | undefined): number {
    const parsed = value === undefined ? 8787 : Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
        throw new Error("PORT must be an integer from 1 through 65535");
    }
    return parsed;
}

function optionalPositiveInteger(value: string | undefined, name: string): number | undefined {
    if (value === undefined) return undefined;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return parsed;
}

async function createStore(
    backend: RelayStoreBackend,
): Promise<{ store: RelayStore; wakeSource: WakeSource }> {
    if (backend === "sqlite") {
        const path = process.env.MURMUR_RELAY_DB ?? "./data/murmur-relay.sqlite";
        if (path !== ":memory:") await mkdir(dirname(resolve(path)), { recursive: true });
        return { store: new SqliteRelayStore(path), wakeSource: new InProcessWakeSource() };
    }
    const connectionString = process.env.MURMUR_RELAY_DB;
    if (connectionString === undefined) throw new Error("MURMUR_RELAY_DB is required");
    const database = new PgPoolDatabase(new Pool({ connectionString }));
    try {
        return {
            store: await PostgresRelayStore.create(database),
            wakeSource: new PostgresWakeSource({ connectionString }),
        };
    } catch (error) {
        await database.close().catch(() => undefined);
        throw error;
    }
}

/** Start the standalone identity-queue relay. */
export async function main(): Promise<void> {
    let stage = "configuration";
    let store: RelayStore | undefined;
    let wakeSource: WakeSource | undefined;
    let service: RelayService | undefined;
    let server: ReturnType<typeof createNodeRelayServer> | undefined;
    try {
        const backend = parseRelayStoreBackend(process.env.MURMUR_RELAY_STORE);
        const host = process.env.HOST ?? "0.0.0.0";
        const listenerPort = port(process.env.PORT);
        const allowedOrigins = parseRelayAllowedOrigins(process.env.MURMUR_RELAY_ORIGINS);
        const maximumAdmissionReferences = optionalPositiveInteger(
            process.env.MURMUR_RELAY_ADMISSION_REFERENCES,
            "MURMUR_RELAY_ADMISSION_REFERENCES",
        );
        const maximumRequestsPerMinutePerAddress = optionalPositiveInteger(
            process.env.MURMUR_RELAY_REQUESTS_PER_MINUTE,
            "MURMUR_RELAY_REQUESTS_PER_MINUTE",
        );
        const maximumTrackedAddresses = optionalPositiveInteger(
            process.env.MURMUR_RELAY_TRACKED_ADDRESSES,
            "MURMUR_RELAY_TRACKED_ADDRESSES",
        );
        const remoteAddressHeader = process.env.MURMUR_RELAY_REMOTE_ADDRESS_HEADER;
        logger.info(
            `relay:start backend=${backend} host=${host} port=${listenerPort} ` +
                `origins=${allowedOrigins === "*" ? "wildcard" : allowedOrigins.length} ` +
                `admission=${remoteAddressHeader === undefined ? "socket" : "header"}`,
        );

        stage = "store-open";
        logger.info(`relay:store-open-start backend=${backend}`);
        ({ store, wakeSource } = await createStore(backend));
        logger.info(`relay:store-open-complete backend=${backend}`);
        const declareRestored = process.env.MURMUR_RELAY_DECLARE_RESTORED;
        if (declareRestored !== undefined && declareRestored !== "1") {
            throw new Error("MURMUR_RELAY_DECLARE_RESTORED must be exactly 1 when set");
        }
        if (declareRestored === "1") {
            const invalidated = await store.declareRestored();
            logger.info(`relay:state-restored invalidated_inboxes=${invalidated}`);
        }

        stage = "service-create";
        logger.info(`relay:service-create-start backend=${backend}`);
        const activeService = new RelayService(
            store,
            maximumAdmissionReferences === undefined ? {} : { maximumAdmissionReferences },
            wakeSource,
        );
        service = activeService;
        logger.info(`relay:service-create-complete backend=${backend}`);

        stage = "connectivity-check";
        logger.info(`relay:connectivity-check-start backend=${backend}`);
        await activeService.health();
        logger.info(`relay:connectivity-check-complete backend=${backend}`);

        stage = "http-create";
        const relayHandler = createRelayFetchHandler(activeService, {
            allowedOrigins,
            ...(maximumRequestsPerMinutePerAddress === undefined
                ? {}
                : { maximumRequestsPerMinutePerAddress }),
            ...(maximumTrackedAddresses === undefined ? {} : { maximumTrackedAddresses }),
            ...(remoteAddressHeader === undefined ? {} : { remoteAddressHeader }),
        });
        const activeServer = createNodeRelayServer(relayHandler);
        server = activeServer;
        stage = "http-listen";
        logger.info(`relay:http-listen-start host=${host} port=${listenerPort}`);
        await listenNodeRelayServer(activeServer, {
            host,
            port: listenerPort,
        });
        logger.info(`relay:ready backend=${backend} host=${host} port=${listenerPort}`);

        let pruneInFlight = false;
        const prune = (): void => {
            if (pruneInFlight) return;
            pruneInFlight = true;
            void (async () => {
                const deadline = Date.now() + PRUNE_DRAIN_BUDGET_MILLISECONDS;
                let removed: number;
                do {
                    removed = await activeService.pruneExpired();
                } while (removed >= RELAY_EXPIRATION_BATCH_ITEMS && Date.now() < deadline);
            })()
                .catch((error: unknown) =>
                    logger.error(`relay:prune-failed ${safeErrorSummary(error)}`),
                )
                .finally(() => {
                    pruneInFlight = false;
                });
        };
        prune();
        const pruneTimer = setInterval(prune, PRUNE_INTERVAL_MILLISECONDS);
        pruneTimer.unref();
        logger.info(
            `relay:maintenance-ready intervalMilliseconds=${PRUNE_INTERVAL_MILLISECONDS} ` +
                `budgetMilliseconds=${PRUNE_DRAIN_BUDGET_MILLISECONDS}`,
        );
        let stopPromise: Promise<void> | undefined;
        const stop = (signal: NodeJS.Signals): void => {
            logger.info(`relay:shutdown-request signal=${signal}`);
            stopPromise ??= (async () => {
                logger.info(`relay:shutdown-start signal=${signal}`);
                clearInterval(pruneTimer);
                let shutdownError: unknown;
                logger.info("relay:http-close-start");
                try {
                    await closeNodeRelayServer(activeServer);
                    logger.info("relay:http-close-complete");
                } catch (error) {
                    shutdownError = error;
                    logger.error(`relay:http-close-failed ${safeErrorSummary(error)}`);
                }
                logger.info("relay:service-close-start");
                try {
                    await activeService.close();
                    logger.info("relay:service-close-complete");
                } catch (error) {
                    shutdownError ??= error;
                    logger.error(`relay:service-close-failed ${safeErrorSummary(error)}`);
                }
                if (shutdownError !== undefined) throw shutdownError;
                logger.info(`relay:shutdown-complete signal=${signal}`);
            })().catch((error: unknown) => {
                logger.error(`relay:shutdown-failed signal=${signal} ${safeErrorSummary(error)}`);
                process.exitCode = 1;
            });
        };
        process.once("SIGINT", () => stop("SIGINT"));
        process.once("SIGTERM", () => stop("SIGTERM"));
    } catch (error) {
        logger.error(`relay:start-failed stage=${stage} ${safeErrorSummary(error)}`);
        logger.info(`relay:start-cleanup-start stage=${stage}`);
        if (server !== undefined) {
            await closeNodeRelayServer(server).catch((cleanupError: unknown) => {
                logger.error(`relay:start-cleanup-http-failed ${safeErrorSummary(cleanupError)}`);
            });
        }
        if (service !== undefined) {
            await service.close().catch((cleanupError: unknown) => {
                logger.error(
                    `relay:start-cleanup-service-failed ${safeErrorSummary(cleanupError)}`,
                );
            });
        } else {
            await wakeSource?.close().catch((cleanupError: unknown) => {
                logger.error(`relay:start-cleanup-wake-failed ${safeErrorSummary(cleanupError)}`);
            });
            await store?.close().catch((cleanupError: unknown) => {
                logger.error(`relay:start-cleanup-store-failed ${safeErrorSummary(cleanupError)}`);
            });
        }
        logger.info(`relay:start-cleanup-complete stage=${stage}`);
        throw error;
    }
}

void main().catch(() => {
    process.exitCode = 1;
});
