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

/** Start the standalone identity-queue relay. */
export async function main(): Promise<void> {
    const allowedOrigins = parseRelayAllowedOrigins(process.env.MURMUR_RELAY_ORIGINS);
    const { store, wakeSource } = await createStore();
    const maximumAdmissionReferences = optionalPositiveInteger(
        process.env.MURMUR_RELAY_ADMISSION_REFERENCES,
        "MURMUR_RELAY_ADMISSION_REFERENCES",
    );
    const maximumInvitationBytes = optionalPositiveInteger(
        process.env.MURMUR_RELAY_INVITATION_BYTES,
        "MURMUR_RELAY_INVITATION_BYTES",
    );
    const maximumInvitationItemsPerAdmissionPrincipal = optionalPositiveInteger(
        process.env.MURMUR_RELAY_INVITATION_ITEMS_PER_PRINCIPAL,
        "MURMUR_RELAY_INVITATION_ITEMS_PER_PRINCIPAL",
    );
    const maximumInvitationBytesPerAdmissionPrincipal = optionalPositiveInteger(
        process.env.MURMUR_RELAY_INVITATION_BYTES_PER_PRINCIPAL,
        "MURMUR_RELAY_INVITATION_BYTES_PER_PRINCIPAL",
    );
    const maximumGlobalInvitationItems = optionalPositiveInteger(
        process.env.MURMUR_RELAY_GLOBAL_INVITATION_ITEMS,
        "MURMUR_RELAY_GLOBAL_INVITATION_ITEMS",
    );
    const maximumGlobalInvitationBytes = optionalPositiveInteger(
        process.env.MURMUR_RELAY_GLOBAL_INVITATION_BYTES,
        "MURMUR_RELAY_GLOBAL_INVITATION_BYTES",
    );
    const service = new RelayService(
        store,
        {
            ...(maximumAdmissionReferences === undefined ? {} : { maximumAdmissionReferences }),
            ...(maximumInvitationBytes === undefined ? {} : { maximumInvitationBytes }),
            ...(maximumInvitationItemsPerAdmissionPrincipal === undefined
                ? {}
                : { maximumInvitationItemsPerAdmissionPrincipal }),
            ...(maximumInvitationBytesPerAdmissionPrincipal === undefined
                ? {}
                : { maximumInvitationBytesPerAdmissionPrincipal }),
            ...(maximumGlobalInvitationItems === undefined ? {} : { maximumGlobalInvitationItems }),
            ...(maximumGlobalInvitationBytes === undefined ? {} : { maximumGlobalInvitationBytes }),
        },
        wakeSource,
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
    const server = createNodeRelayServer(
        createRelayFetchHandler(service, {
            allowedOrigins,
            ...(maximumRequestsPerMinutePerAddress === undefined
                ? {}
                : { maximumRequestsPerMinutePerAddress }),
            ...(maximumTrackedAddresses === undefined ? {} : { maximumTrackedAddresses }),
            ...(remoteAddressHeader === undefined ? {} : { remoteAddressHeader }),
        }),
    );
    await listenNodeRelayServer(server, {
        host: process.env.HOST ?? "0.0.0.0",
        port: port(process.env.PORT),
    });
    let pruneInFlight = false;
    const prune = (): void => {
        if (pruneInFlight) return;
        pruneInFlight = true;
        void (async () => {
            const deadline = Date.now() + PRUNE_DRAIN_BUDGET_MILLISECONDS;
            let removed: number;
            do {
                removed = await service.pruneExpired();
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
    let stopPromise: Promise<void> | undefined;
    const stop = (): void => {
        stopPromise ??= (async () => {
            clearInterval(pruneTimer);
            await closeNodeRelayServer(server);
            await service.close();
        })().catch((error: unknown) => {
            logger.error(`relay:stop-failed ${safeErrorSummary(error)}`);
            process.exitCode = 1;
        });
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
}

void main().catch((error: unknown) => {
    logger.error(`relay:start-failed ${safeErrorSummary(error)}`);
    process.exitCode = 1;
});
