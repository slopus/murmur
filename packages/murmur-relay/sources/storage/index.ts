export { SqliteRelayStore } from "./sqlite/index.js";
export type { SqliteRelayStoreOptions } from "./sqlite/index.js";
export {
    PgPoolDatabase,
    PGliteDatabase,
    PostgresRelayStore,
    POSTGRES_WAKE_CHANNEL,
} from "./postgres/index.js";
export type {
    PGliteDatabaseLike,
    PGliteQueryLike,
    PostgresDatabase,
    PostgresParameter,
    PostgresQuery,
    PostgresSession,
} from "./postgres/index.js";
export type {
    AcknowledgeOutcome,
    PageReadConstraints,
    PublishOutcome,
    RelayStorePublishOutcome,
    QueuedDelivery,
    QueueLimits,
    QueuePage,
    RelayStore,
} from "./types.js";
export type { RelaySessionState } from "./sessionState.js";
export { RELAY_EXPIRATION_BATCH_ITEMS } from "./types.js";
export {
    LOSS_GENERATION_BYTES,
    advanceLossGeneration,
    createGenerationSeed,
    initialLossGeneration,
} from "./continuity.js";

/** Storage backend names accepted by the standalone relay. */
export type RelayStoreBackend = "sqlite" | "postgres";

/** Strictly parse the standalone relay store backend. */
export function parseRelayStoreBackend(value: string | undefined): RelayStoreBackend {
    const backend = value ?? "sqlite";
    if (backend !== "sqlite" && backend !== "postgres") {
        throw new Error("MURMUR_RELAY_STORE must be exactly sqlite or postgres");
    }
    return backend;
}
