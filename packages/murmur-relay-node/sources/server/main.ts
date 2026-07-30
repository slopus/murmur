#!/usr/bin/env node

import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createRelayFetchHandler, RelayService } from "@murmur/relay";
import { createNodeRelayServer } from "./index.js";
import { SqliteRelayStore } from "../storage/index.js";

function positivePort(value: string | undefined): number {
    const port = value === undefined ? 8787 : Number(value);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
        throw new Error("PORT must be an integer from 1 to 65535");
    }
    return port;
}

function allowedOrigins(value: string | undefined): readonly string[] {
    if (value === undefined) {
        return ["*"];
    }
    const origins = value
        .split(",")
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0);
    if (origins.length === 0) {
        throw new Error("MURMUR_RELAY_ORIGINS must contain at least one origin");
    }
    return origins;
}

const PRUNE_INTERVAL_MILLISECONDS = 60 * 60 * 1_000;
const databasePath = resolve(process.env.MURMUR_RELAY_DB ?? "./data/murmur-relay.sqlite");
mkdirSync(dirname(databasePath), { recursive: true });
const store = new SqliteRelayStore(databasePath);
const relay = new RelayService(store);
const server = createNodeRelayServer(createRelayFetchHandler(relay), {
    allowedOrigins: allowedOrigins(process.env.MURMUR_RELAY_ORIGINS),
});
const port = positivePort(process.env.PORT);
const host = process.env.HOST ?? "0.0.0.0";
let pruning = false;

const prune = async (): Promise<void> => {
    if (pruning) {
        return;
    }
    pruning = true;
    try {
        await relay.pruneInactiveTopics();
    } catch {
        process.stderr.write("Murmur relay topic pruning failed\n");
    } finally {
        pruning = false;
    }
};
const pruneTimer = setInterval(() => void prune(), PRUNE_INTERVAL_MILLISECONDS);
pruneTimer.unref();
void prune();

server.listen(port, host, () => {
    process.stdout.write(`Murmur relay listening on http://${host}:${port}\n`);
});

let shuttingDown = false;
const shutdown = (): void => {
    if (shuttingDown) {
        return;
    }
    shuttingDown = true;
    clearInterval(pruneTimer);
    server.close(() => {
        store.close();
        process.exitCode = 0;
    });
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
