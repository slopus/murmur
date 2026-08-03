#!/usr/bin/env node

import { lstat, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { HttpRelayTransport } from "@slopus/murmur";
import { relayUrls, repeatedOption } from "./cli/bootstrap.js";
import { runCli } from "./cli/index.js";
import { MurmurCliRuntime } from "./runtime/index.js";
import { SqliteMurmurStore } from "./storage/index.js";

function databasePath(arguments_: readonly string[]): string {
    const configured = repeatedOption(arguments_, "db");
    if (configured.length > 1) {
        throw new Error("--db may be provided only once");
    }
    if (configured[0] !== undefined) {
        return resolve(configured[0]);
    }
    const directory = resolve(process.env.MURMUR_HOME ?? join(homedir(), ".murmur"));
    return join(directory, "murmur.sqlite");
}

async function main(): Promise<void> {
    const arguments_ = process.argv.slice(2);
    const path = databasePath(arguments_);
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const statistics = await lstat(directory);
    if (!statistics.isDirectory() || statistics.isSymbolicLink()) {
        throw new Error("Murmur data path must be a private directory");
    }
    if ((statistics.mode & 0o077) !== 0) {
        throw new Error("Murmur data directory must already have mode 0700");
    }
    const store = new SqliteMurmurStore(path);
    let runtime: MurmurCliRuntime | undefined;
    try {
        runtime = await MurmurCliRuntime.open({
            store,
            transports: relayUrls(arguments_, process.env.MURMUR_RELAYS).map(
                (url, index) => new HttpRelayTransport(`relay-${index + 1}`, url),
            ),
        });
        await runCli(runtime, arguments_);
    } finally {
        runtime?.destroy();
        await store.close();
    }
}

void main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${JSON.stringify({ error: message })}\n`);
    process.exitCode = 1;
});
