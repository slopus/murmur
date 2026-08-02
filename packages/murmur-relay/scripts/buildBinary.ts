import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

interface BuildOnResolveArguments {
    readonly path: string;
}

interface BuildOnLoadArguments {
    readonly path: string;
}

interface BuildPluginBuilder {
    onResolve(
        options: { readonly filter: RegExp },
        resolveModule: (arguments_: BuildOnResolveArguments) => {
            readonly path: string;
            readonly namespace: string;
        },
    ): void;
    onLoad(
        options: { readonly filter: RegExp; readonly namespace: string },
        loadModule: (arguments_: BuildOnLoadArguments) => {
            readonly contents: string;
            readonly loader: "js";
        },
    ): void;
}

interface BuildPlugin {
    readonly name: string;
    setup(builder: BuildPluginBuilder): void;
}

interface StandaloneBuildResult {
    readonly success: boolean;
    readonly logs: readonly unknown[];
}

interface BunBuildApi {
    build(options: {
        readonly entrypoints: readonly string[];
        readonly target: "bun";
        readonly format: "esm";
        readonly packages: "bundle";
        readonly minify: boolean;
        readonly env: "disable";
        readonly sourcemap: "none";
        readonly plugins: readonly BuildPlugin[];
        readonly compile: {
            readonly outfile: string;
            readonly target?: string;
            readonly autoloadDotenv: false;
            readonly autoloadBunfig: false;
        };
        readonly throw: false;
    }): Promise<StandaloneBuildResult>;
}

declare const Bun: BunBuildApi;

const SQLITE_NAMESPACE = "murmur-bun-sqlite";
const SQLITE_MODULE = `
import { Database } from "bun:sqlite";

class StatementSync {
    #statement;

    constructor(statement) {
        this.#statement = statement;
    }

    setReadBigInts(enabled) {
        this.#statement.safeIntegers(enabled);
    }

    get(...values) {
        const result = this.#statement.get(...values);
        return result === null ? undefined : result;
    }

    all(...values) {
        return this.#statement.all(...values);
    }

    run(...values) {
        return this.#statement.run(...values);
    }
}

class DatabaseSync {
    #database;

    constructor(path) {
        this.#database = new Database(path, { create: true });
    }

    exec(sql) {
        this.#database.exec(sql);
    }

    prepare(sql) {
        return new StatementSync(this.#database.prepare(sql));
    }

    close() {
        this.#database.close();
    }
}

export { DatabaseSync, StatementSync };
`;

const sqlitePlugin: BuildPlugin = {
    name: "murmur-node-sqlite-for-bun",
    setup(builder): void {
        builder.onResolve({ filter: /^node:sqlite$/ }, () => ({
            path: "node:sqlite",
            namespace: SQLITE_NAMESPACE,
        }));
        builder.onLoad(
            {
                filter: /^node:sqlite$/,
                namespace: SQLITE_NAMESPACE,
            },
            () => ({
                contents: SQLITE_MODULE,
                loader: "js",
            }),
        );
    },
};

interface BuildArguments {
    readonly outfile: string;
    readonly target?: string;
}

function parseArguments(arguments_: readonly string[], packageDirectory: string): BuildArguments {
    let outfile = resolve(packageDirectory, "dist/murmur-relay");
    let target: string | undefined;
    for (let index = 0; index < arguments_.length; index += 1) {
        const argument = arguments_[index];
        if (argument !== "--outfile" && argument !== "--target") {
            throw new Error(`Unknown binary build argument: ${argument ?? ""}`);
        }
        const value = arguments_[index + 1];
        if (value === undefined || value.length === 0) {
            throw new Error(`Missing value after ${argument}`);
        }
        if (argument === "--outfile") {
            outfile = resolve(process.cwd(), value);
        } else {
            target = value;
        }
        index += 1;
    }
    return {
        outfile,
        ...(target === undefined ? {} : { target }),
    };
}

async function main(): Promise<void> {
    const packageDirectory = fileURLToPath(new URL("..", import.meta.url));
    const arguments_ = parseArguments(process.argv.slice(2), packageDirectory);
    await mkdir(dirname(arguments_.outfile), { recursive: true });
    const result = await Bun.build({
        entrypoints: [resolve(packageDirectory, "sources/main.ts")],
        target: "bun",
        format: "esm",
        packages: "bundle",
        minify: true,
        env: "disable",
        sourcemap: "none",
        plugins: [sqlitePlugin],
        compile: {
            outfile: arguments_.outfile,
            ...(arguments_.target === undefined ? {} : { target: arguments_.target }),
            autoloadDotenv: false,
            autoloadBunfig: false,
        },
        throw: false,
    });
    if (!result.success) {
        for (const log of result.logs) {
            console.error(String(log));
        }
        throw new Error("Bun could not compile the Murmur relay");
    }
    console.log(`Built standalone Murmur relay: ${arguments_.outfile}`);
}

void main().catch((error: unknown) => {
    const reason = error instanceof Error ? (error.stack ?? error.message) : String(error);
    console.error(reason);
    process.exitCode = 1;
});
