import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const packageDirectory =
    process.env.MURMUR_PACKAGE_DIRECTORY ?? fileURLToPath(new URL("..", import.meta.url));
const packageSpecifiers = [
    "@slopus/murmur",
    "@slopus/murmur/client",
    "@slopus/murmur/crypto",
    "@slopus/murmur/document",
    "@slopus/murmur/identity",
    "@slopus/murmur/mls",
    "@slopus/murmur/sharedSession",
    "@slopus/murmur/storage",
    "@slopus/murmur/transport",
    "@slopus/murmur/utils",
] as const;

describe("published package compatibility", () => {
    it("loads every built export in Node", async () => {
        const script = `
const specifiers = ${JSON.stringify(packageSpecifiers)};
for (const specifier of specifiers) {
    const loaded = await import(specifier);
    if (Object.keys(loaded).length === 0) {
        throw new Error(\`Package export \${specifier} is empty\`);
    }
}
`;
        await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], {
            cwd: packageDirectory,
        });
    });

    it("bundles every built export for browsers", async () => {
        const imports = packageSpecifiers
            .map(
                (specifier, index) =>
                    `import * as packageExport${index.toString()} from ${JSON.stringify(specifier)};`,
            )
            .join("\n");
        const references = packageSpecifiers
            .map((_specifier, index) => `packageExport${index.toString()}`)
            .join(", ");
        const result = await build({
            absWorkingDir: packageDirectory,
            bundle: true,
            format: "esm",
            logLevel: "silent",
            platform: "browser",
            stdin: {
                contents: `${imports}\nglobalThis.__MURMUR_PACKAGE_EXPORTS__ = [${references}];`,
                loader: "js",
                resolveDir: packageDirectory,
                sourcefile: "murmur-browser-smoke.js",
            },
            target: "es2022",
            write: false,
        });
        expect(result.outputFiles).toHaveLength(1);
        expect(result.outputFiles[0]?.text.length).toBeGreaterThan(1_000);
        expect(result.outputFiles[0]?.text).not.toContain('"node:');
    }, 30_000);
});
