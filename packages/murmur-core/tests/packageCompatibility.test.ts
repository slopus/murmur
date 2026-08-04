import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const packageDirectory =
    process.env.MURMUR_PACKAGE_DIRECTORY ?? fileURLToPath(new URL("..", import.meta.url));

describe("published package compatibility", () => {
    it("loads only the root facade export in Node", async () => {
        const script = `
const loaded = await import("@slopus/murmur");
const names = Object.keys(loaded).sort();
if (JSON.stringify(names) !== JSON.stringify(["MemoryMurmurStore", "Murmur"])) {
    throw new Error(\`Unexpected runtime exports: \${names.join(", ")}\`);
}
`;
        await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], {
            cwd: packageDirectory,
        });
    });

    it("bundles the root facade for browsers without Node imports", async () => {
        const result = await build({
            absWorkingDir: packageDirectory,
            bundle: true,
            format: "esm",
            logLevel: "silent",
            platform: "browser",
            stdin: {
                contents:
                    'import { MemoryMurmurStore, Murmur } from "@slopus/murmur";\n' +
                    "globalThis.__MURMUR_PACKAGE_EXPORTS__ = [MemoryMurmurStore, Murmur];",
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
