import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["tests/**/*.test.ts", "sources/**/tests/**/*.test.ts"],
        exclude: ["sources/**/tests/**/*.chaos.test.ts"],
        setupFiles: ["tests/vitestReporterProxy.ts"],
    },
});
