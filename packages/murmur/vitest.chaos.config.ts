import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["sources/**/tests/**/*.chaos.ts", "sources/**/tests/**/*.chaos.test.ts"],
        setupFiles: ["sources/chaos/impl/chaosReporterProxy.ts"],
    },
});
