import { describe, expect, it } from "vitest";
import * as relay from "../index.js";

describe("@murmur/relay public API", () => {
    it("exports only the supported runtime entry points", () => {
        expect(Object.keys(relay).sort()).toEqual([
            "InProcessWakeSource",
            "PgPoolDatabase",
            "PostgresRelayStore",
            "PostgresWakeSource",
            "RelayConflictError",
            "RelayError",
            "RelayService",
            "SqliteRelayStore",
            "closeNodeRelayServer",
            "createNodeRelayServer",
            "createRelayFetchHandler",
            "listenNodeRelayServer",
        ]);
    });
});
