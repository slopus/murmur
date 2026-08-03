import { describe, expect, it } from "vitest";
import { relayUrls, repeatedOption } from "../bootstrap.js";

describe("CLI bootstrap configuration", () => {
    it("uses the public Murmur relay by default", () => {
        expect(relayUrls([], undefined)).toEqual(["https://murmur.cluster-fluster.com"]);
    });

    it("prefers repeatable arguments over environment relays", () => {
        expect(
            relayUrls(
                ["sync", "--relay=https://one.test", "--relay", "https://two.test"],
                "https://environment.test",
            ),
        ).toEqual(["https://one.test", "https://two.test"]);
    });

    it("normalizes a comma-separated environment value", () => {
        expect(relayUrls([], " https://one.test, ,https://two.test ")).toEqual([
            "https://one.test",
            "https://two.test",
        ]);
    });

    it("rejects a missing option value", () => {
        expect(() => repeatedOption(["sync", "--relay"], "relay")).toThrow("Missing --relay value");
    });
});
