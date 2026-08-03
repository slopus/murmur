import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createHumanLogger, safeErrorSummary } from "../logger.js";

describe("human-readable logger", () => {
    it("prints only UTC time, fixed-width module, and self-contained message", async () => {
        const chunks: string[] = [];
        const destination = new Writable({
            write(chunk: Uint8Array, _encoding, callback): void {
                chunks.push(Buffer.from(chunk).toString("utf8"));
                callback();
            },
        });
        const logger = createHumanLogger("RELAY", {
            colorize: false,
            destination,
        });

        logger.info("relay:listen host=0.0.0.0 port=8787");
        await new Promise<void>((resolve) => setImmediate(resolve));

        expect(chunks.join("")).toMatch(
            /^\d{2}:\d{2}:\d{2} RELAY {7}  relay:listen host=0\.0\.0\.0 port=8787\n$/,
        );
    });

    it("colors only the fixed-width module when explicitly enabled", async () => {
        const chunks: string[] = [];
        const destination = new Writable({
            write(chunk: Uint8Array, _encoding, callback): void {
                chunks.push(Buffer.from(chunk).toString("utf8"));
                callback();
            },
        });
        const logger = createHumanLogger("RELAY", {
            colorize: true,
            destination,
        });

        logger.warn("retention:failed error=unavailable");
        await new Promise<void>((resolve) => setImmediate(resolve));

        const ansiEscape = "\u001b";
        expect(chunks.join("")).toMatch(
            new RegExp(
                `^\\d{2}:\\d{2}:\\d{2} ${ansiEscape}\\[38;5;\\d+mRELAY {7}` +
                    `${ansiEscape}\\[0m  retention:failed error=unavailable\\n$`,
            ),
        );
    });

    it("summarizes errors without exposing messages or driver metadata", () => {
        const credentialUrl = "https://user:secret@example.test/path?signature=private";
        const driverError = Object.assign(new TypeError(credentialUrl), {
            code: "ECONNREFUSED",
        });

        expect(safeErrorSummary(driverError)).toBe("type=TypeError");
        expect(safeErrorSummary(new Error(credentialUrl))).toBe("type=Error");
        expect(safeErrorSummary(credentialUrl)).toBe("type=UnknownError");
    });
});
