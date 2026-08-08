import pino, { type DestinationStream, type Logger } from "pino";
import pretty, { type PrettyOptions } from "pino-pretty";

const MODULE_WIDTH = 12;
const MAXIMUM_ERROR_MESSAGE_CHARACTERS = 512;
const RESET_COLOR = "\u001b[0m";
const COLORS = [
    196, 202, 208, 214, 220, 226, 190, 154, 118, 82, 48, 50, 51, 45, 39, 33, 27, 21, 57, 93, 129,
    165, 201, 213, 177, 141, 105, 69,
] as const;
const colorCache = new Map<string, string>();

/** Options for one human-readable Pino logger. */
export interface HumanLoggerOptions {
    /** Override automatic TTY color detection. */
    readonly colorize?: boolean;
    /** Alternate output stream, primarily for tests and embedding. */
    readonly destination?: DestinationStream | NodeJS.WritableStream;
}

function murmurHash3(value: string, seed: number = 0): number {
    let hash = seed ^ value.length;
    for (let index = 0; index < value.length; index += 1) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash ^ (hash >>> 16), 0x85ebca6b);
        hash = Math.imul(hash ^ (hash >>> 13), 0xc2b2ae35);
        hash ^= hash >>> 16;
    }
    return hash >>> 0;
}

function moduleColor(module: string): string {
    const cached = colorCache.get(module);
    if (cached !== undefined) {
        return cached;
    }
    const paletteIndex = murmurHash3(module) % COLORS.length;
    const color = `\u001b[38;5;${COLORS[paletteIndex] ?? COLORS[0]}m`;
    colorCache.set(module, color);
    return color;
}

function timeText(value: unknown): string {
    const timestamp = typeof value === "number" ? value : Date.now();
    const date = new Date(timestamp);
    return [date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()]
        .map((part) => part.toString().padStart(2, "0"))
        .join(":");
}

function errorType(error: unknown): string {
    if (error instanceof EvalError) {
        return "EvalError";
    }
    if (error instanceof RangeError) {
        return "RangeError";
    }
    if (error instanceof ReferenceError) {
        return "ReferenceError";
    }
    if (error instanceof SyntaxError) {
        return "SyntaxError";
    }
    if (error instanceof TypeError) {
        return "TypeError";
    }
    if (error instanceof URIError) {
        return "URIError";
    }
    return error instanceof Error ? "Error" : "UnknownError";
}

function safeErrorCode(error: unknown): string | undefined {
    if (!(error instanceof Error) || !("code" in error)) return undefined;
    const code = (error as Error & { readonly code?: unknown }).code;
    return typeof code === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(code) ? code : undefined;
}

function safeErrorMessage(error: unknown): string | undefined {
    const raw = error instanceof Error ? error.message : typeof error === "string" ? error : "";
    if (raw.length === 0) return undefined;
    const printable = Array.from(raw, (character) => {
        const code = character.charCodeAt(0);
        return code <= 31 || code === 127 ? " " : character;
    }).join("");
    const sanitized = printable
        .replace(
            /\b([A-Za-z][A-Za-z0-9+.-]*):\/\/[^\s"'<>]+/gu,
            (_match, scheme: string) => `${scheme.toLowerCase()}://[redacted]`,
        )
        .replace(
            /\b(password|passwd|pwd|token|secret|authorization|credential|api[_-]?key|signature)\s*[:=]\s*([^\s,;&]+)/giu,
            "$1=[redacted]",
        )
        .replace(/\bbearer\s+[A-Za-z0-9._~+/-]+=*/giu, "Bearer [redacted]")
        .replace(/\s+/gu, " ")
        .trim();
    if (sanitized.length === 0) return undefined;
    return sanitized.length <= MAXIMUM_ERROR_MESSAGE_CHARACTERS
        ? sanitized
        : `${sanitized.slice(0, MAXIMUM_ERROR_MESSAGE_CHARACTERS - 1)}…`;
}

/** Describe an error without exposing URLs, credentials, stacks, or driver metadata. */
export function safeErrorSummary(error: unknown): string {
    const code = safeErrorCode(error);
    const message = safeErrorMessage(error);
    return [
        `type=${errorType(error)}`,
        ...(code === undefined ? [] : [`code=${code}`]),
        ...(message === undefined ? [] : [`message=${JSON.stringify(message)}`]),
    ].join(" ");
}

/** Create a Pino logger rendered as `HH:mm:ss MODULE  message`. */
export function createHumanLogger(module: string, options: HumanLoggerOptions = {}): Logger {
    const normalizedModule = module.trim();
    if (normalizedModule.length === 0) {
        throw new Error("Logger module cannot be empty");
    }
    const paddedModule = normalizedModule.slice(0, MODULE_WIDTH).padEnd(MODULE_WIDTH);
    const colorize = options.colorize ?? Boolean(process.stdout.isTTY);
    const displayedModule = colorize
        ? `${moduleColor(normalizedModule)}${paddedModule}${RESET_COLOR}`
        : paddedModule;
    const prettyOptions: PrettyOptions = {
        colorize: false,
        hideObject: true,
        ignore: "pid,hostname,level,time",
        messageFormat: (log, messageKey) =>
            `${timeText(log["time"])} ${displayedModule}  ${String(log[messageKey] ?? "")}\n`,
        singleLine: true,
        sync: true,
        translateTime: false,
        ...(options.destination === undefined ? {} : { destination: options.destination }),
    };
    return pino({ base: null }, pretty(prettyOptions));
}
