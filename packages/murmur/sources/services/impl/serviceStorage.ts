import type { MurmurStore } from "../../storage/index.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
    type JsonValue,
} from "../../utils/index.js";
import type {
    MurmurServiceJsonValue,
    MurmurServiceStorage,
    MurmurServiceStorageScanOptions,
} from "../types.js";

const SERVICE_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const RELATIVE_KEY_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAXIMUM_SERVICE_ID_CHARACTERS = 64;
const MAXIMUM_RELATIVE_KEY_CHARACTERS = 512;
const MAXIMUM_SERVICE_VALUE_BYTES = 1024 * 1024;
const MAXIMUM_SERVICE_JSON_DEPTH = 32;
const MAXIMUM_SERVICE_JSON_NODES = 10_000;
const MAXIMUM_SERVICE_SCAN_ITEMS = 256;

interface JsonBudget {
    nodes: number;
}

function invalidValue(): never {
    throw new Error("Invalid Murmur service JSON value");
}

function cloneJson(value: unknown, depth: number, budget: JsonBudget): MurmurServiceJsonValue {
    budget.nodes += 1;
    if (depth > MAXIMUM_SERVICE_JSON_DEPTH || budget.nodes > MAXIMUM_SERVICE_JSON_NODES) {
        return invalidValue();
    }
    if (value === null || typeof value === "boolean" || typeof value === "string") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) return invalidValue();
        return value;
    }
    if (Array.isArray(value)) {
        return Object.freeze(value.map((entry) => cloneJson(entry, depth + 1, budget)));
    }
    if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
        return invalidValue();
    }

    const cloned: Record<string, JsonValue> = {};
    for (const [key, entry] of Object.entries(value)) {
        Object.defineProperty(cloned, key, {
            configurable: false,
            enumerable: true,
            value: cloneJson(entry, depth + 1, budget),
            writable: false,
        });
    }
    return Object.freeze(cloned);
}

function copyJson(value: unknown): MurmurServiceJsonValue {
    return cloneJson(value, 0, { nodes: 0 });
}

function encodeJson(value: MurmurServiceJsonValue): Uint8Array {
    const cloned = copyJson(value);
    const encoded = canonicalJsonBytes(cloned);
    if (encoded.length > MAXIMUM_SERVICE_VALUE_BYTES) {
        throw new Error("Murmur service JSON value is too large");
    }
    return encoded;
}

function decodeJson(bytes: Uint8Array): MurmurServiceJsonValue {
    if (bytes.length < 1 || bytes.length > MAXIMUM_SERVICE_VALUE_BYTES) {
        throw new Error("Invalid stored Murmur service JSON");
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid stored Murmur service JSON");
    }
    const cloned = copyJson(parsed);
    const canonical = canonicalJsonBytes(cloned);
    try {
        if (!equalBytes(bytes, canonical)) {
            throw new Error("Stored Murmur service JSON must be canonical");
        }
        return cloned;
    } finally {
        zeroBytes(canonical);
    }
}

function validateSegments(value: string): void {
    if (
        value.length < 1 ||
        value.length > MAXIMUM_RELATIVE_KEY_CHARACTERS ||
        value
            .split("/")
            .some(
                (segment) =>
                    segment === "." || segment === ".." || !RELATIVE_KEY_SEGMENT.test(segment),
            )
    ) {
        throw new Error("Invalid Murmur service storage key");
    }
}

function validateRelativeKey(value: string): void {
    validateSegments(value);
}

function validateRelativePrefix(value: string): void {
    if (value === "") return;
    validateSegments(value.endsWith("/") ? value.slice(0, -1) : value);
}

/** Validate one stable service identifier. */
export function validateServiceId(id: string): void {
    if (id.length < 1 || id.length > MAXIMUM_SERVICE_ID_CHARACTERS || !SERVICE_ID.test(id)) {
        throw new Error("Invalid Murmur service ID");
    }
}

function namespace(id: string): string {
    validateServiceId(id);
    return `murmur/services/v1/${encodeBase64Url(utf8Encode(id))}/state/`;
}

/** Create JSON persistence restricted to one stable service identifier. */
export function createMurmurServiceStorage(
    store: MurmurStore,
    serviceId: string,
): MurmurServiceStorage {
    const prefix = namespace(serviceId);
    return Object.freeze({
        async get(key: string): Promise<MurmurServiceJsonValue | undefined> {
            validateRelativeKey(key);
            const bytes = await store.get(`${prefix}${key}`);
            if (bytes === undefined) return undefined;
            try {
                return decodeJson(bytes);
            } finally {
                zeroBytes(bytes);
            }
        },
        async set(key: string, value: MurmurServiceJsonValue): Promise<void> {
            validateRelativeKey(key);
            const encoded = encodeJson(value);
            try {
                await store.set(`${prefix}${key}`, encoded);
            } finally {
                zeroBytes(encoded);
            }
        },
        async delete(key: string): Promise<void> {
            validateRelativeKey(key);
            await store.delete(`${prefix}${key}`);
        },
        async scan(
            relativePrefix: string,
            options: MurmurServiceStorageScanOptions,
        ): Promise<ReadonlyMap<string, MurmurServiceJsonValue>> {
            validateRelativePrefix(relativePrefix);
            if (
                !Number.isSafeInteger(options.limit) ||
                options.limit < 1 ||
                options.limit > MAXIMUM_SERVICE_SCAN_ITEMS
            ) {
                throw new Error("Invalid Murmur service storage scan");
            }
            if (options.after !== undefined) {
                validateRelativeKey(options.after);
                if (!options.after.startsWith(relativePrefix)) {
                    throw new Error("Invalid Murmur service storage scan");
                }
            }
            const values = await store.scan(`${prefix}${relativePrefix}`, {
                ...(options.after === undefined ? {} : { after: `${prefix}${options.after}` }),
                limit: options.limit,
            });
            const result = new Map<string, MurmurServiceJsonValue>();
            try {
                for (const [key, bytes] of values) {
                    if (!key.startsWith(prefix)) {
                        throw new Error("Invalid Murmur service storage result");
                    }
                    result.set(key.slice(prefix.length), decodeJson(bytes));
                }
            } finally {
                for (const bytes of values.values()) zeroBytes(bytes);
            }
            return result;
        },
    });
}
