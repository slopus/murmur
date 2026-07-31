import { encodeBase64Url } from "./base64Url.js";

const encoder = new TextEncoder();

function encodeValue(value: unknown): string {
    if (value === null) {
        return "null";
    }
    if (value instanceof Uint8Array) {
        return JSON.stringify(encodeBase64Url(value));
    }
    if (typeof value === "string" || typeof value === "boolean") {
        return JSON.stringify(value);
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            throw new Error("Canonical JSON rejects non-finite numbers");
        }
        if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
            throw new Error("Canonical JSON rejects unsafe integers");
        }
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        const items: string[] = [];
        for (let index = 0; index < value.length; index += 1) {
            if (!Object.hasOwn(value, index) || value[index] === undefined) {
                throw new Error("Canonical JSON rejects undefined values");
            }
            items.push(encodeValue(value[index]));
        }
        return `[${items.join(",")}]`;
    }
    if (typeof value === "object") {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new Error("Canonical JSON accepts only plain objects");
        }
        const record = value as Record<string, unknown>;
        const members: string[] = [];
        for (const key of Object.keys(record).sort()) {
            const member = record[key];
            if (member === undefined) {
                throw new Error("Canonical JSON rejects undefined values");
            }
            members.push(`${JSON.stringify(key)}:${encodeValue(member)}`);
        }
        return `{${members.join(",")}}`;
    }
    throw new Error("Unsupported canonical JSON value");
}

/** Encode a strict JSON value with recursively sorted object keys and no whitespace. */
export function canonicalJson(value: unknown): Uint8Array {
    return encoder.encode(encodeValue(value));
}
