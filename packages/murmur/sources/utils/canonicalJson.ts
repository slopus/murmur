import { utf8Encode } from "./bytes.js";

export type JsonValue =
    | boolean
    | null
    | number
    | string
    | readonly JsonValue[]
    | { readonly [key: string]: JsonValue };

function canonicalize(value: JsonValue): string {
    if (value === null || typeof value === "boolean" || typeof value === "string") {
        return JSON.stringify(value);
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            throw new Error("Canonical JSON cannot encode a non-finite number");
        }
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
    }

    const entries = Object.entries(value).sort(([left], [right]) =>
        left < right ? -1 : left > right ? 1 : 0,
    );
    return `{${entries
        .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalize(entry)}`)
        .join(",")}}`;
}

/** Serialize JSON with stable lexicographic object-key ordering. */
export function canonicalJson(value: JsonValue): string {
    return canonicalize(value);
}

/** Serialize canonical JSON directly to UTF-8 bytes. */
export function canonicalJsonBytes(value: JsonValue): Uint8Array {
    return utf8Encode(canonicalJson(value));
}
