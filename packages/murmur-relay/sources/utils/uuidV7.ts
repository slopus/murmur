import { randomBytes } from "@noble/hashes/utils";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAXIMUM_TIMESTAMP = 0xffff_ffff_ffff;
const RANDOM_BITS = 74n;
const RANDOM_LIMIT = 1n << RANDOM_BITS;

function timestampOf(value: string): number {
    return Number.parseInt(value.replaceAll("-", "").slice(0, 12), 16);
}

function randomPartOf(value: string): bigint {
    const compact = value.replaceAll("-", "");
    const randomA = BigInt(`0x${compact.slice(13, 16)}`);
    const randomB =
        (BigInt(Number.parseInt(compact[16]!, 16) & 0x3) << 60n) | BigInt(`0x${compact.slice(17)}`);
    return (randomA << 62n) | randomB;
}

function randomPart(): bigint {
    let value = 0n;
    for (const byte of randomBytes(10)) {
        value = (value << 8n) | BigInt(byte);
    }
    return value & (RANDOM_LIMIT - 1n);
}

function encode(timestamp: number, random: bigint): string {
    const time = timestamp.toString(16).padStart(12, "0");
    const randomA = Number(random >> 62n)
        .toString(16)
        .padStart(3, "0");
    const randomB = (random & ((1n << 62n) - 1n)).toString(16).padStart(16, "0");
    const variant = (Number.parseInt(randomB[0]!, 16) & 0x3) | 0x8;
    const compact = `${time}7${randomA}${variant.toString(16)}${randomB.slice(1)}`;
    return `${compact.slice(0, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}-${compact.slice(16, 20)}-${compact.slice(20)}`;
}

/** Return whether a string is one canonical lowercase UUIDv7. */
export function isUuidV7(value: string): boolean {
    return UUID_V7.test(value);
}

/**
 * Generate a UUIDv7 strictly after `previous`, even within one millisecond or
 * after a wall-clock rollback.
 */
export function nextUuidV7(now: number, previous: string | null): string {
    if (!Number.isSafeInteger(now) || now < 0 || now > MAXIMUM_TIMESTAMP) {
        throw new Error("UUIDv7 timestamp is outside its 48-bit range");
    }
    if (previous === null) {
        return encode(now, randomPart());
    }
    if (!isUuidV7(previous)) {
        throw new Error("Stored event ID is not UUIDv7");
    }
    const previousTimestamp = timestampOf(previous);
    if (now > previousTimestamp) {
        return encode(now, randomPart());
    }
    const incremented = randomPartOf(previous) + 1n;
    if (incremented < RANDOM_LIMIT) {
        return encode(previousTimestamp, incremented);
    }
    if (previousTimestamp >= MAXIMUM_TIMESTAMP) {
        throw new Error("UUIDv7 event ID space is exhausted");
    }
    return encode(previousTimestamp + 1, 0n);
}
