import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";

/** Size of one opaque inbox loss-generation token. */
export const LOSS_GENERATION_BYTES = 32;

/** Create an unpredictable relay generation seed. */
export function createGenerationSeed(): Uint8Array {
    return randomBytes(LOSS_GENERATION_BYTES);
}

/** Derive the stable initial generation for one inbox without materializing it. */
export function initialLossGeneration(seed: Uint8Array, recipient: Uint8Array): Uint8Array {
    if (seed.length !== LOSS_GENERATION_BYTES || recipient.length !== 32) {
        throw new Error("Invalid inbox generation input");
    }
    return hmac(sha256, seed, recipient);
}

/** Advance once for each irrecoverably removed unacknowledged reference. */
export function advanceLossGeneration(generation: Uint8Array, amount = 1): Uint8Array {
    if (
        generation.length !== LOSS_GENERATION_BYTES ||
        !Number.isSafeInteger(amount) ||
        amount < 0
    ) {
        throw new Error("Invalid inbox generation advance");
    }
    const advanced = generation.slice();
    let carry = BigInt(amount);
    for (let index = advanced.length - 1; index >= 0 && carry > 0n; index -= 1) {
        const sum = BigInt(advanced[index]!) + (carry & 0xffn);
        advanced[index] = Number(sum & 0xffn);
        carry = (carry >> 8n) + (sum >> 8n);
    }
    return advanced;
}
