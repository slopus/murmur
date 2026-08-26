import { ed25519 } from "@noble/curves/ed25519";
import {
    deliverySigningBytes,
    queueAckSigningBytes,
    queueReadSigningBytes,
    type SignedDelivery,
    type DeliverySessionControl,
    type SignedQueueAck,
    type SignedQueueRead,
} from "../index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";

export function secret(seed: number): Uint8Array {
    return new Uint8Array(32).fill(seed);
}

export function identity(secretKey: Uint8Array): Uint8Array {
    return ed25519.getPublicKey(secretKey);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return 0;
}

export function recipients(...identities: readonly Uint8Array[]): readonly Uint8Array[] {
    return identities.map((value) => value.slice()).sort(compareBytes);
}

export function eventId(index: number): string {
    return `00000000-0000-7000-8000-${index.toString(16).padStart(12, "0")}`;
}

export function signedDelivery(
    secretKey: Uint8Array,
    targets: readonly Uint8Array[],
    options: {
        readonly id?: number;
        readonly now?: number;
        readonly expiresAt?: number;
        readonly ciphertext?: Uint8Array;
        readonly senderAccount?: Uint8Array;
        readonly targetAccounts?: readonly {
            readonly accountKey: Uint8Array;
            readonly rosterRevision: number;
        }[];
        readonly ownerAccount?: Uint8Array;
        readonly sessionId?: Uint8Array;
        readonly sessionControl?: DeliverySessionControl;
    } = {},
): SignedDelivery {
    const now = options.now ?? 10_000;
    const unsigned: SignedDelivery = {
        version: 1,
        id: encodeBase64Url(new Uint8Array(24).fill(options.id ?? 1)),
        sender: identity(secretKey),
        senderAccount: options.senderAccount?.slice() ?? identity(secretKey),
        recipients: targets.map((target) => target.slice()),
        targetAccounts: (options.targetAccounts ?? []).map((target) => ({
            accountKey: target.accountKey.slice(),
            rosterRevision: target.rosterRevision,
        })),
        ownerAccount: options.ownerAccount?.slice() ?? null,
        sessionId: options.sessionId?.slice() ?? null,
        sessionControl: options.sessionControl ?? null,
        createdAt: now,
        expiresAt: options.expiresAt ?? now + 60_000,
        ciphertext: options.ciphertext?.slice() ?? new Uint8Array([1, 2, 3]),
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(deliverySigningBytes(unsigned), secretKey),
    };
}

export function signedRead(
    secretKey: Uint8Array,
    options: {
        readonly after?: string | null;
        readonly limit?: number;
        readonly waitMilliseconds?: number;
        readonly now?: number;
    } = {},
): SignedQueueRead {
    const unsigned: SignedQueueRead = {
        version: 1,
        recipient: identity(secretKey),
        after: options.after ?? null,
        limit: options.limit ?? 100,
        waitMilliseconds: options.waitMilliseconds ?? 0,
        createdAt: options.now ?? 10_000,
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(queueReadSigningBytes(unsigned), secretKey),
    };
}

export function signedAck(
    secretKey: Uint8Array,
    through: string,
    now: number = 10_000,
): SignedQueueAck {
    const unsigned: SignedQueueAck = {
        version: 1,
        recipient: identity(secretKey),
        through,
        createdAt: now,
        signature: new Uint8Array(64),
    };
    return {
        ...unsigned,
        signature: ed25519.sign(queueAckSigningBytes(unsigned), secretKey),
    };
}
