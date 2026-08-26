import type { StoreTransaction, MurmurStore } from "../../storage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    zeroBytes,
} from "../../utils/index.js";
import {
    deviceRosterHash,
    isActiveDevice,
    parseDeviceRoster,
    serializeDeviceRoster,
} from "./deviceRosterCodec.js";
import type { MurmurDeviceAdded, MurmurDeviceRevoked, MurmurDeviceRoster } from "../types.js";

export const ACCOUNT_EVENT_PREFIX = "murmur/accounts/v1/events/";
export const ACCOUNT_ROSTER_KEY = "murmur/accounts/v1/own-roster";
export const ACCOUNT_PEER_ROSTER_PREFIX = "murmur/accounts/v1/peer-rosters/";
export const ACCOUNT_CONVERGENCE_PREFIX = "murmur/accounts/v1/convergence/";
const MAXIMUM_ACCOUNT_EVENTS = 256;
const MAXIMUM_CONVERGENCE_JOBS = 256;

/** One durable MLS membership job derived from authenticated roster state. */
export interface AccountConvergenceJob {
    readonly key: string;
    readonly account: Uint8Array;
    readonly device: Uint8Array;
    readonly change: "added" | "revoked" | "reset_remove" | "reset_add";
    readonly rosterRevision: number;
    readonly keyPackage?: Uint8Array;
    readonly dependsOn?: string;
}

type AccountEventRecord = {
    readonly version: 1;
    readonly scope: "own";
    readonly type: "added" | "revoked" | "reset";
    readonly id: string;
    readonly account: Uint8Array;
    readonly device: Uint8Array;
    readonly rosterRevision: number;
};

/** One prepared account-event batch sharing the identity-wide drain boundary. */
export interface PreparedAccountEvents {
    readonly keys: readonly string[];
    readonly added: readonly MurmurDeviceAdded[];
    readonly revoked: readonly MurmurDeviceRevoked[];
}

function eventKey(id: string, account: Uint8Array, device: Uint8Array): string {
    if (id.length < 1 || id.length > 128) throw new Error("Invalid account event ID");
    return `${ACCOUNT_EVENT_PREFIX}${id}/${encodeBase64Url(account)}/${encodeBase64Url(device)}`;
}

function encodeEvent(record: AccountEventRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        scope: record.scope,
        type: record.type,
        id: record.id,
        account: encodeBase64Url(record.account),
        device: encodeBase64Url(record.device),
        rosterRevision: record.rosterRevision ?? null,
    });
}

function decodeEvent(value: Uint8Array): AccountEventRecord {
    const parsed = JSON.parse(utf8Decode(value)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid account event");
    }
    const input = parsed as Record<string, unknown>;
    const fields = ["version", "scope", "type", "id", "account", "device", "rosterRevision"];
    if (
        input.version !== 1 ||
        input.scope !== "own" ||
        (input.type !== "added" && input.type !== "revoked" && input.type !== "reset") ||
        typeof input.id !== "string" ||
        typeof input.account !== "string" ||
        typeof input.device !== "string" ||
        (input.rosterRevision !== null &&
            (typeof input.rosterRevision !== "number" ||
                !Number.isSafeInteger(input.rosterRevision) ||
                input.rosterRevision < 1)) ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid account event");
    }
    const account = decodeBase64Url(input.account);
    const device = decodeBase64Url(input.device);
    if (account.length !== 32 || device.length !== 32) throw new Error("Invalid account event");
    if (input.scope === "own" && input.rosterRevision === null) {
        throw new Error("Invalid own-device event");
    }
    return {
        version: 1,
        scope: input.scope,
        type: input.type,
        id: input.id,
        account,
        device,
        ...(input.rosterRevision === null
            ? {}
            : { rosterRevision: input.rosterRevision as number }),
    } as AccountEventRecord;
}

/** Durably record an own-account roster lifecycle event idempotently. */
export async function recordAccountEvent(
    transaction: StoreTransaction,
    record: AccountEventRecord,
): Promise<void> {
    const page = await transaction.scan(ACCOUNT_EVENT_PREFIX, { limit: MAXIMUM_ACCOUNT_EVENTS });
    if (page.size >= MAXIMUM_ACCOUNT_EVENTS) throw new Error("Account event capacity exceeded");
    await transaction.set(eventKey(record.id, record.account, record.device), encodeEvent(record));
}

/** Read one bounded immutable account lifecycle batch. */
export async function prepareAccountEvents(store: MurmurStore): Promise<PreparedAccountEvents> {
    const page = await store.scan(ACCOUNT_EVENT_PREFIX, { limit: MAXIMUM_ACCOUNT_EVENTS });
    const keys: string[] = [];
    const added: MurmurDeviceAdded[] = [];
    const revoked: MurmurDeviceRevoked[] = [];
    for (const [key, bytes] of page) {
        const event = decodeEvent(bytes);
        try {
            keys.push(key);
            const publicEvent = Object.freeze({
                id: event.id,
                account: event.account.slice(),
                device: event.device.slice(),
                rosterRevision: event.rosterRevision,
            });
            if (event.type !== "reset") {
                (event.type === "added" ? added : revoked).push(publicEvent);
            }
        } finally {
            zeroBytes(event.account);
            zeroBytes(event.device);
            zeroBytes(bytes);
        }
    }
    return { keys, added, revoked };
}

/** Delete account events only after every lifecycle callback resolves. */
export async function deletePreparedAccountEvents(
    transaction: StoreTransaction,
    prepared: PreparedAccountEvents,
): Promise<void> {
    for (const key of prepared.keys) await transaction.delete(key);
}

function peerRosterKey(account: Uint8Array): string {
    return `${ACCOUNT_PEER_ROSTER_PREFIX}${encodeBase64Url(account)}`;
}

function rosterKey(account: Uint8Array, ownAccount: Uint8Array): string {
    return equalBytes(account, ownAccount) ? ACCOUNT_ROSTER_KEY : peerRosterKey(account);
}

function convergenceKey(
    account: Uint8Array,
    device: Uint8Array,
    change: AccountConvergenceJob["change"],
): string {
    return `${ACCOUNT_CONVERGENCE_PREFIX}${encodeBase64Url(account)}/${encodeBase64Url(device)}/${change}`;
}

function encodeConvergence(
    account: Uint8Array,
    device: Uint8Array,
    change: AccountConvergenceJob["change"],
    rosterRevision: number,
    keyPackage?: Uint8Array,
    dependsOn?: string,
): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        account: encodeBase64Url(account),
        device: encodeBase64Url(device),
        change,
        rosterRevision,
        keyPackage: keyPackage === undefined ? null : encodeBase64Url(keyPackage),
        dependsOn: dependsOn ?? null,
    });
}

async function queueConvergence(
    transaction: StoreTransaction,
    account: Uint8Array,
    device: Uint8Array,
    change: AccountConvergenceJob["change"],
    rosterRevision: number,
    keyPackage?: Uint8Array,
    dependsOn?: string,
): Promise<void> {
    const page = await transaction.scan(ACCOUNT_CONVERGENCE_PREFIX, {
        limit: MAXIMUM_CONVERGENCE_JOBS,
    });
    if (page.size >= MAXIMUM_CONVERGENCE_JOBS) {
        throw new Error("Account convergence capacity exceeded");
    }
    await transaction.set(
        convergenceKey(account, device, change),
        encodeConvergence(account, device, change, rosterRevision, keyPackage, dependsOn),
    );
}

function activeDevices(roster: MurmurDeviceRoster | undefined): Map<string, Uint8Array> {
    return new Map(
        (roster?.devices ?? [])
            .filter((entry) => entry.status === "active")
            .map((entry) => [encodeBase64Url(entry.deviceKey), entry.deviceKey]),
    );
}

function acceptsRoster(
    current: MurmurDeviceRoster | undefined,
    candidate: MurmurDeviceRoster,
): boolean {
    if (current === undefined) return true;
    const currentHash = deviceRosterHash(current);
    const candidateHash = deviceRosterHash(candidate);
    if (equalBytes(currentHash, candidateHash)) return false;
    if (
        candidate.revision === current.revision + 1 &&
        candidate.parentHash !== null &&
        equalBytes(candidate.parentHash, currentHash)
    ) {
        return true;
    }
    if (
        candidate.revision === current.revision &&
        candidate.parentHash !== null &&
        current.parentHash !== null &&
        equalBytes(candidate.parentHash, current.parentHash)
    ) {
        for (let index = 0; index < candidateHash.length; index += 1) {
            if (candidateHash[index] === currentHash[index]) continue;
            return candidateHash[index]! > currentHash[index]!;
        }
    }
    return false;
}

/** Apply one MLS-authenticated roster update and queue its automatic membership work. */
export async function observeDeviceRoster(
    transaction: StoreTransaction,
    ownAccount: Uint8Array,
    eventId: string,
    senderAccount: Uint8Array,
    senderDevice: Uint8Array,
    rosterBytes: Uint8Array,
    admission?: { readonly device: Uint8Array; readonly keyPackage: Uint8Array },
): Promise<void> {
    const candidate = parseDeviceRoster(rosterBytes);
    if (
        !equalBytes(candidate.accountKey, senderAccount) ||
        !isActiveDevice(candidate, senderDevice)
    ) {
        throw new Error("Roster control sender is not active in its account");
    }
    if (
        admission !== undefined &&
        (!isActiveDevice(candidate, admission.device) || admission.keyPackage.length < 1)
    ) {
        throw new Error("Roster admission does not name an active device");
    }
    const key = rosterKey(candidate.accountKey, ownAccount);
    const stored = await transaction.get(key);
    let current: MurmurDeviceRoster | undefined;
    try {
        if (stored !== undefined) current = parseDeviceRoster(stored);
        const accepted = acceptsRoster(current, candidate);
        const same =
            current !== undefined &&
            equalBytes(deviceRosterHash(current), deviceRosterHash(candidate));
        if (!accepted && !same) throw new Error("Stale or unauthenticated roster transition");
        if (accepted) await transaction.set(key, serializeDeviceRoster(candidate));
        const before = activeDevices(current);
        const after = activeDevices(candidate);
        const changes: { device: Uint8Array; change: "added" | "revoked" }[] = [];
        const resets: Uint8Array[] = [];
        if (accepted) {
            for (const [encoded, device] of after) {
                if (!before.has(encoded)) changes.push({ device, change: "added" });
            }
            for (const [encoded, device] of before) {
                if (!after.has(encoded)) changes.push({ device, change: "revoked" });
            }
            for (const entry of candidate.devices) {
                const prior = current?.devices.find((value) =>
                    equalBytes(value.deviceKey, entry.deviceKey),
                );
                if (
                    entry.status === "active" &&
                    (prior === undefined || prior.status === "active") &&
                    entry.resetGeneration > (prior?.resetGeneration ?? 0)
                ) {
                    resets.push(entry.deviceKey);
                }
            }
        }
        for (const device of resets) {
            const keyPackage =
                admission !== undefined && equalBytes(admission.device, device)
                    ? admission.keyPackage
                    : undefined;
            if (keyPackage !== undefined) {
                await queueConvergence(
                    transaction,
                    candidate.accountKey,
                    device,
                    "reset_add",
                    candidate.revision,
                    keyPackage,
                );
            }
            if (equalBytes(candidate.accountKey, ownAccount)) {
                await recordAccountEvent(transaction, {
                    version: 1,
                    scope: "own",
                    type: "reset",
                    id: eventId,
                    account: candidate.accountKey,
                    device,
                    rosterRevision: candidate.revision,
                });
            }
        }
        for (const change of changes) {
            if (resets.some((device) => equalBytes(device, change.device))) continue;
            const keyPackage =
                change.change === "added" &&
                admission !== undefined &&
                equalBytes(admission.device, change.device)
                    ? admission.keyPackage
                    : undefined;
            if (change.change === "revoked" || keyPackage !== undefined) {
                await queueConvergence(
                    transaction,
                    candidate.accountKey,
                    change.device,
                    change.change,
                    candidate.revision,
                    keyPackage,
                );
            }
            if (equalBytes(candidate.accountKey, ownAccount)) {
                await recordAccountEvent(transaction, {
                    version: 1,
                    scope: "own",
                    type: change.change,
                    id: eventId,
                    account: candidate.accountKey,
                    device: change.device,
                    rosterRevision: candidate.revision,
                });
            }
        }
        if (
            admission !== undefined &&
            !resets.some((device) => equalBytes(device, admission.device))
        ) {
            await queueConvergence(
                transaction,
                candidate.accountKey,
                admission.device,
                "added",
                candidate.revision,
                admission.keyPackage,
            );
        }
    } finally {
        if (stored !== undefined) zeroBytes(stored);
    }
}

function decodeConvergence(key: string, value: Uint8Array): AccountConvergenceJob {
    const parsed = JSON.parse(utf8Decode(value)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid account convergence job");
    }
    const input = parsed as Record<string, unknown>;
    const fields = [
        "version",
        "account",
        "device",
        "change",
        "rosterRevision",
        "keyPackage",
        "dependsOn",
    ];
    if (
        input.version !== 1 ||
        typeof input.account !== "string" ||
        typeof input.device !== "string" ||
        (input.change !== "added" &&
            input.change !== "revoked" &&
            input.change !== "reset_remove" &&
            input.change !== "reset_add") ||
        typeof input.rosterRevision !== "number" ||
        !Number.isSafeInteger(input.rosterRevision) ||
        input.rosterRevision < 1 ||
        (input.keyPackage !== null && typeof input.keyPackage !== "string") ||
        (input.dependsOn !== undefined &&
            input.dependsOn !== null &&
            typeof input.dependsOn !== "string") ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid account convergence job");
    }
    const account = decodeBase64Url(input.account);
    const device = decodeBase64Url(input.device);
    const keyPackage =
        input.keyPackage === null ? undefined : decodeBase64Url(input.keyPackage as string);
    if (
        account.length !== 32 ||
        device.length !== 32 ||
        ((input.change === "added" || input.change === "reset_add") && keyPackage === undefined) ||
        ((input.change === "revoked" || input.change === "reset_remove") &&
            keyPackage !== undefined)
    ) {
        throw new Error("Invalid account convergence job");
    }
    return {
        key,
        account,
        device,
        change: input.change,
        rosterRevision: input.rosterRevision,
        ...(keyPackage === undefined ? {} : { keyPackage }),
        ...(input.dependsOn === undefined || input.dependsOn === null
            ? {}
            : { dependsOn: input.dependsOn as string }),
    };
}

/** Read the bounded durable MLS convergence queue. */
export async function accountConvergenceJobs(
    store: MurmurStore,
): Promise<readonly AccountConvergenceJob[]> {
    const page = await store.scan(ACCOUNT_CONVERGENCE_PREFIX, {
        limit: MAXIMUM_CONVERGENCE_JOBS,
    });
    return [...page].map(([key, bytes]) => {
        try {
            return decodeConvergence(key, bytes);
        } finally {
            zeroBytes(bytes);
        }
    });
}

/** Delete one completed convergence job by its exact prepared key. */
export async function deleteAccountConvergenceJob(store: MurmurStore, key: string): Promise<void> {
    if (!key.startsWith(ACCOUNT_CONVERGENCE_PREFIX)) {
        throw new Error("Invalid account convergence key");
    }
    await store.delete(key);
}
