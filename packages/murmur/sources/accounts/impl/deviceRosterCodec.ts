import { sha256 } from "@noble/hashes/sha2";
import {
    signBytes,
    validateIdentityKeyPair,
    validateIdentityPublicKey,
    verifyBytes,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    type JsonValue,
} from "../../utils/index.js";
import type {
    MurmurDeviceCredential,
    MurmurDeviceRoster,
    MurmurDeviceRosterEntry,
} from "../types.js";

const ROSTER_DOMAIN = utf8Encode("murmur/account-roster/v1");
const DEVICE_AUTHORIZATION_DOMAIN = utf8Encode("murmur/account-device/v1");
const DEVICE_CREDENTIAL_DOMAIN = "murmur.device";
const MAXIMUM_ROSTER_DEVICES = 64;
const MAXIMUM_ROSTER_BYTES = 64 * 1024;

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function bytes(value: unknown, length: number, name: string): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((length * 4) / 3)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (decoded.length !== length || encodeBase64Url(decoded) !== value) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function safeInteger(value: unknown, minimum: number, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return left.length - right.length;
}

function authorizationBytes(
    accountKey: Uint8Array,
    deviceKey: Uint8Array,
    addedAtRevision: number,
): Uint8Array {
    return new Uint8Array([
        ...DEVICE_AUTHORIZATION_DOMAIN,
        ...canonicalJsonBytes({
            accountKey: encodeBase64Url(accountKey),
            addedAtRevision,
            deviceKey: encodeBase64Url(deviceKey),
            version: 1,
        }),
    ]);
}

function rosterEntryJson(entry: MurmurDeviceRosterEntry): JsonValue {
    const value: Record<string, JsonValue> = {
        addedAtRevision: entry.addedAtRevision,
        authorization: encodeBase64Url(entry.authorization),
        deviceKey: encodeBase64Url(entry.deviceKey),
        revokedAtRevision: entry.revokedAtRevision ?? null,
        status: entry.status,
    };
    // Omit zero so pre-reset v1 roster signatures remain byte-for-byte valid.
    if (entry.resetGeneration > 0) value.resetGeneration = entry.resetGeneration;
    return value;
}

function rosterTbsJson(roster: MurmurDeviceRoster): JsonValue {
    return {
        accountKey: encodeBase64Url(roster.accountKey),
        authorDeviceKey: encodeBase64Url(roster.authorDeviceKey),
        devices: roster.devices.map(rosterEntryJson),
        issuedAt: roster.issuedAt,
        mutationId: encodeBase64Url(roster.mutationId),
        parentHash: roster.parentHash === null ? null : encodeBase64Url(roster.parentHash),
        revision: roster.revision,
        version: 1,
    };
}

function rosterTbs(roster: MurmurDeviceRoster): Uint8Array {
    return new Uint8Array([...ROSTER_DOMAIN, ...canonicalJsonBytes(rosterTbsJson(roster))]);
}

function rosterAuthorTbs(roster: MurmurDeviceRoster): Uint8Array {
    return new Uint8Array([...rosterTbs(roster), ...roster.accountSignature]);
}

function assertRosterShape(roster: MurmurDeviceRoster): void {
    validateIdentityPublicKey({ publicKey: roster.accountKey });
    validateIdentityPublicKey({ publicKey: roster.authorDeviceKey });
    if (
        roster.version !== 1 ||
        !Number.isSafeInteger(roster.revision) ||
        roster.revision < 1 ||
        (roster.parentHash !== null && roster.parentHash.length !== 32) ||
        !Number.isSafeInteger(roster.issuedAt) ||
        roster.issuedAt < 0 ||
        roster.mutationId.length !== 16 ||
        roster.accountSignature.length !== 64 ||
        roster.authorSignature.length !== 64 ||
        roster.devices.length < 1 ||
        roster.devices.length > MAXIMUM_ROSTER_DEVICES
    ) {
        throw new Error("Invalid device roster");
    }
    if ((roster.revision === 1) !== (roster.parentHash === null)) {
        throw new Error("Invalid device roster parent");
    }
    let previous: Uint8Array | undefined;
    let authorPresent = false;
    for (const entry of roster.devices) {
        validateIdentityPublicKey({ publicKey: entry.deviceKey });
        if (
            !Number.isSafeInteger(entry.addedAtRevision) ||
            entry.addedAtRevision < 1 ||
            entry.addedAtRevision > roster.revision ||
            entry.authorization.length !== 64 ||
            !Number.isSafeInteger(entry.resetGeneration) ||
            entry.resetGeneration < 0 ||
            (entry.status === "active" && entry.revokedAtRevision !== undefined) ||
            (entry.status === "revoked" &&
                (entry.revokedAtRevision === undefined ||
                    !Number.isSafeInteger(entry.revokedAtRevision) ||
                    entry.revokedAtRevision <= entry.addedAtRevision ||
                    entry.revokedAtRevision > roster.revision)) ||
            (entry.status !== "active" && entry.status !== "revoked")
        ) {
            throw new Error("Invalid device roster entry");
        }
        if (previous !== undefined && compareBytes(previous, entry.deviceKey) >= 0) {
            throw new Error("Device roster entries must be sorted and unique");
        }
        previous = entry.deviceKey;
        if (equalBytes(entry.deviceKey, roster.authorDeviceKey)) authorPresent = true;
        if (
            !verifyBytes(
                { publicKey: roster.accountKey },
                authorizationBytes(roster.accountKey, entry.deviceKey, entry.addedAtRevision),
                entry.authorization,
            )
        ) {
            throw new Error("Invalid device authorization");
        }
    }
    if (!authorPresent) throw new Error("Roster author device is absent");
}

function signRoster(
    unsigned: Omit<MurmurDeviceRoster, "accountSignature" | "authorSignature">,
    account: IdentityKeyPair,
    authorDevice: IdentityKeyPair,
): MurmurDeviceRoster {
    const forAccount: MurmurDeviceRoster = {
        ...unsigned,
        accountSignature: new Uint8Array(64),
        authorSignature: new Uint8Array(64),
    };
    const accountSignature = signBytes(account, rosterTbs(forAccount));
    const forAuthor = { ...forAccount, accountSignature };
    return Object.freeze({
        ...forAuthor,
        devices: Object.freeze(forAuthor.devices),
        authorSignature: signBytes(authorDevice, rosterAuthorTbs(forAuthor)),
    });
}

function authorizedEntry(
    account: IdentityKeyPair,
    deviceKey: Uint8Array,
    addedAtRevision: number,
): MurmurDeviceRosterEntry {
    validateIdentityKeyPair(account);
    validateIdentityPublicKey({ publicKey: deviceKey });
    return Object.freeze({
        deviceKey: deviceKey.slice(),
        addedAtRevision,
        authorization: signBytes(
            account,
            authorizationBytes(account.publicKey, deviceKey, addedAtRevision),
        ),
        status: "active" as const,
        resetGeneration: 0,
    });
}

function cloneEntry(entry: MurmurDeviceRosterEntry): MurmurDeviceRosterEntry {
    return Object.freeze({
        deviceKey: entry.deviceKey.slice(),
        addedAtRevision: entry.addedAtRevision,
        authorization: entry.authorization.slice(),
        status: entry.status,
        resetGeneration: entry.resetGeneration,
        ...(entry.revokedAtRevision === undefined
            ? {}
            : { revokedAtRevision: entry.revokedAtRevision }),
    });
}

/** Create the first account-signed roster containing exactly one active device. */
export function createInitialDeviceRoster(
    account: IdentityKeyPair,
    device: IdentityKeyPair,
    issuedAt: number,
    mutationId: Uint8Array,
): MurmurDeviceRoster {
    validateIdentityKeyPair(account);
    validateIdentityKeyPair(device);
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0 || mutationId.length !== 16) {
        throw new Error("Invalid initial device roster metadata");
    }
    return signRoster(
        {
            version: 1,
            accountKey: account.publicKey.slice(),
            revision: 1,
            parentHash: null,
            issuedAt,
            mutationId: mutationId.slice(),
            authorDeviceKey: device.publicKey.slice(),
            devices: [authorizedEntry(account, device.publicKey, 1)],
        },
        account,
        device,
    );
}

/** Create one direct roster child that authorizes a fresh device. */
export function addDeviceToRoster(
    previous: MurmurDeviceRoster,
    account: IdentityKeyPair,
    authorDevice: IdentityKeyPair,
    deviceKey: Uint8Array,
    issuedAt: number,
    mutationId: Uint8Array,
): MurmurDeviceRoster {
    if (!verifyDeviceRoster(previous)) throw new Error("Invalid previous device roster");
    validateIdentityKeyPair(account);
    validateIdentityKeyPair(authorDevice);
    if (!equalBytes(account.publicKey, previous.accountKey)) {
        throw new Error("Roster account key does not match");
    }
    if (!isActiveDevice(previous, authorDevice.publicKey)) {
        throw new Error("Roster author is not active");
    }
    if (previous.devices.some((entry) => equalBytes(entry.deviceKey, deviceKey))) {
        throw new Error("Device already exists in the roster");
    }
    const revision = previous.revision + 1;
    const devices = [
        ...previous.devices.map(cloneEntry),
        authorizedEntry(account, deviceKey, revision),
    ].sort((left, right) => compareBytes(left.deviceKey, right.deviceKey));
    return signRoster(
        {
            version: 1,
            accountKey: previous.accountKey.slice(),
            revision,
            parentHash: deviceRosterHash(previous),
            issuedAt,
            mutationId: mutationId.slice(),
            authorDeviceKey: authorDevice.publicKey.slice(),
            devices,
        },
        account,
        authorDevice,
    );
}

/** Create one direct roster child revoking an active device. */
export function revokeDeviceFromRoster(
    previous: MurmurDeviceRoster,
    account: IdentityKeyPair,
    authorDevice: IdentityKeyPair,
    deviceKey: Uint8Array,
    issuedAt: number,
    mutationId: Uint8Array,
): MurmurDeviceRoster {
    if (!verifyDeviceRoster(previous)) throw new Error("Invalid previous device roster");
    validateIdentityKeyPair(account);
    validateIdentityKeyPair(authorDevice);
    if (!equalBytes(account.publicKey, previous.accountKey)) {
        throw new Error("Roster account key does not match");
    }
    if (!isActiveDevice(previous, authorDevice.publicKey)) {
        throw new Error("Roster author is not active");
    }
    if (equalBytes(authorDevice.publicKey, deviceKey)) {
        throw new Error("An active device cannot revoke itself");
    }
    const target = previous.devices.find((entry) => equalBytes(entry.deviceKey, deviceKey));
    if (target?.status !== "active") throw new Error("Device is not active");
    const revision = previous.revision + 1;
    const devices = previous.devices.map((entry) =>
        equalBytes(entry.deviceKey, deviceKey)
            ? Object.freeze({
                  ...cloneEntry(entry),
                  status: "revoked" as const,
                  revokedAtRevision: revision,
              })
            : cloneEntry(entry),
    );
    return signRoster(
        {
            version: 1,
            accountKey: previous.accountKey.slice(),
            revision,
            parentHash: deviceRosterHash(previous),
            issuedAt,
            mutationId: mutationId.slice(),
            authorDeviceKey: authorDevice.publicKey.slice(),
            devices,
        },
        account,
        authorDevice,
    );
}

/** Sign one direct roster child advancing this active device's reset generation. */
export function resetDeviceInRoster(
    previous: MurmurDeviceRoster,
    account: IdentityKeyPair,
    authorDevice: IdentityKeyPair,
    deviceKey: Uint8Array,
    issuedAt: number,
    mutationId: Uint8Array,
): MurmurDeviceRoster {
    if (!verifyDeviceRoster(previous)) throw new Error("Invalid previous device roster");
    validateIdentityKeyPair(account);
    validateIdentityKeyPair(authorDevice);
    if (!equalBytes(account.publicKey, previous.accountKey)) {
        throw new Error("Roster account key does not match");
    }
    if (!isActiveDevice(previous, authorDevice.publicKey)) {
        throw new Error("Roster author is not active");
    }
    const target = previous.devices.find((entry) => equalBytes(entry.deviceKey, deviceKey));
    if (target?.status !== "active") throw new Error("Reset device is not active");
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0 || mutationId.length !== 16) {
        throw new Error("Invalid reset roster metadata");
    }
    const revision = previous.revision + 1;
    const devices = previous.devices.map((entry) =>
        equalBytes(entry.deviceKey, deviceKey)
            ? Object.freeze({
                  ...cloneEntry(entry),
                  resetGeneration: entry.resetGeneration + 1,
              })
            : cloneEntry(entry),
    );
    return signRoster(
        {
            version: 1,
            accountKey: previous.accountKey.slice(),
            revision,
            parentHash: deviceRosterHash(previous),
            issuedAt,
            mutationId: mutationId.slice(),
            authorDeviceKey: authorDevice.publicKey.slice(),
            devices,
        },
        account,
        authorDevice,
    );
}

/** Verify canonical roster shape plus account and author signatures. */
export function verifyDeviceRoster(roster: MurmurDeviceRoster): boolean {
    try {
        assertRosterShape(roster);
        return (
            verifyBytes(
                { publicKey: roster.accountKey },
                rosterTbs(roster),
                roster.accountSignature,
            ) &&
            verifyBytes(
                { publicKey: roster.authorDeviceKey },
                rosterAuthorTbs(roster),
                roster.authorSignature,
            )
        );
    } catch {
        return false;
    }
}

/** Return whether one device is active in an authenticated roster snapshot. */
export function isActiveDevice(roster: MurmurDeviceRoster, deviceKey: Uint8Array): boolean {
    return roster.devices.some(
        (entry) => entry.status === "active" && equalBytes(entry.deviceKey, deviceKey),
    );
}

/** Serialize one verified roster as strict canonical JSON. */
export function serializeDeviceRoster(roster: MurmurDeviceRoster): Uint8Array {
    if (!verifyDeviceRoster(roster)) throw new Error("Invalid device roster");
    return canonicalJsonBytes({
        ...(rosterTbsJson(roster) as Record<string, JsonValue>),
        accountSignature: encodeBase64Url(roster.accountSignature),
        authorSignature: encodeBase64Url(roster.authorSignature),
    });
}

/** Parse and authenticate one canonical roster snapshot. */
export function parseDeviceRoster(value: Uint8Array): MurmurDeviceRoster {
    if (value.length < 1 || value.length > MAXIMUM_ROSTER_BYTES) {
        throw new Error("Invalid device roster");
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value)) as unknown;
    } catch {
        throw new Error("Invalid device roster");
    }
    const input = object(parsed, "device roster");
    exact(
        input,
        [
            "accountKey",
            "accountSignature",
            "authorDeviceKey",
            "authorSignature",
            "devices",
            "issuedAt",
            "mutationId",
            "parentHash",
            "revision",
            "version",
        ],
        "device roster",
    );
    if (input.version !== 1 || !Array.isArray(input.devices)) {
        throw new Error("Invalid device roster");
    }
    const devices = input.devices.map((candidate) => {
        const entry = object(candidate, "device roster entry");
        exact(
            entry,
            [
                "addedAtRevision",
                "authorization",
                "deviceKey",
                "resetGeneration",
                "revokedAtRevision",
                "status",
            ].filter((field) => field !== "resetGeneration" || Object.hasOwn(entry, field)),
            "device roster entry",
        );
        if (entry.status !== "active" && entry.status !== "revoked") {
            throw new Error("Invalid device roster entry");
        }
        const revokedAtRevision =
            entry.revokedAtRevision === null
                ? undefined
                : safeInteger(entry.revokedAtRevision, 1, "device revocation revision");
        return Object.freeze({
            deviceKey: bytes(entry.deviceKey, 32, "device key"),
            addedAtRevision: safeInteger(entry.addedAtRevision, 1, "device addition revision"),
            authorization: bytes(entry.authorization, 64, "device authorization"),
            resetGeneration:
                entry.resetGeneration === undefined
                    ? 0
                    : safeInteger(entry.resetGeneration, 0, "device reset generation"),
            status: entry.status,
            ...(revokedAtRevision === undefined ? {} : { revokedAtRevision }),
        });
    });
    const roster: MurmurDeviceRoster = Object.freeze({
        version: 1,
        accountKey: bytes(input.accountKey, 32, "account key"),
        revision: safeInteger(input.revision, 1, "roster revision"),
        parentHash:
            input.parentHash === null ? null : bytes(input.parentHash, 32, "roster parent hash"),
        issuedAt: safeInteger(input.issuedAt, 0, "roster issue time"),
        mutationId: bytes(input.mutationId, 16, "roster mutation ID"),
        authorDeviceKey: bytes(input.authorDeviceKey, 32, "roster author device"),
        devices: Object.freeze(devices),
        accountSignature: bytes(input.accountSignature, 64, "roster account signature"),
        authorSignature: bytes(input.authorSignature, 64, "roster author signature"),
    });
    if (!verifyDeviceRoster(roster) || !equalBytes(serializeDeviceRoster(roster), value)) {
        throw new Error("Invalid device roster");
    }
    return roster;
}

/** Hash the exact authenticated roster encoding for parent and fork binding. */
export function deviceRosterHash(roster: MurmurDeviceRoster): Uint8Array {
    return sha256(serializeDeviceRoster(roster));
}

/** Select the deterministic winner among authenticated direct children. */
export function selectDeviceRosterChild(
    parent: MurmurDeviceRoster,
    candidates: readonly MurmurDeviceRoster[],
): MurmurDeviceRoster | undefined {
    if (!verifyDeviceRoster(parent)) throw new Error("Invalid parent device roster");
    const parentHash = deviceRosterHash(parent);
    const children = candidates.filter(
        (candidate) =>
            verifyDeviceRoster(candidate) &&
            equalBytes(candidate.accountKey, parent.accountKey) &&
            candidate.revision === parent.revision + 1 &&
            candidate.parentHash !== null &&
            equalBytes(candidate.parentHash, parentHash) &&
            isActiveDevice(parent, candidate.authorDeviceKey),
    );
    return children
        .map((roster) => ({ roster, hash: deviceRosterHash(roster) }))
        .sort((left, right) => compareBytes(right.hash, left.hash))[0]?.roster;
}

/** Encode the account authorization used as one MLS BasicCredential identity. */
export function encodeDeviceCredential(
    roster: MurmurDeviceRoster,
    deviceKey: Uint8Array,
): Uint8Array {
    if (!verifyDeviceRoster(roster)) throw new Error("Invalid device roster");
    const entry = roster.devices.find((candidate) => equalBytes(candidate.deviceKey, deviceKey));
    if (entry?.status !== "active") throw new Error("Device is not active");
    return canonicalJsonBytes({
        accountKey: encodeBase64Url(roster.accountKey),
        addedAtRevision: entry.addedAtRevision,
        authorization: encodeBase64Url(entry.authorization),
        deviceKey: encodeBase64Url(entry.deviceKey),
        protocol: DEVICE_CREDENTIAL_DOMAIN,
        version: 1,
    });
}

/** Parse and verify an account-authorized MLS device credential. */
export function decodeDeviceCredential(value: Uint8Array): MurmurDeviceCredential {
    if (value.length < 1 || value.length > 1024) throw new Error("Invalid device credential");
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value)) as unknown;
    } catch {
        throw new Error("Invalid device credential");
    }
    const input = object(parsed, "device credential");
    exact(
        input,
        ["accountKey", "addedAtRevision", "authorization", "deviceKey", "protocol", "version"],
        "device credential",
    );
    if (input.version !== 1 || input.protocol !== DEVICE_CREDENTIAL_DOMAIN) {
        throw new Error("Invalid device credential");
    }
    const credential: MurmurDeviceCredential = Object.freeze({
        version: 1,
        accountKey: bytes(input.accountKey, 32, "credential account key"),
        deviceKey: bytes(input.deviceKey, 32, "credential device key"),
        addedAtRevision: safeInteger(input.addedAtRevision, 1, "credential roster revision"),
        authorization: bytes(input.authorization, 64, "credential authorization"),
    });
    validateIdentityPublicKey({ publicKey: credential.accountKey });
    validateIdentityPublicKey({ publicKey: credential.deviceKey });
    const canonical = canonicalJsonBytes({
        accountKey: encodeBase64Url(credential.accountKey),
        addedAtRevision: credential.addedAtRevision,
        authorization: encodeBase64Url(credential.authorization),
        deviceKey: encodeBase64Url(credential.deviceKey),
        protocol: DEVICE_CREDENTIAL_DOMAIN,
        version: 1,
    });
    if (
        !verifyBytes(
            { publicKey: credential.accountKey },
            authorizationBytes(
                credential.accountKey,
                credential.deviceKey,
                credential.addedAtRevision,
            ),
            credential.authorization,
        ) ||
        !equalBytes(canonical, value)
    ) {
        throw new Error("Invalid device credential");
    }
    return credential;
}
