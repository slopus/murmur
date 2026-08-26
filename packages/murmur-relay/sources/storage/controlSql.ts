import { sha256 } from "@noble/hashes/sha2";
import {
    RelayError,
    deviceRosterToJson,
    parseSignedDelivery,
    signedDeliveryToJson,
    type DeviceRoster,
    type DeviceRosterMutation,
    type DirectoryClaim,
    type DirectoryPrekeyUpload,
    type SignedDelivery,
} from "../protocol/index.js";
import type { DirectoryTicketClaims } from "../directory/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { copyBytes, equalBytes, safeNumberColumn } from "../utils/bytes.js";
import { resolveSessionPublication, type RelaySessionState } from "./sessionState.js";

const MAXIMUM_DIRECTORY_PREKEYS_PER_DEVICE = 256;
const ACCOUNT_DELETION_NONCE_RETENTION_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;

/** Canonical SQLite reads shared by standalone and Durable Object control stores. */
export const RELAY_CONTROL_SQL = Object.freeze({
    readDeviceAccount: "SELECT account_key FROM murmur_device_roster_devices WHERE device_key = ?",
    readRoster: "SELECT revision FROM murmur_device_rosters WHERE account_key = ?",
    readRosterDevices: `SELECT device_key, reset_generation, key_package
        FROM murmur_device_roster_devices
        WHERE account_key = ? ORDER BY device_key`,
    readSession: `SELECT owner_account, epoch, admins_assign_admins,
        anyone_can_add_members, send_policy
        FROM murmur_sessions WHERE session_id = ?`,
    readSessionMembers: `SELECT account_key, roster_revision FROM murmur_session_members
        WHERE session_id = ? ORDER BY account_key`,
    readSessionAdmins: `SELECT account_key FROM murmur_session_admins
        WHERE session_id = ? ORDER BY account_key`,
});

/** Value accepted by both Cloudflare Durable Object SQLite and node:sqlite. */
export type RelayControlSqlValue = Uint8Array | string | number | null;

/** Synchronous SQLite result surface shared by Durable Objects and node:sqlite adapters. */
export interface RelayControlSqlCursor<Row extends Record<string, unknown>> {
    toArray(): Row[];
    one(): Row;
}

/** Small synchronous SQLite execution surface used by relay control state. */
export interface RelayControlSql {
    exec<Row extends Record<string, unknown>>(
        query: string,
        ...bindings: readonly RelayControlSqlValue[]
    ): RelayControlSqlCursor<Row>;
}

/** One terminal-account purge that still has inbox Durable Objects to clear. */
export interface PendingAccountPurge {
    readonly accountDigest: Uint8Array;
    readonly deviceKeys: readonly Uint8Array[];
}

/** Directory claim plus durable notifications that must be fanned out. */
export interface RelayControlDirectoryClaim {
    readonly claim: DirectoryClaim;
    readonly notifications: readonly SignedDelivery[];
}

function textColumn(value: unknown, name: string): string {
    if (typeof value !== "string") throw new Error(`Invalid ${name} in relay control state`);
    return value;
}

function integerColumn(value: unknown, name: string): number {
    try {
        return safeNumberColumn(value);
    } catch {
        throw new Error(`Invalid ${name} in relay control state`);
    }
}

function epochColumn(value: unknown): bigint {
    if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
        return BigInt(value);
    }
    throw new Error("Invalid session epoch in relay control state");
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = left[index]! - right[index]!;
        if (difference !== 0) return difference;
    }
    return 0;
}

/** Shared synchronous SQL implementation of roster, directory, and session control state. */
export class RelayControlSqlStore {
    readonly #sql: RelayControlSql;

    constructor(sql: RelayControlSql, initialize: boolean = true) {
        this.#sql = sql;
        if (initialize) this.#initialize();
    }

    /** Resolve the authoritative account currently owning one exact device key. */
    readDeviceAccount(deviceKey: Uint8Array): Uint8Array | undefined {
        const row = this.#get(RELAY_CONTROL_SQL.readDeviceAccount, deviceKey);
        return row === undefined ? undefined : copyBytes(row.account_key, "device account key");
    }

    /** Read one exact current account roster. */
    readDeviceRoster(accountKey: Uint8Array): DeviceRoster | undefined {
        const row = this.#get(RELAY_CONTROL_SQL.readRoster, accountKey);
        if (row === undefined) return undefined;
        const entries = this.#all(RELAY_CONTROL_SQL.readRosterDevices, accountKey);
        return {
            version: 1,
            accountKey: accountKey.slice(),
            revision: integerColumn(row.revision, "roster revision"),
            devices: entries.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                resetGeneration: integerColumn(entry.reset_generation, "device reset generation"),
            })),
            admissions: entries.map((entry) => ({
                deviceKey: copyBytes(entry.device_key, "roster device key"),
                keyPackage: copyBytes(entry.key_package, "roster KeyPackage"),
            })),
        };
    }

    /** Read relay-visible membership and role state for one exact session. */
    readSessionState(sessionId: Uint8Array): RelaySessionState | undefined {
        const row = this.#get(RELAY_CONTROL_SQL.readSession, sessionId);
        if (row === undefined) return undefined;
        const members = this.#all(RELAY_CONTROL_SQL.readSessionMembers, sessionId);
        const sendPolicy = textColumn(row.send_policy, "session send policy");
        if (sendPolicy !== "everyone" && sendPolicy !== "admins") {
            throw new Error("Invalid relay control session send policy");
        }
        return {
            sessionId: sessionId.slice(),
            epoch: epochColumn(row.epoch),
            ownerAccount: copyBytes(row.owner_account, "session owner account"),
            members: members.map((entry) => copyBytes(entry.account_key, "session member account")),
            rosterRevisions: members.map((entry) => ({
                accountKey: copyBytes(entry.account_key, "session member account"),
                revision: integerColumn(entry.roster_revision, "session roster revision"),
            })),
            admins: this.#all(RELAY_CONTROL_SQL.readSessionAdmins, sessionId).map((entry) =>
                copyBytes(entry.account_key, "session admin account"),
            ),
            adminsAssignAdmins: integerColumn(row.admins_assign_admins, "admin policy") === 1,
            anyoneCanAddMembers: integerColumn(row.anyone_can_add_members, "member policy") === 1,
            sendPolicy,
        };
    }

    /** Validate direct account targeting against current roster state. */
    resolveDirectRecipients(delivery: SignedDelivery): readonly Uint8Array[] {
        const authoritativeAccount = this.readDeviceAccount(delivery.sender);
        if (
            authoritativeAccount === undefined
                ? !equalBytes(delivery.senderAccount, delivery.sender)
                : !equalBytes(delivery.senderAccount, authoritativeAccount)
        ) {
            throw new RelayError(401, "Delivery sender account is not authoritative", {
                error: "unauthorized",
            });
        }
        const stale: DeviceRoster[] = [];
        const current: DeviceRoster[] = [];
        for (const target of delivery.targetAccounts) {
            const roster = this.readDeviceRoster(target.accountKey);
            if (roster === undefined) {
                throw new RelayError(409, "Target account has no registered devices", {
                    error: "roster_missing",
                    accountKey: encodeBase64Url(target.accountKey),
                });
            }
            current.push(roster);
            if (
                roster.revision !== target.rosterRevision ||
                roster.devices.some(
                    (entry) =>
                        !delivery.recipients.some((recipient) =>
                            equalBytes(recipient, entry.deviceKey),
                        ),
                )
            ) {
                stale.push(roster);
            }
        }
        if (stale.length === 0 && current.length > 0) {
            const devices = new Set(
                current.flatMap((roster) =>
                    roster.devices.map((entry) => encodeBase64Url(entry.deviceKey)),
                ),
            );
            if (
                devices.size !== delivery.recipients.length ||
                delivery.recipients.some((recipient) => !devices.has(encodeBase64Url(recipient)))
            ) {
                stale.push(...current);
            }
        }
        if (stale.length > 0) {
            throw new RelayError(409, "Delivery does not match current account devices", {
                error: "stale_roster",
                rosters: stale.map(deviceRosterToJson),
            });
        }
        return delivery.recipients;
    }

    /** Validate session policy and atomically advance relay-visible state. */
    resolveSessionRecipients(
        delivery: SignedDelivery,
        maximumRecipients: number,
    ): readonly Uint8Array[] {
        const control = delivery.sessionControl;
        if (control === null || delivery.sessionId === null || delivery.ownerAccount === null) {
            throw new Error("Missing session-addressed delivery control");
        }
        const authoritativeAccount = this.readDeviceAccount(delivery.sender);
        if (
            authoritativeAccount === undefined ||
            !equalBytes(delivery.senderAccount, authoritativeAccount)
        ) {
            throw new RelayError(401, "Delivery sender account is not authoritative", {
                error: "unauthorized",
            });
        }
        const resolved = resolveSessionPublication(
            delivery.sessionId,
            delivery.ownerAccount,
            delivery.senderAccount,
            control,
            this.readSessionState(delivery.sessionId),
        );
        for (const change of control.type === "commit" ? control.changes : []) {
            if (change.type !== "add") continue;
            const account = this.readDeviceAccount(change.deviceKey);
            if (account === undefined || !equalBytes(account, change.accountKey)) {
                throw new RelayError(403, "Session Add does not name a current account device", {
                    error: "session_unauthorized",
                });
            }
        }
        const coverage = new Set(control.coveredDevices.map(encodeBase64Url));
        const coverageAccounts = new Set(resolved.coverageAccounts.map(encodeBase64Url));
        const acceptedRevisions = new Map(
            resolved.nextState.rosterRevisions.map((entry) => [
                encodeBase64Url(entry.accountKey),
                entry.revision,
            ]),
        );
        const currentRosters = new Map<string, DeviceRoster>();
        const fanout = new Map<string, Uint8Array>();
        const stale: DeviceRoster[] = [];
        const expectedCoverage = new Set<string>();
        const coverageRosters: DeviceRoster[] = [];
        for (const account of resolved.fanoutAccounts) {
            const roster = this.readDeviceRoster(account);
            if (roster === undefined) {
                if (coverageAccounts.has(encodeBase64Url(account))) {
                    throw new RelayError(409, "Session member account has no registered devices", {
                        error: "roster_missing",
                        accountKey: encodeBase64Url(account),
                    });
                }
                continue;
            }
            for (const device of roster.devices) {
                fanout.set(encodeBase64Url(device.deviceKey), device.deviceKey);
            }
            const encodedAccount = encodeBase64Url(account);
            currentRosters.set(encodedAccount, roster);
            if (coverageAccounts.has(encodedAccount)) {
                coverageRosters.push(roster);
                for (const device of roster.devices) {
                    expectedCoverage.add(encodeBase64Url(device.deviceKey));
                }
            }
            if (
                coverageAccounts.has(encodedAccount) &&
                (roster.devices.some(
                    (device) => !coverage.has(encodeBase64Url(device.deviceKey)),
                ) ||
                    (!resolved.stateChanged &&
                        acceptedRevisions.get(encodedAccount) !== roster.revision))
            ) {
                stale.push(roster);
            }
        }
        if (
            coverageAccounts.size > 0 &&
            (coverage.size !== expectedCoverage.size ||
                [...coverage].some((device) => !expectedCoverage.has(device)))
        ) {
            const staleAccounts = new Set(
                stale.map((roster) => encodeBase64Url(roster.accountKey)),
            );
            for (const roster of coverageRosters) {
                if (!staleAccounts.has(encodeBase64Url(roster.accountKey))) stale.push(roster);
            }
        }
        if (stale.length > 0) {
            throw new RelayError(409, "MLS epoch does not cover every current member device", {
                error: "stale_epoch_coverage",
                rosters: stale.map(deviceRosterToJson),
            });
        }
        const recipients = [...fanout.entries()]
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([, device]) => device);
        if (recipients.length < 1 || recipients.length > maximumRecipients) {
            throw new RelayError(413, "Session fanout exceeds relay limit", { error: "limit" });
        }
        if (resolved.stateChanged) {
            this.#writeSessionState({
                ...resolved.nextState,
                rosterRevisions: resolved.coverageAccounts.map((accountKey) => ({
                    accountKey,
                    revision: currentRosters.get(encodeBase64Url(accountKey))!.revision,
                })),
            });
        }
        return recipients;
    }

    /** Apply one replay-protected current-roster mutation. */
    mutateDeviceRoster(
        delivery: SignedDelivery,
        mutation: DeviceRosterMutation,
        now: number,
    ): DeviceRoster {
        if (
            this.#get(
                `SELECT 1 AS present FROM murmur_device_roster_nonces
                 WHERE account_key = ? AND nonce = ?`,
                delivery.sender,
                delivery.id,
            ) !== undefined
        ) {
            throw new RelayError(409, "Device roster mutation was already used", {
                error: "replay",
            });
        }
        const current = this.readDeviceRoster(delivery.sender);
        const devices = new Map(
            (current?.devices ?? []).map((entry) => [encodeBase64Url(entry.deviceKey), entry]),
        );
        const admissions = new Map(
            (current?.admissions ?? []).map((entry) => [encodeBase64Url(entry.deviceKey), entry]),
        );
        const encodedDevice = encodeBase64Url(mutation.deviceKey);
        const existing = devices.get(encodedDevice);
        if (mutation.type === "register") {
            const expectedGeneration = existing === undefined ? 0 : existing.resetGeneration + 1;
            if (mutation.resetGeneration !== expectedGeneration) {
                throw new RelayError(409, "Device reset generation is stale", {
                    error: "reset_generation",
                    expectedGeneration,
                });
            }
            devices.set(encodedDevice, {
                deviceKey: mutation.deviceKey,
                resetGeneration: mutation.resetGeneration,
            });
            admissions.set(encodedDevice, {
                deviceKey: mutation.deviceKey,
                keyPackage: mutation.keyPackage,
            });
        } else {
            if (existing === undefined || mutation.resetGeneration !== existing.resetGeneration) {
                throw new RelayError(409, "Device removal names stale roster state", {
                    error: "reset_generation",
                    expectedGeneration: existing?.resetGeneration ?? null,
                });
            }
            devices.delete(encodedDevice);
            admissions.delete(encodedDevice);
        }
        const sortedDevices = [...devices.values()].sort((left, right) =>
            compareBytes(left.deviceKey, right.deviceKey),
        );
        if (
            delivery.targetAccounts.length !== 0 ||
            delivery.recipients.length !== sortedDevices.length ||
            sortedDevices.some(
                (entry, index) => !equalBytes(entry.deviceKey, delivery.recipients[index]!),
            )
        ) {
            throw new RelayError(409, "Roster mutation recipients are stale", {
                error: "stale_roster",
                ...(current === undefined ? {} : { rosters: [deviceRosterToJson(current)] }),
            });
        }
        const revision = (current?.revision ?? 0) + 1;
        this.#run(
            `INSERT INTO murmur_device_rosters (account_key, revision) VALUES (?, ?)
             ON CONFLICT (account_key) DO UPDATE SET revision = excluded.revision`,
            delivery.sender,
            revision,
        );
        if (mutation.type === "remove" || existing !== undefined) {
            this.#run(
                `DELETE FROM murmur_device_roster_devices
                 WHERE account_key = ? AND device_key = ?`,
                delivery.sender,
                mutation.deviceKey,
            );
        }
        for (const entry of sortedDevices) {
            const admission = admissions.get(encodeBase64Url(entry.deviceKey));
            if (admission === undefined) throw new Error("Missing roster admission");
            this.#run(
                `INSERT INTO murmur_device_roster_devices
                    (account_key, device_key, reset_generation, key_package)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (account_key, device_key) DO UPDATE SET
                    reset_generation = excluded.reset_generation,
                    key_package = excluded.key_package`,
                delivery.sender,
                entry.deviceKey,
                entry.resetGeneration,
                admission.keyPackage,
            );
        }
        this.#run(
            `INSERT INTO murmur_device_roster_nonces (account_key, nonce, created_at)
             VALUES (?, ?, ?)`,
            delivery.sender,
            delivery.id,
            now,
        );
        return this.readDeviceRoster(delivery.sender)!;
    }

    /** Replace or replenish one registered device's directory pool. */
    uploadDirectoryPrekeys(
        delivery: SignedDelivery,
        upload: DirectoryPrekeyUpload,
        now: number,
    ): void {
        if (
            this.#get(
                `SELECT 1 AS present FROM murmur_directory_upload_nonces
                 WHERE account_key = ? AND nonce = ?`,
                delivery.sender,
                delivery.id,
            ) !== undefined
        ) {
            throw new RelayError(409, "Directory upload was already used", { error: "replay" });
        }
        const roster = this.readDeviceRoster(delivery.sender);
        const device = roster?.devices.find((entry) =>
            equalBytes(entry.deviceKey, upload.deviceKey),
        );
        if (device === undefined || device.resetGeneration !== upload.resetGeneration) {
            throw new RelayError(409, "Directory upload names stale roster state", {
                error: "reset_generation",
                expectedGeneration: device?.resetGeneration ?? null,
            });
        }
        this.#run(`DELETE FROM murmur_directory_prekeys WHERE expires_at <= ?`, now);
        const currentDirectory = this.#get(
            `SELECT last_resort_reference, last_resort_expires_at
             FROM murmur_directory_devices WHERE account_key = ? AND device_key = ?`,
            delivery.sender,
            upload.deviceKey,
        );
        const currentAdmission = roster!.admissions.find((entry) =>
            equalBytes(entry.deviceKey, upload.deviceKey),
        );
        if (upload.mode === "replenish") {
            if (
                currentDirectory === undefined ||
                currentAdmission === undefined ||
                !equalBytes(
                    copyBytes(currentDirectory.last_resort_reference, "last-resort reference"),
                    upload.lastResort.reference,
                ) ||
                integerColumn(currentDirectory.last_resort_expires_at, "last-resort expiration") !==
                    upload.lastResort.expiresAt ||
                !equalBytes(currentAdmission.keyPackage, upload.lastResort.keyPackage)
            ) {
                throw new RelayError(409, "Directory last-resort prekey is stale", {
                    error: "last_resort_stale",
                });
            }
        } else {
            this.#run(
                `DELETE FROM murmur_directory_prekeys WHERE account_key = ? AND device_key = ?`,
                delivery.sender,
                upload.deviceKey,
            );
            const reassertsCurrent =
                currentDirectory !== undefined &&
                currentAdmission !== undefined &&
                equalBytes(
                    copyBytes(currentDirectory.last_resort_reference, "last-resort reference"),
                    upload.lastResort.reference,
                ) &&
                integerColumn(currentDirectory.last_resort_expires_at, "last-resort expiration") ===
                    upload.lastResort.expiresAt &&
                equalBytes(currentAdmission.keyPackage, upload.lastResort.keyPackage);
            const published =
                this.#get(
                    `SELECT 1 AS present FROM murmur_directory_prekey_references
                     WHERE account_key = ? AND device_key = ? AND reference = ?`,
                    delivery.sender,
                    upload.deviceKey,
                    upload.lastResort.reference,
                ) !== undefined;
            if (published && !reassertsCurrent) {
                throw new RelayError(409, "Directory prekey reference was already published", {
                    error: "prekey_reuse",
                });
            }
            if (!published) {
                this.#run(
                    `INSERT INTO murmur_directory_prekey_references
                        (account_key, device_key, reference, first_seen_at) VALUES (?, ?, ?, ?)`,
                    delivery.sender,
                    upload.deviceKey,
                    upload.lastResort.reference,
                    now,
                );
            }
        }
        if (upload.lastResort.expiresAt <= now) {
            throw new RelayError(409, "Last-resort prekey is expired", {
                error: "prekey_expired",
            });
        }
        this.#run(
            `INSERT INTO murmur_directory_devices
                (account_key, device_key, last_resort_reference, last_resort_expires_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (account_key, device_key) DO UPDATE SET
                last_resort_reference = excluded.last_resort_reference,
                last_resort_expires_at = excluded.last_resort_expires_at`,
            delivery.sender,
            upload.deviceKey,
            upload.lastResort.reference,
            upload.lastResort.expiresAt,
        );
        this.#run(
            `UPDATE murmur_device_roster_devices SET key_package = ?
             WHERE account_key = ? AND device_key = ?`,
            upload.lastResort.keyPackage,
            delivery.sender,
            upload.deviceKey,
        );
        const additions: DirectoryPrekeyUpload["oneTimePrekeys"][number][] = [];
        for (const entry of upload.oneTimePrekeys) {
            if (entry.expiresAt <= now) {
                throw new RelayError(409, "Directory prekey is expired", {
                    error: "prekey_expired",
                });
            }
            const active = this.#get(
                `SELECT key_package, expires_at FROM murmur_directory_prekeys
                 WHERE account_key = ? AND device_key = ? AND reference = ?`,
                delivery.sender,
                upload.deviceKey,
                entry.reference,
            );
            if (active !== undefined) {
                if (
                    !equalBytes(
                        copyBytes(active.key_package, "directory KeyPackage"),
                        entry.keyPackage,
                    ) ||
                    integerColumn(active.expires_at, "directory prekey expiration") !==
                        entry.expiresAt
                ) {
                    throw new RelayError(409, "Directory prekey reference was already published", {
                        error: "prekey_reuse",
                    });
                }
                continue;
            }
            if (
                this.#get(
                    `SELECT 1 AS present FROM murmur_directory_prekey_references
                     WHERE account_key = ? AND device_key = ? AND reference = ?`,
                    delivery.sender,
                    upload.deviceKey,
                    entry.reference,
                ) !== undefined
            ) {
                throw new RelayError(409, "Directory prekey reference was already published", {
                    error: "prekey_reuse",
                });
            }
            additions.push(entry);
        }
        const activeCount = this.#requiredGet(
            `SELECT COUNT(*) AS item_count FROM murmur_directory_prekeys
             WHERE account_key = ? AND device_key = ?`,
            delivery.sender,
            upload.deviceKey,
        );
        if (
            integerColumn(activeCount.item_count, "directory prekey count") + additions.length >
            MAXIMUM_DIRECTORY_PREKEYS_PER_DEVICE
        ) {
            throw new RelayError(413, "Directory prekey pool exceeds relay limit", {
                error: "limit",
            });
        }
        for (const entry of additions) {
            this.#run(
                `INSERT INTO murmur_directory_prekey_references
                    (account_key, device_key, reference, first_seen_at) VALUES (?, ?, ?, ?)`,
                delivery.sender,
                upload.deviceKey,
                entry.reference,
                now,
            );
            this.#run(
                `INSERT INTO murmur_directory_prekeys
                    (account_key, device_key, reference, key_package, notification_json,
                     expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                delivery.sender,
                upload.deviceKey,
                entry.reference,
                entry.keyPackage,
                JSON.stringify(signedDeliveryToJson(entry.spentNotification)),
                entry.expiresAt,
                now,
            );
        }
        this.#run(
            `INSERT INTO murmur_directory_upload_nonces (account_key, nonce, created_at)
             VALUES (?, ?, ?)`,
            delivery.sender,
            delivery.id,
            now,
        );
    }

    /** Spend one ticket use and claim one prekey per current device. */
    claimDirectory(
        accountKey: Uint8Array,
        ticket: DirectoryTicketClaims,
        now: number,
    ): RelayControlDirectoryClaim {
        const usage = this.#get(
            `SELECT claim_budget, claims_used, expires_at
             FROM murmur_directory_ticket_uses WHERE issuer = ? AND ticket_id = ?`,
            ticket.issuer,
            ticket.ticketId,
        );
        if (usage === undefined) {
            this.#run(
                `INSERT INTO murmur_directory_ticket_uses
                    (issuer, ticket_id, claim_budget, claims_used, expires_at)
                 VALUES (?, ?, ?, 1, ?)`,
                ticket.issuer,
                ticket.ticketId,
                ticket.claimBudget,
                ticket.expiresAt,
            );
        } else {
            if (
                integerColumn(usage.claim_budget, "directory claim budget") !==
                    ticket.claimBudget ||
                integerColumn(usage.expires_at, "directory ticket expiration") !==
                    ticket.expiresAt ||
                integerColumn(usage.claims_used, "directory claims used") >= ticket.claimBudget
            ) {
                throw new RelayError(429, "Directory ticket claim budget is exhausted", {
                    error: "ticket_exhausted",
                });
            }
            this.#run(
                `UPDATE murmur_directory_ticket_uses SET claims_used = claims_used + 1
                 WHERE issuer = ? AND ticket_id = ?`,
                ticket.issuer,
                ticket.ticketId,
            );
        }
        this.#run(`DELETE FROM murmur_directory_prekeys WHERE expires_at <= ?`, now);
        const roster = this.readDeviceRoster(accountKey);
        if (roster === undefined) {
            return {
                claim: {
                    version: 1,
                    accountKey: accountKey.slice(),
                    rosterRevision: 0,
                    devices: [],
                },
                notifications: [],
            };
        }
        const devices: DirectoryClaim["devices"][number][] = [];
        const notifications: SignedDelivery[] = [];
        for (const device of roster.devices) {
            const prekey = this.#get(
                `SELECT reference, key_package, notification_json
                 FROM murmur_directory_prekeys
                 WHERE account_key = ? AND device_key = ? AND expires_at > ?
                 ORDER BY created_at, reference LIMIT 1`,
                accountKey,
                device.deviceKey,
                now,
            );
            if (prekey === undefined) {
                const admission = roster.admissions.find((entry) =>
                    equalBytes(entry.deviceKey, device.deviceKey),
                );
                if (admission === undefined) throw new Error("Missing last-resort KeyPackage");
                devices.push({
                    deviceKey: device.deviceKey.slice(),
                    resetGeneration: device.resetGeneration,
                    keyPackage: admission.keyPackage.slice(),
                    source: "last_resort",
                });
                continue;
            }
            const reference = copyBytes(prekey.reference, "directory prekey reference");
            this.#run(
                `DELETE FROM murmur_directory_prekeys
                 WHERE account_key = ? AND device_key = ? AND reference = ?`,
                accountKey,
                device.deviceKey,
                reference,
            );
            devices.push({
                deviceKey: device.deviceKey.slice(),
                resetGeneration: device.resetGeneration,
                keyPackage: copyBytes(prekey.key_package, "directory KeyPackage"),
                source: "one_time",
            });
            notifications.push(
                parseSignedDelivery(
                    JSON.parse(
                        textColumn(prekey.notification_json, "notification JSON"),
                    ) as unknown,
                ),
            );
        }
        return {
            claim: {
                version: 1,
                accountKey: accountKey.slice(),
                rosterRevision: roster.revision,
                devices,
            },
            notifications,
        };
    }

    /** Delete one owner-authorized relay session state row. */
    deleteSession(ownerAccount: Uint8Array, sessionId: Uint8Array): void {
        this.#run(
            `DELETE FROM murmur_sessions WHERE session_id = ? AND owner_account = ?`,
            sessionId,
            ownerAccount,
        );
    }

    /** Purge all account-linked control state and durably enqueue inbox deletion. */
    deleteAccount(accountKey: Uint8Array, requestId: string, now: number): void {
        const accountDigest = sha256(accountKey);
        this.#run(
            `DELETE FROM murmur_account_deletion_nonces WHERE created_at < ?`,
            now - ACCOUNT_DELETION_NONCE_RETENTION_MILLISECONDS,
        );
        if (
            this.#get(
                `SELECT 1 AS present FROM murmur_account_deletion_nonces
                 WHERE account_digest = ? AND request_id = ?`,
                accountDigest,
                requestId,
            ) !== undefined
        ) {
            throw new RelayError(409, "Account deletion was already applied", {
                error: "replay",
            });
        }
        const devices = this.#all(
            `SELECT device_key FROM murmur_device_roster_devices
             WHERE account_key = ? ORDER BY device_key`,
            accountKey,
        ).map((row) => copyBytes(row.device_key, "account device key"));
        const affectedSessions = this.#all(
            `SELECT session_id FROM murmur_session_members WHERE account_key = ?`,
            accountKey,
        ).map((row) => copyBytes(row.session_id, "account session ID"));
        for (const sessionId of affectedSessions) {
            this.#run(`DELETE FROM murmur_sessions WHERE session_id = ?`, sessionId);
        }
        this.#run(`DELETE FROM murmur_sessions WHERE owner_account = ?`, accountKey);
        this.#run(`DELETE FROM murmur_device_rosters WHERE account_key = ?`, accountKey);
        this.#run(
            `INSERT INTO murmur_account_deletion_nonces
                (account_digest, request_id, created_at) VALUES (?, ?, ?)`,
            accountDigest,
            requestId,
            now,
        );
        const inboxes = new Map(
            [accountKey, ...devices].map((device) => [encodeBase64Url(device), device]),
        );
        for (const device of inboxes.values()) {
            this.#run(
                `INSERT OR IGNORE INTO murmur_account_purge_devices
                    (account_digest, device_key) VALUES (?, ?)`,
                accountDigest,
                device,
            );
        }
    }

    /** Read every pending account purge grouped by deletion digest. */
    pendingAccountPurges(): readonly PendingAccountPurge[] {
        const grouped = new Map<string, { digest: Uint8Array; devices: Uint8Array[] }>();
        for (const row of this.#all(
            `SELECT account_digest, device_key FROM murmur_account_purge_devices
             ORDER BY account_digest, device_key`,
        )) {
            const digest = copyBytes(row.account_digest, "account purge digest");
            const encoded = encodeBase64Url(digest);
            const group = grouped.get(encoded) ?? { digest, devices: [] };
            group.devices.push(copyBytes(row.device_key, "account purge device"));
            grouped.set(encoded, group);
        }
        return [...grouped.values()].map((group) => ({
            accountDigest: group.digest,
            deviceKeys: group.devices,
        }));
    }

    /** Mark one idempotent inbox purge complete. */
    completeAccountPurgeDevice(accountDigest: Uint8Array, deviceKey: Uint8Array): void {
        this.#run(
            `DELETE FROM murmur_account_purge_devices
             WHERE account_digest = ? AND device_key = ?`,
            accountDigest,
            deviceKey,
        );
    }

    #writeSessionState(state: RelaySessionState): void {
        this.#run(
            `INSERT INTO murmur_sessions
                (session_id, owner_account, epoch, admins_assign_admins,
                 anyone_can_add_members, send_policy) VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (session_id) DO UPDATE SET
                owner_account = excluded.owner_account,
                epoch = excluded.epoch,
                admins_assign_admins = excluded.admins_assign_admins,
                anyone_can_add_members = excluded.anyone_can_add_members,
                send_policy = excluded.send_policy`,
            state.sessionId,
            state.ownerAccount,
            state.epoch.toString(),
            state.adminsAssignAdmins ? 1 : 0,
            state.anyoneCanAddMembers ? 1 : 0,
            state.sendPolicy,
        );
        this.#run(`DELETE FROM murmur_session_members WHERE session_id = ?`, state.sessionId);
        this.#run(`DELETE FROM murmur_session_admins WHERE session_id = ?`, state.sessionId);
        const revisions = new Map(
            state.rosterRevisions.map((entry) => [
                encodeBase64Url(entry.accountKey),
                entry.revision,
            ]),
        );
        for (const account of state.members) {
            this.#run(
                `INSERT INTO murmur_session_members
                    (session_id, account_key, roster_revision) VALUES (?, ?, ?)`,
                state.sessionId,
                account,
                revisions.get(encodeBase64Url(account))!,
            );
        }
        for (const account of state.admins) {
            this.#run(
                `INSERT INTO murmur_session_admins (session_id, account_key) VALUES (?, ?)`,
                state.sessionId,
                account,
            );
        }
    }

    #initialize(): void {
        this.#sql.exec(`
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS murmur_control_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL CHECK (version = 1)
            ) STRICT;
            INSERT OR IGNORE INTO murmur_control_schema (singleton, version) VALUES (1, 1);
            CREATE TABLE IF NOT EXISTS murmur_device_rosters (
                account_key BLOB PRIMARY KEY CHECK (length(account_key) = 32),
                revision INTEGER NOT NULL CHECK (revision >= 1)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_device_roster_devices (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                device_key BLOB NOT NULL CHECK (length(device_key) = 32),
                reset_generation INTEGER NOT NULL CHECK (reset_generation >= 0),
                key_package BLOB NOT NULL CHECK (length(key_package) > 0),
                PRIMARY KEY (account_key, device_key)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS murmur_device_roster_device_identity
                ON murmur_device_roster_devices(device_key);
            CREATE TABLE IF NOT EXISTS murmur_device_roster_nonces (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, nonce)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_sessions (
                session_id BLOB PRIMARY KEY CHECK (length(session_id) = 32),
                owner_account BLOB NOT NULL CHECK (length(owner_account) = 32),
                epoch TEXT NOT NULL CHECK (
                    length(epoch) >= 1
                    AND substr(epoch, 1, 1) BETWEEN '1' AND '9'
                    AND epoch NOT GLOB '*[^0-9]*'
                ),
                admins_assign_admins INTEGER NOT NULL CHECK (admins_assign_admins IN (0, 1)),
                anyone_can_add_members INTEGER NOT NULL CHECK (anyone_can_add_members IN (0, 1)),
                send_policy TEXT NOT NULL CHECK (send_policy IN ('everyone', 'admins'))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS murmur_session_owner ON murmur_sessions(owner_account);
            CREATE TABLE IF NOT EXISTS murmur_session_members (
                session_id BLOB NOT NULL REFERENCES murmur_sessions(session_id) ON DELETE CASCADE,
                account_key BLOB NOT NULL CHECK (length(account_key) = 32),
                roster_revision INTEGER NOT NULL CHECK (roster_revision >= 1),
                PRIMARY KEY (session_id, account_key)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS murmur_session_member_account
                ON murmur_session_members(account_key);
            CREATE TABLE IF NOT EXISTS murmur_session_admins (
                session_id BLOB NOT NULL REFERENCES murmur_sessions(session_id) ON DELETE CASCADE,
                account_key BLOB NOT NULL CHECK (length(account_key) = 32),
                PRIMARY KEY (session_id, account_key)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_directory_devices (
                account_key BLOB NOT NULL,
                device_key BLOB NOT NULL,
                last_resort_reference BLOB NOT NULL CHECK (length(last_resort_reference) = 32),
                last_resort_expires_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, device_key),
                FOREIGN KEY (account_key, device_key)
                    REFERENCES murmur_device_roster_devices(account_key, device_key)
                    ON DELETE CASCADE
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_directory_prekeys (
                account_key BLOB NOT NULL,
                device_key BLOB NOT NULL,
                reference BLOB NOT NULL CHECK (length(reference) = 32),
                key_package BLOB NOT NULL CHECK (length(key_package) > 0),
                notification_json TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, device_key, reference),
                FOREIGN KEY (account_key, device_key)
                    REFERENCES murmur_directory_devices(account_key, device_key)
                    ON DELETE CASCADE
            ) STRICT;
            CREATE INDEX IF NOT EXISTS murmur_directory_prekey_claim
                ON murmur_directory_prekeys(account_key, device_key, created_at, reference);
            CREATE TABLE IF NOT EXISTS murmur_directory_prekey_references (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                device_key BLOB NOT NULL CHECK (length(device_key) = 32),
                reference BLOB NOT NULL CHECK (length(reference) = 32),
                first_seen_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, device_key, reference)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_directory_upload_nonces (
                account_key BLOB NOT NULL REFERENCES murmur_device_rosters(account_key)
                    ON DELETE CASCADE,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (account_key, nonce)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_directory_ticket_uses (
                issuer TEXT NOT NULL,
                ticket_id BLOB NOT NULL CHECK (length(ticket_id) = 32),
                claim_budget INTEGER NOT NULL CHECK (claim_budget >= 1),
                claims_used INTEGER NOT NULL CHECK (claims_used >= 1 AND claims_used <= claim_budget),
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (issuer, ticket_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_account_deletion_nonces (
                account_digest BLOB NOT NULL CHECK (length(account_digest) = 32),
                request_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (account_digest, request_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS murmur_account_purge_devices (
                account_digest BLOB NOT NULL CHECK (length(account_digest) = 32),
                device_key BLOB NOT NULL CHECK (length(device_key) = 32),
                PRIMARY KEY (account_digest, device_key)
            ) STRICT;
        `);
        const schema = this.#sql
            .exec<Record<string, unknown>>(
                `SELECT version FROM murmur_control_schema WHERE singleton = 1`,
            )
            .one();
        if (integerColumn(schema.version, "control schema version") !== 1) {
            throw new Error("Unsupported relay control schema version");
        }
    }

    #all(query: string, ...bindings: readonly RelayControlSqlValue[]): Record<string, unknown>[] {
        return this.#sql.exec<Record<string, unknown>>(query, ...bindings).toArray();
    }

    #get(
        query: string,
        ...bindings: readonly RelayControlSqlValue[]
    ): Record<string, unknown> | undefined {
        return this.#all(query, ...bindings)[0];
    }

    #requiredGet(
        query: string,
        ...bindings: readonly RelayControlSqlValue[]
    ): Record<string, unknown> {
        const row = this.#get(query, ...bindings);
        if (row === undefined) throw new Error("Missing relay control state row");
        return row;
    }

    #run(query: string, ...bindings: readonly RelayControlSqlValue[]): void {
        this.#sql.exec(query, ...bindings);
    }
}
