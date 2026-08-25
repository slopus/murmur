import { DatabaseSync, type SQLInputValue, type StatementResultingChanges } from "node:sqlite";
import { copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import type {
    PrivateGroupChallengeOperation,
    PrivateGroupMemberEntry,
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateLimits,
    PrivateGroupStateRecord,
    PrivateGroupStateStore,
    StoredPrivateGroupStateRecord,
} from "../types.js";

/** SQLite private-group store construction options for embedding. */
export interface SqlitePrivateGroupStateStoreOptions {
    readonly database?: DatabaseSync;
}

function row(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid SQLite private-group row");
    }
    return value as Record<string, unknown>;
}

function role(value: unknown): PrivateGroupRole {
    if (value !== "owner" && value !== "administrator" && value !== "member") {
        throw new Error("Invalid private-group member role in SQLite");
    }
    return value;
}

function operation(value: unknown): PrivateGroupChallengeOperation {
    if (value !== "create" && value !== "access") {
        throw new Error("Invalid private-group challenge operation in SQLite");
    }
    return value;
}

function nullableBytes(value: unknown, name: string): Uint8Array | null {
    return value === null ? null : copyBytes(value, name);
}

/** SQLite storage for canonical opaque private-group state and one-use challenges. */
export class SqlitePrivateGroupStateStore implements PrivateGroupStateStore {
    readonly #database: DatabaseSync;
    #closed = false;

    constructor(path: string, options: SqlitePrivateGroupStateStoreOptions = {}) {
        this.#database = options.database ?? new DatabaseSync(path);
        this.#database.exec("PRAGMA journal_mode = WAL");
        this.#database.exec("PRAGMA foreign_keys = ON");
        this.#database.exec("PRAGMA busy_timeout = 5000");
        this.#initializeSchema();
    }

    create(
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
    ): void {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const usage = this.#requiredGet(
                "SELECT COUNT(*) AS group_count FROM murmur_private_group_records",
            );
            if (safeNumberColumn(usage.group_count) >= limits.maximumGroups) {
                throw new Error("Private-group service group quota exceeded");
            }
            this.#run(
                `INSERT INTO murmur_private_group_records
                    (group_id, public_parameters, revision, previous_revision_hash,
                     revision_hash, sealed_state, revision_authenticator, raw_record,
                     encoded_bytes)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                record.opaqueGroupId,
                record.publicParameters,
                BigInt(record.revision),
                record.previousRevisionHash,
                revisionHash,
                record.sealedState,
                record.revisionAuthenticator,
                rawRecord,
                BigInt(rawRecord.length),
            );
            this.#insertMembers(record.opaqueGroupId, record.members);
            this.#database.exec("COMMIT");
        } catch (error: unknown) {
            this.#rollback();
            if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
                throw new Error("Private group or member entry already exists");
            }
            throw error;
        }
    }

    replace(
        expectedRevision: number,
        expectedRevisionHash: Uint8Array,
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        _limits: PrivateGroupStateLimits,
    ): void {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const current = this.#get(
                `SELECT revision, revision_hash FROM murmur_private_group_records
                 WHERE group_id = ?`,
                record.opaqueGroupId,
            );
            if (current === undefined) throw new Error("Unknown private group");
            if (
                safeNumberColumn(current.revision) !== expectedRevision ||
                !equalBytes(
                    copyBytes(current.revision_hash, "private-group revision hash"),
                    expectedRevisionHash,
                )
            ) {
                throw new Error("Private-group revision fork or stale mutation");
            }
            const changed = safeNumberColumn(
                this.#run(
                    `UPDATE murmur_private_group_records
                 SET public_parameters = ?, revision = ?, previous_revision_hash = ?,
                     revision_hash = ?, sealed_state = ?, revision_authenticator = ?,
                     raw_record = ?, encoded_bytes = ?
                 WHERE group_id = ? AND revision = ? AND revision_hash = ?`,
                    record.publicParameters,
                    BigInt(record.revision),
                    record.previousRevisionHash,
                    revisionHash,
                    record.sealedState,
                    record.revisionAuthenticator,
                    rawRecord,
                    BigInt(rawRecord.length),
                    record.opaqueGroupId,
                    BigInt(expectedRevision),
                    expectedRevisionHash,
                ).changes,
            );
            if (changed !== 1) throw new Error("Private-group revision fork or stale mutation");
            this.#run(
                "DELETE FROM murmur_private_group_members WHERE group_id = ?",
                record.opaqueGroupId,
            );
            this.#insertMembers(record.opaqueGroupId, record.members);
            this.#database.exec("COMMIT");
        } catch (error: unknown) {
            this.#rollback();
            if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
                throw new Error("Duplicate private-group member entry");
            }
            throw error;
        }
    }

    read(opaqueGroupId: Uint8Array): StoredPrivateGroupStateRecord | undefined {
        this.#assertOpen();
        const stored = this.#get(
            `SELECT public_parameters, revision, previous_revision_hash, revision_hash,
                    sealed_state, revision_authenticator
             FROM murmur_private_group_records WHERE group_id = ?`,
            opaqueGroupId,
        );
        if (stored === undefined) return undefined;
        const members = this.#all(
            `SELECT entry, role FROM murmur_private_group_members
             WHERE group_id = ? ORDER BY entry`,
            opaqueGroupId,
        ).map(
            (member): PrivateGroupMemberEntry => ({
                entry: copyBytes(member.entry, "private-group member entry"),
                role: role(member.role),
            }),
        );
        return {
            record: {
                version: 1,
                opaqueGroupId: opaqueGroupId.slice(),
                publicParameters: copyBytes(
                    stored.public_parameters,
                    "private-group public parameters",
                ),
                revision: safeNumberColumn(stored.revision),
                previousRevisionHash: nullableBytes(
                    stored.previous_revision_hash,
                    "private-group previous revision hash",
                ),
                members,
                sealedState: copyBytes(stored.sealed_state, "private-group sealed state"),
                revisionAuthenticator: copyBytes(
                    stored.revision_authenticator,
                    "private-group revision authenticator",
                ),
            },
            revisionHash: copyBytes(stored.revision_hash, "private-group revision hash"),
        };
    }

    hasMember(
        opaqueGroupId: Uint8Array,
        entry: Uint8Array,
        expectedRole: PrivateGroupRole,
    ): boolean {
        this.#assertOpen();
        return (
            this.#get(
                `SELECT 1 AS present FROM murmur_private_group_members
                 WHERE group_id = ? AND entry = ? AND role = ?`,
                opaqueGroupId,
                entry,
                expectedRole,
            ) !== undefined
        );
    }

    storeChallenge(
        challenge: PrivateGroupPresentationChallenge,
        maximumPendingChallenges: number,
        now: number,
    ): void {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            this.#run(
                "DELETE FROM murmur_private_group_challenges WHERE expires_at <= ?",
                BigInt(now),
            );
            const count = this.#requiredGet(
                "SELECT COUNT(*) AS challenge_count FROM murmur_private_group_challenges",
            );
            if (safeNumberColumn(count.challenge_count) >= maximumPendingChallenges) {
                throw new Error("Private-group presentation challenge quota exceeded");
            }
            this.#run(
                `INSERT INTO murmur_private_group_challenges
                    (replay_nonce, group_id, entry, role, operation, context, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                challenge.replayNonce,
                challenge.opaqueGroupId,
                challenge.entry,
                challenge.role,
                challenge.operation,
                challenge.context,
                BigInt(challenge.expiresAt),
            );
            this.#database.exec("COMMIT");
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    consumeChallenge(
        replayNonce: Uint8Array,
        now: number,
    ): PrivateGroupPresentationChallenge | undefined {
        this.#assertOpen();
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            this.#run(
                "DELETE FROM murmur_private_group_challenges WHERE expires_at <= ?",
                BigInt(now),
            );
            const stored = this.#get(
                `SELECT group_id, entry, role, operation, context, expires_at
                 FROM murmur_private_group_challenges WHERE replay_nonce = ?`,
                replayNonce,
            );
            if (stored === undefined) {
                this.#database.exec("COMMIT");
                return undefined;
            }
            this.#run(
                "DELETE FROM murmur_private_group_challenges WHERE replay_nonce = ?",
                replayNonce,
            );
            this.#database.exec("COMMIT");
            return {
                opaqueGroupId: copyBytes(stored.group_id, "challenge group ID"),
                entry: copyBytes(stored.entry, "challenge member entry"),
                role: role(stored.role),
                operation: operation(stored.operation),
                replayNonce: replayNonce.slice(),
                context: copyBytes(stored.context, "challenge context"),
                expiresAt: safeNumberColumn(stored.expires_at),
            };
        } catch (error: unknown) {
            this.#rollback();
            throw error;
        }
    }

    close(): void {
        if (!this.#closed) {
            this.#closed = true;
            this.#database.close();
        }
    }

    #insertMembers(opaqueGroupId: Uint8Array, members: readonly PrivateGroupMemberEntry[]): void {
        for (const member of members) {
            this.#run(
                `INSERT INTO murmur_private_group_members (group_id, entry, role)
                 VALUES (?, ?, ?)`,
                opaqueGroupId,
                member.entry,
                member.role,
            );
        }
    }

    #initializeSchema(): void {
        this.#database.exec(`
        CREATE TABLE IF NOT EXISTS murmur_private_group_schema (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            version INTEGER NOT NULL
        ) STRICT;
        INSERT OR IGNORE INTO murmur_private_group_schema (singleton, version) VALUES (1, 1);
        CREATE TABLE IF NOT EXISTS murmur_private_group_records (
            group_id BLOB PRIMARY KEY CHECK (length(group_id) = 32),
            public_parameters BLOB NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 1),
            previous_revision_hash BLOB CHECK (
                previous_revision_hash IS NULL OR length(previous_revision_hash) = 32
            ),
            revision_hash BLOB NOT NULL CHECK (length(revision_hash) = 32),
            sealed_state BLOB NOT NULL,
            revision_authenticator BLOB NOT NULL CHECK (length(revision_authenticator) = 32),
            raw_record BLOB NOT NULL,
            encoded_bytes INTEGER NOT NULL CHECK (
                encoded_bytes > 0 AND length(raw_record) = encoded_bytes
            )
        ) STRICT;
        CREATE TABLE IF NOT EXISTS murmur_private_group_members (
            group_id BLOB NOT NULL REFERENCES murmur_private_group_records(group_id)
                ON DELETE CASCADE,
            entry BLOB NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('owner', 'administrator', 'member')),
            PRIMARY KEY (group_id, entry)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS murmur_private_group_member_role
            ON murmur_private_group_members(group_id, role);
        `);
        this.#initializeChallengeSchema();
    }

    #initializeChallengeSchema(): void {
        this.#database.exec(`
        CREATE TABLE IF NOT EXISTS murmur_private_group_challenges (
            replay_nonce BLOB PRIMARY KEY CHECK (length(replay_nonce) = 32),
            group_id BLOB NOT NULL CHECK (length(group_id) = 32),
            entry BLOB NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('owner', 'administrator', 'member')),
            operation TEXT NOT NULL CHECK (operation IN ('create', 'access')),
            context BLOB NOT NULL,
            expires_at INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS murmur_private_group_challenge_expiry
            ON murmur_private_group_challenges(expires_at);
        `);
        const schema = this.#requiredGet(
            "SELECT version FROM murmur_private_group_schema WHERE singleton = 1",
        );
        if (safeNumberColumn(schema.version) !== 1) {
            throw new Error("Unsupported SQLite private-group schema version");
        }
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("SQLite private-group store is closed");
    }

    #rollback(): void {
        try {
            this.#database.exec("ROLLBACK");
        } catch {
            // The failing statement may already have aborted the transaction.
        }
    }

    #get(
        sql: string,
        ...parameters: readonly SQLInputValue[]
    ): Record<string, unknown> | undefined {
        const result = this.#database.prepare(sql).get(...parameters);
        return result === undefined ? undefined : row(result);
    }

    #requiredGet(sql: string, ...parameters: readonly SQLInputValue[]): Record<string, unknown> {
        const result = this.#get(sql, ...parameters);
        if (result === undefined) throw new Error("SQLite private-group query returned no row");
        return result;
    }

    #all(sql: string, ...parameters: readonly SQLInputValue[]): readonly Record<string, unknown>[] {
        return this.#database
            .prepare(sql)
            .all(...parameters)
            .map(row);
    }

    #run(sql: string, ...parameters: readonly SQLInputValue[]): StatementResultingChanges {
        return this.#database.prepare(sql).run(...parameters);
    }
}
